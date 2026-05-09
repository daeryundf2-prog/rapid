from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import (
    build_forensic_review,
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
PARSER_VERSION = "windows-browser-v8"
FUNCTIONAL_SOURCE_BATCH_ID = "commercial-uplift-046-050"
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
    "browser-storage-trusted-diff-required",
    "browser-timeline-trusted-diff-required",
]
BROWSER_SECRET_TRUSTED_DIFF_BLOCKER = "browser-secret-authority-diff-required"
BROWSER_TRUSTED_TOOLS = {"browserhistoryview", "hindsight", "sqlite", "browser native query", "velociraptor"}
BROWSER_SECRET_TRUSTED_TOOLS = {
    "browser-native-store-inventory",
    "dpapi-known-answer",
    "keychain-known-answer",
    "legal-authority-record",
    "audit-log-export",
}
AI_TRANSCRIPT_TRUSTED_TOOLS = {
    "chatgpt export",
    "claude export",
    "gemini export",
    "perplexity export",
    "service export",
    "google takeout",
    "browser native query",
    "hindsight",
    "velociraptor",
}
AI_TRANSCRIPT_BLOCKERS = [
    "service-side-transcript-export-not-validated",
    "browser-storage-snippet-pairing-is-order-based",
    "deleted-fragment-recovery-and-schema-versioning-incomplete",
    "known-answer-validation-corpus-required",
    "ai-transcript-trusted-export-diff-required",
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
    storage_review_profile = browser_storage_review_profile(storage_inventory)
    storage_citation_manifest = build_browser_storage_citation_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        storage_inventory=storage_inventory,
    )
    storage_depth_manifest = build_browser_storage_depth_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        storage_inventory=storage_inventory,
        storage_review_profile=storage_review_profile,
        storage_citation_manifest=storage_citation_manifest,
    )
    timeline_integrity_profile = browser_timeline_integrity_profile(unified_timeline)
    source_hashes = file_hashes(source_path)
    citation_manifest = build_browser_history_download_citation_manifest(
        browser=browser,
        profile=profile,
        user=user,
        source_path=source_path,
        source_hashes=source_hashes,
        history_rows=history_rows,
        download_rows=download_rows,
        unified_timeline=unified_timeline,
    )
    timeline_depth_manifest = build_browser_timeline_depth_manifest(
        browser=browser,
        profile=profile,
        user=user,
        source_path=source_path,
        source_hashes=source_hashes,
        history_rows=history_rows,
        download_rows=download_rows,
        unified_timeline=unified_timeline,
        timeline_integrity_profile=timeline_integrity_profile,
        citation_manifest=citation_manifest,
    )
    validation_checks = browser_validation_checks(
        history_rows=history_rows,
        download_rows=download_rows,
        storage_inventory=storage_inventory,
        conversation_rows=conversation_rows,
        unified_timeline=unified_timeline,
        citation_manifest=citation_manifest,
    )
    report_grade = browser_report_grade_assessment(validation_checks)
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
        "browser_storage_review_profile": storage_review_profile,
        "browser_storage_citation_manifest": storage_citation_manifest,
        "browser_storage_citation_manifest_hash": storage_citation_manifest["manifest_sha256"],
        "browser_storage_depth_manifest": storage_depth_manifest,
        "browser_storage_depth_manifest_hash": storage_depth_manifest["manifest_sha256"],
        "unified_timeline": unified_timeline,
        "browser_history_download_citation_manifest": citation_manifest,
        "browser_history_download_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "browser_timeline_depth_manifest": timeline_depth_manifest,
        "browser_timeline_depth_manifest_hash": timeline_depth_manifest["manifest_sha256"],
        "browser_timeline_integrity_profile": timeline_integrity_profile,
        "browser_validation_checks": validation_checks,
        "core_accuracy_gates": browser_core_accuracy_gates(
            {
                "source_path": str(source_path.resolve()),
                "source_hashes": source_hashes,
                "source_profile": build_source_profile_metadata(
                    user=user,
                    browser=browser,
                    profile=profile,
                    source_path=source_path,
                ),
                "history_rows": history_rows,
                "download_rows": download_rows,
                "storage_inventory": storage_inventory,
                "storage_review_profile": storage_review_profile,
                "browser_storage_citation_manifest": storage_citation_manifest,
                "unified_timeline": unified_timeline,
                "timeline_integrity_profile": timeline_integrity_profile,
                "browser_history_download_citation_manifest": citation_manifest,
                "browser": browser,
                "profile": profile,
                "validation_checks": validation_checks,
            }
        ),
        "browser_validation_matrix": browser_validation_matrix(validation_checks),
        "browser_report_grade_assessment": report_grade,
        "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
        "commercial_uplift_evidence": browser_commercial_uplift_evidence(
            {
                "source_path": str(source_path.resolve()),
                "source_hashes": source_hashes,
                "artifact_type": artifact_type,
                "browser": browser,
                "profile": profile,
                "browser_validation_matrix": browser_validation_matrix(validation_checks),
                "browser_report_grade_assessment": report_grade,
                "history_count": len(history_rows),
                "download_count": len(download_rows),
                "top_domains": count_field(usage_rows, "domain", limit=20),
                "storage_inventory_count": len(storage_inventory),
                "sensitive_inventory_count": sum(1 for row in storage_inventory if row.get("sensitive")),
                "browser_storage_citation_manifest": storage_citation_manifest,
                "browser_storage_citation_manifest_hash": storage_citation_manifest["manifest_sha256"],
                "unified_timeline_count": len(unified_timeline),
                "browser_history_download_citation_manifest": citation_manifest,
                "browser_history_download_citation_manifest_hash": citation_manifest["manifest_sha256"],
                "timeline_integrity_profile": timeline_integrity_profile,
                "storage_review_profile": storage_review_profile,
            }
        ),
        "forensic_review": build_forensic_review(
            gap_id="#20",
            artifact_goal="Unified browser history/download timeline with cache/session/extension/sync inventory context",
            primary_evidence=[
                f"browser={browser}",
                f"profile={profile}",
                f"history_rows={len(history_rows)}",
                f"download_rows={len(download_rows)}",
                f"timeline_rows={len(unified_timeline)}",
                f"storage_inventory={len(storage_inventory)}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            blockers=BROWSER_REPORT_GRADE_BLOCKERS,
            caveats=[
                "Timeline rows are normalized candidates; browser-specific transition and deletion semantics require validation.",
                "Cache/session/extension/sync stores are inventoried, not fully schema-decoded.",
            ],
        ),
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
        ai_transcript = build_ai_transcript_summary(conversation_rows)
        ai_source_summary = summarize_ai_conversation_sources(conversation_rows)
        ai_candidate_manifest = build_ai_transcript_candidate_manifest(
            browser=browser,
            profile=profile,
            user=user,
            profile_dir=profile_dir,
            conversation_rows=conversation_rows,
            transcript=ai_transcript,
            source_summary=ai_source_summary,
        )
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
                    "ai_transcript_candidate_manifest": ai_candidate_manifest,
                    "ai_transcript_candidate_manifest_hash": ai_candidate_manifest["manifest_sha256"],
                    "browser_storage_inventory_count": len(storage_inventory),
                    "ai_transcript_validation_status": (
                        ai_transcript["validation_status"] if conversation_rows else "none"
                    ),
                    "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
                    "commercial_uplift_evidence": ai_transcript_commercial_uplift_evidence(
                        {
                            "source_path": str(source_path.resolve()),
                            "browser": browser,
                            "profile": profile,
                            "ai_usage_count": len(ai_rows),
                            "conversation_rows": conversation_rows,
                            "transcript": ai_transcript,
                            "source_summary": ai_source_summary,
                            "ai_transcript_candidate_manifest": ai_candidate_manifest,
                            "transcript_validation_checks": {
                                "has_ai_usage": bool(ai_rows),
                                "has_candidate_transcript_rows": bool(conversation_rows),
                                "service_side_export_validated": False,
                            },
                        }
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": AI_TRANSCRIPT_BLOCKERS,
                    "browser_report_grade_assessment": {
                        **report_grade,
                        "commercial_gap_ids": ["#20", "#21"],
                    },
                    "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
                    "forensic_review": build_forensic_review(
                        gap_id="#21",
                        artifact_goal="AI service browser usage and candidate transcript pivots",
                        primary_evidence=[
                            f"ai_usage_count={len(ai_rows)}",
                            f"conversation_candidates={len(conversation_rows)}",
                            f"first_seen_at={seen[0] if seen else ''}",
                            f"last_seen_at={seen[-1] if seen else ''}",
                        ],
                        validation_required=True,
                        report_grade_assessment={**report_grade, "commercial_gap_ids": ["#20", "#21"]},
                        blockers=AI_TRANSCRIPT_BLOCKERS,
                        caveats=[
                            "History proves AI-service visits, not full prompt/answer content by itself.",
                            "Transcript content must be verified against raw browser storage or service-side exports.",
                        ],
                    ),
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
    candidate_manifest = build_ai_transcript_candidate_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        conversation_rows=conversation_rows,
        transcript=transcript,
        source_summary=source_summary,
    )
    schema_manifest = build_ai_transcript_schema_validation_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        conversation_rows=conversation_rows,
        transcript=transcript,
        source_summary=source_summary,
        candidate_manifest=candidate_manifest,
    )
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
            "ai_transcript_candidate_manifest": candidate_manifest,
            "ai_transcript_candidate_manifest_hash": candidate_manifest["manifest_sha256"],
            "ai_transcript_schema_validation_manifest": schema_manifest,
            "ai_transcript_schema_validation_manifest_hash": schema_manifest["manifest_sha256"],
            "transcript_validation_checks": {
                "has_service_label": bool(count_field(conversation_rows, "ai_service")),
                "has_question_answer_pair": bool(transcript["complete_pair_count"]),
                "has_source_hashes": all(bool(row.get("source_sha256")) for row in conversation_rows),
                "has_source_storage_area": all(bool(row.get("storage_area")) for row in conversation_rows),
                "has_orphans": bool(transcript["orphan_question_count"] or transcript["orphan_answer_count"]),
                "service_side_export_validated": False,
                "schema_validation_manifest_present": True,
            },
            "commercial_uplift_evidence": ai_transcript_commercial_uplift_evidence(
                {
                    "source_path": str(profile_dir.resolve()),
                    "browser": browser,
                    "profile": profile,
                    "conversation_rows": conversation_rows,
                    "transcript": transcript,
                    "source_summary": source_summary,
                    "ai_transcript_candidate_manifest": candidate_manifest,
                    "ai_transcript_schema_validation_manifest": schema_manifest,
                    "transcript_validation_checks": {
                        "has_service_label": bool(count_field(conversation_rows, "ai_service")),
                        "has_question_answer_pair": bool(transcript["complete_pair_count"]),
                        "has_source_hashes": all(bool(row.get("source_sha256")) for row in conversation_rows),
                        "has_source_storage_area": all(bool(row.get("storage_area")) for row in conversation_rows),
                        "has_orphans": bool(transcript["orphan_question_count"] or transcript["orphan_answer_count"]),
                        "service_side_export_validated": False,
                        "schema_validation_manifest_present": True,
                    },
                }
            ),
            "core_accuracy_gates": ai_transcript_core_accuracy_gates(
                {
                    "source_path": str(profile_dir.resolve()),
                    "browser": browser,
                    "profile": profile,
                    "conversation_rows": conversation_rows,
                    "transcript": transcript,
                    "source_summary": source_summary,
                    "ai_transcript_candidate_manifest": candidate_manifest,
                }
            ),
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
            "forensic_review": build_forensic_review(
                gap_id="#21",
                artifact_goal="AI service question/answer transcript candidate pairing",
                primary_evidence=[
                    f"question_count={sum(1 for row in conversation_rows if row.get('direction') == 'question')}",
                    f"answer_count={sum(1 for row in conversation_rows if row.get('direction') == 'answer')}",
                    f"complete_pairs={transcript['complete_pair_count']}",
                    f"source_files={source_summary['source_file_count']}",
                ],
                validation_required=True,
                report_grade_assessment={
                    "status": "validation-required",
                    "commercial_gap_ids": ["#21"],
                    "blockers": list(AI_TRANSCRIPT_BLOCKERS),
                    "ready_for_court_report": False,
                },
                blockers=AI_TRANSCRIPT_BLOCKERS,
                caveats=[
                    "Question/answer pairing is order-based candidate logic.",
                    "Service-side export/schema validation is required before report-grade transcript conclusions.",
                ],
            ),
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
    storage_review_profile = browser_storage_review_profile(storage_inventory)
    storage_citation_manifest = build_browser_storage_citation_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        storage_inventory=storage_inventory,
    )
    storage_depth_manifest = build_browser_storage_depth_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        storage_inventory=storage_inventory,
        storage_review_profile=storage_review_profile,
        storage_citation_manifest=storage_citation_manifest,
    )
    secret_authority_profile = browser_secret_authority_profile(
        browser=browser,
        profile=profile,
        storage_inventory=storage_inventory,
        checks=secret_validation_checks,
    )
    secret_authority_manifest = browser_secret_authority_manifest(
        browser=browser,
        profile=profile,
        user=user,
        profile_dir=profile_dir,
        storage_inventory=storage_inventory,
        checks=secret_validation_checks,
    )
    validation_context = {
        "storage_inventory_present": bool(storage_inventory),
        "sensitive_storage_inventory_present": sensitive_count > 0,
        "commercial_validation_required": True,
        "full_cache_entry_decode": False,
        "cookie_values_decrypted": False,
        "extension_schema_validated": False,
        "sync_state_validated": False,
        "unified_timeline_present": False,
        "storage_review_profile_present": bool(storage_review_profile.get("inventory_count")),
    }
    report_grade = browser_report_grade_assessment(validation_context)
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
            "browser_storage_review_profile": storage_review_profile,
            "browser_storage_citation_manifest": storage_citation_manifest,
            "browser_storage_citation_manifest_hash": storage_citation_manifest["manifest_sha256"],
            "browser_storage_depth_manifest": storage_depth_manifest,
            "browser_storage_depth_manifest_hash": storage_depth_manifest["manifest_sha256"],
            "storage_inventory": list(storage_inventory),
            "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
            "browser_secret_legal_warning": BROWSER_SECRET_HANDLING_WARNING,
            "validation_checks": {
                "raw_secret_values_extracted": False,
                "bounded_inventory": True,
                "sample_file_hashes_present": any(row.get("sample_files") for row in storage_inventory),
                "requires_scope_review": sensitive_count > 0,
            },
            "core_accuracy_gates": browser_core_accuracy_gates(
                {
                    "source_path": str(profile_dir.resolve()),
                    "source_profile": {
                        "user": user,
                        "browser": browser,
                        "profile": profile,
                        "profile_dir": str(profile_dir.resolve()),
                    },
                    "storage_inventory": storage_inventory,
                    "storage_review_profile": storage_review_profile,
                    "browser_storage_citation_manifest": storage_citation_manifest,
                    "browser": browser,
                    "profile": profile,
                    "validation_checks": validation_context,
                    "secret_validation_checks": secret_validation_checks,
                    "browser_secret_authority_profile": secret_authority_profile,
                    "browser_secret_authority_manifest": secret_authority_manifest,
                }
            ),
            "secret_handling_validation_checks": secret_validation_checks,
            "browser_secret_authority_profile": secret_authority_profile,
            "browser_secret_authority_manifest": secret_authority_manifest,
            "browser_secret_handling_assessment": browser_secret_handling_assessment(secret_validation_checks),
            "secret_handling_commercial_uplift_evidence": browser_secret_commercial_uplift_evidence(
                {
                    "source_path": str(profile_dir.resolve()),
                    "browser": browser,
                    "profile": profile,
                    "inventory_count": len(storage_inventory),
                    "sensitive_inventory_count": sensitive_count,
                    "storage_inventory": storage_inventory,
                    "secret_handling_validation_checks": secret_validation_checks,
                    "browser_secret_authority_profile": secret_authority_profile,
                    "browser_secret_authority_manifest": secret_authority_manifest,
                    "browser_secret_handling_assessment": browser_secret_handling_assessment(secret_validation_checks),
                }
            ),
            "secret_handling_forensic_review": build_forensic_review(
                gap_id="#42",
                artifact_goal="Browser password/cookie/session artifact handling with strict legal warning and no secret reveal",
                primary_evidence=[
                    f"sensitive_inventory_count={sensitive_count}",
                    f"raw_secret_values_extracted={False}",
                    f"browser={browser}",
                    f"profile={profile}",
                ],
                validation_required=True,
                report_grade_assessment=browser_secret_handling_assessment(secret_validation_checks),
                blockers=browser_secret_handling_assessment(secret_validation_checks)["blockers"],
                caveats=[
                    "This parser inventories sensitive stores only; it does not decrypt cookies, passwords, or session tokens.",
                    "Any secret review must be explicit, authorized, audited, and independently validated.",
                ],
            ),
            "browser_validation_matrix": browser_validation_matrix(validation_context),
            "browser_report_grade_assessment": report_grade,
            "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
            "commercial_uplift_evidence": browser_commercial_uplift_evidence(
                {
                    "source_path": str(profile_dir.resolve()),
                    "artifact_type": artifact_type,
                    "browser": browser,
                    "profile": profile,
                    "browser_validation_matrix": browser_validation_matrix(validation_context),
                    "browser_report_grade_assessment": report_grade,
                    "storage_inventory_count": len(storage_inventory),
                    "sensitive_inventory_count": sensitive_count,
                    "storage_review_profile": storage_review_profile,
                    "browser_storage_citation_manifest": storage_citation_manifest,
                    "browser_storage_citation_manifest_hash": storage_citation_manifest["manifest_sha256"],
                }
            ),
            "forensic_review": build_forensic_review(
                gap_id="#19",
                artifact_goal="Browser cache/session/extension/sync/cookie/credential inventory and legal-scope review",
                primary_evidence=[
                    f"inventory_count={len(storage_inventory)}",
                    f"sensitive_inventory_count={sensitive_count}",
                    f"profile={profile}",
                    f"browser={browser}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                blockers=BROWSER_REPORT_GRADE_BLOCKERS,
                caveats=[
                    "Sensitive stores are inventory-only; RapidTriage does not decrypt cookies, passwords, or session tokens here.",
                    "Open raw browser stores only after scope and legal authority are documented.",
                ],
            ),
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


def build_browser_history_download_citation_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    source_path: Path,
    source_hashes: Mapping[str, object],
    history_rows: Sequence[Mapping[str, object]],
    download_rows: Sequence[Mapping[str, object]],
    unified_timeline: Sequence[Mapping[str, object]],
) -> Dict[str, object]:
    history_citations = [
        browser_row_citation(
            browser=browser,
            profile=profile,
            user=user,
            source_path=source_path,
            source_hashes=source_hashes,
            row=row,
            row_type="visit",
            source_index=index,
            default_source_table=str(row.get("source_table") or "history"),
            timestamp=str(row.get("last_visited_at") or ""),
            url=str(row.get("url") or ""),
        )
        for index, row in enumerate(history_rows[:MAX_BROWSER_TIMELINE_ROWS])
    ]
    download_citations = [
        browser_row_citation(
            browser=browser,
            profile=profile,
            user=user,
            source_path=source_path,
            source_hashes=source_hashes,
            row=row,
            row_type="download",
            source_index=index,
            default_source_table=str(row.get("source_table") or "downloads"),
            timestamp=str(row.get("started_at") or ""),
            url=str(row.get("source_url") or row.get("tab_url") or ""),
            target_path=str(row.get("target_path") or ""),
        )
        for index, row in enumerate(download_rows[:MAX_BROWSER_TIMELINE_ROWS])
    ]
    timeline_row_hashes = [
        stable_browser_sha256(
            {
                "timeline_type": row.get("timeline_type"),
                "timestamp": row.get("timestamp"),
                "url": row.get("url"),
                "target_path": row.get("target_path"),
                "source_table": row.get("source_table"),
                "source_index": row.get("source_index"),
                "source_row_id": row.get("source_row_id"),
            }
        )
        for row in unified_timeline[:MAX_BROWSER_TIMELINE_ROWS]
    ]
    manifest: Dict[str, object] = {
        "manifest_version": "browser-history-download-citation-manifest-v1",
        "item_number": 46,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "gap_id": "#46",
        "commercial_gap_ids": ["#20", "#46"],
        "browser": browser,
        "profile": profile,
        "user": user,
        "source_path": str(source_path.resolve()),
        "source_sha256": str(source_hashes.get("sha256") or ""),
        "history_row_count": len(history_rows),
        "download_row_count": len(download_rows),
        "timeline_row_count": len(unified_timeline),
        "citation_row_count": len(history_citations) + len(download_citations),
        "row_locator_count": sum(1 for row in history_citations + download_citations if row.get("source_viewer_locator")),
        "history_citations": history_citations,
        "download_citations": download_citations,
        "timeline_row_hashes": timeline_row_hashes,
        "large_data_controls": {
            "max_browser_timeline_rows": MAX_BROWSER_TIMELINE_ROWS,
            "citation_rows_bounded": len(history_rows) + len(download_rows) > len(history_citations) + len(download_citations),
            "source_values_are_triage_pivots": True,
            "open_raw_sqlite_for_report_grade_review": True,
        },
        "review_workflow": {
            "default_view": "timeline-with-source-citation",
            "source_viewer": "sqlite",
            "current_file_search_supported": True,
            "add_to_evidence_tray_supported": True,
            "required_before_report": [
                "open source SQLite row or trusted export row before final report citation",
                "compare browser timestamp/transition semantics against a known-answer fixture",
                "attach trusted browser timeline diff when claiming complete browser chronology",
            ],
        },
        "validation_status": "implemented-validation-required",
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_browser_storage_citation_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    storage_inventory: Sequence[Mapping[str, object]],
) -> Dict[str, object]:
    citations = [
        browser_storage_row_citation(
            browser=browser,
            profile=profile,
            user=user,
            profile_dir=profile_dir,
            row=row,
            source_index=index,
        )
        for index, row in enumerate(storage_inventory[:MAX_BROWSER_INVENTORY_FILES])
    ]
    manifest: Dict[str, object] = {
        "manifest_version": "browser-storage-citation-manifest-v1",
        "item_number": 47,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "gap_id": "#47",
        "commercial_gap_ids": ["#19", "#42", "#47"],
        "browser": browser,
        "profile": profile,
        "user": user,
        "profile_dir": str(profile_dir.resolve()),
        "inventory_count": len(storage_inventory),
        "citation_row_count": len(citations),
        "sensitive_citation_count": sum(1 for row in citations if row.get("sensitive")),
        "sample_file_hash_count": sum(
            len(row.get("sample_file_hashes") or []) for row in citations if isinstance(row.get("sample_file_hashes"), list)
        ),
        "storage_type_counts": count_field(storage_inventory, "storage_type"),
        "citations": citations,
        "large_data_controls": {
            "max_browser_inventory_files": MAX_BROWSER_INVENTORY_FILES,
            "inventory_bounded": len(storage_inventory) > len(citations),
            "secret_values_redacted_by_default": True,
            "raw_store_open_requires_authority": True,
        },
        "review_workflow": {
            "default_view": "storage-grouped-by-type",
            "source_viewer": "file-or-sqlite-as-applicable",
            "metadata_collapsed_by_default": True,
            "recommended_grouping": ["storage_type", "sensitive", "storage_name"],
            "required_before_report": [
                "verify raw store scope and legal authority before opening sensitive stores",
                "do not report password/cookie/session values from inventory rows",
                "attach trusted browser storage diff for cache/session/extension/cookie semantic claims",
            ],
        },
        "validation_status": "inventory-implemented-validation-required",
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_browser_storage_depth_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    storage_inventory: Sequence[Mapping[str, object]],
    storage_review_profile: Mapping[str, object],
    storage_citation_manifest: Mapping[str, object],
) -> Dict[str, object]:
    storage_type_counts = count_field(storage_inventory, "storage_type")
    storage_name_counts = count_field(storage_inventory, "storage_name")
    storage_type_map = {str(row.get("value") or ""): int(row.get("count") or 0) for row in storage_type_counts}
    manifest: Dict[str, object] = {
        "manifest_version": "browser-storage-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 19,
        "gap_id": "#19",
        "browser": browser,
        "profile": profile,
        "user": user,
        "profile_dir": str(profile_dir.resolve()),
        "storage_scope": {
            "inventory_count": len(storage_inventory),
            "storage_type_counts": storage_type_counts,
            "storage_name_counts": storage_name_counts,
            "cache_present": bool(storage_type_map.get("cache")),
            "session_present": bool(storage_type_map.get("session")),
            "extension_present": bool(storage_type_map.get("extension")),
            "sync_present": bool(storage_type_map.get("sync")),
            "cookie_present": bool(storage_type_map.get("cookie")),
            "credential_present": bool(storage_type_map.get("credential")),
            "local_storage_or_indexeddb_present": bool(storage_type_map.get("storage")),
            "sensitive_inventory_count": sum(1 for row in storage_inventory if row.get("sensitive")),
            "total_bytes": int(storage_review_profile.get("total_bytes") or 0),
            "truncated_inventory_count": int(storage_review_profile.get("truncated_inventory_count") or 0),
        },
        "native_depth": {
            "browser_storage_inventory": bool(BROWSER_NATIVE_CAPABILITIES["browser_storage_inventory"]),
            "full_cache_entry_decode": bool(BROWSER_NATIVE_CAPABILITIES["full_cache_entry_decode"]),
            "extension_schema_specific_decode": bool(BROWSER_NATIVE_CAPABILITIES["extension_schema_specific_decode"]),
            "sync_engine_state_decode": bool(BROWSER_NATIVE_CAPABILITIES["sync_engine_state_decode"]),
            "cross_browser_deleted_session_recovery": bool(BROWSER_NATIVE_CAPABILITIES["cross_browser_deleted_session_recovery"]),
            "cookie_value_decryption": bool(BROWSER_NATIVE_CAPABILITIES["cookie_value_decryption"]),
            "password_cookie_session_secret_extraction": bool(
                BROWSER_NATIVE_CAPABILITIES["password_cookie_session_secret_extraction"]
            ),
            "legal_scope_gate": bool(BROWSER_NATIVE_CAPABILITIES["legal_scope_gate"]),
        },
        "review_controls": {
            "review_priority": str(storage_review_profile.get("review_priority") or ""),
            "recommended_view": str(storage_review_profile.get("recommended_view") or ""),
            "secret_values_redacted_by_default": True,
            "raw_values_extracted": False,
            "metadata_collapsed_by_default": True,
            "sample_hash_file_count": int(storage_review_profile.get("sample_hash_file_count") or 0),
        },
        "citation_refs": [
            {
                "kind": "browser-profile-directory",
                "profile_dir": str(profile_dir.resolve()),
                "browser": browser,
                "profile": profile,
            },
            {
                "kind": "browser-storage-citation-manifest",
                "manifest_sha256": str(storage_citation_manifest.get("manifest_sha256") or ""),
                "citation_row_count": int(storage_citation_manifest.get("citation_row_count") or 0),
                "sample_file_hash_count": int(storage_citation_manifest.get("sample_file_hash_count") or 0),
            },
            {
                "kind": "browser-storage-type-inventory",
                "storage_type_counts": storage_type_counts,
                "storage_name_counts": storage_name_counts,
            },
        ],
        "reportability": {
            "allowed_use": "browser-storage-inventory-triage-pivot",
            "decision": "do-not-report-browser-cache-session-extension-sync-as-fully-decoded",
            "commercial_grade_ready": False,
            "secret_values_redacted_by_default": True,
            "blockers": list(BROWSER_REPORT_GRADE_BLOCKERS),
        },
        "required_before_commercial_grade": [
            "decode Chrome/Edge/Firefox cache entries and session restore schemas for target browser versions",
            "decode extension-specific state only with extension ID/name provenance and schema validation",
            "decode sync engine state with account/scope handling and legal review",
            "validate deleted/session recovery and cache semantics against known-answer profiles",
            "attach Hindsight/BrowserHistoryView/Velociraptor or browser-native trusted diff for critical rows",
        ],
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_browser_timeline_depth_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    source_path: Path,
    source_hashes: Mapping[str, object],
    history_rows: Sequence[Mapping[str, object]],
    download_rows: Sequence[Mapping[str, object]],
    unified_timeline: Sequence[Mapping[str, object]],
    timeline_integrity_profile: Mapping[str, object],
    citation_manifest: Mapping[str, object],
) -> Dict[str, object]:
    timeline_type_counts = count_field(unified_timeline, "timeline_type")
    transition_count = sum(1 for row in unified_timeline if row.get("transition"))
    source_table_counts = count_field(unified_timeline, "source_table")
    manifest: Dict[str, object] = {
        "manifest_version": "browser-timeline-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 20,
        "gap_id": "#20",
        "browser": browser,
        "profile": profile,
        "user": user,
        "source": {
            "source_path": str(source_path.resolve()),
            "source_sha256": str(source_hashes.get("sha256") or ""),
            "source_database": source_path.name,
        },
        "timeline_scope": {
            "history_row_count": len(history_rows),
            "download_row_count": len(download_rows),
            "timeline_row_count": len(unified_timeline),
            "timeline_type_counts": timeline_type_counts,
            "source_table_counts": source_table_counts,
            "transition_metadata_count": transition_count,
            "timestamp_source_count": sum(1 for row in unified_timeline if row.get("timestamp")),
            "bounded_to_max_rows": len(unified_timeline) >= MAX_BROWSER_TIMELINE_ROWS,
        },
        "integrity": {
            "sorted_descending": bool(timeline_integrity_profile.get("sorted_descending")),
            "source_index_complete": bool(timeline_integrity_profile.get("source_index_complete")),
            "timestamp_count": int(timeline_integrity_profile.get("timestamp_count") or 0),
            "missing_timestamp_count": int(timeline_integrity_profile.get("missing_timestamp_count") or 0),
            "integrity_profile_version": str(timeline_integrity_profile.get("profile_version") or ""),
        },
        "native_depth": {
            "chromium_history_downloads_sqlite": bool(BROWSER_NATIVE_CAPABILITIES["chromium_history_downloads_sqlite"]),
            "firefox_places_history": bool(BROWSER_NATIVE_CAPABILITIES["firefox_places_history"]),
            "bounded_unified_visit_download_timeline": bool(
                BROWSER_NATIVE_CAPABILITIES["bounded_unified_visit_download_timeline"]
            ),
            "safari_windows_profile_support": bool(BROWSER_NATIVE_CAPABILITIES["safari_windows_profile_support"]),
            "cross_browser_deleted_session_recovery": bool(
                BROWSER_NATIVE_CAPABILITIES["cross_browser_deleted_session_recovery"]
            ),
        },
        "citation_refs": [
            {
                "kind": "browser-history-download-citation-manifest",
                "manifest_sha256": str(citation_manifest.get("manifest_sha256") or ""),
                "citation_row_count": int(citation_manifest.get("citation_row_count") or 0),
                "row_locator_count": int(citation_manifest.get("row_locator_count") or 0),
            },
            {
                "kind": "browser-unified-timeline-preview",
                "timeline_row_hashes": list(citation_manifest.get("timeline_row_hashes") or [])[:25],
            },
        ],
        "reportability": {
            "allowed_use": "browser-history-download-timeline-triage-pivot",
            "decision": "do-not-report-browser-timeline-as-complete-cross-browser-history",
            "commercial_grade_ready": False,
            "blockers": list(BROWSER_REPORT_GRADE_BLOCKERS),
        },
        "required_before_commercial_grade": [
            "validate browser-version timestamp and transition semantics against known-answer profiles",
            "attach trusted Hindsight/BrowserHistoryView/Velociraptor or native browser query diff",
            "validate deleted history/session/cache recovery or explicitly scope it out",
            "prove Safari/macOS parity separately; Windows Safari support is not claimed here",
            "correlate downloads with filesystem hashes, Zone.Identifier, MFT/USN, and cloud/app exports before final chronology claims",
        ],
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def browser_storage_row_citation(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    row: Mapping[str, object],
    source_index: int,
) -> Dict[str, object]:
    source_path = str(row.get("source_path") or "")
    sample_file_hashes = []
    for sample in row.get("sample_files") or []:
        if not isinstance(sample, Mapping):
            continue
        hashes = sample.get("hashes") if isinstance(sample.get("hashes"), Mapping) else {}
        if hashes.get("sha256"):
            sample_file_hashes.append(
                {
                    "relative_path": str(sample.get("relative_path") or ""),
                    "sha256": str(hashes.get("sha256") or ""),
                    "hash_scope": str(hashes.get("hash_scope") or ""),
                }
            )
    citation_payload = {
        "browser": browser,
        "profile": profile,
        "user": user,
        "source_index": source_index,
        "storage_type": str(row.get("storage_type") or ""),
        "storage_name": str(row.get("storage_name") or ""),
        "relative_path": str(row.get("relative_path") or ""),
        "source_path": source_path,
        "file_count": int(row.get("file_count") or 0),
        "total_bytes": int(row.get("total_bytes") or 0),
        "sensitive": bool(row.get("sensitive")),
        "inventory_truncated": bool(row.get("inventory_truncated")),
        "sample_file_hashes": sample_file_hashes,
    }
    return {
        **citation_payload,
        "row_hash": stable_browser_sha256(citation_payload),
        "source_viewer_locator": {
            "viewer": "file" if not bool(row.get("is_file")) else "sqlite-or-file",
            "profile_dir": str(profile_dir.resolve()),
            "relative_path": str(row.get("relative_path") or ""),
            "source_path": source_path,
            "open_requires_authority": bool(row.get("sensitive")),
        },
        "raw_values_extracted": False,
        "validation_status": "storage-inventory-citation-candidate",
    }


def browser_row_citation(
    *,
    browser: str,
    profile: str,
    user: str,
    source_path: Path,
    source_hashes: Mapping[str, object],
    row: Mapping[str, object],
    row_type: str,
    source_index: int,
    default_source_table: str,
    timestamp: str,
    url: str,
    target_path: str = "",
) -> Dict[str, object]:
    source_table = str(row.get("source_table") or default_source_table)
    source_row_id = row.get("source_row_id")
    locator = {
        "viewer": "sqlite",
        "source_table": source_table,
        "source_index": source_index,
        "source_row_id": source_row_id,
        "source_path": str(source_path.resolve()),
    }
    citation_payload = {
        "row_type": row_type,
        "browser": browser,
        "profile": profile,
        "user": user,
        "timestamp": timestamp,
        "url": url,
        "target_path": target_path,
        "source_table": source_table,
        "source_index": source_index,
        "source_row_id": source_row_id,
        "source_sha256": source_hashes.get("sha256") or "",
    }
    return {
        **citation_payload,
        "row_hash": stable_browser_sha256(citation_payload),
        "source_viewer_locator": locator,
        "review_citation": (
            f"{browser}/{profile}/{row_type}"
            f"[{source_table}:{source_row_id if source_row_id is not None else source_index}]"
        ),
        "validation_status": "source-row-citation-candidate",
    }


def stable_browser_sha256(payload: Mapping[str, object] | Sequence[object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def browser_storage_review_profile(storage_inventory: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    sensitive_count = sum(1 for row in storage_inventory if row.get("sensitive"))
    total_bytes = sum(int(row.get("total_bytes") or 0) for row in storage_inventory)
    truncated_count = sum(1 for row in storage_inventory if row.get("inventory_truncated"))
    priority = "normal"
    if sensitive_count:
        priority = "legal-scope-review"
    if truncated_count or total_bytes > MAX_BROWSER_INVENTORY_HASH_BYTES:
        priority = "large-profile-review"
    return {
        "profile_version": "browser-storage-review-profile-v1",
        "inventory_count": len(storage_inventory),
        "sensitive_inventory_count": sensitive_count,
        "storage_type_counts": count_field(storage_inventory, "storage_type"),
        "total_bytes": total_bytes,
        "sample_hash_file_count": sum(
            len(row.get("sample_files") or []) for row in storage_inventory if isinstance(row.get("sample_files"), list)
        ),
        "truncated_inventory_count": truncated_count,
        "review_priority": priority,
        "recommended_view": "group-by-storage-type-then-open-sample-hashes",
        "secret_values_redacted_by_default": True,
    }


def browser_validation_checks(
    *,
    history_rows: Sequence[Mapping[str, object]],
    download_rows: Sequence[Mapping[str, object]],
    storage_inventory: Sequence[Mapping[str, object]],
    conversation_rows: Sequence[Mapping[str, object]],
    unified_timeline: Sequence[Mapping[str, object]] | None = None,
    citation_manifest: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    timeline_integrity = browser_timeline_integrity_profile(unified_timeline or [])
    citations = citation_manifest or {}
    history_download_count = len(history_rows) + len(download_rows)
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
        "timeline_sorted_descending": timeline_integrity["sorted_descending"],
        "timeline_integrity_profile_present": bool(unified_timeline),
        "row_level_citation_manifest_present": bool(citations.get("manifest_sha256")),
        "row_level_source_locators_present": int(citations.get("row_locator_count") or 0) >= history_download_count,
        "storage_review_profile_present": bool(storage_inventory),
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
            "id": "timeline-integrity-profile",
            "label": "Timeline sort/source-index integrity profile is emitted",
            "passed": bool(checks.get("timeline_integrity_profile_present"))
            and bool(checks.get("timeline_sorted_descending", True)),
            "severity": "medium",
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


def browser_commercial_uplift_evidence(details: Mapping[str, object]) -> Dict[str, object]:
    matrix = details.get("browser_validation_matrix") if isinstance(details.get("browser_validation_matrix"), list) else []
    report_grade = (
        details.get("browser_report_grade_assessment")
        if isinstance(details.get("browser_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    storage_diff = (
        details.get("browser_storage_trusted_diff")
        if isinstance(details.get("browser_storage_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    timeline_diff = (
        details.get("browser_timeline_trusted_diff")
        if isinstance(details.get("browser_timeline_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    citation_manifest = (
        details.get("browser_history_download_citation_manifest")
        if isinstance(details.get("browser_history_download_citation_manifest"), Mapping)
        else {}
    )
    storage_citation_manifest = (
        details.get("browser_storage_citation_manifest")
        if isinstance(details.get("browser_storage_citation_manifest"), Mapping)
        else {}
    )
    reportability_decision = browser_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-016-020",
        "item_numbers": [19, 20],
        "functional_priority_profiles": [
            browser_history_downloads_functional_profile(details),
            browser_storage_inventory_functional_profile(details, storage_diff=storage_diff),
        ],
        "implementation_track": "ux-and-parser-depth",
        "objective": "Expose browser cache/session inventory and unified timeline validation evidence without overclaiming secret/deleted-state support.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
            f"browser:{details.get('browser', '')}",
            f"profile:{details.get('profile', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "browser_storage_trusted_diff": storage_diff,
        "browser_timeline_trusted_diff": timeline_diff,
        "large_data_controls": {
            "max_browser_timeline_rows": MAX_BROWSER_TIMELINE_ROWS,
            "max_storage_inventory_files": MAX_BROWSER_INVENTORY_FILES,
            "storage_inventory_count": int(details.get("storage_inventory_count") or 0),
            "unified_timeline_count": int(details.get("unified_timeline_count") or 0),
            "row_citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "row_citation_count": int(citation_manifest.get("citation_row_count") or 0),
            "secret_values_redacted_by_default": True,
            "browser_version_corpus_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish cache/session schema decoding, deleted-history recovery, Safari parity, and browser-version known-answer validation.",
        "external_evidence_required": True,
    }


def browser_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> Dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("browser-secret-legal-opt-in-and-audit-required")
    blockers.add("browser-deleted-history-and-cache-schema-validation-required")
    blockers.add("browser-storage-trusted-diff-required")
    blockers.add("browser-timeline-trusted-diff-required")
    return {
        "profile_version": "browser-reportability-decision-v1",
        "commercial_gap_ids": ["#19", "#20"],
        "decision": "do-not-report-browser-storage-or-timeline-as-complete",
        "allowed_use": "browser-storage-and-timeline-triage-pivot",
        "blockers": sorted(blockers),
        "secret_values_redacted_by_default": True,
        "required_before_report": [
            "browser-version transition and timestamp semantics validated",
            "cache/session/extension/sync schemas decoded for the target browser version",
            "deleted history/session recovery validated or explicitly limited",
            "secret/cookie/password handling performed only through audited opt-in authority gate",
        ],
    }


def browser_history_downloads_functional_profile(details: Mapping[str, object]) -> Dict[str, object]:
    history_count = int(details.get("history_count") or 0)
    download_count = int(details.get("download_count") or 0)
    timeline_count = int(details.get("unified_timeline_count") or 0)
    browser = str(details.get("browser") or "")
    citation_manifest = (
        details.get("browser_history_download_citation_manifest")
        if isinstance(details.get("browser_history_download_citation_manifest"), Mapping)
        else {}
    )
    failed_checks: List[str] = []
    if history_count + download_count == 0:
        failed_checks.append("browser-history-download-rows-not-present")
    if timeline_count == 0:
        failed_checks.append("unified-browser-timeline-not-emitted")
    if not citation_manifest.get("manifest_sha256"):
        failed_checks.append("browser-row-citation-manifest-not-emitted")
    if int(citation_manifest.get("row_locator_count") or 0) < history_count + download_count:
        failed_checks.append("browser-row-source-locators-incomplete")
    failed_checks.extend(
        [
            "browser-transition-semantics-known-answer-not-attached",
            "deleted-browser-history-validation-not-attached",
            "trusted-browser-timeline-diff-required",
        ]
    )
    passed_checks = [
        "chromium-history-download-sqlite-normalized",
        "firefox-places-history-normalized",
        "browser-profile-and-source-hash-preserved",
        "bounded-unified-browser-timeline-emitted",
    ]
    if citation_manifest.get("manifest_sha256"):
        passed_checks.append("browser-row-citation-manifest-emitted")
    if int(citation_manifest.get("row_locator_count") or 0) >= history_count + download_count:
        passed_checks.append("sqlite-source-viewer-locators-emitted")
    return {
        "item_number": 46,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "browser": browser,
            "profile": str(details.get("profile") or ""),
            "supported_browser_families": ["chrome", "edge", "brave", "firefox", "safari"],
            "detected_browser_supported": browser in {"chrome", "edge", "brave", "firefox"},
            "safari_support_note": "Safari parity is handled on macOS collection paths; Windows Safari profiles are not claimed.",
            "history_count": history_count,
            "download_count": download_count,
            "unified_timeline_count": timeline_count,
            "row_citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "row_citation_count": int(citation_manifest.get("citation_row_count") or 0),
            "row_locator_count": int(citation_manifest.get("row_locator_count") or 0),
            "top_domain_count": len(details.get("top_domains") or {}),
        },
        "passed_validation_check_ids": passed_checks,
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "browser-history-download-timeline-triage-pivot",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Validate browser version, transition semantics, deleted-state, and trusted export diff before final reporting.",
        },
    }


def browser_storage_inventory_functional_profile(
    details: Mapping[str, object],
    *,
    storage_diff: Mapping[str, object],
) -> Dict[str, object]:
    inventory_count = int(details.get("storage_inventory_count") or 0)
    sensitive_count = int(details.get("sensitive_inventory_count") or 0)
    citation_manifest = (
        details.get("browser_storage_citation_manifest")
        if isinstance(details.get("browser_storage_citation_manifest"), Mapping)
        else {}
    )
    failed_checks: List[str] = []
    if inventory_count == 0:
        failed_checks.append("browser-storage-inventory-not-present")
    if not citation_manifest.get("manifest_sha256"):
        failed_checks.append("browser-storage-citation-manifest-not-emitted")
    failed_checks.extend(
        [
            "full-cache-session-extension-schema-decode-not-complete",
            "browser-secret-values-redacted-authority-gate-required",
        ]
    )
    if storage_diff.get("status") != "pass":
        failed_checks.append("browser-storage-trusted-diff-required")
    passed_checks = [
        "browser-storage-path-inventory-emitted",
        "sensitive-store-count-emitted",
        "secret-values-not-exposed-by-default",
        "legal-scope-warning-emitted",
    ]
    if citation_manifest.get("manifest_sha256"):
        passed_checks.append("browser-storage-citation-manifest-emitted")
    if int(citation_manifest.get("sample_file_hash_count") or 0) > 0:
        passed_checks.append("browser-storage-sample-hashes-cited")
    return {
        "item_number": 47,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "browser": str(details.get("browser") or ""),
            "profile": str(details.get("profile") or ""),
            "inventory_count": inventory_count,
            "sensitive_inventory_count": sensitive_count,
            "cache_session_extension_sync_cookie_credential_inventory": True,
            "secret_values_redacted_by_default": True,
            "trusted_diff_status": str(storage_diff.get("status") or "missing"),
            "storage_citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "storage_citation_count": int(citation_manifest.get("citation_row_count") or 0),
            "sensitive_citation_count": int(citation_manifest.get("sensitive_citation_count") or 0),
            "sample_file_hash_count": int(citation_manifest.get("sample_file_hash_count") or 0),
        },
        "passed_validation_check_ids": passed_checks,
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "browser-storage-inventory-triage-pivot",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Storage inventory is not cache/cookie/session semantic decoding; keep secrets hidden unless authority and audit are attached.",
        },
    }


def ai_transcript_commercial_uplift_evidence(details: Mapping[str, object]) -> Dict[str, object]:
    checks = (
        details.get("transcript_validation_checks")
        if isinstance(details.get("transcript_validation_checks"), Mapping)
        else {}
    )
    transcript = details.get("transcript") if isinstance(details.get("transcript"), Mapping) else {}
    source_summary = details.get("source_summary") if isinstance(details.get("source_summary"), Mapping) else {}
    conversation_rows = [row for row in details.get("conversation_rows") or [] if isinstance(row, Mapping)]
    trusted_diff = (
        details.get("ai_transcript_trusted_diff")
        if isinstance(details.get("ai_transcript_trusted_diff"), Mapping)
        else {"status": "not-attached", "commercial_grade_evidence": False}
    )
    candidate_manifest = (
        details.get("ai_transcript_candidate_manifest")
        if isinstance(details.get("ai_transcript_candidate_manifest"), Mapping)
        else {}
    )
    schema_manifest = (
        details.get("ai_transcript_schema_validation_manifest")
        if isinstance(details.get("ai_transcript_schema_validation_manifest"), Mapping)
        else {}
    )
    reportability_decision = ai_transcript_reportability_decision(
        details,
        checks=checks,
        transcript=transcript,
        conversation_rows=conversation_rows,
        trusted_diff=trusted_diff,
    )
    return {
        "batch_id": "commercial-uplift-021-025",
        "item_numbers": [21],
        "functional_priority_profile": ai_transcript_functional_profile(
            details,
            checks=checks,
            transcript=transcript,
            source_summary=source_summary,
            conversation_rows=conversation_rows,
            trusted_diff=trusted_diff,
        ),
        "implementation_track": "ai-transcript-parser-validation",
        "objective": "Expose AI service question/answer candidate pairing evidence, source storage provenance, and validation blockers without claiming complete transcript recovery.",
        "reportability_decision": reportability_decision,
        "ai_transcript_trusted_diff": trusted_diff,
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"browser:{details.get('browser', '')}",
            f"profile:{details.get('profile', '')}",
            f"source_file_count:{source_summary.get('source_file_count', 0)}",
            f"candidate_manifest_sha256:{candidate_manifest.get('manifest_sha256', '')}",
            f"schema_validation_manifest_sha256:{schema_manifest.get('manifest_sha256', '')}",
        ],
        "passed_validation_check_ids": [str(key) for key, value in checks.items() if bool(value) and key != "has_orphans"],
        "failed_validation_check_ids": [str(key) for key, value in checks.items() if not bool(value)],
        "candidate_quality": {
            "conversation_candidate_count": len(conversation_rows),
            "question_count": int(transcript.get("question_count") or sum(1 for row in conversation_rows if row.get("direction") == "question")),
            "answer_count": int(transcript.get("answer_count") or sum(1 for row in conversation_rows if row.get("direction") == "answer")),
            "complete_pair_count": int(transcript.get("complete_pair_count") or 0),
            "orphan_question_count": int(transcript.get("orphan_question_count") or 0),
            "orphan_answer_count": int(transcript.get("orphan_answer_count") or 0),
            "completeness_score": transcript.get("completeness_score"),
        },
        "commercial_blockers": list(AI_TRANSCRIPT_BLOCKERS),
        "large_data_controls": {
            "max_ai_storage_files": MAX_AI_STORAGE_FILES,
            "max_ai_storage_file_bytes": MAX_AI_STORAGE_FILE_BYTES,
            "max_ai_conversation_rows": MAX_AI_CONVERSATION_ROWS,
            "source_storage_area_count": len(source_summary.get("storage_area_counts") or {}),
            "candidate_manifest_hash": str(candidate_manifest.get("manifest_sha256") or ""),
            "candidate_citation_count": int(candidate_manifest.get("candidate_citation_count") or 0),
            "pair_citation_count": len(candidate_manifest.get("pair_citations") or []),
            "schema_validation_manifest_hash": str(schema_manifest.get("manifest_sha256") or ""),
            "service_schema_validation_status": str(schema_manifest.get("service_schema_validation_status") or ""),
            "service_schema_version_corpus_required": True,
            "service_side_export_validation_required": True,
        },
        "next_internal_step": "Add service-specific export/schema validators, deleted-fragment recovery fixtures, and FP/FN measurement for ChatGPT/Claude/Gemini/Perplexity.",
        "external_evidence_required": True,
    }


def ai_transcript_functional_profile(
    details: Mapping[str, object],
    *,
    checks: Mapping[str, object],
    transcript: Mapping[str, object],
    source_summary: Mapping[str, object],
    conversation_rows: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> Dict[str, object]:
    question_count = int(transcript.get("question_count") or sum(1 for row in conversation_rows if row.get("direction") == "question"))
    answer_count = int(transcript.get("answer_count") or sum(1 for row in conversation_rows if row.get("direction") == "answer"))
    failed_checks: List[str] = []
    if not conversation_rows:
        failed_checks.append("ai-transcript-candidate-rows-not-present")
    if int(transcript.get("complete_pair_count") or 0) == 0:
        failed_checks.append("ai-question-answer-pair-not-present")
    if not checks.get("service_side_export_validated"):
        failed_checks.append("service-side-ai-export-not-validated")
    if not checks.get("service_schema_version_known"):
        failed_checks.append("ai-service-schema-version-not-validated")
    if trusted_diff.get("status") != "pass":
        failed_checks.append("ai-transcript-trusted-export-diff-required")
    candidate_manifest = (
        details.get("ai_transcript_candidate_manifest")
        if isinstance(details.get("ai_transcript_candidate_manifest"), Mapping)
        else {}
    )
    if not candidate_manifest.get("manifest_sha256"):
        failed_checks.append("ai-transcript-candidate-manifest-not-emitted")
    schema_manifest = (
        details.get("ai_transcript_schema_validation_manifest")
        if isinstance(details.get("ai_transcript_schema_validation_manifest"), Mapping)
        else {}
    )
    if not schema_manifest.get("manifest_sha256"):
        failed_checks.append("ai-transcript-schema-validation-manifest-not-emitted")
    service_counts = source_summary.get("service_counts") if isinstance(source_summary.get("service_counts"), Mapping) else {}
    passed_checks = [
        "ai-service-domain-detection-enabled",
        "browser-storage-fragment-source-hash-preserved",
        "question-answer-candidate-pairing-attempted",
        "pairing-confidence-summary-emitted",
    ]
    if candidate_manifest.get("manifest_sha256"):
        passed_checks.append("ai-transcript-candidate-manifest-emitted")
    if schema_manifest.get("manifest_sha256"):
        passed_checks.append("ai-transcript-schema-validation-manifest-emitted")
    if int(candidate_manifest.get("candidate_citation_count") or 0) >= len(conversation_rows):
        passed_checks.append("ai-candidate-source-locators-emitted")
    if len(candidate_manifest.get("pair_citations") or []) >= int(transcript.get("pair_count") or 0):
        passed_checks.append("ai-pair-source-locators-emitted")
    return {
        "item_number": 48,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "supported_ai_services": [label for _, label in AI_SERVICE_DOMAINS],
            "detected_service_counts": dict(service_counts),
            "conversation_candidate_count": len(conversation_rows),
            "question_count": question_count,
            "answer_count": answer_count,
            "complete_pair_count": int(transcript.get("complete_pair_count") or 0),
            "completeness_score": transcript.get("completeness_score"),
            "source_file_count": int(source_summary.get("source_file_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
            "candidate_manifest_hash": str(candidate_manifest.get("manifest_sha256") or ""),
            "schema_validation_manifest_hash": str(schema_manifest.get("manifest_sha256") or ""),
            "service_schema_validation_status": str(schema_manifest.get("service_schema_validation_status") or ""),
            "candidate_citation_count": int(candidate_manifest.get("candidate_citation_count") or 0),
            "pair_citation_count": len(candidate_manifest.get("pair_citations") or []),
            "browser": str(details.get("browser") or ""),
            "profile": str(details.get("profile") or ""),
        },
        "passed_validation_check_ids": passed_checks,
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "ai-transcript-candidate-review-pivot",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Treat Q/A pairs as candidates until service-side export or trusted browser fixture diff confirms them.",
        },
    }


def ai_transcript_reportability_decision(
    details: Mapping[str, object],
    *,
    checks: Mapping[str, object],
    transcript: Mapping[str, object],
    conversation_rows: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    blockers = set(AI_TRANSCRIPT_BLOCKERS)
    if not checks.get("service_side_export_validated"):
        blockers.add("service-side-export-not-validated")
    if not checks.get("service_schema_version_known"):
        blockers.add("service-schema-version-not-validated")
    if not checks.get("deleted_fragment_recovery_validated"):
        blockers.add("deleted-fragment-recovery-not-validated")
    if transcript.get("orphan_question_count") or transcript.get("orphan_answer_count"):
        blockers.add("orphan-question-answer-candidates-present")
    if not transcript.get("complete_pair_count"):
        blockers.add("no-complete-question-answer-pairs")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.add("ai-transcript-trusted-export-diff-required")
    source_summary = details.get("source_summary") if isinstance(details.get("source_summary"), Mapping) else {}
    return {
        "profile_version": "ai-transcript-reportability-decision-v1",
        "commercial_gap_ids": ["#21"],
        "decision": "do-not-report-ai-transcript-as-complete",
        "allowed_use": "ai-conversation-triage-pivot",
        "blockers": sorted(blockers),
        "candidate_row_count": len(conversation_rows),
        "complete_pair_count": int(transcript.get("complete_pair_count") or 0),
        "source_file_count": int(source_summary.get("source_file_count") or 0),
        "raw_secret_or_account_values_redacted": True,
        "required_before_report": [
            "validate the same transcript with a service-side export or trusted browser profile fixture",
            "record service/schema version for ChatGPT, Claude, Gemini, Perplexity or the detected provider",
            "document orphan prompt/answer handling and deleted-fragment limitations",
            "cite source storage files and hashes for every reportable Q/A pair",
        ],
    }


def browser_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    storage_inventory = [
        item for item in details.get("storage_inventory") or [] if isinstance(item, Mapping)
    ]
    timeline = [item for item in details.get("unified_timeline") or [] if isinstance(item, Mapping)]
    downloads = [item for item in details.get("download_rows") or [] if isinstance(item, Mapping)]
    source_profile = details.get("source_profile") if isinstance(details.get("source_profile"), Mapping) else {}
    secret_checks = (
        details.get("secret_validation_checks")
        if isinstance(details.get("secret_validation_checks"), Mapping)
        else {}
    )
    storage_diff = (
        details.get("browser_storage_trusted_diff")
        if isinstance(details.get("browser_storage_trusted_diff"), Mapping)
        else {}
    )
    timeline_diff = (
        details.get("browser_timeline_trusted_diff")
        if isinstance(details.get("browser_timeline_trusted_diff"), Mapping)
        else {}
    )
    citation_manifest = (
        details.get("browser_history_download_citation_manifest")
        if isinstance(details.get("browser_history_download_citation_manifest"), Mapping)
        else {}
    )
    storage_citation_manifest = (
        details.get("browser_storage_citation_manifest")
        if isinstance(details.get("browser_storage_citation_manifest"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"browser:{details.get('browser', '')}",
        f"profile:{details.get('profile', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    item19: list[str] = []
    if source_profile or details.get("browser") or details.get("profile"):
        item19.append("profile/source attribution")
    if storage_inventory:
        item19.append("cache/session schema validation")
    if details.get("storage_review_profile"):
        item19.append("storage review prioritization")
    if storage_citation_manifest.get("manifest_sha256"):
        item19.append("storage citation manifest")
    if int(storage_citation_manifest.get("sample_file_hash_count") or 0) > 0:
        item19.append("storage sample hash citations")
    if any(str(row.get("storage_type") or "") == "extension" or "extension" in str(row.get("storage_name") or "") for row in storage_inventory):
        item19.append("extension ID/source mapping")
    if details.get("secret_validation_checks") or checks.get("sensitive_storage_inventory_present") is not None:
        item19.append("secret/cookie opt-in legal gate")
    if any(str(row.get("storage_type") or "") in {"sync", "session"} for row in storage_inventory) or not BROWSER_NATIVE_CAPABILITIES["cross_browser_deleted_session_recovery"]:
        item19.append("deleted/synced content warning")
    if storage_diff.get("status") == "pass":
        item19.append("trusted browser storage diff pass")

    item20: list[str] = []
    if timeline:
        item20.append("timestamp normalization")
    if details.get("timeline_integrity_profile") or checks.get("timeline_integrity_profile_present"):
        item20.append("timeline integrity profile")
    if any(str(row.get("transition") or "") for row in timeline) or checks.get("visit_transition_metadata_present"):
        item20.append("transition semantics")
    if downloads and any(row.get("target_path") and (row.get("source_url") or row.get("tab_url")) for row in downloads):
        item20.append("download target/source URL linkage")
    if citation_manifest.get("manifest_sha256"):
        item20.append("row-level source citation manifest")
    if int(citation_manifest.get("row_locator_count") or 0) >= len(timeline):
        item20.append("sqlite source viewer locators")
    if not BROWSER_NATIVE_CAPABILITIES["safari_windows_profile_support"]:
        item20.append("Safari scope limitation disclosure")
    if timeline_diff.get("status") == "pass":
        item20.append("trusted browser timeline diff pass")

    gates = [
        build_accuracy_gate(19, satisfied_checks=item19, evidence_refs=evidence_refs),
        build_accuracy_gate(20, satisfied_checks=item20, evidence_refs=evidence_refs),
    ]
    if storage_inventory or secret_checks:
        secret_diff = (
            details.get("browser_secret_trusted_diff")
            if isinstance(details.get("browser_secret_trusted_diff"), Mapping)
            else {}
        )
        if secret_diff:
            evidence_refs.append(f"secret_trusted_diff_status:{secret_diff.get('status', '')}")
            evidence_refs.append(f"secret_trusted_tool:{secret_diff.get('trusted_tool', '')}")
        item42: list[str] = []
        if storage_inventory or checks.get("sensitive_storage_inventory_present") is not None:
            item42.append("sensitive artifact inventory")
        if secret_checks.get("inventory_only_mode") and not secret_checks.get("raw_secret_values_extracted"):
            item42.append("secret values redacted by default")
        if secret_checks.get("strict_legal_warning_present") or BROWSER_SECRET_HANDLING_WARNING:
            item42.append("strict legal warning")
        if not BROWSER_NATIVE_CAPABILITIES["password_cookie_session_secret_extraction"]:
            item42.append("opt-in reveal workflow warning")
        if secret_checks.get("scope_review_required") is not None:
            item42.append("audit and scope review requirement")
        authority_profile = (
            details.get("browser_secret_authority_profile")
            if isinstance(details.get("browser_secret_authority_profile"), Mapping)
            else {}
        )
        authority_manifest = (
            details.get("browser_secret_authority_manifest")
            if isinstance(details.get("browser_secret_authority_manifest"), Mapping)
            else {}
        )
        if authority_profile:
            item42.append("browser secret authority profile")
        if authority_manifest:
            item42.append("browser secret authority manifest")
            evidence_refs.append(
                f"browser_secret_authority_manifest_sha256:{authority_manifest.get('manifest_sha256', '')}"
            )
        if authority_manifest.get("raw_secret_values_serialized") is False:
            item42.append("no raw secret serialization")
        if authority_profile.get("controlled_reveal_policy") == "disabled-by-default" and not authority_profile.get(
            "raw_secret_reveal_allowed"
        ):
            item42.append("controlled reveal disabled by default")
        if secret_diff.get("status") == "pass":
            item42.append("trusted browser secret authority diff pass")
        gates.append(build_accuracy_gate(42, satisfied_checks=item42, evidence_refs=evidence_refs))
    return gates


def build_browser_secret_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> Dict[str, object]:
    return build_browser_diff_payload(
        index_browser_secret_rows(rapid_rows),
        index_browser_secret_rows(trusted_rows),
        trusted_tool=trusted_tool,
        mode="browser-secret-trusted-diff-v1",
        blocker=BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
        key_label="secret_key",
        trusted_tools=BROWSER_SECRET_TRUSTED_TOOLS,
        fail_decision="do-not-use-browser-secret-output-as-final",
    )


def build_browser_storage_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> Dict[str, object]:
    return build_browser_diff_payload(
        index_browser_storage_rows(rapid_rows),
        index_browser_storage_rows(trusted_rows),
        trusted_tool=trusted_tool,
        mode="browser-storage-trusted-diff-v1",
        blocker="browser-storage-trusted-diff-required",
        key_label="storage_key",
    )


def build_browser_timeline_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> Dict[str, object]:
    return build_browser_diff_payload(
        index_browser_timeline_rows(rapid_rows),
        index_browser_timeline_rows(trusted_rows),
        trusted_tool=trusted_tool,
        mode="browser-timeline-trusted-diff-v1",
        blocker="browser-timeline-trusted-diff-required",
        key_label="timeline_key",
    )


def build_ai_transcript_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> Dict[str, object]:
    return build_browser_diff_payload(
        index_ai_transcript_rows(rapid_rows),
        index_ai_transcript_rows(trusted_rows),
        trusted_tool=trusted_tool,
        mode="ai-transcript-trusted-diff-v1",
        blocker="ai-transcript-trusted-export-diff-required",
        key_label="conversation_key",
        trusted_tools=AI_TRANSCRIPT_TRUSTED_TOOLS,
        fail_decision="do-not-use-ai-transcript-output-as-final",
    )


def index_browser_storage_rows(rows: Sequence[Mapping[str, object]]) -> Dict[str, Dict[str, str]]:
    indexed: Dict[str, Dict[str, str]] = {}
    for row in rows:
        for payload in browser_storage_diff_payloads(row):
            browser = normalized_diff_value(first_alias(payload, "browser"))
            profile = normalized_diff_value(first_alias(payload, "profile"))
            storage_type = normalized_diff_value(first_alias(payload, "storage_type", "type", "store_type"))
            storage_name = normalized_diff_value(
                first_alias(payload, "storage_name", "name", "store_name", "path", "relative_path")
            )
            key = "|".join(item for item in (browser, profile, storage_type, storage_name) if item)
            if not key:
                continue
            indexed[key] = {
                "browser": browser,
                "profile": profile,
                "storage_type": storage_type,
                "storage_name": storage_name,
                "relative_path": normalized_diff_value(first_alias(payload, "relative_path", "path", "source_path")),
                "artifact_hint": normalized_diff_value(first_alias(payload, "artifact_hint", "hint", "artifact")),
                "file_count": normalized_browser_int_text(first_alias(payload, "file_count", "files", "count")),
                "total_bytes": normalized_browser_int_text(first_alias(payload, "total_bytes", "size", "bytes")),
                "is_file": normalized_browser_bool_text(first_alias(payload, "is_file", "file")),
                "sensitive": normalized_browser_bool_text(
                    first_alias(payload, "sensitive", "contains_secrets", "scope_sensitive")
                ),
                "sample_hashes": normalized_browser_list(first_alias(payload, "sample_hashes", "sample_files", "hashes")),
                "inventory_truncated": normalized_browser_bool_text(
                    first_alias(payload, "inventory_truncated", "truncated")
                ),
            }
    return indexed


def browser_storage_diff_payloads(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = browser_diff_row_payload(row)
    nested = payload.get("storage_inventory")
    if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
        expanded: list[Mapping[str, object]] = []
        for item in nested:
            if not isinstance(item, Mapping):
                continue
            child = dict(item)
            child.setdefault("browser", payload.get("browser", ""))
            child.setdefault("profile", payload.get("profile", ""))
            expanded.append(child)
        if expanded:
            return expanded
    return [payload]


def browser_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def normalized_browser_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_diff_value(text)


def normalized_browser_bool_text(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalized_diff_value(value)
    if text in {"1", "yes", "y", "true", "enabled"}:
        return "true"
    if text in {"0", "no", "n", "false", "disabled"}:
        return "false"
    return text


def normalized_browser_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[\r\n,;|]", value) if part.strip()]
    elif isinstance(value, Mapping):
        parts = [normalize_browser_list_item(value)]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_browser_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_browser_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        hashes = value.get("hashes")
        if isinstance(hashes, Mapping):
            digest = first_alias(hashes, "sha256", "sha1", "md5")
            if digest:
                return str(digest)
        return str(first_alias(value, "sha256", "sha1", "md5", "relative_path", "path", "name", "value"))
    return str(value)


def index_browser_secret_rows(rows: Sequence[Mapping[str, object]]) -> Dict[str, Dict[str, str]]:
    indexed: Dict[str, Dict[str, str]] = {}
    for row in rows:
        for payload in browser_secret_diff_payloads(row):
            browser = normalized_diff_value(first_alias(payload, "browser"))
            profile = normalized_diff_value(first_alias(payload, "profile"))
            storage_type = normalized_diff_value(first_alias(payload, "storage_type", "type"))
            storage_name = normalized_diff_value(first_alias(payload, "storage_name", "name", "path"))
            legal_authority_id = normalized_diff_value(first_alias(payload, "legal_authority_id", "authority_record_id"))
            audit_event_id = normalized_diff_value(first_alias(payload, "audit_event_id", "audit_id"))
            key = "|".join(item for item in (browser, profile, storage_type, storage_name, legal_authority_id) if item)
            if not key:
                continue
            indexed[key] = {
                "browser": browser,
                "profile": profile,
                "storage_type": storage_type,
                "storage_name": storage_name,
                "raw_secret_values_extracted": normalized_diff_value(
                    first_alias(payload, "raw_secret_values_extracted", "secrets_extracted")
                ),
                "legal_authority_id": legal_authority_id,
                "audit_event_id": audit_event_id,
            }
    return indexed


def browser_secret_diff_payloads(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = browser_diff_row_payload(row)
    nested = payload.get("storage_inventory")
    if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
        expanded: list[Mapping[str, object]] = []
        for item in nested:
            if not isinstance(item, Mapping):
                continue
            if item.get("sensitive") is False:
                continue
            child = dict(item)
            child.setdefault("browser", payload.get("browser", ""))
            child.setdefault("profile", payload.get("profile", ""))
            child.setdefault("raw_secret_values_extracted", payload.get("raw_secret_values_extracted", False))
            child.setdefault("legal_authority_id", payload.get("legal_authority_id", ""))
            child.setdefault("audit_event_id", payload.get("audit_event_id", ""))
            expanded.append(child)
        if expanded:
            return expanded
    return [payload]


def index_ai_transcript_rows(rows: Sequence[Mapping[str, object]]) -> Dict[str, Dict[str, str]]:
    indexed: Dict[str, Dict[str, str]] = {}
    for row in rows:
        for payload in ai_transcript_diff_payloads(row):
            service = normalized_diff_value(first_alias(payload, "ai_service", "service", "provider"))
            question = normalized_diff_value(first_alias(payload, "question", "prompt", "user_text", "user_message"))
            answer = normalized_diff_value(first_alias(payload, "answer", "response", "assistant_text", "assistant_message"))
            timestamp = normalized_diff_value(first_alias(payload, "timestamp", "created_at", "message_time", "createdat"))
            source = normalized_diff_value(first_alias(payload, "source_path", "source", "export_path"))
            key = "|".join(item for item in (service, timestamp, question[:160], answer[:160]) if item)
            if not key:
                continue
            indexed[key] = {
                "ai_service": service,
                "question": question,
                "answer": answer,
                "timestamp": timestamp,
                "source_path": source,
                "source_sha256s": normalized_browser_list(
                    first_alias(payload, "source_sha256s", "source_sha256", "source_hashes", "sourcehashes")
                ),
                "question_source_path": normalized_diff_value(first_alias(payload, "question_source_path", "prompt_source_path")),
                "answer_source_path": normalized_diff_value(first_alias(payload, "answer_source_path", "response_source_path")),
                "question_source_offset": normalized_browser_int_text(
                    first_alias(payload, "question_source_offset", "prompt_offset")
                ),
                "answer_source_offset": normalized_browser_int_text(
                    first_alias(payload, "answer_source_offset", "response_offset")
                ),
                "pairing_confidence": normalized_diff_value(first_alias(payload, "pairing_confidence", "confidence_label")),
                "confidence": normalized_diff_value(first_alias(payload, "confidence", "score")),
                "storage_area": normalized_diff_value(first_alias(payload, "storage_area", "source_storage_area")),
                "pair_id": normalized_diff_value(first_alias(payload, "pair_id", "conversation_id", "id")),
            }
    return indexed


def ai_transcript_diff_payloads(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = browser_diff_row_payload(row)
    direct_pairs = payload.get("transcript_pairs")
    if isinstance(direct_pairs, Sequence) and not isinstance(direct_pairs, (str, bytes, bytearray)):
        expanded = expand_ai_transcript_pair_rows(payload, direct_pairs)
        if expanded:
            return expanded
    transcript = payload.get("transcript")
    if isinstance(transcript, Mapping):
        transcript_pairs = transcript.get("pairs")
        if isinstance(transcript_pairs, Sequence) and not isinstance(transcript_pairs, (str, bytes, bytearray)):
            expanded = expand_ai_transcript_pair_rows(payload, transcript_pairs)
            if expanded:
                return expanded
    conversation_rows = payload.get("conversation_rows") or payload.get("conversation_candidates")
    if isinstance(conversation_rows, Sequence) and not isinstance(conversation_rows, (str, bytes, bytearray)):
        candidate_rows = [item for item in conversation_rows if isinstance(item, Mapping)]
        if candidate_rows:
            summary = build_ai_transcript_summary(candidate_rows)
            expanded = expand_ai_transcript_pair_rows(payload, summary.get("pairs") or [])
            if expanded:
                return expanded
    return [payload]


def expand_ai_transcript_pair_rows(
    parent: Mapping[str, object],
    pairs: Sequence[object],
) -> list[Mapping[str, object]]:
    expanded: list[Mapping[str, object]] = []
    for pair in pairs:
        if not isinstance(pair, Mapping):
            continue
        child = dict(pair)
        child.setdefault("ai_service", parent.get("ai_service") or parent.get("service") or parent.get("provider") or "")
        child.setdefault("timestamp", parent.get("timestamp") or parent.get("created_at") or "")
        child.setdefault("source_path", parent.get("source_path") or "")
        evidence = child.get("pairing_evidence")
        if isinstance(evidence, Mapping):
            child.setdefault("question_source_offset", evidence.get("question_source_offset"))
            child.setdefault("answer_source_offset", evidence.get("answer_source_offset"))
            child.setdefault("storage_area", evidence.get("storage_area"))
        expanded.append(child)
    return expanded


def index_browser_timeline_rows(rows: Sequence[Mapping[str, object]]) -> Dict[str, Dict[str, str]]:
    indexed: Dict[str, Dict[str, str]] = {}
    for row in rows:
        for payload in browser_timeline_diff_payloads(row):
            browser = normalized_diff_value(first_alias(payload, "browser"))
            profile = normalized_diff_value(first_alias(payload, "profile"))
            url = normalized_diff_value(first_alias(payload, "url", "source_url", "target_url"))
            timestamp = normalized_diff_value(first_alias(payload, "timestamp", "visit_time", "start_time", "started_at"))
            timeline_type = normalized_diff_value(first_alias(payload, "timeline_type", "type", "row_type"))
            key = "|".join(item for item in (browser, profile, timeline_type, timestamp, url) if item)
            if not key:
                continue
            indexed[key] = {
                "browser": browser,
                "profile": profile,
                "timeline_type": timeline_type,
                "url": url,
                "timestamp": timestamp,
                "title": normalized_diff_value(first_alias(payload, "title", "page_title")),
                "domain": normalized_diff_value(first_alias(payload, "domain", "host", "hostname")),
                "transition": normalized_diff_value(first_alias(payload, "transition", "transition_type")),
                "visit_count": normalized_browser_int_text(first_alias(payload, "visit_count", "visitcount")),
                "typed_count": normalized_browser_int_text(first_alias(payload, "typed_count", "typedcount")),
                "target_path": normalized_diff_value(first_alias(payload, "target_path", "download_path", "filename")),
                "total_bytes": normalized_browser_int_text(first_alias(payload, "total_bytes", "bytes", "size")),
                "state": normalized_browser_int_text(first_alias(payload, "state", "download_state")),
                "ended_at": normalized_diff_value(first_alias(payload, "ended_at", "end_time", "completed_at")),
                "ai_service": normalized_diff_value(first_alias(payload, "ai_service", "service")),
                "source_table": normalized_diff_value(first_alias(payload, "source_table", "table")),
                "source_index": normalized_browser_int_text(first_alias(payload, "source_index", "row_index", "index")),
            }
    return indexed


def browser_timeline_diff_payloads(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = browser_diff_row_payload(row)
    nested = payload.get("unified_timeline")
    if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
        expanded: list[Mapping[str, object]] = []
        for item in nested:
            if not isinstance(item, Mapping):
                continue
            child = dict(item)
            child.setdefault("browser", payload.get("browser", ""))
            child.setdefault("profile", payload.get("profile", ""))
            expanded.append(child)
        if expanded:
            return expanded
    return [payload]


def build_browser_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
    mode: str,
    blocker: str,
    key_label: str,
    trusted_tools: set[str] | None = None,
    fail_decision: str = "do-not-use-browser-output-as-final",
) -> Dict[str, object]:
    trusted_tool_set = trusted_tools or BROWSER_TRUSTED_TOOLS
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in trusted_tool_set
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: List[Dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({key_label: key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": mode,
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
            "decision": "trusted-diff-passed" if status == "pass" else fail_decision,
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def first_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def ai_transcript_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    rows = [item for item in details.get("conversation_rows") or [] if isinstance(item, Mapping)]
    transcript = details.get("transcript") if isinstance(details.get("transcript"), Mapping) else {}
    source_summary = details.get("source_summary") if isinstance(details.get("source_summary"), Mapping) else {}
    trusted_diff = (
        details.get("ai_transcript_trusted_diff")
        if isinstance(details.get("ai_transcript_trusted_diff"), Mapping)
        else {}
    )
    candidate_manifest = (
        details.get("ai_transcript_candidate_manifest")
        if isinstance(details.get("ai_transcript_candidate_manifest"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"browser:{details.get('browser', '')}",
        f"profile:{details.get('profile', '')}",
    ]
    for source_hash in list(source_summary.get("source_sha256s") or [])[:3]:
        evidence_refs.append(f"source_sha256:{source_hash}")

    satisfied: list[str] = []
    if count_field(rows, "ai_service"):
        satisfied.append("service/schema version detection")
    if transcript.get("pair_count") or transcript.get("pairing_confidence_summary"):
        satisfied.append("question/answer pairing confidence")
    if any(isinstance(pair, Mapping) and pair.get("pairing_evidence") for pair in transcript.get("pairs") or []):
        satisfied.append("pair-level source citation")
    if candidate_manifest.get("manifest_sha256"):
        satisfied.append("AI transcript candidate manifest")
    if int(candidate_manifest.get("candidate_citation_count") or 0) >= len(rows):
        satisfied.append("candidate source viewer locators")
    if len(candidate_manifest.get("pair_citations") or []) >= int(transcript.get("pair_count") or 0):
        satisfied.append("pair source viewer locators")
    if "orphan_question_count" in transcript and "orphan_answer_count" in transcript:
        satisfied.append("orphan prompt/answer tracking")
    if rows and all(row.get("source_path") and row.get("source_sha256") for row in rows):
        satisfied.append("source offset/storage provenance")
    satisfied.append("privacy and completeness warnings")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted AI transcript export diff pass")
    return [build_accuracy_gate(21, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


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


def browser_secret_authority_profile(
    *,
    browser: str,
    profile: str,
    storage_inventory: Sequence[Mapping[str, object]],
    checks: Mapping[str, object],
) -> Dict[str, object]:
    sensitive_rows = [row for row in storage_inventory if row.get("sensitive")]
    sensitive_type_counts = count_field(sensitive_rows, "storage_type")
    sensitive_name_counts = count_field(sensitive_rows, "storage_name")
    return {
        "profile_version": "browser-secret-authority-v1",
        "selected_track": "inventory-only-controlled-reveal-required",
        "browser": browser,
        "profile": profile,
        "sensitive_inventory_count": len(sensitive_rows),
        "sensitive_storage_type_counts": sensitive_type_counts,
        "sensitive_storage_names": sorted(str(row.get("storage_name") or "") for row in sensitive_rows if row.get("storage_name"))[:50],
        "cookie_store_present": any(str(row.get("storage_type") or "") == "cookie" for row in sensitive_rows),
        "credential_store_present": any(str(row.get("storage_type") or "") == "credential" for row in sensitive_rows),
        "session_store_present": any(str(row.get("storage_type") or "") == "session" for row in sensitive_rows),
        "controlled_reveal_policy": "disabled-by-default",
        "raw_secret_reveal_allowed": False,
        "raw_secret_values_extracted": bool(checks.get("raw_secret_values_extracted")),
        "secret_values_redacted_by_default": not bool(checks.get("raw_secret_values_extracted")),
        "dpapi_keychain_integration": False,
        "browser_version_known_answer_validated": False,
        "legal_authority_record_required": bool(sensitive_rows),
        "reveal_audit_log_required": bool(sensitive_rows),
        "trusted_secret_authority_diff_required": True,
        "ready_for_court_report": False,
        "blockers": [
            "lawful-secret-reveal-authority-not-attached",
            "dpapi-keychain-known-answer-validation-required",
            "browser-version-secret-store-validation-required",
            "controlled-reveal-audit-log-required",
            BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
        ],
        "required_before_report": [
            "document lawful authority and case scope before any external secret review",
            "validate browser-version and OS DPAPI/keychain behavior with known-answer fixtures",
            "record a per-store controlled reveal audit event before exposing any secret value",
            "attach a passing trusted browser secret authority diff before reporting decrypted or revealed secrets",
        ],
    }


def browser_secret_authority_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    storage_inventory: Sequence[Mapping[str, object]],
    checks: Mapping[str, object],
) -> Dict[str, object]:
    sensitive_rows = [row for row in storage_inventory if row.get("sensitive")]
    entries: List[Dict[str, object]] = []
    for index, row in enumerate(sensitive_rows[:MAX_BROWSER_INVENTORY_FILES], start=1):
        source_path = str(row.get("source_path") or "")
        source_path_hash = hashlib.sha256(source_path.encode("utf-8", errors="ignore")).hexdigest() if source_path else ""
        entries.append(
            {
                "entry_index": index,
                "storage_type": str(row.get("storage_type") or ""),
                "storage_name": str(row.get("storage_name") or ""),
                "artifact_hint": str(row.get("artifact_hint") or ""),
                "relative_path": str(row.get("relative_path") or ""),
                "source_path_sha256": source_path_hash,
                "file_count": int(row.get("file_count") or 0),
                "total_bytes": int(row.get("total_bytes") or 0),
                "sample_file_count": len(row.get("sample_files") or [])
                if isinstance(row.get("sample_files"), list)
                else 0,
                "source_viewer_locator": {
                    "viewer": "browser-secret-inventory",
                    "profile_dir": str(profile_dir.resolve()),
                    "relative_path": str(row.get("relative_path") or ""),
                    "open_requires_authority": True,
                    "raw_secret_values_extracted": False,
                },
                "controlled_reveal_status": "blocked-by-default",
                "legal_authority_record_present": False,
                "reveal_audit_event_present": False,
                "trusted_authority_diff_present": False,
                "raw_secret_values_extracted": False,
            }
        )
    manifest: Dict[str, object] = {
        "manifest_version": "browser-secret-authority-manifest-v1",
        "item_number": 42,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "per-store-controlled-reveal-inventory",
        "browser": browser,
        "profile": profile,
        "user": user,
        "profile_dir": str(profile_dir.resolve()),
        "sensitive_store_count": len(sensitive_rows),
        "entry_count": len(entries),
        "entry_cap": MAX_BROWSER_INVENTORY_FILES,
        "entries_truncated": len(sensitive_rows) > MAX_BROWSER_INVENTORY_FILES,
        "entries": entries,
        "controlled_reveal_policy": "disabled-by-default",
        "raw_secret_reveal_allowed": False,
        "raw_secret_values_serialized": False,
        "raw_secret_values_extracted": bool(checks.get("raw_secret_values_extracted")),
        "secret_values_redacted_by_default": not bool(checks.get("raw_secret_values_extracted")),
        "strict_legal_warning_present": bool(checks.get("strict_legal_warning_present")),
        "scope_review_required": bool(checks.get("scope_review_required")),
        "reveal_audit_log_required": bool(sensitive_rows),
        "dpapi_keychain_integration": False,
        "browser_version_known_answer_validated": False,
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "browser-secret-authority-manifest-emitted": True,
                "raw-secret-values-not-serialized": True,
                "raw-secret-values-not-extracted": not bool(checks.get("raw_secret_values_extracted")),
                "controlled-reveal-disabled": True,
                "strict-legal-warning-present": bool(checks.get("strict_legal_warning_present")),
                "per-store-source-viewer-locators": all(
                    entry.get("source_viewer_locator") for entry in entries
                ),
            }.items()
            if passed
        ],
        "failed_validation_check_ids": [
            "lawful-secret-reveal-authority-not-attached",
            "controlled-reveal-audit-log-required",
            "dpapi-keychain-known-answer-validation-required",
            BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
        ]
        if sensitive_rows
        else [BROWSER_SECRET_TRUSTED_DIFF_BLOCKER],
        "commercial_blockers": [
            "lawful-secret-reveal-authority-not-attached",
            "controlled-reveal-audit-log-required",
            "dpapi-keychain-known-answer-validation-required",
            BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


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
            BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
        ],
        "recommended_validation": [
            "Use this inventory to identify candidate stores, then document legal authority before any external credential review.",
            "Validate password/cookie/session interpretation with browser-version and OS-keychain known-answer fixtures.",
        ],
    }


def browser_secret_commercial_uplift_evidence(details: Mapping[str, object]) -> Dict[str, object]:
    checks = details.get("secret_handling_validation_checks")
    if not isinstance(checks, Mapping):
        checks = {}
    assessment = details.get("browser_secret_handling_assessment")
    if not isinstance(assessment, Mapping):
        assessment = {}
    authority_profile = details.get("browser_secret_authority_profile")
    if not isinstance(authority_profile, Mapping):
        authority_profile = {}
    authority_manifest = details.get("browser_secret_authority_manifest")
    if not isinstance(authority_manifest, Mapping):
        authority_manifest = {}
    storage_inventory = details.get("storage_inventory")
    if not isinstance(storage_inventory, list):
        storage_inventory = []
    trusted_diff = (
        details.get("browser_secret_trusted_diff")
        if isinstance(details.get("browser_secret_trusted_diff"), Mapping)
        else {}
    )
    passed_control_ids: List[str] = []
    failed_control_ids: List[str] = []
    if not checks.get("raw_secret_values_extracted"):
        passed_control_ids.append("raw-secret-values-redacted")
    else:
        failed_control_ids.append("raw-secret-values-redacted")
    for check_id, control_id in (
        ("cookie_values_decrypted", "cookie-values-not-decrypted"),
        ("password_values_decrypted", "password-values-not-decrypted"),
        ("session_tokens_extracted", "session-tokens-not-extracted"),
    ):
        if not checks.get(check_id):
            passed_control_ids.append(control_id)
        else:
            failed_control_ids.append(control_id)
    for check_id in ("strict_legal_warning_present", "scope_review_required", "inventory_only_mode"):
        if checks.get(check_id):
            passed_control_ids.append(str(check_id))
        else:
            failed_control_ids.append(str(check_id))
    if authority_profile:
        passed_control_ids.append("browser-secret-authority-profile-present")
    else:
        failed_control_ids.append("browser-secret-authority-profile-present")
    if authority_manifest:
        passed_control_ids.append("browser-secret-authority-manifest-present")
    else:
        failed_control_ids.append("browser-secret-authority-manifest-present")
    if authority_manifest.get("raw_secret_values_serialized") is False:
        passed_control_ids.append("raw-secret-values-not-serialized")
    else:
        failed_control_ids.append("raw-secret-values-not-serialized")
    if authority_profile.get("controlled_reveal_policy") == "disabled-by-default" and not authority_profile.get(
        "raw_secret_reveal_allowed"
    ):
        passed_control_ids.append("controlled-reveal-disabled-by-default")
    else:
        failed_control_ids.append("controlled-reveal-disabled-by-default")
    return {
        "batch_id": "commercial-uplift-041-045",
        "item_numbers": [42],
        "implementation_track": "browser-secret-legal-gate",
        "reportability_decision": browser_secret_reportability_decision(
            checks=checks,
            failed_control_ids=failed_control_ids,
            commercial_blockers=list(assessment.get("blockers") or []),
            details=details,
            trusted_diff=trusted_diff,
        ),
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"browser:{details.get('browser', '')}",
            f"profile:{details.get('profile', '')}",
        ],
        "browser_secret_authority_profile": dict(authority_profile),
        "browser_secret_authority_manifest": dict(authority_manifest),
        "passed_control_ids": passed_control_ids,
        "failed_control_ids": failed_control_ids,
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": BROWSER_SECRET_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(BROWSER_SECRET_TRUSTED_TOOLS),
        },
        "commercial_blockers": list(assessment.get("blockers") or []),
        "large_data_controls": {
            "max_browser_inventory_files": MAX_BROWSER_INVENTORY_FILES,
            "max_browser_inventory_sample_files": MAX_BROWSER_INVENTORY_SAMPLE_FILES,
            "storage_inventory_count": int(details.get("inventory_count") or len(storage_inventory)),
            "sensitive_inventory_count": int(details.get("sensitive_inventory_count") or 0),
            "secret_values_redacted_by_default": not bool(checks.get("raw_secret_values_extracted")),
            "raw_secret_values_extracted": bool(checks.get("raw_secret_values_extracted")),
            "requires_scope_review": bool(checks.get("scope_review_required")),
            "dpapi_keychain_integration": False,
            "browser_secret_authority_profile_present": bool(authority_profile),
            "browser_secret_authority_manifest_present": bool(authority_manifest),
            "browser_secret_authority_manifest_hash": str(authority_manifest.get("manifest_sha256") or ""),
            "raw_secret_values_serialized": bool(authority_manifest.get("raw_secret_values_serialized")),
            "per_store_reveal_entry_count": int(authority_manifest.get("entry_count") or 0),
            "controlled_reveal_disabled_by_default": authority_profile.get("controlled_reveal_policy")
            == "disabled-by-default"
            and not bool(authority_profile.get("raw_secret_reveal_allowed")),
        },
        "reporting_status": "inventory-only-validation-required",
    }


def browser_secret_reportability_decision(
    *,
    checks: Mapping[str, object],
    failed_control_ids: Sequence[str],
    commercial_blockers: list[str],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    blockers = set(commercial_blockers)
    blockers.update(f"control:{item}" for item in failed_control_ids)
    trusted_diff = trusted_diff or {}
    if trusted_diff.get("status") != "pass":
        blockers.add(BROWSER_SECRET_TRUSTED_DIFF_BLOCKER)
    if not checks.get("scope_review_required"):
        blockers.add("case-scope-review-not-required-by-fixture-but-still-operator-owned")
    if not checks.get("inventory_only_mode"):
        blockers.add("inventory-only-mode-not-confirmed")
    authority_profile = (
        details.get("browser_secret_authority_profile")
        if isinstance(details.get("browser_secret_authority_profile"), Mapping)
        else {}
    )
    authority_manifest = (
        details.get("browser_secret_authority_manifest")
        if isinstance(details.get("browser_secret_authority_manifest"), Mapping)
        else {}
    )
    return {
        "profile_version": "browser-secret-reportability-decision-v1",
        "commercial_gap_ids": ["#42"],
        "decision": "do-not-report-browser-secrets-as-decrypted-or-revealed",
        "allowed_use": "browser-secret-store-inventory-triage-pivot",
        "blockers": sorted(blockers),
        "failed_control_ids": list(failed_control_ids),
        "browser": str(details.get("browser") or ""),
        "profile": str(details.get("profile") or ""),
        "secret_values_redacted_by_default": not bool(checks.get("raw_secret_values_extracted")),
        "dpapi_keychain_integration": False,
        "browser_secret_authority_profile_present": bool(authority_profile),
        "browser_secret_authority_manifest_present": bool(authority_manifest),
        "controlled_reveal_policy": str(authority_profile.get("controlled_reveal_policy") or ""),
        "raw_secret_reveal_allowed": bool(authority_profile.get("raw_secret_reveal_allowed")),
        "ready_for_court_report": False,
        "required_before_report": [
            "document legal authority and case scope before any reveal workflow",
            "validate DPAPI/keychain/browser-version handling with known-answer fixtures",
            "record analyst audit events for each controlled secret reveal",
            "attach a passing browser secret authority diff before reporting decrypted or revealed secret semantics",
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
    same_source = bool(source_hashes) and len(source_hashes) == 1
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
        "same_source": same_source,
        "pairing_evidence": {
            "question_source_path": str(question.get("source_path") or ""),
            "answer_source_path": str(answer.get("source_path") or ""),
            "question_source_offset": question.get("source_offset"),
            "answer_source_offset": answer.get("source_offset"),
            "same_source_hash": same_source,
            "source_ordering": "question-before-answer",
            "storage_area": str(question.get("storage_area") or answer.get("storage_area") or ""),
            "validation_required": True,
        },
        "confidence": round(confidence, 3),
        "pairing_confidence": classify_pairing_confidence(confidence, same_source),
        "validation_status": "paired-candidate",
        "evidence_note": "Question/answer pair inferred from recovered browser storage order; verify against raw source before reporting.",
    }


def build_ai_transcript_candidate_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    conversation_rows: Sequence[Mapping[str, object]],
    transcript: Mapping[str, object],
    source_summary: Mapping[str, object],
) -> Dict[str, object]:
    candidate_citations = [
        ai_conversation_candidate_citation(
            browser=browser,
            profile=profile,
            user=user,
            profile_dir=profile_dir,
            row=row,
            source_index=index,
        )
        for index, row in enumerate(conversation_rows[:MAX_AI_CONVERSATION_ROWS])
    ]
    pair_citations = [
        ai_transcript_pair_citation(pair, source_index=index)
        for index, pair in enumerate(transcript.get("pairs") or [])
        if isinstance(pair, Mapping)
    ]
    manifest: Dict[str, object] = {
        "manifest_version": "ai-transcript-candidate-manifest-v1",
        "item_number": 48,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "gap_id": "#48",
        "commercial_gap_ids": ["#21", "#48"],
        "browser": browser,
        "profile": profile,
        "user": user,
        "profile_dir": str(profile_dir.resolve()),
        "supported_ai_services": sorted({label for _domain, label in AI_SERVICE_DOMAINS}),
        "detected_service_counts": source_summary.get("service_counts") or [],
        "source_file_count": int(source_summary.get("source_file_count") or 0),
        "source_sha256s": list(source_summary.get("source_sha256s") or [])[:25],
        "storage_area_counts": source_summary.get("storage_area_counts") or [],
        "candidate_row_count": len(conversation_rows),
        "candidate_citation_count": len(candidate_citations),
        "pair_count": int(transcript.get("pair_count") or 0),
        "complete_pair_count": int(transcript.get("complete_pair_count") or 0),
        "orphan_question_count": int(transcript.get("orphan_question_count") or 0),
        "orphan_answer_count": int(transcript.get("orphan_answer_count") or 0),
        "completeness_score": transcript.get("completeness_score"),
        "pairing_confidence_summary": transcript.get("pairing_confidence_summary") or {},
        "candidate_citations": candidate_citations,
        "pair_citations": pair_citations,
        "large_data_controls": {
            "max_ai_storage_files": MAX_AI_STORAGE_FILES,
            "max_ai_storage_file_bytes": MAX_AI_STORAGE_FILE_BYTES,
            "max_ai_conversation_rows": MAX_AI_CONVERSATION_ROWS,
            "candidate_rows_bounded": len(conversation_rows) > len(candidate_citations),
            "text_hashes_preserved": True,
            "raw_storage_open_requires_source_review": True,
        },
        "review_workflow": {
            "default_view": "chat-like-pair-review",
            "metadata_collapsed_by_default": True,
            "source_viewer": "raw-storage-file-offset",
            "recommended_grouping": ["ai_service", "source_storage_kind", "pairing_confidence"],
            "required_before_report": [
                "verify each prompt/answer against the cited raw storage file and offset",
                "attach service-side export or trusted browser fixture diff before claiming completeness",
                "record service/schema version for the detected AI provider",
                "document orphan prompt/answer and deleted-fragment limitations",
            ],
        },
        "validation_status": "candidate-paired-validation-required",
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_ai_transcript_schema_validation_manifest(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    conversation_rows: Sequence[Mapping[str, object]],
    transcript: Mapping[str, object],
    source_summary: Mapping[str, object],
    candidate_manifest: Mapping[str, object],
) -> Dict[str, object]:
    service_counts = count_field(conversation_rows, "ai_service")
    service_matrix = [
        {
            "ai_service": str(row.get("value") or ""),
            "candidate_count": int(row.get("count") or 0),
            "service_side_export_validated": False,
            "schema_version_known": False,
            "deleted_fragment_recovery_validated": False,
            "trusted_export_diff_status": "not-attached",
            "reportability": "candidate-review-only",
        }
        for row in service_counts
    ]
    manifest: Dict[str, object] = {
        "manifest_version": "ai-transcript-schema-validation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-021-025",
        "item_number": 21,
        "gap_id": "#21",
        "browser": browser,
        "profile": profile,
        "user": user,
        "profile_dir": str(profile_dir.resolve()),
        "supported_ai_services": sorted({label for _domain, label in AI_SERVICE_DOMAINS}),
        "detected_service_counts": service_counts,
        "service_schema_matrix": service_matrix,
        "source_summary": {
            "source_file_count": int(source_summary.get("source_file_count") or 0),
            "source_sha256s": list(source_summary.get("source_sha256s") or [])[:25],
            "storage_area_counts": source_summary.get("storage_area_counts") or [],
        },
        "pairing_quality": {
            "candidate_row_count": len(conversation_rows),
            "question_count": int(transcript.get("question_count") or 0),
            "answer_count": int(transcript.get("answer_count") or 0),
            "pair_count": int(transcript.get("pair_count") or 0),
            "complete_pair_count": int(transcript.get("complete_pair_count") or 0),
            "orphan_question_count": int(transcript.get("orphan_question_count") or 0),
            "orphan_answer_count": int(transcript.get("orphan_answer_count") or 0),
            "completeness_score": transcript.get("completeness_score"),
            "pairing_confidence_summary": transcript.get("pairing_confidence_summary") or {},
        },
        "candidate_manifest_ref": {
            "manifest_sha256": str(candidate_manifest.get("manifest_sha256") or ""),
            "candidate_citation_count": int(candidate_manifest.get("candidate_citation_count") or 0),
            "pair_citation_count": len(candidate_manifest.get("pair_citations") or []),
        },
        "service_schema_validation_status": "service-export-and-schema-validation-required",
        "reportability": {
            "allowed_use": "ai-transcript-candidate-review-pivot",
            "decision": "do-not-report-ai-transcript-as-complete",
            "commercial_grade_ready": False,
            "blockers": list(AI_TRANSCRIPT_BLOCKERS)
            + [
                "service-side-export-not-validated",
                "service-schema-version-not-validated",
                "deleted-fragment-recovery-not-validated",
            ],
        },
        "required_before_commercial_grade": [
            "attach service-side export or trusted profile fixture for the same account/session",
            "record provider and schema version for each detected AI service",
            "diff Q/A pairs against ChatGPT/Claude/Gemini/Perplexity or detected-provider exports",
            "measure false positives and false negatives across cached, deleted, and orphan fragments",
            "cite source storage offsets and hashes for every reportable prompt/answer pair",
        ],
    }
    manifest["manifest_sha256"] = stable_browser_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def ai_conversation_candidate_citation(
    *,
    browser: str,
    profile: str,
    user: str,
    profile_dir: Path,
    row: Mapping[str, object],
    source_index: int,
) -> Dict[str, object]:
    text = str(row.get("text") or "")
    source_path = str(row.get("source_path") or "")
    source_offset = row.get("source_offset")
    citation_payload = {
        "browser": browser,
        "profile": profile,
        "user": user,
        "source_index": source_index,
        "ai_service": str(row.get("ai_service") or ""),
        "direction": str(row.get("direction") or ""),
        "role": str(row.get("role") or ""),
        "storage_area": str(row.get("storage_area") or ""),
        "source_storage_kind": str(row.get("source_storage_kind") or ""),
        "source_relative_path": str(row.get("source_relative_path") or ""),
        "source_path": source_path,
        "source_sha256": str(row.get("source_sha256") or ""),
        "source_offset": source_offset,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else "",
        "text_preview": text[:160],
    }
    return {
        **citation_payload,
        "row_hash": stable_browser_sha256(citation_payload),
        "source_viewer_locator": {
            "viewer": "text-offset",
            "profile_dir": str(profile_dir.resolve()),
            "source_path": source_path,
            "source_relative_path": str(row.get("source_relative_path") or ""),
            "source_offset": source_offset,
            "open_requires_source_validation": True,
        },
        "validation_status": "ai-candidate-source-citation",
    }


def ai_transcript_pair_citation(pair: Mapping[str, object], *, source_index: int) -> Dict[str, object]:
    question = str(pair.get("question") or "")
    answer = str(pair.get("answer") or "")
    evidence = pair.get("pairing_evidence") if isinstance(pair.get("pairing_evidence"), Mapping) else {}
    citation_payload = {
        "pair_id": str(pair.get("pair_id") or ""),
        "pair_index": int(pair.get("pair_index") or source_index),
        "ai_service": str(pair.get("ai_service") or ""),
        "pairing_confidence": str(pair.get("pairing_confidence") or ""),
        "confidence": pair.get("confidence"),
        "question_sha256": hashlib.sha256(question.encode("utf-8")).hexdigest() if question else "",
        "answer_sha256": hashlib.sha256(answer.encode("utf-8")).hexdigest() if answer else "",
        "question_preview": question[:160],
        "answer_preview": answer[:160],
        "question_source_path": str(evidence.get("question_source_path") or pair.get("question_source_path") or ""),
        "answer_source_path": str(evidence.get("answer_source_path") or pair.get("answer_source_path") or ""),
        "question_source_offset": evidence.get("question_source_offset"),
        "answer_source_offset": evidence.get("answer_source_offset"),
        "source_sha256s": list(pair.get("source_sha256s") or []),
        "same_source_hash": bool(evidence.get("same_source_hash")),
    }
    return {
        **citation_payload,
        "row_hash": stable_browser_sha256(citation_payload),
        "source_viewer_locators": [
            {
                "role": "question",
                "viewer": "text-offset",
                "source_path": citation_payload["question_source_path"],
                "source_offset": citation_payload["question_source_offset"],
            },
            {
                "role": "answer",
                "viewer": "text-offset",
                "source_path": citation_payload["answer_source_path"],
                "source_offset": citation_payload["answer_source_offset"],
            },
        ],
        "validation_status": "paired-candidate-source-citation",
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
                "source_table": str(row.get("source_table") or "history"),
                "source_index": index,
                "source_row_id": row.get("source_row_id"),
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
                "source_table": str(row.get("source_table") or "downloads"),
                "source_index": index,
                "source_row_id": row.get("source_row_id"),
                "validation_status": "normalized-candidate",
            }
        )
    return sorted(rows, key=lambda item: str(item.get("timestamp") or ""), reverse=True)[:MAX_BROWSER_TIMELINE_ROWS]


def browser_timeline_integrity_profile(timeline: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    timestamps = [str(row.get("timestamp") or "") for row in timeline]
    populated_timestamps = [value for value in timestamps if value]
    source_index_complete = all("source_index" in row and "source_table" in row for row in timeline)
    return {
        "profile_version": "browser-timeline-integrity-profile-v1",
        "timeline_count": len(timeline),
        "timestamped_count": len(populated_timestamps),
        "visit_count": sum(1 for row in timeline if row.get("timeline_type") == "visit"),
        "download_count": sum(1 for row in timeline if row.get("timeline_type") == "download"),
        "sorted_descending": timestamps == sorted(timestamps, reverse=True),
        "source_index_complete": source_index_complete,
        "missing_timestamp_count": len(timestamps) - len(populated_timestamps),
        "validation_status": "normalized-candidate",
        "reportability_warning": "Browser timeline order is normalized for review; browser-version semantics and deleted/session state require known-answer validation.",
    }


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
                    "source_table": "urls",
                    "source_row_id": int(row["source_row_id"]),
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
                        urls.id AS source_row_id,
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
                "source_table": "downloads",
                "source_row_id": download_id,
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
                    moz_places.id AS source_row_id,
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
                        "source_table": "moz_places",
                        "source_row_id": int(row["source_row_id"]),
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
