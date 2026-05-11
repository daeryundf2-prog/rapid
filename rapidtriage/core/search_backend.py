from __future__ import annotations

import hashlib
import json
from typing import Mapping, Sequence

QC_SEARCH_BACKEND_ITEMS = {
    48: "Add a SearchBackend abstraction so the UI and CLI can target different indexing engines consistently.",
    49: "Keep SQLite FTS as the default local backend with explicit limits and query-plan metadata.",
    50: "Evaluate a local Lucene/Tantivy-style backend for million-row text/artifact search.",
}

DEFAULT_SEARCH_BACKEND_ID = "sqlite-fts-local"


def stable_backend_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    payload = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def available_search_backends() -> list[dict[str, object]]:
    return [
        {
            "backend_id": DEFAULT_SEARCH_BACKEND_ID,
            "family": "sqlite-fts",
            "qc_prep_item_numbers": [48, 49],
            "status": "implemented-default-local",
            "default": True,
            "requires_external_service": False,
            "supports": {
                "local_only": True,
                "fts_queries": True,
                "cursor_pagination": True,
                "query_plan_metadata": True,
                "million_row_target": "requires-benchmark-evidence",
            },
            "limits": {
                "default_limit": 500,
                "max_interactive_limit": 5000,
                "requires_explicit_truncation_disclosure": True,
                "requires_resume_cursor": True,
            },
            "commercial_blockers": [
                "large-case-search-latency-benchmark-required",
                "trusted-query-plan-and-hit-parity-diff-required",
                "10m-row-regression-not-attached",
            ],
        },
        {
            "backend_id": "local-inverted-index-candidate",
            "family": "lucene-tantivy-style-local-inverted-index",
            "qc_prep_item_numbers": [48, 50],
            "status": "evaluated-design-contract-no-production-dependency",
            "default": False,
            "requires_external_service": False,
            "supports": {
                "local_only": True,
                "segment_indexing": True,
                "term_dictionary": True,
                "stored_source_locator": True,
                "million_row_target": "design-target-pending-benchmark",
            },
            "limits": {
                "prototype_dependency_added": False,
                "packaging_review_required": True,
                "parity_diff_required_before_enablement": True,
            },
            "commercial_blockers": [
                "million-row-synthetic-benchmark-required",
                "case-db-sqlite-parity-diff-required",
                "packaging-and-index-corruption-recovery-review-required",
            ],
        },
    ]


def select_search_backend(preferred_backend_id: str | None = None) -> dict[str, object]:
    backends = available_search_backends()
    if preferred_backend_id:
        for backend in backends:
            if backend["backend_id"] == preferred_backend_id:
                return dict(backend)
    return dict(next(backend for backend in backends if backend.get("default")))


def build_search_backend_contract(
    *,
    keywords: Sequence[str],
    limit: int,
    preferred_backend_id: str | None = None,
    corpus_estimate: Mapping[str, object] | None = None,
) -> dict[str, object]:
    selected = select_search_backend(preferred_backend_id)
    candidates = available_search_backends()
    sqlite_plan = build_sqlite_fts_backend_plan(keywords=keywords, limit=limit, corpus_estimate=corpus_estimate or {})
    local_candidate = build_local_inverted_candidate_evaluation(corpus_estimate=corpus_estimate or {})
    contract_core: dict[str, object] = {
        "profile_version": "search-backend-contract-v1",
        "qc_prep_item_numbers": [48, 49, 50],
        "selected_backend_id": selected["backend_id"],
        "default_backend_id": DEFAULT_SEARCH_BACKEND_ID,
        "backend_abstraction_status": "implemented",
        "ui_cli_contract": {
            "backend_id": True,
            "query_options": True,
            "limit": True,
            "cursor_or_resume": True,
            "source_locator": True,
            "truncation_warning": True,
            "query_plan_metadata": True,
        },
        "selected_backend": selected,
        "candidate_backends": candidates,
        "sqlite_fts_default_plan": sqlite_plan,
        "local_inverted_candidate_evaluation": local_candidate,
        "commercial_claim_allowed": False,
        "commercial_blockers": sorted(
            set(selected.get("commercial_blockers") or [])
            | set(sqlite_plan.get("commercial_blockers") or [])
            | set(local_candidate.get("commercial_blockers") or [])
        ),
    }
    return {
        **contract_core,
        "contract_hash": stable_backend_sha256(contract_core),
    }


def build_sqlite_fts_backend_plan(
    *,
    keywords: Sequence[str],
    limit: int,
    corpus_estimate: Mapping[str, object],
) -> dict[str, object]:
    normalized_limit = max(1, min(int(limit or 500), 5000))
    plan_core = {
        "profile_version": "sqlite-fts-backend-plan-v1",
        "qc_prep_item_number": 49,
        "backend_id": DEFAULT_SEARCH_BACKEND_ID,
        "keyword_count": len([keyword for keyword in keywords if str(keyword).strip()]),
        "requested_limit": int(limit or 0),
        "effective_interactive_limit": normalized_limit,
        "cursor_pagination_required": True,
        "query_plan_metadata_required": True,
        "searched_rows_and_total_rows_required": True,
        "per_table_truncation_disclosure_required": True,
        "estimated_document_rows": int(corpus_estimate.get("document_rows") or 0),
        "estimated_artifact_rows": int(corpus_estimate.get("artifact_rows") or 0),
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "trusted-sqlite-fts-query-plan-diff-required",
            "large-row-count-search-benchmark-required",
            "source-viewer-hit-parity-validation-required",
        ],
    }
    return {**plan_core, "plan_hash": stable_backend_sha256(plan_core)}


def build_local_inverted_candidate_evaluation(*, corpus_estimate: Mapping[str, object]) -> dict[str, object]:
    target_rows = int(corpus_estimate.get("target_rows") or 1_000_000)
    evaluation_core = {
        "profile_version": "local-inverted-index-candidate-evaluation-v1",
        "qc_prep_item_number": 50,
        "candidate_family": "lucene-tantivy-style-local-inverted-index",
        "target_rows": target_rows,
        "prototype_dependency_added": False,
        "enablement_status": "candidate-only-not-default",
        "required_parity_tests": [
            "same query returns same source locator set as SQLite FTS on known-answer corpus",
            "index rebuild produces stable manifest and segment hashes",
            "corrupt segment recovery does not hide missing rows",
            "million-row ingest/search benchmark records p50/p95 latency and memory",
        ],
        "decision": "do-not-enable-before-benchmark-and-packaging-review",
        "commercial_blockers": [
            "million-row-synthetic-benchmark-required",
            "sqlite-fts-parity-diff-required",
            "index-corruption-recovery-test-required",
            "packaging-review-for-new-search-dependency-required",
        ],
    }
    return {**evaluation_core, "evaluation_hash": stable_backend_sha256(evaluation_core)}
