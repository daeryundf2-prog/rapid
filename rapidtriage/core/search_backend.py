from __future__ import annotations

import hashlib
import json
from typing import Mapping, Sequence

QC_SEARCH_BACKEND_ITEMS = {
    48: "Add a SearchBackend abstraction so the UI and CLI can target different indexing engines consistently.",
    49: "Keep SQLite FTS as the default local backend with explicit limits and query-plan metadata.",
    50: "Evaluate a local Lucene/Tantivy-style backend for million-row text/artifact search.",
    51: "Add optional Elasticsearch/OpenSearch adapter for lab/server deployments without making it mandatory.",
    52: "Normalize index schema across documents, file metadata, EVTX, Registry, OCR, email, messenger, browser, AI, and timeline rows.",
    53: "Add 100k, 1M, and 10M synthetic benchmark generators with reproducible manifests.",
    54: "Make cursor pagination uniform across files, docs, artifacts, search, timeline, report candidates, and review queues.",
    55: "Enforce true UI virtualization and persisted viewport for massive tables.",
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
            "status": "functional-sidecar-prototype-not-default",
            "default": False,
            "requires_external_service": False,
            "supports": {
                "local_only": True,
                "processed_text_sidecar_query": True,
                "stores_full_text": False,
                "segment_indexing": True,
                "term_dictionary": True,
                "stored_source_locator": True,
                "million_row_target": "design-target-pending-benchmark",
            },
            "limits": {
                "prototype_dependency_added": False,
                "prototype_runtime_available": True,
                "default_interactive_limit": 500,
                "max_interactive_limit": 5000,
                "packaging_review_required": True,
                "parity_diff_required_before_enablement": True,
            },
            "commercial_blockers": [
                "million-row-synthetic-benchmark-required",
                "case-db-sqlite-parity-diff-required",
                "packaging-and-index-corruption-recovery-review-required",
            ],
        },
        {
            "backend_id": "elasticsearch-opensearch-optional",
            "family": "external-lab-search-service",
            "qc_prep_item_numbers": [48, 51],
            "status": "optional-adapter-contract-no-mandatory-service",
            "default": False,
            "requires_external_service": True,
            "supports": {
                "local_only": False,
                "multi_case_server_lab_mode": True,
                "bulk_index_api": True,
                "point_in_time_cursor": True,
                "source_locator_storage": True,
                "evidence_content_export_guard": True,
            },
            "limits": {
                "mandatory_for_desktop": False,
                "requires_cluster_health_check": True,
                "requires_index_template_hash": True,
                "requires_evidence_redaction_policy": True,
            },
            "commercial_blockers": [
                "external-search-adapter-integration-test-required",
                "index-template-and-mapping-diff-required",
                "evidence-content-export-policy-review-required",
                "cluster-failure-fallback-validation-required",
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
    external_adapter = build_external_search_adapter_contract(corpus_estimate=corpus_estimate or {})
    index_schema = build_normalized_index_schema_contract()
    benchmark_generators = build_synthetic_benchmark_generator_manifest()
    cursor_contract = build_uniform_cursor_pagination_contract()
    virtualization_contract = build_ui_virtualization_contract()
    contract_core: dict[str, object] = {
        "profile_version": "search-backend-contract-v1",
        "qc_prep_item_numbers": [48, 49, 50, 51, 52, 53, 54, 55],
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
        "external_search_adapter_contract": external_adapter,
        "normalized_index_schema_contract": index_schema,
        "synthetic_benchmark_generator_manifest": benchmark_generators,
        "uniform_cursor_pagination_contract": cursor_contract,
        "ui_virtualization_contract": virtualization_contract,
        "commercial_claim_allowed": False,
        "commercial_blockers": sorted(
            set(selected.get("commercial_blockers") or [])
            | set(sqlite_plan.get("commercial_blockers") or [])
            | set(local_candidate.get("commercial_blockers") or [])
            | set(external_adapter.get("commercial_blockers") or [])
            | set(index_schema.get("commercial_blockers") or [])
            | set(benchmark_generators.get("commercial_blockers") or [])
            | set(cursor_contract.get("commercial_blockers") or [])
            | set(virtualization_contract.get("commercial_blockers") or [])
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
        "prototype_runtime_available": True,
        "sidecar_query_command": "rapidtriage docs-index-search <docs-index.json> -k <keyword>",
        "stores_full_text": False,
        "enablement_scope": "processed-document-text-sidecar-only",
        "enablement_status": "candidate-only-not-default",
        "implemented_controls": [
            "query existing docs-index sidecars without re-extracting document text",
            "return source locators, text hashes, matched terms, scores, result hashes, and truncation state",
            "cap interactive result windows at 5000 rows until benchmark evidence exists",
            "force source-viewer verification because the sidecar stores no full text previews",
        ],
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


def build_external_search_adapter_contract(*, corpus_estimate: Mapping[str, object]) -> dict[str, object]:
    target_rows = int(corpus_estimate.get("target_rows") or 1_000_000)
    contract_core = {
        "profile_version": "external-search-adapter-contract-v1",
        "qc_prep_item_number": 51,
        "backend_id": "elasticsearch-opensearch-optional",
        "adapter_status": "contract-only-optional-lab-server",
        "mandatory_for_single_case_desktop": False,
        "target_rows": target_rows,
        "supported_service_families": ["Elasticsearch", "OpenSearch"],
        "required_connection_controls": [
            "explicit analyst opt-in",
            "cluster health check before indexing",
            "TLS/authentication configuration capture",
            "local SQLite fallback if external service is unavailable",
        ],
        "required_index_controls": [
            "versioned index template hash",
            "case-scoped index naming",
            "source locator stored for every hit",
            "bulk indexing result counts and failure rows",
            "point-in-time or search_after cursor support",
        ],
        "privacy_controls": {
            "export_evidence_text_to_external_service_by_default": False,
            "redaction_policy_required": True,
            "local_only_enterprise_mode_must_disable": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "external-search-adapter-integration-test-required",
            "index-template-and-mapping-diff-required",
            "cluster-failure-fallback-validation-required",
            "privacy-redaction-policy-approval-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_backend_sha256(contract_core)}


def build_normalized_index_schema_contract() -> dict[str, object]:
    artifact_families = [
        "document",
        "file_metadata",
        "evtx",
        "registry",
        "ocr",
        "email",
        "messenger",
        "browser",
        "ai_transcript",
        "timeline",
    ]
    required_fields = [
        "case_id",
        "source_id",
        "artifact_family",
        "artifact_type",
        "source_path",
        "source_hash_sha256",
        "record_id",
        "record_locator",
        "event_time_utc",
        "event_time_source",
        "title",
        "body_text",
        "actor",
        "target",
        "url",
        "ip",
        "email",
        "phone",
        "parser_name",
        "parser_version",
        "confidence",
        "review_state",
    ]
    family_requirements = {
        family: {
            "must_emit_source_locator": True,
            "must_emit_parser_identity": True,
            "must_emit_hash_or_limitation": True,
            "must_emit_timezone_assumption": family in {"evtx", "browser", "email", "messenger", "ai_transcript", "timeline"},
        }
        for family in artifact_families
    }
    contract_core = {
        "profile_version": "normalized-index-schema-contract-v1",
        "qc_prep_item_number": 52,
        "artifact_families": artifact_families,
        "required_fields": required_fields,
        "family_requirements": family_requirements,
        "schema_evolution": {
            "versioned_schema_required": True,
            "unknown_fields_allowed": True,
            "breaking_change_requires_migration_manifest": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "all-artifact-family-fixture-schema-diff-required",
            "source-locator-completeness-benchmark-required",
            "timezone-and-parser-version-normalization-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_backend_sha256(contract_core)}


def build_synthetic_benchmark_generator_manifest(
    *,
    targets: Sequence[int] = (100_000, 1_000_000, 10_000_000),
    seed: str = "rapidforensic-qc-search-benchmark-v1",
) -> dict[str, object]:
    normalized_targets = [int(target) for target in targets]
    generators = []
    for target in normalized_targets:
        generators.append(
            {
                "target_rows": target,
                "generator_id": f"synthetic-index-corpus-{target}",
                "seed": seed,
                "artifact_mix": {
                    "document": 20,
                    "file_metadata": 15,
                    "evtx": 15,
                    "registry": 10,
                    "ocr": 10,
                    "email": 10,
                    "messenger": 10,
                    "browser": 5,
                    "ai_transcript": 3,
                    "timeline": 2,
                },
                "must_emit_manifest": True,
                "must_emit_expected_keyword_counts": True,
                "must_emit_expected_source_locator_counts": True,
            }
        )
    manifest_core = {
        "profile_version": "synthetic-benchmark-generator-manifest-v1",
        "qc_prep_item_number": 53,
        "targets": normalized_targets,
        "generators": generators,
        "reproducibility_controls": {
            "stable_seed": seed,
            "deterministic_row_order_required": True,
            "manifest_hash_required": True,
            "expected_counts_required": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "100k-generator-runtime-evidence-required",
            "1m-generator-runtime-evidence-required",
            "10m-generator-runtime-evidence-required",
            "expected-count-known-answer-diff-required",
        ],
    }
    return {**manifest_core, "manifest_hash": stable_backend_sha256(manifest_core)}


def build_uniform_cursor_pagination_contract() -> dict[str, object]:
    collections = [
        "files",
        "documents",
        "artifacts",
        "search",
        "timeline",
        "report_candidates",
        "review_queue",
    ]
    collection_contracts = {
        collection: {
            "cursor_required": True,
            "stable_sort_required": True,
            "resume_token_required": True,
            "total_or_searched_count_required": True,
            "truncation_state_required": True,
            "source_locator_required": collection in {"documents", "artifacts", "search", "timeline", "report_candidates"},
        }
        for collection in collections
    }
    contract_core = {
        "profile_version": "uniform-cursor-pagination-contract-v1",
        "qc_prep_item_number": 54,
        "collections": collections,
        "collection_contracts": collection_contracts,
        "cursor_shape": {
            "cursor": "opaque-string",
            "page_size": "bounded-int",
            "sort_key": "stable-field-list",
            "direction": "next-or-previous",
            "filters_hash": "sha256-of-active-filters",
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "all-endpoint-cursor-contract-test-required",
            "large-result-resume-after-restart-test-required",
            "cursor-filter-mutation-safety-test-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_backend_sha256(contract_core)}


def build_ui_virtualization_contract() -> dict[str, object]:
    contract_core = {
        "profile_version": "ui-virtualization-contract-v1",
        "qc_prep_item_number": 55,
        "target_views": [
            "file_table",
            "artifact_table",
            "search_results",
            "timeline",
            "review_queue",
            "report_candidates",
        ],
        "required_behaviors": {
            "dom_windowing_required": True,
            "row_height_strategy_recorded": True,
            "overscan_bounds_recorded": True,
            "keyboard_navigation_preserves_focus": True,
            "selection_state_survives_virtual_unmount": True,
            "viewport_restore_required": True,
            "deep_link_to_row_required": True,
        },
        "persistence_contract": {
            "case_id": True,
            "view_id": True,
            "active_filters_hash": True,
            "sort_hash": True,
            "cursor": True,
            "focused_row_id": True,
            "scroll_anchor": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "browser-e2e-100k-row-virtualization-test-required",
            "keyboard-triage-focus-retention-test-required",
            "viewport-restore-after-navigation-test-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_backend_sha256(contract_core)}
