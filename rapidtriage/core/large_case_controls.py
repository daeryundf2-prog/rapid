from __future__ import annotations

import hashlib
import json
import platform
from typing import Sequence


def stable_large_case_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_source_search_full_cursor_contract() -> dict[str, object]:
    contract_core = {
        "profile_version": "source-search-full-cursor-scan-contract-v1",
        "qc_prep_item_number": 56,
        "sqlite_row_cap_policy": "no-silent-fixed-row-cap",
        "large_file_byte_window_policy": "bounded-read-with-resume-token",
        "required_diagnostics": [
            "sqlite_scanned_table_count",
            "sqlite_scanned_row_count",
            "sqlite_full_cursor_scan",
            "sqlite_result_limit_reached",
            "sqlite_resume_state",
            "sqlite_truncated_tables",
            "file_scan_start_offset",
            "file_scan_end_offset",
            "file_resume_state",
        ],
        "result_limit_policy": {
            "limit_results_not_rows": True,
            "must_disclose_result_limit": True,
            "must_emit_resume_state_when_limit_reached": True,
            "api_resume_token_round_trip_supported": True,
            "large_file_resume_token_round_trip_supported": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "source-search-trusted-locator-diff-required",
            "large-sqlite-current-file-search-benchmark-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}


def build_hash_cache_persistence_contract() -> dict[str, object]:
    contract_core = {
        "profile_version": "hash-cache-persistence-contract-v1",
        "qc_prep_item_number": 57,
        "cache_key_fields": ["source_path", "size", "mtime_ns", "inode", "device", "sha256"],
        "required_behaviors": {
            "persist_across_runs": True,
            "invalidate_on_size_change": True,
            "invalidate_on_mtime_change": True,
            "invalidate_on_inode_or_device_change": True,
            "content_hash_keyed_rows": True,
            "path_disclosure_minimized": True,
        },
        "existing_runtime_bridge": {
            "module": "rapidtriage.core.hash_cache",
            "manifest": "hash-cache-persistence-manifest-v1",
            "current_state": "explicit-export-import-snapshot",
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "automatic-on-disk-cache-load-save-required",
            "large-case-hit-ratio-benchmark-required",
            "trusted-hash-cache-manifest-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}


def build_duplicate_grouping_contract() -> dict[str, object]:
    contract_core = {
        "profile_version": "duplicate-grouping-contract-v1",
        "qc_prep_item_number": 58,
        "grouping_modes": [
            "exact-content-hash",
            "fuzzy-text-shingle",
            "perceptual-image-hash",
            "perceptual-video-keyframe-hash",
        ],
        "required_review_controls": {
            "representative_required": True,
            "group_members_preserved": True,
            "auto_suppression_disabled_by_default": True,
            "source_locator_required_per_member": True,
            "collapse_state_persisted": True,
        },
        "existing_runtime_bridge": {
            "exact_hash_module": "rapidtriage.core.files",
            "search_hit_dedup_module": "rapidtriage.core.analysis",
            "current_state": "exact-hash-and-search-hit-baseline",
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "fuzzy-text-near-duplicate-corpus-required",
            "perceptual-media-corpus-required",
            "trusted-duplicate-group-manifest-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}


def build_parser_isolation_contract(*, parser_families: Sequence[str] | None = None) -> dict[str, object]:
    families = list(parser_families or ["evtx", "registry", "ese", "mft", "usn", "sqlite", "office", "pdf", "media"])
    contract_core = {
        "profile_version": "parser-isolation-contract-v1",
        "qc_prep_item_number": 59,
        "parser_families": families,
        "required_behaviors": {
            "subprocess_per_risky_parser": True,
            "crash_report_per_parser": True,
            "partial_output_quarantine": True,
            "case_run_continues_after_parser_crash": True,
            "stderr_stdout_captured_bounded": True,
        },
        "existing_runtime_bridge": {
            "module": "rapidtriage.core.run",
            "manifest": "parser-crash-isolation-manifest-v1",
            "ledger": "parser-crash-isolation-ledger-v1",
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "subprocess-isolation-enabled-for-all-risky-parsers",
            "hostile-parser-crash-corpus-required",
            "quarantine-cleanup-e2e-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}


def build_memory_cap_contract(*, requested_cap_bytes: int = 0) -> dict[str, object]:
    os_family = platform.system() or "unknown"
    hard_cap_possible = os_family in {"Linux", "Darwin"}
    contract_core = {
        "profile_version": "memory-cap-contract-v1",
        "qc_prep_item_number": 60,
        "platform": os_family,
        "requested_cap_bytes": int(requested_cap_bytes or 0),
        "hard_cap_possible": hard_cap_possible,
        "required_behaviors": {
            "stage_boundary_rss_checks": True,
            "configured_cap_recorded": True,
            "over_cap_action_recorded": True,
            "cooperative_warning_when_hard_cap_unavailable": True,
            "per_parser_cap_policy_required": True,
        },
        "existing_runtime_bridge": {
            "module": "rapidtriage.core.run",
            "manifest": "memory-cap-enforcement-manifest-v1",
            "telemetry": "memory-cap-stage-telemetry-manifest-v1",
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "os-level-hard-limit-validation-required",
            "per-parser-rss-limit-test-required",
            "large-evidence-memory-regression-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}


def build_large_case_resilience_contract(*, requested_cap_bytes: int = 0) -> dict[str, object]:
    source_search = build_source_search_full_cursor_contract()
    hash_cache = build_hash_cache_persistence_contract()
    duplicate_grouping = build_duplicate_grouping_contract()
    parser_isolation = build_parser_isolation_contract()
    memory_cap = build_memory_cap_contract(requested_cap_bytes=requested_cap_bytes)
    contracts = [source_search, hash_cache, duplicate_grouping, parser_isolation, memory_cap]
    contract_core: dict[str, object] = {
        "profile_version": "large-case-resilience-contract-v1",
        "qc_prep_item_numbers": [56, 57, 58, 59, 60],
        "source_search_full_cursor_contract": source_search,
        "hash_cache_persistence_contract": hash_cache,
        "duplicate_grouping_contract": duplicate_grouping,
        "parser_isolation_contract": parser_isolation,
        "memory_cap_contract": memory_cap,
        "commercial_claim_allowed": False,
        "commercial_blockers": sorted(
            {blocker for contract in contracts for blocker in contract.get("commercial_blockers", [])}
        ),
    }
    return {**contract_core, "contract_hash": stable_large_case_sha256(contract_core)}
