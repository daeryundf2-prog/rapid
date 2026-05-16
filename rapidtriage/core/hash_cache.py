from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping

from .forensic_accuracy import build_accuracy_gate


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
HASH_CACHE_GAP_ID = "#76"
HASH_CACHE_TRUSTED_DIFF_BLOCKER_76 = "trusted-hash-cache-manifest-diff-missing"
HASH_CACHE_TRUSTED_TOOLS = {"hash-cache-manifest", "content-addressed-cache-oracle", "known-answer-hash-cache-export"}
HASH_CACHE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "hash-cache-report-grade-validation-plan-v1"
HASH_CACHE_REPORT_GRADE_BLOCKERS = [
    HASH_CACHE_TRUSTED_DIFF_BLOCKER_76,
    "automatic-on-disk-cache-wiring-required",
    "large-case-hit-ratio-validation-required",
    "cross-platform-cache-key-semantics-required",
    "content-addressed-lookup-mode-required",
    "multi-run-stale-cache-replay-required",
]
_HASH_CACHE: dict[tuple[str, int, int, int, int], dict[str, str]] = {}
_HASH_CACHE_STATS = {
    "hits": 0,
    "misses": 0,
    "invalidations": 0,
}
_HASH_CACHE_EVENTS: list[dict[str, object]] = []
_HASH_CACHE_SESSION_SEQUENCE = 0
_HASH_CACHE_SESSION_ID = hashlib.sha256(b"rapidtriage-hash-cache-session-0").hexdigest()


def reset_hash_cache() -> None:
    global _HASH_CACHE_SESSION_ID, _HASH_CACHE_SESSION_SEQUENCE
    _HASH_CACHE.clear()
    _HASH_CACHE_EVENTS.clear()
    for key in _HASH_CACHE_STATS:
        _HASH_CACHE_STATS[key] = 0
    _HASH_CACHE_SESSION_SEQUENCE += 1
    _HASH_CACHE_SESSION_ID = hashlib.sha256(
        f"rapidtriage-hash-cache-session-{_HASH_CACHE_SESSION_SEQUENCE}".encode("ascii")
    ).hexdigest()


def compute_hashes_cached(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    resolved = path.expanduser().resolve()
    stat_result = resolved.stat()
    key = hash_cache_key(resolved, stat_result)
    stale_keys = [existing for existing in _HASH_CACHE if existing[0] == str(resolved) and existing != key]
    for stale_key in stale_keys:
        _HASH_CACHE.pop(stale_key, None)
    if stale_keys:
        _HASH_CACHE_STATS["invalidations"] += len(stale_keys)
        append_hash_cache_event("invalidated", resolved, key, cache_hit=False)
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        _HASH_CACHE_STATS["hits"] += 1
        append_hash_cache_event("hit", resolved, key, cache_hit=True)
        return dict(cached)
    _HASH_CACHE_STATS["misses"] += 1
    append_hash_cache_event("miss", resolved, key, cache_hit=False)
    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    hashes = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    _HASH_CACHE[key] = hashes
    return dict(hashes)


def hash_cache_key(path: Path, stat_result) -> tuple[str, int, int, int, int]:
    return (
        str(path),
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(getattr(stat_result, "st_ino", 0) or 0),
        int(getattr(stat_result, "st_dev", 0) or 0),
    )


def append_hash_cache_event(action: str, path: Path, key: tuple[str, int, int, int, int], *, cache_hit: bool) -> None:
    _HASH_CACHE_EVENTS.append(
        {
            "action": action,
            "path_hash": hashlib.sha256(str(path).encode("utf-8")).hexdigest(),
            "name": path.name,
            "size": key[1],
            "mtime_ns": key[2],
            "inode": key[3],
            "device": key[4],
            "cache_hit": cache_hit,
        }
    )
    if len(_HASH_CACHE_EVENTS) > 500:
        del _HASH_CACHE_EVENTS[:-500]


def build_hash_cache_manifest(*, max_entries: int = 100, max_events: int = 100) -> dict[str, object]:
    entries = []
    for key, hashes in sorted(_HASH_CACHE.items(), key=lambda item: (item[0][0], item[0][1], item[0][2]))[:max_entries]:
        path_text, size, mtime_ns, inode, device = key
        path = Path(path_text)
        entries.append(
            {
                "path_hash": hashlib.sha256(path_text.encode("utf-8")).hexdigest(),
                "name": path.name,
                "size": size,
                "mtime_ns": mtime_ns,
                "inode": inode,
                "device": device,
                "algorithms": sorted(hashes),
                "sha256": hashes.get("sha256", ""),
            }
        )
    recent_events = _HASH_CACHE_EVENTS[-max_events:]
    entries_head_hash = hashlib.sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()
    events_head_hash = hashlib.sha256(json.dumps(recent_events, sort_keys=True).encode("utf-8")).hexdigest()
    persistence_manifest = build_hash_cache_persistence_manifest(max_entries=max_entries)
    manifest_core = {
        "profile": "hash-cache-manifest-v1",
        "profile_version": "hash-cache-manifest-v1",
        "item_number": 76,
        "cache_session_id": _HASH_CACHE_SESSION_ID,
        "entry_count": len(_HASH_CACHE),
        "event_count": len(_HASH_CACHE_EVENTS),
        "entries_truncated": len(_HASH_CACHE) > max_entries,
        "events_truncated": len(_HASH_CACHE_EVENTS) > max_events,
        "entries_head_hash": entries_head_hash,
        "events_head_hash": events_head_hash,
        "persistence_manifest": persistence_manifest,
        "persistence_manifest_hash": persistence_manifest["manifest_hash"],
        "stats": dict(_HASH_CACHE_STATS),
        "cache_key_fields": ["path", "size", "mtime_ns", "inode", "device"],
        "algorithms": list(HASH_ALGORITHMS),
        "policy": {
            "scope": "process-local-with-explicit-snapshot",
            "persistent_across_restarts": True,
            "persistence_mode": "explicit-export-import-snapshot",
            "export_import_contract_declared": True,
            "stale_entry_invalidation": "same-path size/mtime/inode/device mismatch invalidates previous entries",
            "path_disclosure": "full paths are hashed in manifest entries; basename is retained for analyst orientation",
            "persistent_cache_next_step": "Promote explicit snapshots to an automatic content-addressed on-disk cache only after large-case hit-ratio validation.",
        },
        "invalidation_proof": {
            "invalidations": _HASH_CACHE_STATS["invalidations"],
            "same_path_invalidation_events": sum(1 for event in _HASH_CACHE_EVENTS if event.get("action") == "invalidated"),
            "latest_invalidation_event": next(
                (event for event in reversed(_HASH_CACHE_EVENTS) if event.get("action") == "invalidated"),
                None,
            ),
        },
        "entries": entries,
        "recent_events": recent_events,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_hash_cache_persistence_manifest(*, max_entries: int = 100) -> dict[str, object]:
    rows = []
    for key, hashes in sorted(_HASH_CACHE.items(), key=lambda item: (item[1].get("sha256", ""), item[0][0]))[:max_entries]:
        path_text, size, mtime_ns, inode, device = key
        row_core = {
            "content_address_key": hashes.get("sha256", ""),
            "path_hash": hashlib.sha256(path_text.encode("utf-8")).hexdigest(),
            "name": Path(path_text).name,
            "size": size,
            "mtime_ns": mtime_ns,
            "inode": inode,
            "device": device,
            "algorithms": sorted(hashes),
            "md5": hashes.get("md5", ""),
            "sha1": hashes.get("sha1", ""),
            "sha256": hashes.get("sha256", ""),
        }
        rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_hashes = [str(row["row_hash"]) for row in rows]
    manifest_core = {
        "profile_version": "hash-cache-persistence-manifest-v1",
        "item_number": 76,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "snapshot_format": "hash-cache-persistent-snapshot-v1",
        "persistence_mode": "explicit-export-import-snapshot",
        "content_address_key": "sha256",
        "cache_key_fields": ["path", "size", "mtime_ns", "inode", "device"],
        "row_count": len(rows),
        "row_head_hash": hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest(),
        "rows": rows,
        "automatic_on_disk_cache": False,
        "large_case_hit_ratio_validated": False,
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def export_hash_cache_snapshot(path: Path, *, max_entries: int = 1000) -> dict[str, object]:
    snapshot_path = path.expanduser().resolve()
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    for key, hashes in sorted(_HASH_CACHE.items(), key=lambda item: (item[0][0], item[0][1], item[0][2]))[:max_entries]:
        entries.append(
            {
                "key": list(key),
                "hashes": dict(hashes),
            }
        )
    persistence_manifest = build_hash_cache_persistence_manifest(max_entries=max_entries)
    snapshot_core = {
        "profile_version": "hash-cache-persistent-snapshot-v1",
        "item_number": 76,
        "cache_session_id": _HASH_CACHE_SESSION_ID,
        "entry_count": len(entries),
        "entries": entries,
        "persistence_manifest": persistence_manifest,
        "persistence_manifest_hash": persistence_manifest["manifest_hash"],
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "commercial_claim_allowed": False,
    }
    snapshot = {
        **snapshot_core,
        "snapshot_hash": hashlib.sha256(json.dumps(snapshot_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }
    snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "profile_version": "hash-cache-snapshot-export-report-v1",
        "path": str(snapshot_path),
        "entry_count": len(entries),
        "snapshot_hash": snapshot["snapshot_hash"],
        "persistence_manifest_hash": persistence_manifest["manifest_hash"],
    }


def import_hash_cache_snapshot(path: Path) -> dict[str, object]:
    snapshot_path = path.expanduser().resolve()
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if payload.get("profile_version") != "hash-cache-persistent-snapshot-v1":
        raise ValueError("unsupported hash cache snapshot profile")
    imported = 0
    skipped = 0
    for entry in payload.get("entries", []):
        if not isinstance(entry, Mapping):
            skipped += 1
            continue
        key_values = entry.get("key")
        hashes = entry.get("hashes")
        if not isinstance(key_values, list) or len(key_values) != 5 or not isinstance(hashes, Mapping):
            skipped += 1
            continue
        key = (
            str(key_values[0]),
            int(key_values[1]),
            int(key_values[2]),
            int(key_values[3]),
            int(key_values[4]),
        )
        if not all(str(hashes.get(name) or "") for name in HASH_ALGORITHMS):
            skipped += 1
            continue
        _HASH_CACHE[key] = {name: str(hashes.get(name) or "") for name in HASH_ALGORITHMS}
        imported += 1
    return {
        "profile_version": "hash-cache-snapshot-import-report-v1",
        "path": str(snapshot_path),
        "imported_count": imported,
        "skipped_count": skipped,
        "snapshot_hash": str(payload.get("snapshot_hash") or ""),
        "persistence_manifest_hash": str(payload.get("persistence_manifest_hash") or ""),
    }


def hash_cache_assessment(
    *,
    cache_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = dict(cache_manifest) if cache_manifest else build_hash_cache_manifest()
    validation_plan = hash_cache_report_grade_validation_plan(
        cache_manifest=manifest,
        trusted_diff=trusted_diff,
    )
    satisfied = [
        "MD5/SHA1/SHA256 captured",
        "path-size-mtime-inode cache key recorded",
        "hit/miss counters emitted",
        "hash cache assessment attached",
        "hash-cache manifest hash emitted",
        "stale same-path invalidation policy emitted",
        "persistent snapshot manifest emitted",
        "content-addressed cache rows emitted",
        "automatic persistent cache limitation warning",
        "hash cache report-grade validation plan emitted",
        "hash cache report-grade ready slots emitted",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted hash-cache manifest diff pass")
    blockers = list(
        dict.fromkeys(
            [
                "automatic-on-disk-cache-not-enabled-without-explicit-snapshot-import",
                "cache-lookup-still-uses-path-size-mtime-key-with-content-addressed-export-evidence",
                "large-scale-hash-cache-hit-ratio-validation-remains-required",
                *validation_plan["blockers"],
            ]
        )
    )
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers = list(dict.fromkeys([*blockers, HASH_CACHE_TRUSTED_DIFF_BLOCKER_76]))
    return {
        "component": "file-hash-cache",
        "status": "in-process-path-size-mtime-cache-validation-plan-emitted",
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "algorithm_count": len(HASH_ALGORITHMS),
        "algorithms": list(HASH_ALGORITHMS),
        "cache_session_id": str(manifest.get("cache_session_id") or ""),
        "entry_count": len(_HASH_CACHE),
        "hit_count": _HASH_CACHE_STATS["hits"],
        "miss_count": _HASH_CACHE_STATS["misses"],
        "invalidation_count": _HASH_CACHE_STATS["invalidations"],
        "entries_head_hash": str(manifest.get("entries_head_hash") or ""),
        "events_head_hash": str(manifest.get("events_head_hash") or ""),
        "persistence_manifest_hash": str(manifest.get("persistence_manifest_hash") or ""),
        "hash_cache_manifest": manifest,
        "hash_cache_report_grade_validation_plan": validation_plan,
        "hash_cache_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "trusted_hash_cache_diff": dict(trusted_diff) if trusted_diff else missing_hash_cache_trusted_diff(),
        "core_accuracy_gates": [
            build_accuracy_gate(
                76,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"entry_count:{len(_HASH_CACHE)}",
                    f"hit_count:{_HASH_CACHE_STATS['hits']}",
                    f"miss_count:{_HASH_CACHE_STATS['misses']}",
                    f"manifest_hash:{manifest.get('manifest_hash', '')}",
                    f"persistence_manifest_hash:{manifest.get('persistence_manifest_hash', '')}",
                    f"hash_cache_report_grade_validation_plan_hash:{validation_plan['validation_plan_hash']}",
                    f"hash_cache_report_grade_ready_slots:{validation_plan['ready_slot_count']}",
                    f"hash_cache_report_grade_blocking_slots:{validation_plan['blocking_slot_count']}",
                ],
            )
        ],
        "blockers": blockers,
    }


def hash_cache_report_grade_validation_plan(
    *,
    cache_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = dict(cache_manifest)
    policy = manifest.get("policy") if isinstance(manifest.get("policy"), Mapping) else {}
    persistence_manifest = (
        manifest.get("persistence_manifest") if isinstance(manifest.get("persistence_manifest"), Mapping) else {}
    )
    stats = manifest.get("stats") if isinstance(manifest.get("stats"), Mapping) else {}
    invalidation_proof = (
        manifest.get("invalidation_proof") if isinstance(manifest.get("invalidation_proof"), Mapping) else {}
    )
    key_policy = {
        "cache_key_fields": list(manifest.get("cache_key_fields") or []),
        "scope": str(policy.get("scope") or ""),
        "persistence_mode": str(policy.get("persistence_mode") or ""),
        "stale_entry_invalidation": str(policy.get("stale_entry_invalidation") or ""),
        "path_disclosure": str(policy.get("path_disclosure") or ""),
    }
    key_policy_hash = hashlib.sha256(json.dumps(key_policy, sort_keys=True).encode("utf-8")).hexdigest()
    counter_profile = {
        "entries": int(manifest.get("entry_count") or 0),
        "events": int(manifest.get("event_count") or 0),
        "hits": int(stats.get("hits") or 0),
        "misses": int(stats.get("misses") or 0),
        "invalidations": int(stats.get("invalidations") or 0),
        "same_path_invalidation_events": int(invalidation_proof.get("same_path_invalidation_events") or 0),
    }
    counter_profile_hash = hashlib.sha256(json.dumps(counter_profile, sort_keys=True).encode("utf-8")).hexdigest()
    snapshot_contract = {
        "snapshot_format": str(persistence_manifest.get("snapshot_format") or ""),
        "persistence_mode": str(persistence_manifest.get("persistence_mode") or ""),
        "content_address_key": str(persistence_manifest.get("content_address_key") or ""),
        "row_count": int(persistence_manifest.get("row_count") or 0),
        "export_import_contract_declared": bool(policy.get("export_import_contract_declared")),
    }
    snapshot_contract_hash = hashlib.sha256(
        json.dumps(snapshot_contract, sort_keys=True).encode("utf-8")
    ).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "hash-cache-run-manifest",
            "status": "ready",
            "evidence_ref": "hash_cache_manifest_hash",
            "evidence_hash": str(manifest.get("manifest_hash") or ""),
            "description": "File-scan outputs archive the hash cache manifest used for review.",
        },
        {
            "slot_id": "cache-key-policy",
            "status": "ready",
            "evidence_ref": "key_policy_hash",
            "evidence_hash": key_policy_hash,
            "description": "Path, size, mtime, inode, device, scope, and invalidation policy are fixed.",
        },
        {
            "slot_id": "hit-miss-invalidation-counters",
            "status": "ready",
            "evidence_ref": "counter_profile_hash",
            "evidence_hash": counter_profile_hash,
            "description": "Hit, miss, invalidation, entry, and event counts are preserved for cache review.",
        },
        {
            "slot_id": "content-addressed-persistence-rows",
            "status": "ready",
            "evidence_ref": "persistence_manifest_hash",
            "evidence_hash": str(manifest.get("persistence_manifest_hash") or ""),
            "description": "Explicit snapshots include SHA-256 content-addressed persistence rows.",
        },
        {
            "slot_id": "explicit-snapshot-export-import-contract",
            "status": "ready",
            "evidence_ref": "snapshot_contract_hash",
            "evidence_hash": snapshot_contract_hash,
            "description": "The manifest declares the snapshot profile and export/import persistence mode.",
        },
        {
            "slot_id": "same-path-invalidation-proof",
            "status": "ready",
            "evidence_ref": "invalidation_proof_hash",
            "evidence_hash": hashlib.sha256(
                json.dumps(invalidation_proof, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "description": "Same-path stale entry invalidation evidence is hashed for regression review.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-hash-cache-manifest",
            "status": "blocked",
            "blocker": HASH_CACHE_TRUSTED_DIFF_BLOCKER_76,
            "required_evidence": "independent trusted hash-cache manifest diff across hits, misses, and invalidations",
        },
        {
            "slot_id": "automatic-on-disk-cache",
            "status": "blocked",
            "blocker": "automatic-on-disk-cache-wiring-required",
            "required_evidence": "automatic startup/load/save cache store with safe invalidation and case-boundary controls",
        },
        {
            "slot_id": "large-case-hit-ratio",
            "status": "blocked",
            "blocker": "large-case-hit-ratio-validation-required",
            "required_evidence": "large-case replay proving hit ratio, saved wall time, and stale-cache safety",
        },
        {
            "slot_id": "cross-platform-cache-key-semantics",
            "status": "blocked",
            "blocker": "cross-platform-cache-key-semantics-required",
            "required_evidence": "Windows, macOS, and Linux path/mtime/inode/device semantics comparison",
        },
        {
            "slot_id": "content-addressed-lookup-mode",
            "status": "blocked",
            "blocker": "content-addressed-lookup-mode-required",
            "required_evidence": "lookup mode that can reuse hashes by trusted content address when path metadata changes safely",
        },
        {
            "slot_id": "multi-run-stale-cache-replay",
            "status": "blocked",
            "blocker": "multi-run-stale-cache-replay-required",
            "required_evidence": "multi-run corpus proving stale entries are invalidated without false cache hits",
        },
    ]
    trusted_status = str((trusted_diff or {}).get("status") or "missing")
    plan_core = {
        "profile_version": HASH_CACHE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 76,
        "gap_id": HASH_CACHE_GAP_ID,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "hash_cache_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "cache_session_id": str(manifest.get("cache_session_id") or ""),
        "entry_count": counter_profile["entries"],
        "event_count": counter_profile["events"],
        "hit_count": counter_profile["hits"],
        "miss_count": counter_profile["misses"],
        "invalidation_count": counter_profile["invalidations"],
        "entries_head_hash": str(manifest.get("entries_head_hash") or ""),
        "events_head_hash": str(manifest.get("events_head_hash") or ""),
        "persistence_manifest_hash": str(manifest.get("persistence_manifest_hash") or ""),
        "persistence_row_head_hash": str(persistence_manifest.get("row_head_hash") or ""),
        "key_policy_hash": key_policy_hash,
        "counter_profile_hash": counter_profile_hash,
        "snapshot_contract_hash": snapshot_contract_hash,
        "explicit_snapshot_export_import": True,
        "automatic_on_disk_cache": False,
        "large_case_hit_ratio_validated": False,
        "trusted_hash_cache_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(HASH_CACHE_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as process-local hash-cache evidence with explicit snapshots only; do not claim automatic large-case cache acceleration until blocker slots are satisfied.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_hash": validation_plan_hash,
        "validation_plan_sha256": validation_plan_hash,
    }


def missing_hash_cache_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "blocker": HASH_CACHE_TRUSTED_DIFF_BLOCKER_76,
        "required_trusted_tools": sorted(HASH_CACHE_TRUSTED_TOOLS),
    }


def build_hash_cache_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "hash-cache-manifest",
) -> dict[str, object]:
    mismatches: list[dict[str, object]] = []
    for field in (
        "algorithms",
        "cache_session_id",
        "entry_count",
        "hit_count",
        "miss_count",
        "invalidation_count",
        "entries_head_hash",
        "events_head_hash",
        "persistence_manifest_hash",
    ):
        rapid_value = rapid_assessment.get(field)
        trusted_value = trusted_assessment.get(field)
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    rapid_manifest = rapid_assessment.get("hash_cache_manifest")
    trusted_manifest = trusted_assessment.get("hash_cache_manifest")
    if isinstance(rapid_manifest, Mapping) and isinstance(trusted_manifest, Mapping):
        for field in (
            "profile",
            "entry_count",
            "entries_head_hash",
            "events_head_hash",
            "persistence_manifest_hash",
            "manifest_hash",
        ):
            if rapid_manifest.get(field) != trusted_manifest.get(field):
                mismatches.append(
                    {
                        "field": f"hash_cache_manifest.{field}",
                        "rapid": rapid_manifest.get(field),
                        "trusted": trusted_manifest.get(field),
                    }
                )
    status = "pass" if not mismatches and trusted_tool in HASH_CACHE_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "compared_fields": [
            "algorithms",
            "cache_session_id",
            "entry_count",
            "hit_count",
            "miss_count",
            "invalidation_count",
            "hash_cache_manifest.profile",
            "hash_cache_manifest.entry_count",
            "hash_cache_manifest.entries_head_hash",
            "hash_cache_manifest.events_head_hash",
            "hash_cache_manifest.persistence_manifest_hash",
            "hash_cache_manifest.manifest_hash",
        ],
        "mismatches": mismatches,
        "blocker": None if status == "pass" else HASH_CACHE_TRUSTED_DIFF_BLOCKER_76,
    }
