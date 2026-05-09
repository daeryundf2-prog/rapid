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
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted hash-cache manifest diff pass")
    blockers = [
        "automatic-on-disk-cache-not-enabled-without-explicit-snapshot-import",
        "cache-lookup-still-uses-path-size-mtime-key-with-content-addressed-export-evidence",
        "large-scale-hash-cache-hit-ratio-validation-remains-required",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(HASH_CACHE_TRUSTED_DIFF_BLOCKER_76)
    return {
        "component": "file-hash-cache",
        "status": "in-process-path-size-mtime-cache",
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
                ],
            )
        ],
        "blockers": blockers,
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
