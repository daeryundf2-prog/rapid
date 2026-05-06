from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from .forensic_accuracy import build_accuracy_gate


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
HASH_CACHE_GAP_ID = "#76"
HASH_CACHE_TRUSTED_DIFF_BLOCKER_76 = "trusted-hash-cache-manifest-diff-missing"
HASH_CACHE_TRUSTED_TOOLS = {"hash-cache-manifest", "content-addressed-cache-oracle", "known-answer-hash-cache-export"}
_HASH_CACHE: dict[tuple[str, int, int], dict[str, str]] = {}
_HASH_CACHE_STATS = {
    "hits": 0,
    "misses": 0,
}


def compute_hashes_cached(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    resolved = path.expanduser().resolve()
    stat_result = resolved.stat()
    key = (str(resolved), int(stat_result.st_size), int(stat_result.st_mtime_ns))
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        _HASH_CACHE_STATS["hits"] += 1
        return dict(cached)
    _HASH_CACHE_STATS["misses"] += 1
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


def hash_cache_assessment(*, trusted_diff: Mapping[str, object] | None = None) -> dict[str, object]:
    satisfied = [
        "MD5/SHA1/SHA256 captured",
        "path-size-mtime cache key recorded",
        "hit/miss counters emitted",
        "hash cache assessment attached",
        "persistent cache limitation warning",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted hash-cache manifest diff pass")
    blockers = [
        "cache-is-process-local-not-persistent-across-restarts",
        "cache-key-uses-path-size-mtime-not-verified-content-addressed-store",
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
        "entry_count": len(_HASH_CACHE),
        "hit_count": _HASH_CACHE_STATS["hits"],
        "miss_count": _HASH_CACHE_STATS["misses"],
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
    for field in ("algorithms", "entry_count", "hit_count", "miss_count"):
        rapid_value = rapid_assessment.get(field)
        trusted_value = trusted_assessment.get(field)
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in HASH_CACHE_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [HASH_CACHE_GAP_ID],
        "compared_fields": ["algorithms", "entry_count", "hit_count", "miss_count"],
        "mismatches": mismatches,
        "blocker": None if status == "pass" else HASH_CACHE_TRUSTED_DIFF_BLOCKER_76,
    }
