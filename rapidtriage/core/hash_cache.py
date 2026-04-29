from __future__ import annotations

import hashlib
from pathlib import Path


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
HASH_CACHE_GAP_ID = "#76"
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


def hash_cache_assessment() -> dict[str, object]:
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
        "blockers": [
            "cache-is-process-local-not-persistent-across-restarts",
            "cache-key-uses-path-size-mtime-not-verified-content-addressed-store",
            "large-scale-hash-cache-hit-ratio-validation-remains-required",
        ],
    }
