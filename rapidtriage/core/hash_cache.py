from __future__ import annotations

import hashlib
from pathlib import Path


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
_HASH_CACHE: dict[tuple[str, int, int], dict[str, str]] = {}


def compute_hashes_cached(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    resolved = path.expanduser().resolve()
    stat_result = resolved.stat()
    key = (str(resolved), int(stat_result.st_size), int(stat_result.st_mtime_ns))
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        return dict(cached)
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
