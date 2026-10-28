from __future__ import annotations

import hashlib
from pathlib import Path

DIGEST_CHUNK_BYTES = 1024 * 1024


def hash_file_digests(path: Path, *, chunk_size: int = DIGEST_CHUNK_BYTES) -> dict[str, str]:
    """Compute md5, sha1 and sha256 of a file in one read loop."""
    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


class RunDigestCache:
    """Run-scoped digest cache keyed by (absolute path, size, mtime_ns).

    Entries from an earlier mtime for the same path are dropped on the next
    compute, so a modified file is always re-read.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, int, int], dict[str, str]] = {}

    def seed(self, path: Path, *, size: int, mtime_ns: int, digests: dict[str, str]) -> None:
        key = (str(path.expanduser().resolve()), int(size), int(mtime_ns))
        self._entries[key] = dict(digests)

    def compute(self, path: Path, *, chunk_size: int = DIGEST_CHUNK_BYTES) -> dict[str, str]:
        resolved = path.expanduser().resolve()
        stat_result = resolved.stat()
        key = (str(resolved), int(stat_result.st_size), int(stat_result.st_mtime_ns))
        cached = self._entries.get(key)
        if cached is not None:
            return dict(cached)
        for stale in [existing for existing in self._entries if existing[0] == key[0] and existing != key]:
            del self._entries[stale]
        digests = hash_file_digests(resolved, chunk_size=chunk_size)
        self._entries[key] = digests
        return dict(digests)
