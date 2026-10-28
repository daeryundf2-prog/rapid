from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Mapping
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


DIGEST_NAMES = ("md5", "sha1", "sha256")


class RunDigestCache:
    """Run-scoped digest cache keyed by (absolute path, size, mtime_ns).

    Entries from an earlier mtime for the same path are dropped on the next
    compute, so a modified file is always re-read. Files hashed while they were
    written (E01 extraction) are seeded with :meth:`seed_extracted`: their digest
    is served while the file keeps its size and has not been modified since the
    seed, so the run never re-reads them for hashing.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, int, int], dict[str, str]] = {}
        self._written: dict[str, tuple[int, int, dict[str, str]]] = {}

    def seed(self, path: Path, *, size: int, mtime_ns: int, digests: dict[str, str]) -> None:
        key = (str(path.expanduser().resolve()), int(size), int(mtime_ns))
        self._entries[key] = dict(digests)

    def seed_extracted(self, extract_dir: Path, file_digests: Mapping[str, object]) -> int:
        """Seed ``{relative POSIX path: {size_bytes, md5, sha1, sha256}}`` rows under ``extract_dir``.

        No file is opened or stat'ed here; :meth:`lookup` checks size and mtime
        (not newer than this call) when a path is first asked for."""
        base = str(extract_dir.expanduser().resolve())
        written_before_ns = time.time_ns()
        seeded = 0
        for rel, row in file_digests.items():
            if not isinstance(row, Mapping):
                continue
            digests = {name: str(row.get(name) or "") for name in DIGEST_NAMES}
            if not all(digests.values()):
                continue
            try:
                size = int(row.get("size_bytes"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            path_text = os.path.join(base, *str(rel).split("/"))
            self._written[os.path.normcase(path_text)] = (size, written_before_ns, digests)
            seeded += 1
        return seeded

    def lookup(self, resolved: Path, stat_result: os.stat_result) -> dict[str, str] | None:
        """Cached digests of an already resolved/stat'ed path, else ``None`` (nothing is read)."""
        key = (str(resolved), int(stat_result.st_size), int(stat_result.st_mtime_ns))
        cached = self._entries.get(key)
        if cached is not None:
            return dict(cached)
        written = self._written.get(os.path.normcase(str(resolved)))
        if written is None:
            return None
        size, written_before_ns, digests = written
        if size != key[1] or key[2] > written_before_ns:
            return None  # changed since extraction: hash the bytes again
        self._entries[key] = dict(digests)
        return dict(digests)

    def compute(self, path: Path, *, chunk_size: int = DIGEST_CHUNK_BYTES) -> dict[str, str]:
        resolved = path.expanduser().resolve()
        stat_result = resolved.stat()
        key = (str(resolved), int(stat_result.st_size), int(stat_result.st_mtime_ns))
        cached = self.lookup(resolved, stat_result)
        if cached is not None:
            return cached
        for stale in [existing for existing in self._entries if existing[0] == key[0] and existing != key]:
            del self._entries[stale]
        digests = hash_file_digests(resolved, chunk_size=chunk_size)
        self._entries[key] = digests
        return dict(digests)
