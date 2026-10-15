from __future__ import annotations

import hashlib
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class SqliteSnapshotError(sqlite3.OperationalError):
    pass


JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
_JOURNAL_HEADER_BYTES = 28
_MAX_JOURNAL_HEADER_SCAN = 64


def classify_rollback_journal(path: Path) -> dict[str, object]:
    """Classify a rollback ``-journal`` sidecar without modifying it.

    SQLite treats a journal as hot only when its header carries the journal
    magic and it still describes page records to roll back.  A journal whose
    header was zeroed (``journal_mode=PERSIST`` commit) or whose record count
    is zero is a committed/stale leftover and is ignored.  ``nRec`` of
    ``0xFFFFFFFF`` (no-sync mode) means the records run to the end of file.
    """

    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return {"status": "absent", "hot": False}
    if size == 0:
        return {"status": "empty", "hot": False}
    with path.open("rb") as handle:
        header = handle.read(_JOURNAL_HEADER_BYTES)
        if len(header) < _JOURNAL_HEADER_BYTES or header[:8] != JOURNAL_MAGIC:
            reason = "zeroed-header" if not any(header) else "no-journal-magic"
            return {"status": "committed-or-invalid", "reason": reason, "hot": False, "size": size}
        sector_size = int.from_bytes(header[20:24], "big")
        page_size = int.from_bytes(header[24:28], "big")
        if sector_size < 32 or sector_size > 65536 or sector_size & (sector_size - 1):
            sector_size = 512
        offset = 0
        for _ in range(_MAX_JOURNAL_HEADER_SCAN):
            if header[:8] != JOURNAL_MAGIC:
                break
            n_rec = int.from_bytes(header[8:12], "big")
            if n_rec == 0xFFFFFFFF:
                if size > offset + sector_size:
                    return {"status": "hot", "reason": "nrec-unsynced-records-present", "hot": True, "size": size}
                break
            if n_rec:
                return {"status": "hot", "reason": "nrec-nonzero", "nrec": n_rec, "hot": True, "size": size}
            # nRec == 0: no records in this segment; a later segment header may
            # start at the next sector boundary.
            offset += sector_size
            if offset + _JOURNAL_HEADER_BYTES > size:
                break
            handle.seek(offset)
            header = handle.read(_JOURNAL_HEADER_BYTES)
        return {
            "status": "committed-or-invalid",
            "reason": "no-page-records",
            "hot": False,
            "size": size,
            "page_size": page_size,
        }


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _fingerprint(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    if not stat.S_ISREG(before.st_mode):
        raise SqliteSnapshotError(f"SQLite source is not a regular file: {path}")
    digest = _sha256(path)
    after = path.lstat()
    keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
    if any(getattr(before, key) != getattr(after, key) for key in keys):
        raise SqliteSnapshotError(f"SQLite source changed while fingerprinting: {path}")
    return {
        "path": str(path),
        "exists": True,
        "sha256": digest,
        **{key: getattr(after, key) for key in keys},
    }


@contextmanager
def open_sqlite_snapshot(
    path: Path, *, provenance: dict[str, object] | None = None
) -> Iterator[sqlite3.Connection]:
    paths = {kind: path.with_name(path.name + suffix) for kind, suffix in (
        ("database", ""), ("wal", "-wal"), ("shm", "-shm"), ("journal", "-journal")
    )}
    try:
        with tempfile.TemporaryDirectory(prefix="rapidtriage-sqlite-") as directory:
            before = {kind: _fingerprint(source) for kind, source in paths.items()}
            if not before["database"]["exists"]:
                raise SqliteSnapshotError(f"SQLite source database is missing: {path}")
            journal = classify_rollback_journal(paths["journal"])
            if journal["hot"]:
                raise SqliteSnapshotError(
                    f"SQLite hot journal (rollback pending, {journal['reason']}) is unsupported: {paths['journal']}"
                )
            working = Path(directory) / "snapshot.sqlite"
            for kind, destination in (("database", working), ("wal", working.with_name(working.name + "-wal"))):
                if before[kind]["exists"]:
                    shutil.copyfile(paths[kind], destination)
                    if _sha256(destination) != before[kind]["sha256"]:
                        raise SqliteSnapshotError(f"SQLite working copy hash mismatch: {paths[kind]}")
            after = {kind: _fingerprint(source) for kind, source in paths.items()}
            if before != after:
                raise SqliteSnapshotError("SQLite source set changed during snapshot copying")
            if provenance is not None:
                provenance.update({
                    "profile_version": "sqlite-working-snapshot-v1",
                    "source_path": str(path),
                    "files": [dict(row, copied=kind in {"database", "wal"} and bool(row["exists"])) for kind, row in before.items()],
                    "hash_scope": "individual-source-files; database hash excludes WAL",
                    "wal_included": bool(before["wal"]["exists"]),
                    "stability_check": "before-after fingerprints and copy hashes; not atomic live acquisition",
                    "shm_policy": "rebuilt only in private working directory",
                    "journal_status": journal["status"],
                    "journal_reason": journal.get("reason", ""),
                    "journal_policy": "hot only when magic d9d505f920a163d7 and page records present; otherwise ignored, never copied",
                })
            # The working copy is private: with a WAL the copy needs a rebuilt
            # -shm next to it, otherwise ``immutable=1`` keeps SQLite from
            # creating any sidecar at all.
            options = "mode=ro" if before["wal"]["exists"] else "mode=ro&immutable=1"
            connection = sqlite3.connect(f"{working.as_uri()}?{options}", uri=True)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only=ON")
                yield connection
            finally:
                connection.close()
    except OSError as exc:
        raise SqliteSnapshotError(f"SQLite snapshot filesystem failure: {exc}") from exc
