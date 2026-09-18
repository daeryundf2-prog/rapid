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
            if before["journal"].get("st_size", 0):
                raise SqliteSnapshotError("SQLite nonempty rollback journal is unsupported; possible hot journal")
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
                })
            connection = sqlite3.connect(f"{working.as_uri()}?mode=ro", uri=True)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only=ON")
                yield connection
            finally:
                connection.close()
    except OSError as exc:
        raise SqliteSnapshotError(f"SQLite snapshot filesystem failure: {exc}") from exc
