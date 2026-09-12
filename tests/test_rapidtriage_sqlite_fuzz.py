from __future__ import annotations

import hashlib
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path

HAS_FASTAPI = True
try:
    from fastapi import HTTPException
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import (
        build_source_preview,
        build_source_search,
        build_sqlite_preview,
        build_sqlite_table_page,
        first_sqlite_table_name,
        is_probably_binary,
        is_sqlite_candidate,
    )
from rapidtriage.core.source_reader import (
    is_probably_binary as core_is_probably_binary,
)
from rapidtriage.core.source_reader import (
    is_probably_binary_bytes,
)

SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db3", ".txt", ".bin", "")


def _seeded_bytes(seed: int, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


def malformed_sqlite_payloads() -> dict[str, bytes]:
    """Attacker-controlled byte strings that reach the read-only SQLite path."""
    return {
        "empty": b"",
        "truncated-magic-8": SQLITE_MAGIC[:8],
        "truncated-magic-15": SQLITE_MAGIC[:15],
        "magic-only": SQLITE_MAGIC,
        "magic-zeroed-header": SQLITE_MAGIC + bytes(84),
        "magic-random-header": SQLITE_MAGIC + _seeded_bytes(1, 84),
        "magic-corrupt-pages": SQLITE_MAGIC + _seeded_bytes(2, 8192),
        "magic-oversized-tail": SQLITE_MAGIC + (b"\xff" * 262_144),
        "random-bytes": _seeded_bytes(3, 8192),
        "random-with-magic-inside": _seeded_bytes(4, 2048) + SQLITE_MAGIC + _seeded_bytes(5, 2048),
    }


def _corrupt_valid_database(directory: Path) -> Path:
    """Header-valid SQLite file whose interior pages are overwritten."""
    source = directory / "valid-source.db"
    connection = sqlite3.connect(source)
    try:
        connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
        connection.executemany("INSERT INTO notes(body) VALUES (?)", [(f"row {index}",) for index in range(200)])
        connection.commit()
    finally:
        connection.close()
    raw = bytearray(source.read_bytes())
    for offset in range(512, min(len(raw), 2048)):
        raw[offset] ^= 0xFF
    corrupted = directory / "corrupt-pages.db"
    corrupted.write_bytes(bytes(raw))
    return corrupted


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RapidTriageSqliteFuzzTests(unittest.TestCase):
    def test_binary_and_sqlite_candidate_checks_never_raise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for name, payload in malformed_sqlite_payloads().items():
                for suffix in SQLITE_SUFFIXES:
                    path = Path(tmp_dir) / f"{name}{suffix}"
                    path.write_bytes(payload)
                    with self.subTest(payload=name, suffix=suffix):
                        self.assertIsInstance(is_probably_binary(path), bool)
                        self.assertIsInstance(core_is_probably_binary(path), bool)
                        self.assertIsInstance(is_probably_binary_bytes(payload), bool)
                        self.assertIsInstance(is_sqlite_candidate(path), bool)
                        self.assertIsInstance(is_sqlite_candidate(path, suffix), bool)

    def test_sqlite_preview_returns_failed_payload_not_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for name, payload in malformed_sqlite_payloads().items():
                path = Path(tmp_dir) / f"{name}.db"
                path.write_bytes(payload)
                with self.subTest(payload=name):
                    result = build_sqlite_preview(path)
                    self.assertIsInstance(result, dict)
                    self.assertIn(result["preview_type"], {"binary", "sqlite"})
                    if result["preview_type"] == "binary":
                        self.assertIn("error", result["sqlite"])
                    self.assertIsInstance(first_sqlite_table_name(path), str)

    def test_sqlite_table_page_fails_closed_on_corrupt_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payloads = malformed_sqlite_payloads()
            payloads["corrupt-valid-db"] = _corrupt_valid_database(Path(tmp_dir)).read_bytes()
            for name, payload in payloads.items():
                path = Path(tmp_dir) / f"{name}.db"
                path.write_bytes(payload)
                with self.subTest(payload=name):
                    try:
                        result = build_sqlite_table_page(
                            run_id="fuzz-run",
                            source_path=path,
                            table="notes",
                            offset=0,
                            limit=10,
                            where_column=None,
                            where_contains=None,
                            order_by=None,
                            descending=False,
                        )
                    except HTTPException as exc:
                        self.assertIn(exc.status_code, {400, 404})
                    else:
                        self.assertEqual(result["command"], "source-sqlite-table")

    def test_source_preview_and_search_degrade_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for name, payload in malformed_sqlite_payloads().items():
                for suffix in (".db", ".bin", ".log"):
                    path = Path(tmp_dir) / f"{name}{suffix}"
                    path.write_bytes(payload)
                    with self.subTest(payload=name, suffix=suffix):
                        preview = build_source_preview("fuzz-run", path)
                        self.assertIsInstance(preview, dict)
                        self.assertIn("preview_type", preview)
                        search = build_source_search(path, ["needle"], limit=5, context=20)
                        self.assertIsInstance(search, dict)
                        self.assertIn("match_count", search["summary"])

    def test_readonly_open_does_not_mutate_or_create_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            candidates = []
            for name, payload in malformed_sqlite_payloads().items():
                path = Path(tmp_dir) / f"{name}.db"
                path.write_bytes(payload)
                candidates.append(path)
            candidates.append(_corrupt_valid_database(Path(tmp_dir)))
            for path in candidates:
                before = _file_sha256(path)
                with self.subTest(path=path.name):
                    build_sqlite_preview(path)
                    first_sqlite_table_name(path)
                    try:
                        build_sqlite_table_page(
                            run_id="fuzz-run",
                            source_path=path,
                            table="notes",
                            offset=0,
                            limit=5,
                            where_column=None,
                            where_contains=None,
                            order_by=None,
                            descending=False,
                        )
                    except HTTPException:
                        pass
                    self.assertEqual(_file_sha256(path), before)
                    for sidecar_suffix in ("-wal", "-shm", "-journal"):
                        self.assertFalse(
                            path.with_name(path.name + sidecar_suffix).exists(),
                            f"unexpected sidecar {sidecar_suffix} for {path.name}",
                        )


if __name__ == "__main__":
    unittest.main()
