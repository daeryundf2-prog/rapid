"""T-183 (QA-186): same-hash propagation never spreads through empty files.

Zero-byte rows and the digests of the empty byte string are excluded from the
propagation; the summary carries ``skipped_empty`` (rows the guard left out).
Synthetic rows only.
"""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.case_db import (
    CaseDatabase,
    apply_schema,
    apply_tag_ids,
    create_case_tag,
)
from rapidtriage.core.case_db.review_tools import (
    EMPTY_FILE_HASHES,
    hash_propagation_targets,
)

CASE = "CASE-T183"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _insert_file(
    connection: sqlite3.Connection,
    path: str,
    *,
    size: int | None,
    md5: str | None = None,
    sha1: str | None = None,
    sha256: str | None = None,
    source: int | None = None,
) -> int:
    cursor = connection.execute(
        "INSERT INTO file_record (citation_id, case_id, evidence_source_id, path, normalized_path, size_bytes, "
        "hash_md5, hash_sha1, hash_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '2026-11-13T00:00:00+00:00')",
        (f"F-{path}", CASE, source, path, path.lower(), size, md5, sha1, sha256),
    )
    return int(cursor.lastrowid or 0)


def _insert_source(connection: sqlite3.Connection, name: str) -> int:
    cursor = connection.execute(
        "INSERT INTO evidence_source (citation_id, case_id, display_name, source_type, original_path, added_at) "
        "VALUES (?, ?, ?, 'folder', ?, '2026-11-13T00:00:00+00:00')",
        (f"S-{name}", CASE, name, f"C:/{name}"),
    )
    return int(cursor.lastrowid or 0)


def _target(file_id: int) -> dict[str, str]:
    return {"target_type": "file_record", "target_id": str(file_id)}


class HashPropagationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = CaseDatabase(Path(self.temp.name) / "case.db")
        self.database.initialize()
        self.database.create_case(case_id=CASE, examiner="검사관 A")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_known_empty_digests_are_the_digests_of_no_bytes(self) -> None:
        self.assertEqual(EMPTY_FILE_HASHES["hash_md5"], hashlib.md5(b"").hexdigest())
        self.assertEqual(EMPTY_FILE_HASHES["hash_sha1"], hashlib.sha1(b"").hexdigest())
        self.assertEqual(EMPTY_FILE_HASHES["hash_sha256"], hashlib.sha256(b"").hexdigest())

    def test_three_zero_byte_files_propagate_nothing(self) -> None:
        # Acceptance: 3 zero-byte files → 0 propagated, skipped_empty = 2 (the two other than the tagged one).
        with self.database.connect() as connection:
            apply_schema(connection)
            empties = [
                _insert_file(connection, f"C:/empty{index}.txt", size=0, md5=EMPTY_MD5, sha1=EMPTY_SHA1, sha256=EMPTY_SHA256)
                for index in range(3)
            ]
            tag = create_case_tag(connection, CASE, name="빈 파일 검사")
            result = apply_tag_ids(connection, CASE, [_target(empties[0])], add_ids=[tag["id"]], propagate_by_hash=True)
            propagation = result["propagation"]
            self.assertEqual(propagation["added_rows"], 0)
            self.assertEqual(propagation["matched_file_rows"], 0)
            self.assertEqual(propagation["skipped_empty"], 2)
            self.assertEqual(result["applied_count"], 1)
            self.assertEqual([item["target_id"] for item in result["targets"]], [str(empties[0])])
            tagged = connection.execute("SELECT COUNT(*) FROM review_mark WHERE case_id = ?", (CASE,)).fetchone()[0]
            self.assertEqual(tagged, 1)

    def test_empty_digest_alone_is_excluded_even_without_a_size(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            rows = [_insert_file(connection, f"C:/nosize{index}.txt", size=None, sha256=EMPTY_SHA256.upper()) for index in range(3)]
            out, summary = hash_propagation_targets(connection, CASE, [_target(rows[0])])
            self.assertEqual(out, [_target(rows[0])])
            self.assertEqual((summary["added_rows"], summary["skipped_empty"]), (0, 2))

    def test_zero_byte_rows_with_a_real_hash_are_not_added_and_are_counted(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            real = "a" * 32
            seed = _insert_file(connection, "C:/photo.jpg", size=1024, md5=real)
            copy = _insert_file(connection, "C:/photo-copy.jpg", size=1024, md5=real)
            truncated = _insert_file(connection, "C:/photo-zero.jpg", size=0, md5=real)
            out, summary = hash_propagation_targets(connection, CASE, [_target(seed)])
            self.assertEqual([item["target_id"] for item in out], [str(seed), str(copy)])
            self.assertEqual((summary["added_rows"], summary["skipped_empty"]), (1, 1))
            self.assertNotIn(str(truncated), {item["target_id"] for item in out})

    def test_zero_byte_target_does_not_spread_its_hashes(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            odd = "b" * 32  # a zero-byte row with an unexpected digest (e.g. a partially recovered entry)
            seed = _insert_file(connection, "C:/zero.bin", size=0, md5=odd)
            _insert_file(connection, "C:/full.bin", size=10, md5=odd)
            out, summary = hash_propagation_targets(connection, CASE, [_target(seed)])
            self.assertEqual(out, [_target(seed)])
            self.assertEqual((summary["added_rows"], summary["skipped_empty"]), (0, 1))

    def test_mixed_selection_propagates_the_real_hash_only(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            real = "c" * 32
            seed = _insert_file(connection, "C:/doc.pdf", size=500, md5=real)
            twin = _insert_file(connection, "C:/doc2.pdf", size=500, md5=real)
            empty_seed = _insert_file(connection, "C:/a.txt", size=0, md5=EMPTY_MD5)
            for index in range(4):
                _insert_file(connection, f"C:/b{index}.txt", size=0, md5=EMPTY_MD5)
            out, summary = hash_propagation_targets(connection, CASE, [_target(seed), _target(empty_seed)])
            self.assertEqual({item["target_id"] for item in out}, {str(seed), str(twin), str(empty_seed)})
            self.assertEqual((summary["added_rows"], summary["skipped_empty"]), (1, 4))
            self.assertEqual(summary["hash_values"], 1)

    def test_skipped_empty_stays_inside_the_run(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            run_a = _insert_source(connection, "run-a")
            run_b = _insert_source(connection, "run-b")
            in_a = [_insert_file(connection, f"C:/a{index}.txt", size=0, md5=EMPTY_MD5, source=run_a) for index in range(2)]
            _insert_file(connection, "C:/b0.txt", size=0, md5=EMPTY_MD5, source=run_b)
            out, summary = hash_propagation_targets(connection, CASE, [_target(in_a[0])])
            self.assertEqual(out, [_target(in_a[0])])
            self.assertEqual(summary["skipped_empty"], 1)

    def test_non_empty_propagation_is_unchanged(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            real = "d" * 32
            rows = [_insert_file(connection, f"C:/same{index}.jpg", size=None, md5=real) for index in range(3)]
            out, summary = hash_propagation_targets(connection, CASE, [_target(rows[0])])
            self.assertEqual([item["target_id"] for item in out], [str(row) for row in rows])
            self.assertEqual((summary["matched_file_rows"], summary["added_rows"], summary["skipped_empty"]), (3, 2, 0))


if __name__ == "__main__":
    unittest.main()
