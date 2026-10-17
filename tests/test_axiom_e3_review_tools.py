"""AXIOM adoption E3 (plan §3.3): case tags, tag batches with hash propagation,
string-tag migration, histogram baselines, mark history and related media."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.case_db import (
    CaseDatabase,
    ReviewToolError,
    apply_schema,
    apply_tag_ids,
    create_case_tag,
    delete_case_tag,
    list_case_tags,
    review_schema,
    review_tools,
    update_case_tag,
)
from rapidtriage.core.case_db.review_schema import SYSTEM_TAGS

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client
    from tests.test_rapidtriage_run import build_run_fixture


def _insert_file(
    connection: sqlite3.Connection, case_id: str, path: str, md5: str | None, source: int | None = None
) -> int:
    cursor = connection.execute(
        "INSERT INTO file_record (citation_id, case_id, evidence_source_id, path, normalized_path, hash_md5, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, '2026-10-17T00:00:00+00:00')",
        (f"F-{path}", case_id, source, path, path.lower(), md5),
    )
    return int(cursor.lastrowid or 0)


def _insert_source(connection: sqlite3.Connection, case_id: str, name: str) -> int:
    cursor = connection.execute(
        "INSERT INTO evidence_source (citation_id, case_id, display_name, source_type, original_path, added_at) "
        "VALUES (?, ?, ?, 'folder', ?, '2026-10-17T00:00:00+00:00')",
        (f"S-{name}", case_id, name, f"C:/{name}"),
    )
    return int(cursor.lastrowid or 0)


class CaseTagCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = CaseDatabase(Path(self.temp.name) / "case.db")
        self.database.initialize()
        self.database.create_case(case_id="CASE-E3", examiner="검사관 A")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_crud_unique_name_shortcut_and_soft_delete(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            tags = list_case_tags(connection, "CASE-E3")
            # System tags exist with the console's existing keys (우선순위 n = n).
            self.assertEqual({tag["name"] for tag in tags}, set(SYSTEM_TAGS))
            self.assertEqual({tag["shortcut"] for tag in tags if tag["name"] == "우선순위 3"}, {3})
            created = create_case_tag(
                connection, "CASE-E3", name="  DLP   유출 후보 ", color_token="tag-7", shortcut=7, description="외부 반출", actor="검사관 A"
            )
            self.assertEqual((created["name"], created["color_token"], created["shortcut"]), ("DLP 유출 후보", "tag-7", 7))
            self.assertEqual(created["created_by"], "검사관 A")
            with self.assertRaises(ReviewToolError) as dup:
                create_case_tag(connection, "CASE-E3", name="dlp 유출 후보")
            self.assertEqual(dup.exception.status, 409)
            self.assertIn("같은 이름", str(dup.exception))
            with self.assertRaises(ReviewToolError) as taken:
                create_case_tag(connection, "CASE-E3", name="변호인 검토", shortcut=2)
            self.assertIn("우선순위 2", str(taken.exception))
            with self.assertRaises(ReviewToolError) as bad_color:
                create_case_tag(connection, "CASE-E3", name="색 오류", color_token="red")
            self.assertEqual(bad_color.exception.status, 422)
            with self.assertRaises(ReviewToolError):
                create_case_tag(connection, "CASE-E3", name="단축키 오류", shortcut=10)
            # Free key 2, then take it; system tags cannot be renamed or deleted.
            update_case_tag(connection, "CASE-E3", self._tag_id(connection, "우선순위 2"), shortcut=None)
            lawyer = create_case_tag(connection, "CASE-E3", name="변호인 검토", shortcut=2)
            self.assertEqual(lawyer["shortcut"], 2)
            with self.assertRaises(ReviewToolError) as rename_system:
                update_case_tag(connection, "CASE-E3", self._tag_id(connection, "북마크"), name="책갈피")
            self.assertEqual(rename_system.exception.status, 409)
            with self.assertRaises(ReviewToolError):
                delete_case_tag(connection, "CASE-E3", self._tag_id(connection, "북마크"))
            deleted = delete_case_tag(connection, "CASE-E3", lawyer["id"], actor="검사관 B")
            self.assertIsNotNone(deleted["deleted_at"])
            self.assertEqual(deleted["deleted_by"], "검사관 B")
            self.assertIsNone(deleted["shortcut"])
            live = {tag["name"] for tag in list_case_tags(connection, "CASE-E3")}
            self.assertNotIn("변호인 검토", live)
            # The soft-deleted row is kept and its name can be reused.
            everything = list_case_tags(connection, "CASE-E3", include_deleted=True)
            self.assertIn("변호인 검토", {tag["name"] for tag in everything if tag["deleted_at"]})
            again = create_case_tag(connection, "CASE-E3", name="변호인 검토", shortcut=2)
            self.assertNotEqual(again["id"], lawyer["id"])

    def _tag_id(self, connection: sqlite3.Connection, name: str) -> int:
        return int(connection.execute("SELECT id FROM case_tag WHERE name = ? AND deleted_at = ''", (name,)).fetchone()[0])

    def test_marks_carry_ids_rename_rewrites_names_delete_removes_with_history(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            file_a = _insert_file(connection, "CASE-E3", "C:/a.jpg", "a" * 32)
            file_b = _insert_file(connection, "CASE-E3", "C:/b.jpg", "b" * 32)
            tag = create_case_tag(connection, "CASE-E3", name="관심", shortcut=6)
            targets = [{"target_type": "file_record", "target_id": str(file_a)}, {"target_type": "file_record", "target_id": str(file_b)}]
            result = apply_tag_ids(connection, "CASE-E3", targets, add_ids=[tag["id"]], actor="검사관 A")
            self.assertEqual((result["applied_count"], result["changed_count"], result["created_count"]), (2, 2, 2))
            counts = {item["name"]: item["count"] for item in list_case_tags(connection, "CASE-E3")}
            self.assertEqual(counts["관심"], 2)
            row = connection.execute("SELECT tags_json, tag_ids_json FROM review_mark WHERE target_id = ?", (str(file_a),)).fetchone()
            self.assertEqual((json.loads(row[0]), json.loads(row[1])), (["관심"], [tag["id"]]))
            update_case_tag(connection, "CASE-E3", tag["id"], name="핵심 관심")
            row = connection.execute("SELECT tags_json FROM review_mark WHERE target_id = ?", (str(file_a),)).fetchone()
            self.assertEqual(json.loads(row[0]), ["핵심 관심"])
            # The same request again changes nothing.
            again = apply_tag_ids(connection, "CASE-E3", targets[:1], add_ids=[tag["id"]], actor="검사관 A")
            self.assertEqual(again["changed_count"], 0)
            deleted = delete_case_tag(connection, "CASE-E3", tag["id"], actor="검사관 B")
            self.assertEqual(deleted["removed_from_marks"], 2)
            row = connection.execute("SELECT tags_json, tag_ids_json FROM review_mark WHERE target_id = ?", (str(file_a),)).fetchone()
            self.assertEqual((json.loads(row[0]), json.loads(row[1])), ([], []))
            history = connection.execute(
                "SELECT actor, changed_fields_json FROM review_mark_history WHERE target_id = ? ORDER BY version", (str(file_a),)
            ).fetchall()
            self.assertEqual([entry[0] for entry in history], ["검사관 A", "검사관 B"])
            self.assertTrue(all("tags" in json.loads(entry[1]) for entry in history))
            audit = {str(entry[0]) for entry in connection.execute("SELECT action FROM audit_event")}
            self.assertTrue({"tag.created", "tag.updated", "tag.deleted", "review.tags-applied"} <= audit)

    def test_string_tag_marks_from_mark_review_get_ids(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            file_id = _insert_file(connection, "CASE-E3", "C:/x.txt", None)
        mark = self.database.mark_review(
            case_id="CASE-E3", target_type="file_record", target_id=str(file_id), tags=["북마크", "새 태그"], reviewer="검사관 A"
        )
        self.assertEqual(mark["tags"], ["북마크", "새 태그"])
        with self.database.connect() as connection:
            ids = json.loads(connection.execute("SELECT tag_ids_json FROM review_mark").fetchone()[0])
            names = [connection.execute("SELECT name, kind, created_by FROM case_tag WHERE id = ?", (tag_id,)).fetchone() for tag_id in ids]
        self.assertEqual([tuple(name) for name in names], [("북마크", "system", "system"), ("새 태그", "user", "검사관 A")])

    def test_migration_turns_string_tags_into_case_tags(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            first = _insert_file(connection, "CASE-E3", "C:/m1", None)
            second = _insert_file(connection, "CASE-E3", "C:/m2", None)
            # An older DB: no case_tag table, no tag_ids_json column, string tags on marks.
            connection.execute("DROP TABLE case_tag")
            connection.execute("ALTER TABLE review_mark DROP COLUMN tag_ids_json")
            for index, (target, tags) in enumerate(((first, ["우선순위 1", "외부 반출"]), (second, ["외부 반출", "  외부   반출 "]))):
                connection.execute(
                    "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, tags_json, reviewer, created_at, updated_at) "
                    "VALUES (?, 'CASE-E3', 'file_record', ?, ?, '검사관 C', 't', 't')",
                    (f"R-{index}", str(target), json.dumps(tags, ensure_ascii=False)),
                )
        with self.database.connect() as connection:
            apply_schema(connection)  # migrates
            tags = {tag["name"]: tag for tag in list_case_tags(connection, "CASE-E3")}
            self.assertEqual(tags["외부 반출"]["count"], 2)
            self.assertEqual(tags["외부 반출"]["created_by"], "검사관 C")
            self.assertEqual((tags["우선순위 1"]["kind"], tags["우선순위 1"]["shortcut"], tags["우선순위 1"]["count"]), ("system", 1, 1))
            rows = connection.execute("SELECT tags_json, tag_ids_json FROM review_mark ORDER BY id").fetchall()
            self.assertEqual(json.loads(rows[1][0]), ["외부 반출"])  # the duplicate spelling folded into one tag
            self.assertEqual(len(json.loads(rows[1][1])), 1)
            # Idempotent: a second apply creates nothing new.
            before = connection.execute("SELECT COUNT(*) FROM case_tag").fetchone()[0]
            apply_schema(connection)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM case_tag").fetchone()[0], before)

    def test_hash_propagation_scope_and_cap(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            same = [_insert_file(connection, "CASE-E3", f"C:/dup{index}.jpg", "ABCDEF" + "0" * 26) for index in range(4)]
            _insert_file(connection, "CASE-E3", "C:/other.jpg", "1" * 32)
            hashless = _insert_file(connection, "CASE-E3", "C:/nohash.txt", None)
            tag = create_case_tag(connection, "CASE-E3", name="같은 사진")
            result = apply_tag_ids(
                connection,
                "CASE-E3",
                [{"target_type": "file_record", "target_id": str(same[0])}, {"target_type": "file_record", "target_id": str(hashless)}],
                add_ids=[tag["id"]],
                propagate_by_hash=True,
            )
            self.assertEqual(result["applied_count"], 5)  # 4 same-MD5 rows (case-insensitive) + the hashless seed
            self.assertEqual(result["propagation"]["matched_file_rows"], 4)
            self.assertEqual(result["propagation"]["hashless_targets"], 1)
            self.assertEqual({item["target_id"] for item in result["targets"]}, {str(i) for i in [*same, hashless]})
            with self.assertRaises(ReviewToolError) as refused:
                apply_tag_ids(
                    connection,
                    "CASE-E3",
                    [{"target_type": "file_record", "target_id": str(same[1])}],
                    add_ids=[tag["id"]],
                    propagate_by_hash=True,
                    cap=3,
                )
            self.assertEqual(refused.exception.status, 422)
            self.assertIn("상한 3건", str(refused.exception))
            # Same run only: an identical file of another evidence source (another run) is left alone.
            run_a = _insert_source(connection, "CASE-E3", "run-a")
            run_b = _insert_source(connection, "CASE-E3", "run-b")
            in_a = [_insert_file(connection, "CASE-E3", f"C:/a{index}.jpg", "c" * 32, run_a) for index in range(2)]
            _insert_file(connection, "CASE-E3", "C:/b0.jpg", "c" * 32, run_b)
            scoped = apply_tag_ids(
                connection,
                "CASE-E3",
                [{"target_type": "file_record", "target_id": str(in_a[0])}],
                add_ids=[tag["id"]],
                propagate_by_hash=True,
                evidence_source_id=run_b,  # the fallback never overrides the target's own run
            )
            self.assertEqual({item["target_id"] for item in scoped["targets"]}, {str(i) for i in in_a})
            with self.assertRaises(ReviewToolError) as unknown:
                apply_tag_ids(connection, "CASE-E3", [{"target_type": "file_record", "target_id": str(same[0])}], add_ids=[99999])
            self.assertEqual(unknown.exception.status, 404)


class ReviewToolsRegressionTests(unittest.TestCase):
    """Adversarial review of E3 (items 3, 4, 5, 6, 7, 13 and the write-safe system-tag read of 2)."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = CaseDatabase(Path(self.temp.name) / "case.db")
        self.database.initialize()
        self.database.create_case(case_id="CASE-R", examiner="검사관 A")

    def test_concurrent_first_open_alter_race_is_not_an_error(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            file_id = _insert_file(connection, "CASE-R", "C:/r.txt", None)
            connection.execute(
                "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, tags_json, tag_ids_json, reviewer, created_at, updated_at) "
                "VALUES ('R-1', 'CASE-R', 'file_record', ?, '[\"경합 태그\"]', NULL, '검사관 A', 't', 't')",
                (str(file_id),),
            )
            # Another connection added the column between the check and the ALTER.
            real_columns = review_schema._columns
            with patch.object(
                review_schema, "_columns", side_effect=lambda conn, table: real_columns(conn, table) - {"tag_ids_json"}
            ):
                review_schema.apply_review_schema(connection)  # "duplicate column name" is swallowed
            ids = json.loads(connection.execute("SELECT tag_ids_json FROM review_mark WHERE citation_id = 'R-1'").fetchone()[0])
            self.assertEqual(len(ids), 1)  # the idempotent string-tag migration still ran

    def test_system_tag_creation_survives_a_concurrent_insert(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            list_case_tags(connection, "CASE-R")
            # A stale "live" view (another request inserted the tags first) must not raise IntegrityError.
            with patch.object(review_schema, "live_tag_rows", return_value=[]):
                review_schema.ensure_system_tags(connection, "CASE-R")
            names = [row[0] for row in connection.execute("SELECT name FROM case_tag WHERE case_id = 'CASE-R' AND deleted_at = ''")]
            self.assertEqual(sorted(names), sorted(SYSTEM_TAGS))

    def test_deleting_a_tag_keeps_each_marks_reviewer(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            file_id = _insert_file(connection, "CASE-R", "C:/keep.txt", None)
            tag = create_case_tag(connection, "CASE-R", name="삭제될 태그")
            target = [{"target_type": "file_record", "target_id": str(file_id)}]
            apply_tag_ids(connection, "CASE-R", target, add_ids=[tag["id"]], actor="검사관 A")
            delete_case_tag(connection, "CASE-R", tag["id"], actor="검사관 B")
            reviewer = connection.execute("SELECT reviewer FROM review_mark WHERE target_id = ?", (str(file_id),)).fetchone()[0]
            self.assertEqual(reviewer, "검사관 A")
            last = connection.execute(
                "SELECT actor, current_json FROM review_mark_history WHERE target_id = ? ORDER BY version DESC LIMIT 1", (str(file_id),)
            ).fetchone()
            self.assertEqual(last[0], "검사관 B")  # the deleter is the history actor
            self.assertEqual(json.loads(last[1])["reviewer"], "검사관 A")

    def test_hash_propagation_without_a_scope_is_refused_when_the_case_has_several_runs(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            run_a = _insert_source(connection, "CASE-R", "run-a")
            _insert_file(connection, "CASE-R", "C:/a.jpg", "d" * 32, run_a)
            other_run = _insert_source(connection, "CASE-R", "run-b")
            _insert_file(connection, "CASE-R", "C:/b.jpg", "d" * 32, other_run)
            orphan = _insert_file(connection, "CASE-R", "C:/orphan.jpg", "d" * 32, None)
            tag = create_case_tag(connection, "CASE-R", name="범위")
            with self.assertRaises(ReviewToolError) as refused:
                apply_tag_ids(
                    connection,
                    "CASE-R",
                    [{"target_type": "file_record", "target_id": str(orphan)}],
                    add_ids=[tag["id"]],
                    propagate_by_hash=True,
                )
            self.assertEqual(refused.exception.status, 422)
            self.assertIn("어느 런", str(refused.exception))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_mark").fetchone()[0], 0)
            # With an explicit evidence source the same request is scoped to that run.
            scoped = apply_tag_ids(
                connection,
                "CASE-R",
                [{"target_type": "file_record", "target_id": str(orphan)}],
                add_ids=[tag["id"]],
                propagate_by_hash=True,
                evidence_source_id=run_a,
            )
            self.assertEqual(scoped["propagation"]["matched_file_rows"], 1)

    def test_tag_batch_applies_assignee_priority_and_due_at(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            existing = _insert_file(connection, "CASE-R", "C:/w1.txt", None)
            fresh = _insert_file(connection, "CASE-R", "C:/w2.txt", None)
            tag = create_case_tag(connection, "CASE-R", name="배정")
            apply_tag_ids(connection, "CASE-R", [{"target_type": "file_record", "target_id": str(existing)}], add_ids=[tag["id"]])
            targets = [{"target_type": "file_record", "target_id": str(existing)}, {"target_type": "file_record", "target_id": str(fresh)}]
            result = apply_tag_ids(
                connection, "CASE-R", targets, add_ids=[tag["id"]], assignee="검사관 C", priority="p1", due_at="2026-10-31"
            )
            self.assertEqual(result["changed_count"], 2)  # the already-tagged row changes too (workflow fields)
            rows = connection.execute("SELECT assignee, priority, due_at FROM review_mark ORDER BY id").fetchall()
            self.assertEqual([tuple(row) for row in rows], [("검사관 C", "high", "2026-10-31")] * 2)
            with self.assertRaises(ReviewToolError) as bad:
                apply_tag_ids(connection, "CASE-R", targets, add_ids=[tag["id"]], priority="someday")
            self.assertEqual(bad.exception.status, 422)
            self.assertIn("우선순위", str(bad.exception))

    def test_oversized_target_lists_and_hash_lists_never_hit_the_sql_variable_limit(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            source = _insert_source(connection, "CASE-R", "run-a")
            files = [_insert_file(connection, "CASE-R", f"C:/h{index}", f"{index:032x}", source) for index in range(120)]
            tag = create_case_tag(connection, "CASE-R", name="많은 해시")
            targets = [{"target_type": "file_record", "target_id": str(file_id)} for file_id in files]
            with self.assertRaises(ReviewToolError) as refused:
                apply_tag_ids(connection, "CASE-R", targets, add_ids=[tag["id"]], propagate_by_hash=True, cap=100)
            self.assertIn("요청 120행", str(refused.exception))
            # 120 distinct hashes with a 50-variable limit: one bound JSON list per column instead of 120 "?".
            connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 50)
            result = apply_tag_ids(connection, "CASE-R", targets, add_ids=[tag["id"]], propagate_by_hash=True)
            self.assertEqual((result["applied_count"], result["propagation"]["hash_values"]), (120, 120))

    def test_unique_index_race_on_tag_create_and_update_is_korean_409(self) -> None:
        with self.database.connect() as connection:
            apply_schema(connection)
            first = create_case_tag(connection, "CASE-R", name="경합", shortcut=7)
            second = create_case_tag(connection, "CASE-R", name="다른 것")
            # The pre-checks passed before the other request committed: the unique index decides.
            with patch.object(review_tools, "_check_name_free"), patch.object(review_tools, "_check_shortcut", return_value=7):
                with self.assertRaises(ReviewToolError) as created:
                    create_case_tag(connection, "CASE-R", name="경합")
                self.assertEqual(created.exception.status, 409)
                with self.assertRaises(ReviewToolError) as updated:
                    update_case_tag(connection, "CASE-R", second["id"], shortcut=7)
                self.assertEqual(updated.exception.status, 409)
                self.assertIn("다시 시도", str(updated.exception))
            self.assertEqual(first["shortcut"], 7)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ReviewToolsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        root = base / "case-root"
        root.mkdir()
        build_run_fixture(root)
        # Three copies of one picture: a same-hash group for propagation and related media.
        picture = root / "Users" / "alice" / "Desktop" / "screen-capture.png"
        picture.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8)
        for name in ("copy-a.png", "copy-b.png"):
            shutil.copyfile(picture, root / "Users" / "alice" / "Documents" / name)
        cls.picture_md5 = hashlib.md5(picture.read_bytes()).hexdigest()
        cls.client = api_test_client(RunJobStore(), case_db_roots=[cls.temp.name])
        response = cls.client.post(
            "/api/runs",
            json={"root": str(root), "mode": "fraud", "output_dir": str(base / "run-out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        cls.handle = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={}).json()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.temp.cleanup()

    def _tags_url(self, suffix: str = "") -> str:
        return f"/api/cases/{self.handle['case_id']}/tags{suffix}?run_id={self.run_id}"

    def _batch(self, targets, **body):
        return self.client.post(
            "/api/case-db/review-batch",
            json={"database": self.handle["database"], "case_id": self.handle["case_id"], "run_id": self.run_id, "targets": targets, **body},
        )

    def test_tags_crud_over_http_with_korean_errors(self) -> None:
        listed = self.client.get(self._tags_url())
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertTrue(listed.json()["exists"])
        self.assertEqual(len(listed.json()["color_tokens"]), 8)
        created = self.client.post(self._tags_url(), json={"name": "HTTP 태그", "color_token": "tag-6", "shortcut": 8, "created_by": "검사관 A"})
        self.assertEqual(created.status_code, 201, created.text)
        tag = created.json()["tag"]
        self.assertEqual((tag["shortcut"], tag["created_by"]), (8, "검사관 A"))
        conflict = self.client.post(self._tags_url(), json={"name": "다른 태그", "shortcut": 8})
        self.assertEqual(conflict.status_code, 409)
        self.assertIn("HTTP 태그", conflict.json()["detail"])
        empty = self.client.post(self._tags_url(), json={"name": " "})
        self.assertEqual(empty.status_code, 422)
        self.assertEqual(empty.json()["detail"], "태그 이름을 입력하세요.")
        malformed = self.client.post(self._tags_url(), content=b"{", headers={"Content-Type": "application/json"})
        self.assertEqual(malformed.status_code, 422)
        self.assertIn("JSON", json.dumps(malformed.json()["detail"], ensure_ascii=False))
        patched = self.client.patch(self._tags_url(f"/{tag['id']}"), json={"shortcut": None, "description": "설명"})
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual((patched.json()["tag"]["shortcut"], patched.json()["tag"]["description"]), (None, "설명"))
        self.assertEqual(self.client.patch(self._tags_url(f"/{tag['id']}"), json={}).status_code, 422)
        deleted = self.client.delete(self._tags_url(f"/{tag['id']}"))
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertIsNotNone(deleted.json()["tag"]["deleted_at"])
        self.assertEqual(self.client.delete(self._tags_url(f"/{tag['id']}")).status_code, 404)
        wrong_case = self.client.get(f"/api/cases/not-this-case/tags?run_id={self.run_id}")
        self.assertEqual(wrong_case.status_code, 404)
        self.assertEqual(self.client.get(f"/api/cases/{self.handle['case_id']}/tags").status_code, 422)

    def test_review_batch_tag_ids_and_hash_propagation(self) -> None:
        tag = self.client.post(self._tags_url(), json={"name": "같은 해시"}).json()["tag"]
        connection = sqlite3.connect(self.handle["database"])
        try:
            rows = connection.execute(
                "SELECT id, path FROM file_record WHERE case_id = ? AND lower(hash_md5) = ? ORDER BY id",
                (self.handle["case_id"], self.picture_md5),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 3, rows)
        files = self.client.get(f"/api/runs/{self.run_id}/files?offset=0&limit=500").json()["candidates"]
        seed_index = next(index for index, row in enumerate(files) if row["path"] == rows[0][1])
        located = [{"collection": "files", "locator": f"/candidates/{seed_index}"}]
        mixed = self._batch(located, tag_ids=[tag["id"]], status="relevant")
        self.assertEqual(mixed.status_code, 422)
        propagated = self._batch(located, tag_ids=[tag["id"]], propagate_by_hash=True, reviewer="검사관 A")
        self.assertEqual(propagated.status_code, 200, propagated.text)
        payload = propagated.json()
        self.assertEqual(payload["applied_count"], 3)
        self.assertEqual(payload["propagation"]["matched_file_rows"], 3)
        listed = {item["name"]: item["count"] for item in self.client.get(self._tags_url()).json()["tags"]}
        self.assertEqual(listed["같은 해시"], 3)
        review_map = self.client.get(f"/api/runs/{self.run_id}/review-map").json()
        tagged = [mark for mark in review_map["marks"] if "같은 해시" in mark["tags"]]
        self.assertEqual(len(tagged), 3)
        # Mark history: author and time per change.
        history = self.client.get(f"/api/runs/{self.run_id}/review-history", params={"collection": "files", "locator": f"/candidates/{seed_index}"})
        self.assertEqual(history.status_code, 200, history.text)
        entry = history.json()["entries"][0]
        self.assertEqual(entry["author"], "검사관 A")
        self.assertEqual(entry["tags_after"], ["같은 해시"])
        self.assertTrue(entry["changed_at"])
        # Remove by id.
        removed = self._batch(located, remove_tag_ids=[tag["id"]])
        self.assertEqual(removed.status_code, 200, removed.text)
        listed = {item["name"]: item["count"] for item in self.client.get(self._tags_url()).json()["tags"]}
        self.assertEqual(listed["같은 해시"], 2)
        no_tags = self._batch(located, propagate_by_hash=True)
        self.assertEqual(no_tags.status_code, 422)
        self.assertIn("전파할 태그", no_tags.json()["detail"])

    def test_explicit_database_must_exist_and_is_never_created_by_a_read(self) -> None:
        """Adversarial review of E3 item 2: ``?database=<new path>`` is a 404 and creates no file."""
        missing = Path(self.temp.name) / "probe" / "new-case.db"
        case_id = self.handle["case_id"]
        for url in (f"/api/cases/{case_id}/tags", f"/api/cases/{case_id}/histogram-baselines"):
            response = self.client.get(url, params={"database": str(missing)})
            self.assertEqual(response.status_code, 404, response.text)
            self.assertIn("케이스 DB 파일을 찾을 수 없습니다", response.json()["detail"])
        created = self.client.post(f"/api/cases/{case_id}/tags", params={"database": str(missing)}, json={"name": "x"})
        self.assertEqual(created.status_code, 404, created.text)
        self.assertFalse(missing.exists())
        self.assertFalse(missing.parent.exists())
        # The existing case DB still works through ``database=``.
        existing = self.client.get(f"/api/cases/{case_id}/tags", params={"database": self.handle["database"]})
        self.assertEqual(existing.status_code, 200, existing.text)

    def test_review_batch_tag_ids_apply_workflow_fields_and_korean_body_errors(self) -> None:
        """Adversarial review of E3 items 6 and 12."""
        tag = self.client.post(self._tags_url(), json={"name": "배정 태그"}).json()["tag"]
        files = self.client.get(f"/api/runs/{self.run_id}/files?offset=0&limit=5").json()["candidates"]
        located = [{"collection": "files", "locator": "/candidates/0"}]
        self.assertTrue(files)
        applied = self._batch(located, tag_ids=[tag["id"]], assignee="검사관 D", priority="urgent", due_at="2026-11-01")
        self.assertEqual(applied.status_code, 200, applied.text)
        target = applied.json()["targets"][0]
        connection = sqlite3.connect(self.handle["database"])
        try:
            row = connection.execute(
                "SELECT assignee, priority, due_at FROM review_mark WHERE target_type = ? AND target_id = ?",
                (target["target_type"], target["target_id"]),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(tuple(row), ("검사관 D", "urgent", "2026-11-01"))
        bad_priority = self._batch(located, tag_ids=[tag["id"]], priority="someday")
        self.assertEqual(bad_priority.status_code, 422)
        self.assertIn("우선순위", bad_priority.json()["detail"])
        malformed = self._batch(located, tag_ids=["x"])
        self.assertEqual(malformed.status_code, 422)
        detail = malformed.json()["detail"]
        self.assertEqual(detail[0]["msg"], "태그(tag_ids)의 1번째 항목은 정수여야 합니다")
        missing = self.client.post("/api/case-db/review-batch", json={"case_id": "x", "targets": located})
        self.assertEqual(missing.status_code, 422)
        self.assertIn("케이스 DB(database) 값이 필요합니다", [item["msg"] for item in missing.json()["detail"]])

    def test_histogram_baseline_save_and_compare(self) -> None:
        base_url = f"/api/cases/{self.handle['case_id']}/histogram-baselines?run_id={self.run_id}"
        current = self.client.get(f"/api/runs/{self.run_id}/histogram")
        self.assertEqual(current.status_code, 200, current.text)
        bars = {bar["key"]: bar for bar in current.json()["bars"]}
        self.assertIn("collection:files", bars)
        self.assertTrue(any(key.startswith("kind:") for key in bars))
        self.assertNotIn("delta", bars["collection:files"])
        saved = self.client.post(base_url, json={"name": "처리 직후", "created_by": "검사관 A"})
        self.assertEqual(saved.status_code, 201, saved.text)
        baseline = saved.json()["baseline"]
        self.assertEqual(baseline["counts"]["collection:files"]["count"], bars["collection:files"]["count"])
        self.assertEqual(self.client.post(base_url, json={"name": "처리 직후"}).status_code, 409)
        self.assertEqual(self.client.post(base_url, json={"name": ""}).status_code, 422)
        listed = self.client.get(base_url).json()["baselines"]
        self.assertEqual([item["name"] for item in listed], ["처리 직후"])
        # Tamper the stored counts to prove the comparison reads the baseline, then compare.
        connection = sqlite3.connect(self.handle["database"])
        try:
            stored = json.loads(connection.execute("SELECT counts_json FROM histogram_baseline WHERE id = ?", (baseline["id"],)).fetchone()[0])
            stored["collection:files"]["count"] += 5
            stored["kind:retired"] = {"label": "없어진 종류", "count": 2}
            connection.execute("UPDATE histogram_baseline SET counts_json = ? WHERE id = ?", (json.dumps(stored), baseline["id"]))
            connection.commit()
        finally:
            connection.close()
        compared = self.client.get(f"/api/runs/{self.run_id}/histogram?compare={baseline['id']}").json()
        by_key = {bar["key"]: bar for bar in compared["bars"]}
        self.assertEqual(by_key["collection:files"]["delta"], -5)
        self.assertEqual((by_key["kind:retired"]["count"], by_key["kind:retired"]["delta"]), (0, -2))
        self.assertEqual(compared["baseline"]["name"], "처리 직후")
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/histogram?compare=99999").status_code, 404)

    def test_export_context_names_case_and_evidence_numbers(self) -> None:
        context = self.client.get(f"/api/runs/{self.run_id}/export-context")
        self.assertEqual(context.status_code, 200, context.text)
        payload = context.json()
        self.assertEqual(payload["case_id"], self.handle["case_id"])
        self.assertIsNone(payload["case_number"])  # no 케이스 만들기 case number on a quick run
        self.assertIn("-EVID-", payload["evidence_number"])
        self.assertEqual(self.client.get("/api/runs/missing/export-context").status_code, 404)

    def test_related_media_counts_same_hash_files(self) -> None:
        picture = next(
            row["path"]
            for row in self.client.get(f"/api/runs/{self.run_id}/files?offset=0&limit=500").json()["candidates"]
            if row["path"].endswith("screen-capture.png")
        )
        related = self.client.get(f"/api/runs/{self.run_id}/related-media", params={"path": picture})
        self.assertEqual(related.status_code, 200, related.text)
        self.assertEqual((related.json()["count"], related.json()["source"]), (2, "case-db"))
        self.assertTrue(all(path.endswith(("copy-a.png", "copy-b.png")) for path in related.json()["paths"]))


if __name__ == "__main__":
    unittest.main()
