from __future__ import annotations

import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows.browser import extract_chromium_history_and_downloads
from rapidtriage.artifacts.windows.common import open_sqlite_snapshot
from rapidtriage.core import sqlite_snapshot
from rapidtriage.core.source_reader import (
    build_sqlite_table_preview,
    search_sqlite_source,
)

try:
    from rapidtriage.api.app.sqlite import (
        build_sqlite_preview,
        build_sqlite_table_page,
        first_sqlite_table_name,
        search_sqlite_file,
    )
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    HAS_FASTAPI = False
else:
    HAS_FASTAPI = True


class SqliteSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "evidence"
        self.source.mkdir()
        self.path = self.source / "History ?#.db"
        self.working = self.root / "working"
        self.working.mkdir()
        self.original_temporary_directory = tempfile.TemporaryDirectory
        self.patch = mock.patch.object(
            sqlite_snapshot.tempfile, "TemporaryDirectory",
            side_effect=lambda **kwargs: self.original_temporary_directory(dir=self.working, **kwargs),
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def make_database(self, *, wal: bool = True, without_rowid: bool = False) -> None:
        producer = self.root / "producer.db"
        connection = sqlite3.connect(producer)
        try:
            connection.execute("PRAGMA journal_mode=WAL" if wal else "PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            suffix = " WITHOUT ROWID" if without_rowid else ""
            connection.execute(
                "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)" + suffix
            )
            connection.commit()
            if wal:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("INSERT INTO urls VALUES (1, 'https://example.invalid/marker', 'wal-only-marker', 1, 1)")
            connection.commit()
            shutil.copyfile(producer, self.path)
            if wal:
                shutil.copyfile(Path(str(producer) + "-wal"), Path(str(self.path) + "-wal"))
        finally:
            connection.close()

    def inventory(self) -> dict[str, tuple[str, int]]:
        return {
            path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
            for path in self.source.iterdir()
        }

    def assert_clean(self, before: dict[str, tuple[str, int]]) -> None:
        self.assertEqual(before, self.inventory())
        self.assertFalse(Path(str(self.path) + "-shm").exists())
        self.assertEqual([], list(self.working.iterdir()))

    @unittest.skipUnless(HAS_FASTAPI, "fastapi required")
    def test_committed_wal_row_across_all_readers_preserves_source(self) -> None:
        self.make_database()
        before = self.inventory()
        database_only = self.root / "database-only.db"
        shutil.copyfile(self.path, database_only)
        with open_sqlite_snapshot(database_only) as connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM urls").fetchone()[0])
        original_connect = sqlite3.connect
        destinations = []

        def connect(database, **kwargs):
            destinations.append(database)
            self.assertTrue(str(database).startswith(self.working.as_uri() + "/"))
            self.assertNotIn("immutable", str(database))
            return original_connect(database, **kwargs)

        with mock.patch.object(sqlite_snapshot.sqlite3, "connect", side_effect=connect):
            with open_sqlite_snapshot(self.path) as connection:
                self.assertEqual("wal-only-marker", connection.execute("SELECT title FROM urls").fetchone()["title"])
                self.assertEqual(1, connection.execute("PRAGMA query_only").fetchone()[0])
            history, downloads = extract_chromium_history_and_downloads(self.path)
            self.assertEqual("wal-only-marker", history[0]["title"])
            self.assertTrue(history[0]["sqlite_snapshot"]["wal_included"])
            self.assertEqual([], downloads)
            preview = build_sqlite_table_preview(self.path, table="urls", offset=0, limit=1)
            self.assertEqual("wal-only-marker", preview["rows"][0]["values"]["title"])
            matches, metadata = search_sqlite_source(self.path, ["wal-only-marker"], relative_path=self.path.name, limit=1, context=20)
            self.assertEqual(1, len(matches))
            self.assertEqual(self.path.name, matches[0]["source_path"])
            self.assertTrue(metadata["sqlite_snapshot"]["wal_included"])
            self.assertEqual("urls", first_sqlite_table_name(self.path))
            preview = build_sqlite_preview(self.path)
            metadata = preview["sqlite"]["database_metadata"]
            self.assertTrue(metadata["sqlite_snapshot"]["wal_included"])
            self.assertEqual(str(self.path), metadata["database_list"][0]["file"])
            for file in metadata["sqlite_snapshot"]["files"]:
                if file["exists"]:
                    self.assertEqual(before[Path(file["path"]).name][0], file["sha256"])
            row = preview["sqlite"]["tables"][0]["rows"][0]
            self.assertEqual("wal-only-marker", row["values"]["title"])
            self.assertEqual(str(self.path), row["source_viewer_locator"]["source_path"])
            page = self.api_page()
            self.assertEqual("wal-only-marker", page["rows"][0]["values"]["title"])
            matches, _, _ = search_sqlite_file(self.path, ["wal-only-marker"], limit=1, context=20)
            self.assertEqual(1, len(matches))
        self.assertEqual(8, len(destinations))
        self.assert_clean(before)

    def test_no_wal_and_without_rowid(self) -> None:
        self.make_database(wal=False, without_rowid=True)
        before = self.inventory()
        preview = build_sqlite_table_preview(self.path, table="urls", offset=0, limit=1)
        self.assertFalse(preview["rowid_supported"])
        self.assertEqual(1, preview["row_count"])
        self.assertFalse(preview["sqlite_snapshot"]["wal_included"])
        matches, metadata = search_sqlite_source(self.path, ["marker"], relative_path=self.path.name, limit=1, context=20, row_scan_limit=1)
        self.assertEqual(1, len(matches))
        self.assertEqual(1, metadata["sqlite_scanned_rows"])
        if HAS_FASTAPI:
            self.assertEqual("", self.api_page()["rows"][0]["rowid"])
            self.assertEqual(1, len(search_sqlite_file(self.path, ["marker"], limit=1, context=20)[0]))
        self.assert_clean(before)

    def test_exception_closes_connection_and_cleans_sidecars(self) -> None:
        self.make_database()
        before = self.inventory()
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with open_sqlite_snapshot(self.path) as connection:
                connection.execute("SELECT * FROM urls").fetchall()
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("DELETE FROM urls")
                raise RuntimeError("consumer")
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        self.assert_clean(before)

    def test_copy_error_fails_closed(self) -> None:
        self.make_database()
        before = self.inventory()
        copyfile = shutil.copyfile

        def fail_wal(source, destination):
            if str(source).endswith("-wal"):
                raise OSError("copy denied")
            return copyfile(source, destination)

        with mock.patch.object(sqlite_snapshot.shutil, "copyfile", side_effect=fail_wal), mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
            with self.assertRaisesRegex(sqlite_snapshot.SqliteSnapshotError, "copy denied"):
                with open_sqlite_snapshot(self.path):
                    self.fail("snapshot yielded")
            connect.assert_not_called()
        self.assert_clean(before)

    def test_source_set_changes_fail_closed(self) -> None:
        self.make_database()
        copyfile = shutil.copyfile
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                target = Path(str(self.path) + suffix)
                original = target.read_bytes() if target.exists() else None

                def change_source(source, destination, target=target):
                    result = copyfile(source, destination)
                    if source == self.path:
                        target.write_bytes(b"changed")
                    return result

                with mock.patch.object(sqlite_snapshot.shutil, "copyfile", side_effect=change_source), mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
                    with self.assertRaises(sqlite_snapshot.SqliteSnapshotError):
                        with open_sqlite_snapshot(self.path):
                            self.fail("snapshot yielded")
                    connect.assert_not_called()
                self.assertEqual([], list(self.working.iterdir()))
                if original is None:
                    target.unlink()
                else:
                    target.write_bytes(original)

    def test_changed_database_and_corrupt_copy_fail_closed(self) -> None:
        self.make_database()
        copyfile = shutil.copyfile
        for change_source in (True, False):
            with self.subTest(change_source=change_source):
                original = self.path.read_bytes()

                def change_copy(source, destination, change_source=change_source):
                    result = copyfile(source, destination)
                    if source == self.path:
                        target = source if change_source else destination
                        target.write_bytes(b"X" + target.read_bytes()[1:])
                    return result

                with mock.patch.object(sqlite_snapshot.shutil, "copyfile", side_effect=change_copy), mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
                    with self.assertRaises(sqlite_snapshot.SqliteSnapshotError):
                        with open_sqlite_snapshot(self.path):
                            self.fail("snapshot yielded")
                    connect.assert_not_called()
                self.path.write_bytes(original)
                self.assertEqual([], list(self.working.iterdir()))

    def test_hot_journal_rejected_and_empty_journal_preserved(self) -> None:
        self.make_database(wal=False)
        journal = Path(str(self.path) + "-journal")
        journal.write_bytes(bytes.fromhex("d9d505f920a163d7") + bytes(1024))
        before = self.inventory()
        with mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
            with self.assertRaisesRegex(sqlite_snapshot.SqliteSnapshotError, "hot journal"):
                with open_sqlite_snapshot(self.path):
                    self.fail("snapshot yielded")
            connect.assert_not_called()
        self.assert_clean(before)
        journal.write_bytes(b"")
        before = self.inventory()
        with open_sqlite_snapshot(self.path) as connection:
            self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM urls").fetchone()[0])
        self.assert_clean(before)

    def test_missing_database_and_nonregular_sidecar_fail_closed(self) -> None:
        with self.assertRaises(sqlite_snapshot.SqliteSnapshotError):
            with open_sqlite_snapshot(self.path):
                self.fail("snapshot yielded")
        self.make_database(wal=False)
        wal = Path(str(self.path) + "-wal")
        wal.symlink_to(self.path)
        with self.assertRaisesRegex(sqlite_snapshot.SqliteSnapshotError, "regular file"):
            with open_sqlite_snapshot(self.path):
                self.fail("snapshot yielded")
        self.assertEqual([], list(self.working.iterdir()))

    def test_wal_creation_and_removal_during_copy_fail_closed(self) -> None:
        self.make_database(wal=False)
        copyfile = shutil.copyfile
        wal = Path(str(self.path) + "-wal")
        for create in (True, False):
            with self.subTest(create=create):
                def change_membership(source, destination, create=create):
                    result = copyfile(source, destination)
                    if source == self.path:
                        if create:
                            wal.write_bytes(b"new WAL")
                        else:
                            wal.unlink()
                    return result

                with mock.patch.object(sqlite_snapshot.shutil, "copyfile", side_effect=change_membership), mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
                    with self.assertRaises(sqlite_snapshot.SqliteSnapshotError):
                        with open_sqlite_snapshot(self.path):
                            self.fail("snapshot yielded")
                    connect.assert_not_called()
                self.assertEqual([], list(self.working.iterdir()))

    def test_existing_shm_is_not_copied_or_modified(self) -> None:
        self.make_database()
        shm = Path(str(self.path) + "-shm")
        shm.write_bytes(b"synthetic stale shared memory")
        before = self.inventory()
        provenance = {}
        with open_sqlite_snapshot(self.path, provenance=provenance) as connection:
            self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM urls").fetchone()[0])
        self.assertEqual(before, self.inventory())
        self.assertEqual([], list(self.working.iterdir()))
        self.assertFalse(next(row for row in provenance["files"] if row["path"] == str(shm))["copied"])

    def test_setup_failure_closes_connection(self) -> None:
        self.make_database()
        before = self.inventory()
        connection = mock.Mock()
        connection.execute.side_effect = sqlite3.OperationalError("setup failed")
        with mock.patch.object(sqlite_snapshot.sqlite3, "connect", return_value=connection):
            with self.assertRaisesRegex(sqlite3.OperationalError, "setup failed"):
                with open_sqlite_snapshot(self.path):
                    self.fail("snapshot yielded")
        connection.close.assert_called_once_with()
        self.assert_clean(before)

    def test_connect_failure_cleans_working_directory(self) -> None:
        self.make_database()
        before = self.inventory()
        with mock.patch.object(sqlite_snapshot.sqlite3, "connect", side_effect=sqlite3.OperationalError("connect failed")):
            with self.assertRaisesRegex(sqlite3.OperationalError, "connect failed"):
                with open_sqlite_snapshot(self.path):
                    self.fail("snapshot yielded")
        self.assert_clean(before)

    def test_nested_snapshots_are_unique(self) -> None:
        self.make_database()
        before = self.inventory()
        with open_sqlite_snapshot(self.path) as first, open_sqlite_snapshot(self.path) as second:
            first_path = first.execute("PRAGMA database_list").fetchone()[2]
            second_path = second.execute("PRAGMA database_list").fetchone()[2]
            self.assertNotEqual(first_path, second_path)
            self.assertEqual(2, len(list(self.working.iterdir())))
        self.assert_clean(before)

    def api_page(self, **kwargs):
        return build_sqlite_table_page(
            run_id="synthetic", source_path=self.path, table="urls", offset=0, limit=1,
            where_column=None, where_contains=None, order_by=None, descending=False, **kwargs,
        )
