import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import knowledgec


def _fixture(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.executescript("""
            CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZSTARTDATE REAL,
                ZENDDATE REAL, ZVALUESTRING TEXT, ZVALUEINTEGER INTEGER, ZVALUEDOUBLE REAL,
                ZVALUEBINARY BLOB, ZSOURCE INTEGER, ZSTRUCTUREDMETADATA INTEGER);
            CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID TEXT, ZDEVICEID TEXT);
            CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY,
                Z_DKNOTIFICATIONUSAGEMETADATAKEY__BUNDLEID TEXT, "extra""field" TEXT);
            INSERT INTO ZSOURCE VALUES (42, 'example.producer', 'synthetic-device');
            INSERT INTO ZSTRUCTUREDMETADATA VALUES (34, 'example.subject', '한글 자료');
        """)
        streams = ("/app/inFocus", "/app/usage", "/device/isLocked", "/display/isBacklit",
                   "/safari/history", "/app/webUsage", "/notification/usage", "/app/intents",
                   "/device/batteryPercentage", "/new/synthetic")
        for pk, stream in enumerate(streams, 1):
            db.execute("INSERT INTO ZOBJECT VALUES (?,?,?,?,?,?,?,?,?,?)", (
                pk, stream, 0.125, 1.5, "example.focus" if pk <= 2 else None,
                0 if pk in (3, 4) else None, 0.75 if pk == 9 else None,
                b"\x00\xff" if pk == 10 else None, 42, 34 if pk == 7 else None,
            ))
        db.commit()


class KnowledgeCTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "evidence"
        self.system_db = self.root / knowledgec.SYSTEM_DB

    def rows(self):
        return list(knowledgec.KnowledgeCProvider().collect(self.root))

    def test_known_and_generic_streams_join_to_actual_keys(self):
        _fixture(self.system_db)
        events = self.rows()
        self.assertEqual(len(events), 10)
        self.assertTrue(all(row.artifact_type == "macos-knowledgec-event" for row in events))
        first = events[0].details
        self.assertEqual((first["start_raw"], first["end_raw"]), (0.125, 1.5))
        self.assertEqual(first["timestamp"], "2001-01-01T00:00:00.125000+00:00")
        self.assertEqual(first["end_at"], "2001-01-01T00:00:01.500000+00:00")
        self.assertEqual((first["source_row_id"], first["scope"]), (1, "system"))
        self.assertEqual(first["source_bundle_id"], "example.producer")
        self.assertEqual(first["source_device"], "synthetic-device")
        self.assertEqual(first["bundle_id"], "example.focus")
        self.assertEqual(events[2].details["value"], 0)
        self.assertEqual(events[8].details["value"], 0.75)
        self.assertEqual(events[6].details["bundle_id"], "example.subject")
        self.assertEqual(events[6].details["structured_metadata"]['extra"field'], "한글 자료")
        self.assertEqual(events[-1].details["value"], {"hex": "00ff"})
        self.assertEqual([e.details["stream"] for e in events if e.details["unknown_stream"]], ["/new/synthetic"])
        self.assertIn("unknown-stream", events[-1].details["warnings"])

    def test_ambiguous_bundle_and_extra_value_columns(self):
        _fixture(self.system_db)
        with closing(sqlite3.connect(self.system_db)) as db:
            db.execute("ALTER TABLE ZSTRUCTUREDMETADATA ADD COLUMN Z_OTHER__BUNDLEID TEXT")
            db.execute("UPDATE ZSTRUCTUREDMETADATA SET Z_OTHER__BUNDLEID='example.alternate'")
            db.execute("ALTER TABLE ZOBJECT ADD COLUMN ZVALUEMETADATA BLOB")
            db.execute("UPDATE ZOBJECT SET ZVALUEMETADATA=x'0102' WHERE Z_PK=7")
            db.execute("INSERT INTO ZOBJECT (ZSTREAMNAME) VALUES (NULL), (''), (x'01')")
            db.commit()
        events = self.rows()
        self.assertEqual(len(events), 10)
        notification = events[6].details
        self.assertEqual(notification["values"]["ZVALUEMETADATA"], {"hex": "0102"})
        self.assertIsNone(notification["bundle_id"])
        self.assertIsNone(notification["value"])
        self.assertIn("ambiguous-metadata-bundle", notification["warnings"])
        self.assertEqual(notification["source_bundle_id"], "example.producer")
        self.assertEqual(notification["structured_metadata"]["Z_OTHER__BUNDLEID"], "example.alternate")

    def test_user_only_wal_visible_and_evidence_identical(self):
        path = self.root / "Users" / "sample" / knowledgec.USER_DB
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("CREATE TABLE ZOBJECT (ZSTREAMNAME, ZSTARTDATE, ZENDDATE, ZVALUESTRING)")
            writer.execute("INSERT INTO ZOBJECT VALUES ('/safari/history',0,-1,?)", ("한글",))
            writer.commit()
            def hashes():
                return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.parent.iterdir()}
            before = hashes()
            row, = self.rows()
            self.assertEqual(before, hashes())
            self.assertEqual(row.details["source_row_id"], 1)
            self.assertEqual(row.details["start_at"], "2001-01-01T00:00:00+00:00")
            self.assertEqual(row.details["end_at"], "2000-12-31T23:59:59+00:00")
            self.assertEqual(row.details["scope"], "user")
            self.assertEqual(row.details["owner"], "sample")
            self.assertEqual(row.details["value"], "한글")
            self.assertEqual(row.details["structured_metadata"], {})
            self.assertTrue(row.details["source_snapshot"]["wal_included"])
            self.assertEqual({f["name"]: f["sha256"] for f in row.details["source_snapshot"]["files"]}, before)

    def test_big_entry_and_out_of_range_time(self):
        path = self.root / knowledgec.USER_DB
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE ZOBJECT (ZSTREAMNAME, ZSTARTDATE, ZVALUEBINARY)")
            db.execute("INSERT INTO ZOBJECT VALUES ('/new/blob',1e300,zeroblob(100000))")
            db.commit()
        row, = self.rows()
        self.assertEqual(row.details["scope"], "user")
        self.assertEqual(row.details["coverage_status"], "partial")
        self.assertEqual(row.details["timestamp"], "")
        self.assertEqual(row.details["start_raw"], 1e300)
        self.assertEqual(row.details["value"], {"hex": "00" * knowledgec.MAX_VALUE_BYTES})
        self.assertIn("value-truncated:ZVALUEBINARY", row.details["warnings"])
        self.assertIn("invalid-start-time", row.details["warnings"])

    def test_caps_report_partial_coverage(self):
        _fixture(self.system_db)
        for cap, limit, reason, count in [
            ("MAX_ROWS", 2, "row-cap", 3),
            ("MAX_OUTPUT_BYTES", 1, "output-byte-cap", 1),
            ("MAX_SNAPSHOT_BYTES", 1, "snapshot-byte-cap", 1),
            ("MAX_METADATA_COLUMNS", 1, "metadata-column-cap", 11),
            ("MAX_VALUE_COLUMNS", 1, "value-column-cap", 11),
        ]:
            with self.subTest(cap=cap), patch.object(knowledgec, cap, limit):
                rows = self.rows()
                self.assertEqual(len(rows), count)
                self.assertEqual([r.details["reason"] for r in rows if r.artifact_type.endswith("diagnostic")], [reason])

    def test_bad_database_and_missing_table(self):
        self.system_db.parent.mkdir(parents=True)
        self.system_db.write_bytes(b"synthetic damaged database")
        bad, = self.rows()
        self.assertEqual(bad.artifact_type, "macos-knowledgec-diagnostic")
        self.assertTrue(bad.details["reason"].startswith("snapshot-read-error:"))
        self.system_db.unlink()
        with closing(sqlite3.connect(self.system_db)) as db:
            db.execute("CREATE VIEW ZOBJECT AS SELECT '/new/view' AS ZSTREAMNAME")
        missing, = self.rows()
        self.assertEqual(missing.details["reason"], "missing-stream-column")

    def test_symlinked_ancestor_and_sidecar_are_not_opened(self):
        outside = self.root.parent / "outside"
        _fixture(outside / knowledgec.SYSTEM_DB)
        self.root.mkdir()
        (self.root / "private").symlink_to(outside / "private", target_is_directory=True)
        self.assertEqual(self.rows(), [])
        (self.root / "private").unlink()
        _fixture(self.system_db)
        self.system_db.with_suffix(".db-wal").symlink_to(outside / knowledgec.SYSTEM_DB)
        with patch.object(knowledgec, "open_sqlite_snapshot", side_effect=AssertionError("opened symlink")):
            diagnostic, = self.rows()
        self.assertEqual(diagnostic.details["reason"], "non-regular-snapshot-member")
