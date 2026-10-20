"""R6 S2 lane B: adb backup inner databases handed to the existing app parsers.

Synthetic fixtures only (built in ``tempfile``): a fake KakaoTalk schema and a generic app
database inside ``.ab`` files. Q-S2-2 (hand-off), Q-S2-3 (hostile member names), Q-S2-4 (caps,
memory with a zlib bomb), Q-S2-12 (planted secret bytes never reach the outputs).
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import tarfile
import tempfile
import tracemalloc
import unittest
import zlib
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.mobile import MobileExportProvider, adb_backup
from rapidtriage.artifacts.mobile.adb_backup import safe_component
from rapidtriage.core.files import (
    MOBILE_INNER_DIR_NAME,
    MOBILE_INNER_INDEX_NAME,
    MOBILE_INNER_MARKER_NAME,
    is_tool_output_dir,
    iter_evidence_paths,
    register_tool_output_dir,
    unregister_tool_output_dir,
)

SECRET = "R6S2-PLANTED-SECRET-7f3a"
MIB = 1024 * 1024


def sqlite_bytes(script: str) -> bytes:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "x.db"
        connection = sqlite3.connect(path)
        connection.executescript(script)
        connection.commit()
        connection.close()
        return path.read_bytes()


def kakao_db() -> bytes:
    return sqlite_bytes(
        "CREATE TABLE chat_logs(_id INTEGER PRIMARY KEY, chat_id INTEGER, user_id INTEGER, message TEXT, created_at INTEGER);"
        "CREATE TABLE chat_rooms(_id INTEGER PRIMARY KEY, name TEXT);"
        f"INSERT INTO chat_logs(chat_id, user_id, message, created_at) VALUES (1, 2, '{SECRET}', 1700000000);"
        f"INSERT INTO chat_rooms(name) VALUES ('{SECRET}-room');"
    )


def app_db() -> bytes:
    return sqlite_bytes(
        f"CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes(body) VALUES ('{SECRET}');"
    )


def tar_bytes(members: list[tuple[str, bytes]], *, extra: list[tarfile.TarInfo] = ()) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
        for info in extra:
            archive.addfile(info)
    return buffer.getvalue()


def ab(payload: bytes, *, compressed: bool) -> bytes:
    return b"ANDROID BACKUP\n5\n" + (b"1" if compressed else b"0") + b"\nnone\n" + (zlib.compress(payload) if compressed else payload)


def files_under(root: Path) -> set[Path]:
    return {Path(dirpath) / name for dirpath, _dirs, names in os.walk(root) for name in names}


class _Sandbox(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.evidence = self.base / "evidence"
        self.output = self.base / "output"
        self.evidence.mkdir()
        self.output.mkdir()
        self.inner = self.output / MOBILE_INNER_DIR_NAME

    def write_ab(self, name: str, data: bytes) -> Path:
        path = self.evidence / name
        path.write_bytes(data)
        return path

    def collect(self) -> list:
        return list(MobileExportProvider(inner_dir=self.inner).collect(self.evidence))


class InnerHandoffTests(_Sandbox):
    """Q-S2-2: inner databases reach the KakaoTalk / Android app-data parsers."""

    def members(self) -> list[tuple[str, bytes]]:
        return [
            ("apps/com.kakao.talk/_manifest", b"1\ncom.kakao.talk\n"),
            ("apps/com.kakao.talk/db/KakaoTalk.db", kakao_db()),
            ("apps/com.example/db/app.db", app_db()),
            ("apps/com.example/db/app.db-journal", b"\0" * 512),
            ("apps/com.example/sp/prefs.xml", f"<map><string name='t'>{SECRET}</string></map>".encode()),
        ]

    def check(self, compressed: bool) -> None:
        backup = self.write_ab("phone.ab", ab(tar_bytes(self.members()), compressed=compressed))
        before = files_under(self.evidence)
        rows = self.collect()
        self.assertEqual(files_under(self.evidence), before, "nothing is written next to the evidence")
        by_type: dict[str, list] = {}
        for row in rows:
            by_type.setdefault(row.artifact_type, []).append(row)
        header = by_type["android-backup"][0].details
        self.assertEqual(header["status"], "completed")
        self.assertEqual(header["inner_databases_extracted"], 2)
        self.assertEqual(header["inner_records_handed"], 2)
        self.assertEqual(header["inner_copy_label"], "해제 사본, 증거 아님")
        chat = by_type["mobile-chat-database"]
        self.assertEqual(len(chat), 1)
        chat_details = chat[0].details
        self.assertEqual(chat_details["service"], "KakaoTalk")
        self.assertEqual(chat_details["recovery_method"], "adb-backup-extracted")
        self.assertEqual(chat_details["container_backup_path"], str(backup))
        self.assertEqual(chat_details["container_member"], "apps/com.kakao.talk/db/KakaoTalk.db")
        self.assertEqual(chat[0].provider, "mobile-export-artifacts")
        self.assertEqual(chat[0].path, str(backup))
        tables = {table["table"] for table in chat_details["table_summaries"]}
        self.assertEqual(tables, {"chat_logs", "chat_rooms"})
        app = by_type["android-app-data"]
        self.assertEqual(len(app), 1)
        app_details = app[0].details
        self.assertEqual(app_details["recovery_method"], "adb-backup-extracted")
        self.assertEqual(app_details["package"], "com.example")
        self.assertEqual(app_details["container_member"], "apps/com.example/db/app.db")
        self.assertEqual(app_details["data_category"], "database")
        for details in (chat_details, app_details):
            inner = Path(details["inner_path"])
            self.assertTrue(inner.is_file())
            self.assertTrue(str(inner.resolve()).startswith(str(self.inner.resolve())))
            self.assertFalse(str(inner.resolve()).startswith(str(self.evidence.resolve())))
        # the -journal companion sits next to its database under the same safe name
        app_inner = Path(app_details["inner_path"])
        self.assertTrue((app_inner.parent / (app_inner.name + "-journal")).is_file())
        members = {row.details["member_name"]: row.details for row in by_type["android-backup-member"]}
        self.assertNotIn("inner_path", members["apps/com.example/sp/prefs.xml"])
        self.assertEqual(members["apps/com.example/db/app.db-journal"]["inner_companion_of"], "app.db")
        # marker + index say "copies, not evidence"
        self.assertIn("해제 사본, 증거 아님", (self.inner / MOBILE_INNER_MARKER_NAME).read_text(encoding="utf-8"))
        index = json.loads((self.inner / MOBILE_INNER_INDEX_NAME).read_text(encoding="utf-8"))
        self.assertEqual((index["label_ko"], index["evidence"], index["copy_count"]), ("해제 사본, 증거 아님", False, 3))
        # Q-S2-12: no planted secret in any row or the index
        dumped = json.dumps([row.to_dict() for row in rows], ensure_ascii=False, default=str)
        self.assertNotIn(SECRET, dumped)
        self.assertNotIn(SECRET, json.dumps(index, ensure_ascii=False))

    def test_compressed_backup(self) -> None:
        self.check(compressed=True)

    def test_plain_backup(self) -> None:
        self.check(compressed=False)

    def test_without_inner_dir_nothing_is_written(self) -> None:
        self.write_ab("phone.ab", ab(tar_bytes(self.members()), compressed=True))
        rows = list(MobileExportProvider().collect(self.evidence))
        self.assertEqual({row.artifact_type for row in rows}, {"android-backup", "android-backup-member"})
        self.assertFalse(self.inner.exists())
        self.assertEqual(files_under(self.output), set())

    def test_encrypted_backup_unchanged(self) -> None:
        header = b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"\n".join([b"aa" * 32, b"bb" * 32, b"10000", b"cc" * 16, b"dd" * 48]) + b"\n"
        self.write_ab("enc.ab", header + b"\x8f" * 256)
        rows = self.collect()
        self.assertEqual([row.artifact_type for row in rows], ["android-backup"])
        self.assertEqual(rows[0].details["status"], "encrypted-not-unpacked")
        self.assertFalse(self.inner.exists())

    def test_inner_folder_pruned_from_rescans(self) -> None:
        self.write_ab("phone.ab", ab(tar_bytes(self.members()), compressed=True))
        # R6 S2 review: an inner folder inside the evidence tree is refused (nothing is written there)
        inside = self.evidence / "out" / MOBILE_INNER_DIR_NAME
        before = files_under(self.evidence)
        provider = MobileExportProvider(inner_dir=inside)
        rows = list(provider.collect(self.evidence))
        self.assertEqual(files_under(self.evidence), before)
        self.assertFalse(any(row.artifact_type == "mobile-chat-database" for row in rows))
        self.assertTrue(any("증거 폴더 안" in note for note in provider.collection_notes))
        # the run's own (registered) copy folder outside the evidence holds the copies
        rows = list(MobileExportProvider(inner_dir=self.inner).collect(self.evidence))
        self.assertTrue(any(row.artifact_type == "mobile-chat-database" for row in rows))
        self.assertFalse(is_tool_output_dir(self.inner), "the marker alone never prunes a folder")
        register_tool_output_dir(self.inner)
        self.addCleanup(unregister_tool_output_dir, self.inner)
        self.assertTrue(is_tool_output_dir(self.inner))
        # an unmarked / marked-but-unregistered folder of the same name is ordinary evidence
        plain = self.evidence / "other" / MOBILE_INNER_DIR_NAME
        plain.mkdir(parents=True)
        (plain / "note.txt").write_text("x", encoding="utf-8")
        (plain / MOBILE_INNER_MARKER_NAME).write_text("x", encoding="utf-8")
        self.assertFalse(is_tool_output_dir(plain))
        self.assertIn(plain / "note.txt", list(iter_evidence_paths(self.evidence, "*")))

    def test_cli_writes_inner_copies_next_to_output(self) -> None:
        from rapidtriage.cli import main

        self.write_ab("phone.ab", ab(tar_bytes(self.members()), compressed=True))
        output = self.output / "mobile.json"
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            code = main(["artifacts", str(self.evidence), "--kind", "mobile-export", "--output", str(output)])
        self.assertIn(code, (0, None))
        payload = json.loads(output.read_text(encoding="utf-8"))
        rows = payload.get("artifacts") or []
        extracted = [row for row in rows if (row.get("details") or row.get("fields") or {}).get("recovery_method") == "adb-backup-extracted"]
        self.assertEqual(len(extracted), 2)
        self.assertTrue((self.output / MOBILE_INNER_DIR_NAME / MOBILE_INNER_INDEX_NAME).is_file())
        self.assertNotIn(SECRET, output.read_text(encoding="utf-8"))


class RunStageTests(_Sandbox):
    """The run's artifacts stage copies inner databases under ``<output>/mobile-inner``."""

    def test_artifact_stage_uses_run_output(self) -> None:
        from rapidtriage.core.input_root import resolve_input_root
        from rapidtriage.core.run import collect_artifact_stages

        members = InnerHandoffTests.members(self)
        self.write_ab("phone.ab", ab(tar_bytes(members), compressed=True))
        results, _manifest = collect_artifact_stages(
            resolve_input_root(self.evidence),
            ("mobile-export",),
            artifacts_dir=self.output / "artifacts",
            resume=False,
            rule_set=None,
        )
        payload, path, _reused, _delta = results["mobile-export"]
        records = Path(str(payload.get("records_path") or ""))
        text = records.read_text(encoding="utf-8") if records.is_file() else path.read_text(encoding="utf-8")
        self.assertEqual(text.count("adb-backup-extracted"), 2)
        self.assertNotIn(SECRET, text)
        self.assertTrue((self.output / MOBILE_INNER_DIR_NAME / MOBILE_INNER_INDEX_NAME).is_file())
        self.assertFalse((self.evidence / MOBILE_INNER_DIR_NAME).exists())


class HostileNameTests(_Sandbox):
    """Q-S2-3: hostile member names never escape the output folder."""

    def test_hostile_members(self) -> None:
        db = app_db()
        symlink = tarfile.TarInfo("apps/com.evil/db/link.db")
        symlink.type, symlink.linkname = tarfile.SYMTYPE, "../../../../outside.db"
        hardlink = tarfile.TarInfo("apps/com.evil/db/hard.db")
        hardlink.type, hardlink.linkname = tarfile.LNKTYPE, "apps/com.evil/db/dup.db"
        device = tarfile.TarInfo("apps/com.evil/db/dev.db")
        device.type, device.devmajor, device.devminor = tarfile.CHRTYPE, 1, 3
        members = [
            ("apps/com.evil/db/../../x.db", db),
            ("apps/com.evil/db/C:\\x.db", db),
            ("apps/com.evil/db/a:b.db", db),
            ("apps/com.evil/db/dup.db", db),
            ("apps/com.evil/db/dup.db", db),
            ("apps/com.evil/db/CON.db", db),
            ("apps/com.evil/db/" + "n" * 300 + ".db", db),
            ("apps/../../db/x.db", db),
            ("apps/com.evil/../x.db", db),
            ("apps/com.evil/f/..", db),
        ]
        self.write_ab("evil.ab", ab(tar_bytes(members, extra=[symlink, hardlink, device]), compressed=True))
        before = files_under(self.base)
        rows = self.collect()
        new_files = files_under(self.base) - before
        self.assertTrue(new_files)
        for path in new_files:
            self.assertTrue(str(path.resolve()).startswith(str(self.inner.resolve()) + os.sep), path)
        self.assertFalse((self.base / "outside.db").exists())
        written = [path for path in new_files if path.parent.parent.parent == self.inner]
        names = sorted(path.name for path in written)
        for name in names:
            self.assertRegex(name, r"^[A-Za-z0-9._-]{1,120}$")
            self.assertNotIn("..", name.replace("...", ""))
        self.assertIn("x.db", names)
        self.assertIn("a_b.db", names)
        self.assertIn("dup.db", names)
        self.assertIn("dup-1.db", names)
        self.assertIn("_CON.db", names)
        self.assertTrue(any(len(name) == 120 and name.endswith(".db") for name in names))
        members = {}
        for row in rows:
            if row.artifact_type == "android-backup-member":
                members.setdefault(row.details["member_name"], []).append(row.details)
        for name in ("apps/com.evil/db/link.db", "apps/com.evil/db/hard.db", "apps/com.evil/db/dev.db"):
            self.assertNotIn("inner_path", members[name][0])
            self.assertIsNone(members[name][0]["sha256"])
        self.assertNotIn("inner_path", members["apps/com.evil/../x.db"][0])  # domain ".." is not an app domain
        handed = [row for row in rows if row.details.get("recovery_method") == "adb-backup-extracted"]
        self.assertTrue(handed)
        for row in handed:
            self.assertNotIn("..", row.details["inner_hint"].split("/"))
            self.assertNotIn(":", row.details["inner_hint"])

    def test_safe_component_rule(self) -> None:
        cases = {
            "../../x.db": "x.db",
            "C:\\x.db": "x.db",
            "a:b.db": "a_b.db",
            "..": "member.db",
            ".hidden.db": "hidden.db",
            "nul\x00.db": "nul_.db",
            "NUL.db": "_NUL.db",
            "com1.txt": "_com1.txt",
            "카톡.db": "__.db",
            "/abs/path/z.db": "z.db",
        }
        for raw, expected in cases.items():
            self.assertEqual(safe_component(raw), expected, raw)
        long_name = safe_component("a" * 500 + ".sqlite")
        self.assertEqual(len(long_name), 120)
        self.assertTrue(long_name.endswith(".sqlite"))


class CapTests(_Sandbox):
    """Q-S2-4: per-database, count and total caps; memory stays bounded with a bomb."""

    def test_over_size_database_skipped(self) -> None:
        size = 64 * MIB + 1
        path = self.evidence / "big.ab"
        with path.open("wb") as handle:
            handle.write(b"ANDROID BACKUP\n5\n0\nnone\n")
            with tarfile.open(fileobj=handle, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                info = tarfile.TarInfo("apps/com.big/db/big.db")
                info.size = size
                archive.addfile(info, _SqliteZeros(size))
                small = app_db()
                info = tarfile.TarInfo("apps/com.big/db/small.db")
                info.size = len(small)
                archive.addfile(info, io.BytesIO(small))
        rows = self.collect()
        members = {row.details.get("member_name"): row.details for row in rows if row.artifact_type == "android-backup-member"}
        self.assertEqual(members["apps/com.big/db/big.db"]["inner_extract_skipped"], "cap")
        self.assertEqual(members["apps/com.big/db/big.db"]["inner_extract_skipped_reason"], "size")
        self.assertIn("inner_path", members["apps/com.big/db/small.db"])
        self.assertEqual(rows[0].details["inner_databases_extracted"], 1)

    def test_count_cap_201st_database(self) -> None:
        tiny = b"SQLite format 3\x00" + b"\0" * 496
        members = [(f"apps/com.many/db/d{index:03d}.db", tiny) for index in range(201)]
        self.write_ab("many.ab", ab(tar_bytes(members), compressed=True))
        with mock.patch("rapidtriage.artifacts.android.build_android_app_data_record", side_effect=_light_record):
            rows = self.collect()
        header = rows[0].details
        self.assertEqual(header["inner_databases_extracted"], 200)
        members_rows = {row.details["member_name"]: row.details for row in rows if row.artifact_type == "android-backup-member"}
        self.assertEqual(members_rows["apps/com.many/db/d200.db"]["inner_extract_skipped"], "cap")
        self.assertEqual(members_rows["apps/com.many/db/d200.db"]["inner_extract_skipped_reason"], "count")
        self.assertEqual(sum(1 for row in rows if row.details.get("recovery_method") == "adb-backup-extracted"), 200)

    def test_total_cap(self) -> None:
        db = app_db()
        members = [(f"apps/com.total/db/t{index}.db", db) for index in range(4)]
        self.write_ab("total.ab", ab(tar_bytes(members), compressed=True))
        # MAX_INNER_EXTRACT_BYTES (1 GiB) is lowered so the cap is reached with small fixtures.
        with mock.patch.object(adb_backup, "MAX_INNER_EXTRACT_BYTES", len(db) * 2 + 1):
            rows = self.collect()
        members_rows = {row.details["member_name"]: row.details for row in rows if row.artifact_type == "android-backup-member"}
        reasons = [members_rows[f"apps/com.total/db/t{index}.db"].get("inner_extract_skipped_reason") for index in range(4)]
        self.assertEqual(reasons, [None, None, "total", "total"])
        self.assertEqual(rows[0].details["inner_bytes_written"], len(db) * 2)
        self.assertEqual(adb_backup.MAX_INNER_EXTRACT_BYTES, 1024 * MIB)

    def test_bomb_memory_bounded(self) -> None:
        encoder = zlib.compressobj(9)
        info = tarfile.TarInfo("apps/com.bomb/db/bomb.db")
        info.size = 60 * MIB
        parts = [encoder.compress(info.tobuf(format=tarfile.GNU_FORMAT) + b"SQLite format 3\x00")]
        zeros = b"\0" * (4 * MIB)
        parts.extend(encoder.compress(zeros) for _ in range(14))
        parts.append(encoder.compress(b"\0" * (4 * MIB - 16)))  # rest of bomb.db (60 MiB, block aligned)
        second = tarfile.TarInfo("apps/com.bomb/f/huge.bin")
        second.size = 4 * 1024 * MIB
        parts.append(encoder.compress(second.tobuf(format=tarfile.GNU_FORMAT)))
        parts.extend(encoder.compress(b"\0" * (64 * MIB)) for _ in range(4))
        parts.append(encoder.flush())
        self.write_ab("bomb.ab", b"ANDROID BACKUP\n5\n1\nnone\n" + b"".join(parts))
        del parts, zeros
        tracemalloc.start()
        try:
            rows = self.collect()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 200 * MIB)
        header = rows[0].details
        self.assertEqual(header["status"], "partial")
        written = [path for path in files_under(self.inner) if path.name.endswith(".db")]
        for path in written:
            self.assertLessEqual(path.stat().st_size, 64 * MIB)


class _SqliteZeros(io.RawIOBase):
    """Readable ``SQLite format 3`` header followed by zeros (never held in memory)."""

    def __init__(self, size: int) -> None:
        self.remaining = size
        self.head = b"SQLite format 3\x00"

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        size = self.remaining if size is None or size < 0 else min(size, self.remaining)
        out = bytearray()
        if self.head and size:
            take = self.head[:size]
            out += take
            self.head = self.head[len(take):]
        out += b"\0" * (size - len(out))
        self.remaining -= len(out)
        return bytes(out)


def _light_record(path: Path, package: str):
    from rapidtriage.core.models import ArtifactRecord

    return ArtifactRecord(provider="x", artifact_type="android-app-data", path=str(path), supported=True, details={"package": package})


if __name__ == "__main__":
    unittest.main()
