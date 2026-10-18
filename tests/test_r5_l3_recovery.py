"""R5 L3 recovery: adb backup unpacking, Google Docs stubs (cloud-sync) and URL carving
(synthetic fixtures generated here)."""

from __future__ import annotations

import io
import json
import sqlite3
import tarfile
import tempfile
import time
import unittest
import zlib
from pathlib import Path

from rapidtriage.artifacts.cloud_sync import CloudSyncClientsProvider, google_doc_fields
from rapidtriage.artifacts.mobile import MobileExportProvider
from rapidtriage.artifacts.mobile.adb_backup import collect_adb_backup, member_parts
from rapidtriage.core.derived.url_classes import load_url_classes
from rapidtriage.core.url_carving import (
    CHUNK_BYTES,
    UrlCarveState,
    clean_url,
    scan_url_source,
    source_kind,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import analyses, create_app
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_analyses import write_run

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

SALT_HEX = "A1" * 32  # synthetic key material lines of an encrypted header: never in a row
TOKEN = "r5-l3-token"


def sqlite_bytes() -> bytes:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "msg.db"
        connection = sqlite3.connect(path)
        connection.executescript("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO messages(body) VALUES ('synthetic');")
        connection.commit()
        connection.close()
        return path.read_bytes()


def tar_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def adb_backup(members: dict[str, bytes], *, compressed: bool = True, encrypted: bool = False) -> bytes:
    if encrypted:
        header = b"ANDROID BACKUP\n5\n1\nAES-256\n" + "\n".join([SALT_HEX, SALT_HEX, "10000", SALT_HEX, SALT_HEX * 3]).encode() + b"\n"
        return header + b"\x8f" * 256
    payload = tar_bytes(members)
    return b"ANDROID BACKUP\n5\n" + (b"1" if compressed else b"0") + b"\nnone\n" + (zlib.compress(payload) if compressed else payload)


MEMBERS = {
    "apps/com.example.chat/_manifest": b"1\ncom.example.chat\n",
    "apps/com.example.chat/db/msg.db": b"",  # replaced in setUp
    "apps/com.example.chat/sp/prefs.xml": b"<map><string name='k'>v</string></map>",
    "shared/0/DCIM/a.jpg": b"\xff\xd8\xff" + b"\x00" * 10,
}


class AdbBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.members = dict(MEMBERS)
        self.members["apps/com.example.chat/db/msg.db"] = sqlite_bytes()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_compressed_backup_members(self) -> None:
        rows = list(collect_adb_backup(self.write("phone.ab", adb_backup(self.members))))
        header = rows[0].details
        self.assertEqual(rows[0].artifact_type, "android-backup")
        self.assertEqual((header["status"], header["member_count"], header["package_count"]), ("completed", 4, 1))
        members = {row.details["member_name"]: row.details for row in rows[1:]}
        database = members["apps/com.example.chat/db/msg.db"]
        self.assertEqual((database["package"], database["backup_domain"], database["data_category"]), ("com.example.chat", "db", "database"))
        self.assertEqual(database["sqlite_schema_inventory"]["tables"][0]["table"], "messages")
        self.assertEqual(len(database["sha256"]), 64)
        self.assertEqual(database["timestamp"], "2023-11-14T22:13:20Z")
        self.assertEqual(members["shared/0/DCIM/a.jpg"]["backup_domain"], "shared")
        self.assertEqual(rows[1].details["recovery_method"], "adb-backup-unpacked")
        self.assertNotIn("synthetic", json.dumps([row.details for row in rows], default=str).replace("synthetic-", ""))

    def test_uncompressed_encrypted_and_corrupt(self) -> None:
        plain = list(collect_adb_backup(self.write("plain.ab", adb_backup(self.members, compressed=False))))
        self.assertEqual(plain[0].details["member_count"], 4)
        encrypted = list(collect_adb_backup(self.write("enc.ab", adb_backup({}, encrypted=True))))
        self.assertEqual(len(encrypted), 1)
        self.assertEqual(encrypted[0].details["status"], "encrypted-not-unpacked")
        self.assertIn("대입", encrypted[0].details["status_reason"])
        self.assertEqual(encrypted[0].details["pbkdf2_rounds"], 10000)
        self.assertNotIn(SALT_HEX, json.dumps(encrypted[0].details))
        data = adb_backup(self.members)
        cut = list(collect_adb_backup(self.write("cut.ab", data[: len(data) // 2])))
        self.assertEqual(cut[0].details["status"], "partial")
        bad = list(collect_adb_backup(self.write("bad.ab", b"ANDROID BACKUP\nx\n")))
        self.assertEqual(bad[0].details["status"], "unreadable")

    def test_mobile_provider_hook(self) -> None:
        self.write("phone.ab", adb_backup(self.members))
        records = list(MobileExportProvider().collect(self.root))
        types = [record.artifact_type for record in records]
        self.assertEqual(types.count("android-backup"), 1)
        self.assertEqual(types.count("android-backup-member"), 4)
        self.assertEqual(records[0].details["mobile_acquisition_root_kind"], "android-adb-backup")

    def test_member_parts(self) -> None:
        self.assertEqual(member_parts("apps/a.b/f/x/y.txt"), ("a.b", "f", "x/y.txt"))
        self.assertEqual(member_parts("shared/0/z"), ("", "shared", "0/z"))


class GoogleStubTests(unittest.TestCase):
    def test_stubs_and_drivefs_mime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "Users" / "park" / "Google Drive"
            folder.mkdir(parents=True)
            (folder / "계획.gdoc").write_text(
                json.dumps({"url": "https://docs.google.com/open?id=1AbCdEfGhIjKlMnOp", "doc_id": "1AbCdEfGhIjKlMnOp",
                            "email": "park@example.com", "resource_key": "SECRETRESOURCEKEY"}),
                encoding="utf-8",
            )
            (folder / "표.gsheet").write_text(json.dumps({"doc_id": "1ZyXwVuTsRqPoNmLk", "email": "park@example.com"}), encoding="utf-8")
            (folder / "broken.gslides").write_text("{not json", encoding="utf-8")
            records = list(CloudSyncClientsProvider().collect(root))
        files = {record.details["file_name"]: record.details for record in records if record.artifact_type == "cloud-sync-file"}
        self.assertEqual(set(files), {"계획.gdoc", "표.gsheet"})
        doc = files["계획.gdoc"]
        self.assertEqual((doc["google_doc_type"], doc["actor"]), ("document", "park@example.com"))
        self.assertEqual(doc["google_doc_url"], "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp")
        self.assertEqual(files["표.gsheet"]["google_doc_url"], "https://docs.google.com/spreadsheets/d/1ZyXwVuTsRqPoNmLk")
        self.assertNotIn("SECRETRESOURCEKEY", json.dumps([record.details for record in records], ensure_ascii=False, default=str))
        inventory = [record.details for record in records if record.artifact_type == "cloud-sync-inventory"]
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["inventory_status"], "partial-errors")
        self.assertEqual(google_doc_fields("application/vnd.google-apps.presentation", "1AbCdEfGhIjKlMnOp")["google_doc_type_label"], "Google 프레젠테이션")
        self.assertEqual(google_doc_fields("application/pdf", "x"), {})


class UrlCarvingTests(unittest.TestCase):
    def test_ascii_utf16_dedupe_redaction_and_boundary(self) -> None:
        classes = load_url_classes()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pagefile.sys"
            boundary_url = b"https://mail.naver.com/v2/read/0/123"
            data = bytearray(b"\x00" * (CHUNK_BYTES + 4096))
            data[100:140] = b"GET https://www.google.com/search?q=x\x00\x00"
            utf16 = "https://thepiratebay.org/description.php?id=1".encode("utf-16-le")
            data[1000 : 1000 + len(utf16)] = utf16
            token = b"https://api.example.com/cb?access_token=SECRET123&x=1 "
            data[3000 : 3000 + len(token)] = token
            data[5000:5040] = b"https://www.google.com/search?q=x\x00\x00\x00\x00\x00\x00\x00"
            start = CHUNK_BYTES - 10  # straddles the first window edge
            data[start : start + len(boundary_url)] = boundary_url
            data[7000:7020] = b"http://notahost/\x00\x00\x00\x00"
            path.write_bytes(bytes(data))
            state = UrlCarveState(classes, 100)
            entries, scanned = scan_url_source(path, state=state, read_limit=len(data))
        self.assertEqual(scanned, len(data))
        by_url = {entry["url"]: entry for entry in entries}
        google = by_url["https://www.google.com/search?q=x"]
        self.assertEqual((google["hit_count"], google["url_class"], google["offset"]), (2, "search", 104))
        self.assertEqual(by_url["https://thepiratebay.org/description.php?id=1"]["encoding"], "utf-16le")
        self.assertEqual(by_url["https://thepiratebay.org/description.php?id=1"]["url_class"], "torrent")
        redacted = next(entry for entry in entries if entry["host"] == "api.example.com")
        self.assertNotIn("SECRET123", json.dumps(redacted))
        self.assertTrue(redacted["url_tokens_redacted"])
        boundary = by_url[boundary_url.decode()]
        self.assertEqual((boundary["offset"], boundary["url_class"]), (start, "webmail"))
        self.assertFalse(any(entry["host"] == "notahost" for entry in entries))
        self.assertIsNone(clean_url("https://a/"))
        self.assertEqual(source_kind(Path("pagefile.sys")), "pagefile")
        self.assertIsNone(source_kind(Path("hiberfil.sys")))
        self.assertEqual(source_kind(Path("disk.unalloc")), "unallocated")

    def test_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unallocated.bin"
            path.write_bytes(b" ".join(f"https://host{index}.example.com/p".encode() for index in range(50)))
            state = UrlCarveState(None, 10)
            entries, _scanned = scan_url_source(path, state=state, read_limit=path.stat().st_size)
        self.assertEqual(len(entries), 10)
        self.assertTrue(state.capped)


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class UrlCarveAnalysisTests(unittest.TestCase):
    def test_analysis_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            evidence = base / "evidence"
            evidence.mkdir()
            (evidence / "pagefile.sys").write_bytes(b"\x00" * 64 + b"https://www.google.com/maps/@37.5,127.0,15z " + b"\x00" * 64)
            (evidence / "hiberfil.sys").write_bytes(b"https://never.example.com/")
            (evidence / "notes.txt").write_bytes(b"https://never2.example.com/")
            run_dir = write_run(base, "run", evidence)
            store = RunJobStore()
            run_id = store.import_completed_run(run_dir).run_id
            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
            created = client.post(f"/api/runs/{run_id}/analyses", json={"kind": "url-carve", "options": {}})
            self.assertEqual(created.status_code, 202, created.text)
            analysis_id = created.json()["analysis_id"]
            deadline = time.monotonic() + 20
            while True:
                state = client.get(f"/api/runs/{run_id}/analyses/{analysis_id}").json()
                if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            self.assertEqual(state["status"], "completed", state)
            self.assertEqual(state["summary"]["candidate_count"], 1)
            rows = client.get(f"/api/runs/{run_id}/analyses/{analysis_id}/rows").json()
            bad = client.post(f"/api/runs/{run_id}/analyses", json={"kind": "url-carve", "options": {"sources": ["hiberfil"]}})
        row = rows["rows"][0] if "rows" in rows else rows["records"][0]
        details = row.get("details") or row
        self.assertEqual(row.get("artifact_type"), "carved-url-candidate")
        self.assertEqual((details["source_kind"], details["recovery_method"], details["latitude"]), ("pagefile", "carved-url", 37.5))
        self.assertEqual(bad.status_code, 422)


if __name__ == "__main__":
    unittest.main()
