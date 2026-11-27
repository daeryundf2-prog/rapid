"""ZIP members served read-only by the file routes (``archive.zip::entry``): bytes, ranges, hex,
text, the entry list, and every guard (exact name, traversal, nesting, encryption, size/ratio)."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app

from rapidtriage.core.jobs import RunJobStore

TOKEN = "rapidtriage-test-token"
TEXT_BODY = "첫 줄 evidence line\n" * 40
BINARY_BODY = bytes(range(256)) * 64


def tiny_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00" + b"\xff\x00\x00" * 2 + b"\x00" + b"\x00\x00\xff" * 2)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def write_case(root: Path) -> Path:
    archive_path = root / "case" / "bundle.zip"
    archive_path.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("docs/notes.txt", TEXT_BODY)
        archive.writestr("bin/blob.bin", BINARY_BODY)
        archive.writestr("images/dot.png", tiny_png())
        archive.writestr("Docs/Case.txt", "case-sensitive twin")
        archive.writestr("bomb/zeros.bin", b"\0" * (4 * 1024 * 1024))
        archive.writestr("../escape.txt", "outside")
        archive.writestr("inner.zip", NESTED_ZIP)
        archive.writestr("folder/", "")
        archive.writestr("secret/locked.txt", "flagged as encrypted below")
    mark_encrypted(archive_path, "secret/locked.txt")
    return archive_path


def mark_encrypted(archive_path: Path, name: str) -> None:
    """Set the 'encrypted' flag bit on one member (zipfile cannot write encrypted members)."""
    data = bytearray(archive_path.read_bytes())
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        local_offset = archive.getinfo(name).header_offset
    data[local_offset + 6] |= 0x1
    central = data.find(b"PK\x01\x02")
    while central != -1:
        name_length = struct.unpack_from("<H", data, central + 28)[0]
        if data[central + 46 : central + 46 + name_length] == name.encode():
            data[central + 8] |= 0x1
        central = data.find(b"PK\x01\x02", central + 4)
    archive_path.write_bytes(bytes(data))


def build_nested_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(zipfile.ZipInfo("deep.txt", date_time=(2026, 1, 2, 3, 4, 5)), "second level")
    return buffer.getvalue()


NESTED_ZIP = build_nested_zip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ArchiveEntryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        base = Path(self._temp.name)
        self.root = base / "evidence"
        run_dir = base / "run"
        self.root.mkdir()
        run_dir.mkdir()
        self.archive = write_case(self.root)
        self.outside = base / "outside.zip"
        self.outside.write_bytes(self.archive.read_bytes())
        self.archive_hash = sha256(self.archive)
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "fraud",
                    "root": str(self.root),
                    "output_dir": str(run_dir),
                    "source": {"type": "folder", "source_path": str(self.root), "analysis_root": str(self.root)},
                    "outputs": {"summary": str(summary_path)},
                }
            ),
            encoding="utf-8",
        )
        store = RunJobStore()
        self.run_id = store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def tearDown(self) -> None:
        # Whatever a test asked for, the evidence archive is byte-for-byte untouched.
        self.assertEqual(sha256(self.archive), self.archive_hash)
        self._temp.cleanup()

    def get(self, route: str, path: str, **params: object):
        return self.client.get(f"/api/runs/{self.run_id}/{route}", params={"path": path, **params})

    def entry(self, name: str) -> str:
        return f"case/bundle.zip::{name}"

    def test_source_file_streams_the_member_and_honours_one_range(self) -> None:
        whole = self.get("source-file", self.entry("bin/blob.bin"))
        self.assertEqual(whole.status_code, 200, whole.text)
        self.assertEqual(whole.content, BINARY_BODY)
        self.assertEqual(whole.headers["accept-ranges"], "bytes")
        self.assertIn("blob.bin", whole.headers["content-disposition"])

        ranged = self.client.get(
            f"/api/runs/{self.run_id}/source-file",
            params={"path": self.entry("bin/blob.bin")},
            headers={"Range": "bytes=1000-1099"},
        )
        self.assertEqual(ranged.status_code, 206, ranged.text)
        self.assertEqual(ranged.content, BINARY_BODY[1000:1100])
        self.assertEqual(ranged.headers["content-range"], f"bytes 1000-1099/{len(BINARY_BODY)}")

        suffix = self.client.get(
            f"/api/runs/{self.run_id}/source-file",
            params={"path": self.entry("bin/blob.bin")},
            headers={"Range": "bytes=-16"},
        )
        self.assertEqual(suffix.content, BINARY_BODY[-16:])

        outside = self.client.get(
            f"/api/runs/{self.run_id}/source-file",
            params={"path": self.entry("bin/blob.bin")},
            headers={"Range": f"bytes={len(BINARY_BODY)}-"},
        )
        self.assertEqual(outside.status_code, 416)

    def test_hex_range_text_and_preview_read_the_member(self) -> None:
        hex_range = self.get("source-hex-range", self.entry("bin/blob.bin"), offset=4096, length=32)
        self.assertEqual(hex_range.status_code, 200, hex_range.text)
        payload = hex_range.json()
        self.assertEqual(payload["size"], len(BINARY_BODY))
        self.assertEqual(payload["range_hashes"]["sha256"], hashlib.sha256(BINARY_BODY[4096:4128]).hexdigest())
        self.assertTrue(payload["path"].endswith("bundle.zip::bin/blob.bin"))

        text = self.get("source-text", self.entry("docs/notes.txt"), max_bytes=256)
        self.assertEqual(text.status_code, 200, text.text)
        self.assertTrue(text.json()["text"].startswith("첫 줄 evidence line"))
        self.assertFalse(text.json()["complete"])

        image = self.get("source-preview", self.entry("images/dot.png"))
        self.assertEqual(image.status_code, 200, image.text)
        self.assertEqual(image.json()["preview_type"], "image")
        self.assertEqual(image.json()["container_path"], str(self.archive.resolve()))

        thumbnail = self.get("source-thumbnail", self.entry("images/dot.png"), size=32)
        self.assertEqual(thumbnail.status_code, 200, thumbnail.text)
        self.assertEqual(thumbnail.headers["content-type"], "image/jpeg")

    def test_entry_list_reports_sizes_times_and_refusals(self) -> None:
        response = self.get("source-archive-entries", "case/bundle.zip")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        entries = {entry["name"]: entry for entry in payload["entries"]}
        self.assertEqual(payload["total"], len(entries))
        notes = entries["docs/notes.txt"]
        self.assertEqual(notes["size"], len(TEXT_BODY.encode("utf-8")))
        self.assertLess(notes["compressed_size"], notes["size"])
        self.assertTrue(notes["modified_at"])
        self.assertTrue(notes["openable"])
        self.assertTrue(entries["secret/locked.txt"]["encrypted"])
        self.assertFalse(entries["secret/locked.txt"]["openable"])
        self.assertFalse(entries["bomb/zeros.bin"]["openable"])
        self.assertFalse(entries["../escape.txt"]["openable"])
        self.assertTrue(entries["inner.zip"]["nested_archive"])
        self.assertTrue(entries["folder/"]["is_directory"])

        page = self.get("source-archive-entries", "case/bundle.zip", offset=2, limit=3)
        self.assertEqual([entry["name"] for entry in page.json()["entries"]], [e["name"] for e in payload["entries"][2:5]])
        self.assertTrue(page.json()["has_next"])

    def test_guards_refuse_unsafe_requests(self) -> None:
        cases = {
            "traversal": (self.entry("../escape.txt"), 400, "parent traversal"),
            "absolute": (self.entry("/etc/passwd"), 400, "relative"),
            "missing": (self.entry("docs/absent.txt"), 404, "항목이 없습니다"),
            "case-folded twin": (self.entry("docs/case.txt"), 404, "항목이 없습니다"),
            "encrypted": (self.entry("secret/locked.txt"), 422, "암호화된 ZIP 항목"),
            "zip bomb ratio": (self.entry("bomb/zeros.bin"), 422, "압축 폭탄"),
            "directory": (self.entry("folder/"), 422, "폴더"),
            "nested member": (self.entry("inner.zip::deep.txt"), 422, "한 단계"),
        }
        for label, (path, status, message) in cases.items():
            for route in ("source-file", "source-preview", "source-hex-range", "source-text"):
                with self.subTest(label=label, route=route):
                    response = self.get(route, path)
                    self.assertEqual(response.status_code, status, response.text[:300])
                    self.assertIn(message, json.dumps(response.json(), ensure_ascii=False))

        nested = self.get("source-file", self.entry("inner.zip"))
        self.assertEqual(nested.status_code, 200)
        self.assertEqual(nested.content, NESTED_ZIP)
        nested_list = self.get("source-archive-entries", self.entry("inner.zip"))
        self.assertEqual(nested_list.status_code, 422)

    def test_container_must_be_a_run_source_file(self) -> None:
        # The same allowlist as plain files: a ZIP outside the run's roots is never opened.
        response = self.get("source-file", f"{self.outside}::docs/notes.txt")
        self.assertIn(response.status_code, (403, 404), response.text[:300])
        listing = self.get("source-archive-entries", str(self.outside))
        self.assertIn(listing.status_code, (403, 404), listing.text[:300])


if __name__ == "__main__":
    unittest.main()
