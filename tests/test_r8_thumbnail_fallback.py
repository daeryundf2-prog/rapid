"""R8 T-018: an image that does not decode is "no preview" (204), not an English 415.

Deleted, zero-filled or truncated pictures (IMG-A: recovered ICO files; IMG-B: 25 console 415s)
used to answer ``415 source file could not be decoded as an image`` and the grid drew blank
tiles. The thumbnail route now answers ``204 No Content`` with ``X-RapidTriage-Thumbnail:
unavailable`` (the T-017 front-end contract), logs one line without the path, writes no cache
file, and still refuses credential files first. A file that is not an image type at all keeps
its 415, with the Korean error envelope.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest

try:
    from PIL import Image
except ModuleNotFoundError:  # pragma: no cover - Pillow is optional for the server
    Image = None  # type: ignore[assignment]

TOKEN = "r8-thumbnail-token"
THUMBNAIL_LOGGER = "rapidtriage.api.app.thumbnail"


def _jpeg_bytes() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (640, 320), (200, 40, 40)).save(out, format="JPEG")
    return out.getvalue()


def _png_bytes() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (300, 300), (10, 120, 200)).save(out, format="PNG")
    return out.getvalue()


@unittest.skipIf(Image is None, "Pillow is required for thumbnail tests")
class ThumbnailFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.evidence = base / "evidence" / "비밀폴더"
        self.evidence.mkdir(parents=True)
        self.output = base / "out"
        self.output.mkdir()
        store = RunJobStore()
        summary = {"command": "run", "root": str(self.evidence), "output_dir": str(self.output), "outputs": {}}
        store._jobs["r1"] = RunJob(
            run_id="r1", request=RunRequest(root=str(self.evidence), mode="fraud"), status="completed", summary=summary
        )
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)

    def write(self, name: str, data: bytes) -> Path:
        path = self.evidence / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def thumb(self, path: Path, size: int = 128):
        return self.client.get("/api/runs/r1/source-thumbnail", params={"path": str(path), "size": size})

    def cache_files(self) -> list[Path]:
        return sorted((self.output / "thumbs").glob("*")) if (self.output / "thumbs").is_dir() else []

    def broken_fixtures(self) -> dict[str, bytes]:
        jpeg = _jpeg_bytes()
        return {
            "깨진헤더.jpg": b"\xff\xd8\xff\xe0" + b"\x00garbage-not-a-jpeg" * 8,
            "zero-filled.gif": b"\x00" * 4096,
            "truncated.jpg": jpeg[: len(jpeg) // 3],
            "truncated.png": _png_bytes()[:120],
            "100365-lync.ico": b"\x00" * 2048,
            "short-header.ico": b"\x00\x00\x01\x00\x05\x00",
        }

    def test_undecodable_images_answer_204_with_unavailable_header(self) -> None:
        for name, data in self.broken_fixtures().items():
            path = self.write(name, data)
            with self.subTest(file=name), self.assertLogs(THUMBNAIL_LOGGER, level="WARNING") as logs:
                response = self.thumb(path)
                self.assertEqual(response.status_code, 204, response.text)
                self.assertEqual(response.headers["x-rapidtriage-thumbnail"], "unavailable")
                self.assertEqual(response.content, b"")
                self.assertNotIn("decoded", response.text)
                # Exactly one log line: extension and size, never the path or the file name.
                self.assertEqual(len(logs.records), 1, logs.output)
                line = logs.output[0]
                self.assertIn(f"ext={path.suffix.lower()}", line)
                self.assertIn(f"bytes={len(data)}", line)
                self.assertNotIn(path.stem, line)
                self.assertNotIn(str(self.evidence), line)
                self.assertNotIn("비밀폴더", line)
        self.assertEqual(self.cache_files(), [], "an undecodable image must not leave a cache file")

    def test_valid_images_still_return_identical_jpeg_bytes(self) -> None:
        from rapidtriage.api.app.thumbnail import (
            render_thumbnail_jpeg,
            thumbnail_cache_path,
        )

        photo = self.write("photo.jpg", _jpeg_bytes())
        response = self.thumb(photo)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"], "image/jpeg")
        self.assertNotIn("x-rapidtriage-thumbnail", response.headers)
        self.assertEqual(response.content, render_thumbnail_jpeg(photo, 128))
        cached = thumbnail_cache_path(self.output, photo.resolve(), 128)
        self.assertEqual(cached.read_bytes(), response.content, "cache location and name are unchanged")

    def test_ico_files_decode_to_a_thumbnail(self) -> None:
        icon = self.evidence / "app.ico"
        Image.new("RGBA", (48, 48), (20, 160, 20, 128)).save(icon, format="ICO", sizes=[(16, 16), (48, 48)])
        bmp_icon = self.evidence / "OLD.ICO"
        Image.new("RGB", (32, 32), (1, 2, 3)).save(bmp_icon, format="ICO", bitmap_format="bmp")
        for path in (icon, bmp_icon):
            with self.subTest(file=path.name):
                response = self.thumb(path, size=64)
                self.assertEqual(response.status_code, 200, response.text)
                with Image.open(io.BytesIO(response.content)) as thumb:
                    self.assertEqual(thumb.format, "JPEG")

    def test_non_image_type_keeps_415_with_korean_envelope(self) -> None:
        notes = self.write("notes.txt", b"not an image")
        response = self.thumb(notes)
        self.assertEqual(response.status_code, 415)
        body = response.json()
        self.assertEqual(body["code"], "UNSUPPORTED_MEDIA")
        self.assertRegex(body["message"], "[가-힣]")

    def test_read_only_run_writes_nothing_for_good_or_broken_images(self) -> None:
        photo = self.write("photo.jpg", _jpeg_bytes())
        broken = self.write("broken.gif", b"\x00" * 512)
        with patch("rapidtriage.api.app.routes_media.may_persist", return_value=False):
            good = self.thumb(photo)
            with self.assertLogs(THUMBNAIL_LOGGER, level="WARNING"):
                bad = self.thumb(broken)
        self.assertEqual(good.status_code, 200)
        self.assertEqual(good.headers["content-type"], "image/jpeg")
        self.assertEqual(bad.status_code, 204)
        self.assertEqual(bad.headers["x-rapidtriage-thumbnail"], "unavailable")
        self.assertFalse((self.output / "thumbs").exists(), "a read-only run folder stays untouched")

    def test_credential_file_is_refused_before_decoding(self) -> None:
        secret = self.write("Users/alice/.claude/oauth-token.png", b'{"token": "FAKE-T018"}')
        response = self.thumb(secret)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["code"], "CREDENTIAL_FILE_WITHHELD")
        self.assertNotIn("x-rapidtriage-thumbnail", response.headers)


if __name__ == "__main__":
    unittest.main()
