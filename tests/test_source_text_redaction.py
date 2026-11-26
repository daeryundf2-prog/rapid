"""The console's text views get the file's text with secrets masked as in the server preview.

``GET /api/runs/{run}/source-text`` (``runops.build_source_text``) serves the text-prefix view and
"더 보기"; only ``source-file`` (원본 열기) hands out raw bytes.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.runops import build_source_text
from rapidtriage.core.doc_text import (
    decode_text_bytes,
    decode_text_with,
    detect_and_decode_text,
)
from rapidtriage.core.jobs import RunJobStore

HAS_FASTAPI = True
try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from tests.test_rapidtriage_api import api_test_client

# Synthetic BitLocker recovery password: every group is a multiple of 11 and at most 720885.
KEY = "111111-222222-333333-444444-555555-666666-000000-123453"
MASKED = "XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXX53"


def key_digits_shown(text: str) -> bool:
    """Any run of digits from the key other than the two the mask keeps."""
    return bool(re.search(r"\d", text.replace("XXXX53", "")))


class DecodeTextPrefixTests(unittest.TestCase):
    def test_a_complete_read_decodes_as_decode_text_bytes(self) -> None:
        for data in (
            "로그 ok".encode(),
            "한글 ok".encode("cp949"),
            "setup log line 0001".encode("utf-16-le") + b"x",
            "A😀".encode("utf-32"),
            b"a\xf0",
        ):
            with self.subTest(data=data):
                self.assertEqual(detect_and_decode_text(data)[0], decode_text_bytes(data))

    def test_a_character_cut_by_the_cap_is_left_out_without_switching_codec(self) -> None:
        self.assertEqual(detect_and_decode_text("가나".encode()[:5], final=False), ("가", "utf-8"))
        self.assertEqual(detect_and_decode_text("한글".encode("cp949")[:3], final=False), ("한", "cp949"))
        # A complete file that ends in half a character fails both strict codecs, as on the server.
        self.assertEqual(detect_and_decode_text("가나".encode()[:5]), ("가\ufffd", "utf-8"))

    def test_a_longer_read_in_the_prefix_codec_starts_with_the_prefix_text(self) -> None:
        for codec_name in ("utf-8", "cp949", "utf-16", "utf-32"):
            data = ("setup log 0001 한글 줄\r\n" * 40).encode(codec_name)
            for cut in range(1, len(data), 7):
                prefix, codec = detect_and_decode_text(data[:cut], final=False)
                with self.subTest(codec=codec_name, cut=cut):
                    self.assertTrue(decode_text_with(data, codec).startswith(prefix))


class BuildSourceTextTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, name: str, text: str, encoding: str = "utf-8") -> Path:
        path = self.root / name
        path.write_text(text, encoding=encoding)
        return path

    def test_masks_a_recovery_key_and_says_so(self) -> None:
        for encoding in ("utf-8", "utf-16", "cp949"):
            with self.subTest(encoding=encoding):
                payload = build_source_text(self.write("notes.txt", f"복구 키\n{KEY}\n끝\n", encoding))
                self.assertEqual(payload["text"], f"복구 키\n{MASKED}\n끝\n")
                self.assertTrue(payload["redacted"])
                self.assertTrue(payload["complete"])

    def test_plain_text_is_unchanged_and_not_marked(self) -> None:
        payload = build_source_text(self.write("plain.log", "a,b\n1,2\n"))
        self.assertEqual(payload["text"], "a,b\n1,2\n")
        self.assertFalse(payload["redacted"])

    def test_a_key_the_cap_cuts_in_two_never_shows_in_part(self) -> None:
        for before in range(40, 101):
            path = self.write("cut.log", "x" * before + KEY + "\n" + "y" * 500)
            payload = build_source_text(path, max_bytes=100)
            with self.subTest(before=before):
                self.assertFalse(payload["complete"])
                self.assertFalse(key_digits_shown(payload["text"]), payload["text"])
                self.assertLessEqual(len(payload["text"]), 100)
                if before + len(KEY) > 100 and before < 100:
                    self.assertTrue(payload["redacted"])
                    self.assertEqual(payload["text"], "x" * before)

    def test_a_key_past_the_cap_is_not_read_into_the_text(self) -> None:
        payload = build_source_text(self.write("later.log", "a" * 300 + KEY), max_bytes=100)
        self.assertEqual(payload["text"], "a" * 100)
        self.assertFalse(payload["redacted"])
        self.assertEqual(payload["bytes_read"], 100)

    def test_a_private_key_block_cut_by_the_cap_is_masked(self) -> None:
        body = "pre\n-----BEGIN RSA PRIVATE KEY-----\n" + "QUJD" * 200 + "\n-----END RSA PRIVATE KEY-----\npost"
        payload = build_source_text(self.write("deploy.txt", body), max_bytes=80)
        self.assertEqual(payload["text"], "pre\n[RSA PRIVATE KEY — 본문 저장하지 않음]")
        self.assertNotIn("QUJD", payload["text"])
        self.assertTrue(payload["redacted"])

    def test_a_secret_store_is_withheld(self) -> None:
        payload = build_source_text(self.write("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"))
        self.assertNotIn("abc", payload["text"])
        self.assertTrue(payload["redacted"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ConsoleTextViewRedactionTests(unittest.TestCase):
    """A synthetic BitLocker key in a text file is masked in every console text view."""

    def test_every_text_view_masks_the_key_and_only_source_file_is_raw(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            run_dir = Path(temp) / "run"
            root.mkdir()
            run_dir.mkdir()
            (root / "notes.txt").write_text(f"복구 키\n{KEY}\n", encoding="utf-8")
            # Past the preview's 20000 characters: the console offers 더 보기 for the rest.
            (root / "long.txt").write_text("줄\n" * 15000 + f"{KEY}\n", encoding="utf-8")
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(root),
                        "output_dir": str(run_dir),
                        "source": {"type": "folder", "source_path": str(root), "analysis_root": str(root)},
                        "outputs": {"summary": str(summary_path)},
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            run_id = store.import_completed_run(run_dir).run_id
            client = api_test_client(store)

            def get(route: str, path: str, **params: object) -> dict[str, object]:
                response = client.get(f"/api/runs/{run_id}/{route}", params={"path": path, **params})
                self.assertEqual(response.status_code, 200, response.text)
                return response.json()

            preview = get("source-preview", "notes.txt")
            self.assertIn(MASKED, preview["text"])
            self.assertTrue(get("source-preview", "long.txt")["truncated"])

            for path, params in (
                ("notes.txt", {}),  # the text-prefix view
                ("long.txt", {}),  # 더 보기
                ("long.txt", {"max_bytes": 60_020}),  # the 2 MB cap cutting the key
            ):
                with self.subTest(path=path, params=params):
                    payload = get("source-text", path, **params)
                    self.assertNotIn(KEY, payload["text"])
                    self.assertFalse(key_digits_shown(payload["text"].replace("줄", "")))
                    self.assertTrue(payload["redacted"])

            raw = client.get(f"/api/runs/{run_id}/source-file", params={"path": "notes.txt"})
            self.assertIn(KEY, raw.content.decode("utf-8"))

            too_large = client.get(
                f"/api/runs/{run_id}/source-text", params={"path": "notes.txt", "max_bytes": 3 * 1024 * 1024}
            )
            self.assertEqual(too_large.status_code, 422)


if __name__ == "__main__":
    unittest.main()
