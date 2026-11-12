"""R8 RI-03: credential / secret files are never served as raw bytes, previews, thumbnails or hashes.

``/source-hex-range``, ``/source-sqlite-table`` and ``/source-sqlite-wal-preview`` already refused a
credential file (``core/credential_files.credential_file_reason``) while ``/source-file`` handed the
same file out as a download. Every source route now refuses it the same way (403, Korean message,
``detail.code = CREDENTIAL_FILE_WITHHELD``); ordinary files are unchanged.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest

TOKEN = "r8-credential-token"
FAKE = "FAKE-R8-CRED-VALUE-0001"
CREDENTIAL_FILES = (
    "Users/alice/.claude/.credentials.json",
    "Users/alice/.ssh/id_rsa",
    "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
    "Users/alice/.claude/oauth-token.png",
)


class CredentialDownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.evidence = base / "evidence"
        self.output = base / "out"
        self.output.mkdir()
        for relative in CREDENTIAL_FILES:
            path = self.evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"token": FAKE}), encoding="utf-8")
        self.normal = self.evidence / "Users/alice/Documents/memo.txt"
        self.normal.parent.mkdir(parents=True, exist_ok=True)
        self.normal.write_text("ordinary memo", encoding="utf-8")
        message = EmailMessage()
        message["Subject"] = "keys"
        message.set_content("see attached")
        message.add_attachment(FAKE.encode(), maintype="application", subtype="octet-stream", filename="id_rsa")
        message.add_attachment(b"hello", maintype="text", subtype="plain", filename="readme.txt")
        self.mail = self.evidence / "Users/alice/mail.eml"
        self.mail.write_bytes(bytes(message))
        store = RunJobStore()
        summary = {"command": "run", "root": str(self.evidence), "output_dir": str(self.output), "outputs": {}}
        store._jobs["r1"] = RunJob(
            run_id="r1", request=RunRequest(root=str(self.evidence), mode="fraud"), status="completed", summary=summary
        )
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)

    def get(self, route: str, path: Path, **params: object):
        return self.client.get(f"/api/runs/r1/{route}", params={"path": str(path), **params})

    def assertRefused(self, response, route: str) -> None:
        self.assertEqual(response.status_code, 403, f"{route}: {response.text}")
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "CREDENTIAL_FILE_WITHHELD", route)
        self.assertIn("자격 증명 파일", detail["message"])
        self.assertTrue(detail["credential_reason"])
        self.assertNotIn(FAKE, response.text)

    def test_every_raw_route_refuses_credential_files(self) -> None:
        routes = (
            ("source-file", {}),
            ("source-thumbnail", {}),
            ("source-hex-range", {}),
            ("source-sqlite-table", {"table": "t"}),
            ("source-sqlite-wal-preview", {}),
            ("source-image-gallery", {}),
            ("source-media-cue", {}),
            ("source-email-attachment", {}),
        )
        for relative in CREDENTIAL_FILES:
            path = self.evidence / relative
            for route, params in routes:
                with self.subTest(file=relative, route=route):
                    self.assertRefused(self.get(route, path, **params), route)

    def test_preview_and_metadata_withhold_body_and_hashes(self) -> None:
        for relative in CREDENTIAL_FILES:
            path = self.evidence / relative
            with self.subTest(file=relative):
                preview = self.get("source-preview", path)
                self.assertEqual(preview.status_code, 200, preview.text)
                self.assertEqual(preview.json()["preview_type"], "withheld")
                self.assertNotIn(FAKE, preview.text)
                metadata = self.get("source-metadata", path, hash="true")
                self.assertEqual(metadata.status_code, 200, metadata.text)
                body = metadata.json()
                self.assertEqual(body["hashes"], {})
                self.assertEqual(body["hash_status"], "withheld")
                self.assertEqual(body["name"], path.name)

    def test_ordinary_file_download_unchanged(self) -> None:
        response = self.get("source-file", self.normal)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, b"ordinary memo")
        metadata = self.get("source-metadata", self.normal, hash="true").json()
        self.assertEqual(metadata["hash_status"], "computed")

    def test_credential_email_attachment_content_withheld(self) -> None:
        secret = self.get("source-email-attachment", self.mail, attachment_index=1, include_content="true")
        self.assertEqual(secret.status_code, 200, secret.text)
        self.assertNotIn(FAKE, secret.text)
        self.assertNotIn("RkFLRS1SOC1DUkVE", secret.text)  # base64 of the fake value
        self.assertIn("withheld-credential-file", secret.text)
        plain = self.get("source-email-attachment", self.mail, attachment_index=2, include_content="true")
        self.assertEqual(plain.status_code, 200, plain.text)
        self.assertIn("included-base64", plain.text)


if __name__ == "__main__":
    unittest.main()
