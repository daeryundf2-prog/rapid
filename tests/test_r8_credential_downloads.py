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
import zipfile
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.credential_files import credential_file_reason
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


#: T-347: 20 synthetic credential files (one per rule family, image extensions included), placed
#: below ``Users/alice``. Every one is generated at test time with a fake value — never a real key.
GRID_CREDENTIAL_FILES = (
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    "certs/server.pem",
    "certs/tls.key",
    ".netrc",
    ".pypirc",
    ".git-credentials",
    ".docker/config.json",
    ".azure/msal_token_cache.json",
    "AppData/Local/github-copilot/hosts.json",
    "AppData/Local/Google/Chrome/User Data/Default/Login Data",
    "AppData/Local/Google/Chrome/User Data/Default/Cookies",
    "AppData/Local/Google/Chrome/User Data/Default/Web Data",
    ".sandbox-secrets/vault.bin",
    ".aws/credentials",
    ".claude/oauth-token.png",
    ".gemini/oauth_creds.json",
    ".codex/session-token.jpg",
)
#: 20 ordinary files (some look "secret-ish" but fall outside the rule) that stay 200.
GRID_ORDINARY_FILES = tuple(f"Documents/note-{index:02d}.txt" for index in range(16)) + (
    "Documents/secret plan.txt",
    ".claude/settings.json",
    ".claude/screenshot.png",
    "Pictures/photo.png",
)
#: The 9 route groups of the grid (each group's routes must all refuse for a cell to pass).
GRID_GROUPS = (
    "source-file",
    "thumbnail",
    "hex",
    "sqlite",
    "email-attachment",
    "gallery-media",
    "ocr",
    "archive-member",
    "outputs-file",
)


def fake_value(index: int) -> str:
    return f"FAKE-T347-CRED-{index:02d}-NOT-A-SECRET"


def make_client(evidence: Path, output: Path, outputs: dict[str, str]) -> TestClient:
    store = RunJobStore()
    summary = {"command": "run", "root": str(evidence), "output_dir": str(output), "outputs": outputs}
    store._jobs["r1"] = RunJob(
        run_id="r1", request=RunRequest(root=str(evidence), mode="fraud"), status="completed", summary=summary
    )
    return TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})


class CredentialGridTests(unittest.TestCase):
    """T-347 acceptance: 9 route groups x 20 credential files = 180 cells, every cell 403
    ``CREDENTIAL_FILE_WITHHELD`` with none of the file's bytes in the body; ordinary files 200."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.evidence = base / "evidence"
        output = base / "out"
        self.home = self.evidence / "Users" / "alice"
        self.home.mkdir(parents=True)
        self.archive = self.home / "backup.zip"
        self.credential_paths: list[Path] = []
        outputs: dict[str, str] = {}
        with zipfile.ZipFile(self.archive, "w") as archive:
            for index, relative in enumerate(GRID_CREDENTIAL_FILES):
                body = json.dumps({"token": fake_value(index)}).encode()
                path = self.home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
                self.credential_paths.append(path)
                archive.writestr(relative, body)
                copied = output / "extract" / "pick" / "Users" / "alice" / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(body)
                outputs[f"cred_{index:02d}"] = str(copied)
            for index, relative in enumerate(GRID_ORDINARY_FILES):
                path = self.home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"ordinary file {index}", encoding="utf-8")
                archive.writestr(relative, f"ordinary file {index}")
        report = output / "report_ok.json"
        report.write_text(json.dumps({"ok": True}), encoding="utf-8")
        outputs["report_ok"] = str(report)
        for index, path in enumerate(self.credential_paths):
            self.assertTrue(credential_file_reason(path), f"fixture {index} must be a credential file: {path}")
        for relative in GRID_ORDINARY_FILES:
            self.assertEqual(credential_file_reason(self.home / relative), "", relative)
        self.client = make_client(self.evidence, output, outputs)
        self.addCleanup(self.client.close)

    def source(self, route: str, path: str, **params: object):
        return self.client.get(f"/api/runs/r1/{route}", params={"path": path, **params})

    def group_requests(self, group: str, index: int) -> list:
        path = str(self.credential_paths[index])
        if group == "source-file":
            return [self.source("source-file", path)]
        if group == "thumbnail":
            return [self.source("source-thumbnail", path)]
        if group == "hex":
            return [self.source("source-hex-range", path)]
        if group == "sqlite":
            return [self.source("source-sqlite-table", path, table="t"), self.source("source-sqlite-wal-preview", path)]
        if group == "email-attachment":
            return [self.source("source-email-attachment", path, include_content="true")]
        if group == "gallery-media":
            return [self.source("source-image-gallery", path), self.source("source-media-cue", path)]
        if group == "ocr":
            return [self.source("source-ocr-queue", path), self.source("source-ocr-translation", path)]
        if group == "archive-member":
            member = f"{self.archive}::{GRID_CREDENTIAL_FILES[index]}"
            # source-search applies the same member judgment as the preview (review WB-10/11 P2-8).
            return [self.source("source-preview", member), self.source("source-search", member, keyword="secret")]
        if group == "outputs-file":
            name = f"cred_{index:02d}"
            return [
                self.client.get(f"/api/runs/r1/outputs/{name}/file"),
                self.client.get(f"/api/runs/r1/outputs/{name}/preview"),
            ]
        raise AssertionError(group)

    def cell_refused(self, responses: list, index: int) -> bool:
        secret = fake_value(index).encode()
        for response in responses:
            if response.status_code != 403 or secret in response.content:
                return False
            detail = response.json().get("detail")
            if not isinstance(detail, dict) or detail.get("code") != "CREDENTIAL_FILE_WITHHELD":
                return False
            if set(detail) != {"code", "message", "credential_reason"}:
                return False  # no OCR text, rows, hex or hashes ride along with the refusal
        return True

    def test_180_cells_refused_with_zero_body_bytes(self) -> None:
        failures = []
        refused = 0
        for group in GRID_GROUPS:
            for index in range(len(GRID_CREDENTIAL_FILES)):
                if self.cell_refused(self.group_requests(group, index), index):
                    refused += 1
                else:
                    failures.append(f"{group} x {GRID_CREDENTIAL_FILES[index]}")
        self.assertEqual(failures, [])
        self.assertEqual(refused, 180)

    def test_ordinary_files_unchanged(self) -> None:
        served = 0
        for index, relative in enumerate(GRID_ORDINARY_FILES):
            response = self.source("source-file", str(self.home / relative))
            self.assertEqual(response.status_code, 200, f"{relative}: {response.text}")
            self.assertEqual(response.content, f"ordinary file {index}".encode())
            served += 1
        self.assertEqual(served, 20)
        member = self.source("source-preview", f"{self.archive}::Documents/note-00.txt")
        self.assertEqual(member.status_code, 200, member.text)
        searched = self.source("source-search", f"{self.archive}::Documents/note-00.txt", keyword="ordinary")
        self.assertEqual(searched.status_code, 200, searched.text)
        self.assertIn("ordinary file 0", member.text)
        report = self.client.get("/api/runs/r1/outputs/report_ok/file")
        self.assertEqual(report.status_code, 200, report.text)
        self.assertEqual(report.json(), {"ok": True})

    def test_image_named_credential_file_yields_zero_ocr_characters(self) -> None:
        index = GRID_CREDENTIAL_FILES.index(".claude/oauth-token.png")
        image = self.credential_paths[index]
        # A sidecar next to it (as an OCR engine would leave one): still nothing comes out.
        image.with_name(f"{image.name}.ocr.txt").write_text(fake_value(index), encoding="utf-8")
        for route in ("source-ocr-translation", "source-ocr-queue"):
            with self.subTest(route=route):
                response = self.source(route, str(image))
                self.assertEqual(response.status_code, 403, response.text)
                self.assertNotIn(fake_value(index), response.text)
                self.assertNotIn("text", response.json()["detail"])
        # A queue anchored on an ordinary image in the same folder never lists the credential image.
        queue = self.source("source-ocr-queue", str(self.home / ".claude/screenshot.png"))
        self.assertEqual(queue.status_code, 200, queue.text)
        names = [item["source_name"] for item in queue.json()["items"]]
        self.assertIn("screenshot.png", names)
        self.assertNotIn("oauth-token.png", names)
        self.assertNotIn(fake_value(index), queue.text)
        preview = self.source("source-preview", str(image))
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["preview_type"], "withheld")
        self.assertNotIn(fake_value(index), preview.text)


class PrePolicyExtractZipTests(unittest.TestCase):
    """T-347: an extract zip written before the credential policy (no marker) is never served."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        evidence = base / "evidence"
        evidence.mkdir()
        output = base / "out"
        folder = output / "extract" / "legacy"
        (folder / "Users/alice/.ssh").mkdir(parents=True)
        (folder / "Users/alice/.ssh/id_rsa").write_text(FAKE, encoding="utf-8")
        (folder / "Users/alice/memo.txt").write_text("ordinary memo", encoding="utf-8")
        (folder / "rapidtriage-extract-manifest.json").write_text(
            json.dumps({"summary": {"extracted_count": 2}}), encoding="utf-8"
        )
        self.archive = output / "extract" / "legacy.zip"
        with zipfile.ZipFile(self.archive, "w") as legacy:  # the pre-policy zip: credential inside
            legacy.writestr("Users/alice/.ssh/id_rsa", FAKE)
            legacy.writestr("Users/alice/memo.txt", "ordinary memo")
        self.client = make_client(evidence, output, {})
        self.addCleanup(self.client.close)

    def extract_entry(self) -> dict:
        exports = self.client.get("/api/runs/r1/dashboard").json()["exports"]
        return next(item for item in exports if item["type"] == "extract")

    def test_pre_policy_zip_is_not_reused(self) -> None:
        refused = self.client.get("/api/runs/r1/extract/legacy/file")
        self.assertEqual(refused.status_code, 404, refused.text)
        self.assertEqual(refused.json()["detail"]["code"], "EXPORT_NOT_WRITTEN")
        self.assertNotIn(FAKE.encode(), refused.content)
        entry = self.extract_entry()
        self.assertEqual(entry["build_url"], "/api/runs/r1/extract/legacy/zip")
        self.assertEqual(entry["status"], "zip 다시 만들기 필요")

        rebuilt = self.client.post("/api/runs/r1/extract/legacy/zip")
        self.assertEqual(rebuilt.status_code, 200, rebuilt.text)
        self.assertEqual(rebuilt.json()["status"], "written")
        self.assertEqual(rebuilt.json()["skipped_credential_files"], 1)
        served = self.client.get("/api/runs/r1/extract/legacy/file")
        self.assertEqual(served.status_code, 200, served.text)
        self.assertNotIn(FAKE.encode(), served.content)
        with zipfile.ZipFile(self.archive) as bundle:
            self.assertNotIn("Users/alice/.ssh/id_rsa", bundle.namelist())
            self.assertIn("Users/alice/memo.txt", bundle.namelist())
        again = self.client.post("/api/runs/r1/extract/legacy/zip")
        self.assertEqual(again.json()["status"], "exists")
        entry = self.extract_entry()
        self.assertIsNone(entry["build_url"])
        self.assertEqual(entry["status"], "zip 준비됨")


if __name__ == "__main__":
    unittest.main()
