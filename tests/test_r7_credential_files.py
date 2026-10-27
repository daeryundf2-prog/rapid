"""R7 fix: credential / secret files never have their bodies indexed, extracted or previewed.

A synthetic home tree (the ``test_ai_agents_presence`` Windows builder plus the general credential
file list) runs through ``run --mode seizure``; the whole output folder, every case DB table and a
scratch v4 search index must hold none of the fake token values, while a name search still finds
the files and ordinary JSON documents stay indexed.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.core.credential_files import (
    BODY_WITHHELD,
    CREDENTIAL_FILE_RECORD_TYPE,
    credential_file_reason,
    redact_credential_text,
)
from tests.test_ai_agents_presence import SECRET_VALUES, build_windows_image, write

NORMAL_VALUE = "NORMALDOCVALUE0099"
FAKE_VALUES = {
    "Users/alice/.netrc": ("machine h login u password {}", "FAKE-NETRC-0006"),
    "Users/alice/.pypirc": ("[pypi]\nusername=__token__\npassword={}\n", "FAKE-PYPIRC-0008"),
    "Users/alice/.git-credentials": ("https://u:{}@github.com\n", "FAKE-GITCRED-0009"),
    "Users/alice/.aws/credentials": ("[default]\naws_secret_access_key={}\n", "FAKE-AWS-0010"),
    "Users/alice/.azure/msal_token_cache.json": ('{{"AccessToken": "{}"}}', "FAKE-AZURE-0011"),
    "Users/alice/.docker/config.json": ('{{"auths": {{"x": {{"auth": "{}"}}}}}}', "FAKE-DOCKER-0012"),
    "Users/alice/keys/server.pem": ("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", "FAKE-PEM-0013"),
    "Users/alice/.ssh/id_rsa": ("{}", "FAKE-IDRSA-0014"),
    "Users/alice/keys/private.key": ("{}", "FAKE-KEY-0015"),
    "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Web Data": ("{}", "FAKE-WEBDATA-0016"),
    "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data": ("{}", "FAKE-LOGINDATA-0022"),
    "Users/alice/.gemini/jetski-standalone-oauth-token": ("{}", "FAKE-JETSKI-0017"),
    "Users/alice/.codex/.sandbox-secrets/s.json": ('{{"k": "{}"}}', "FAKE-SANDBOX-0018"),
    "Users/alice/.codex/mcp-oauth-locks/l.json": ('{{"k": "{}"}}', "FAKE-MCPLOCK-0019"),
    "Users/alice/.claude/buddy-tokens.json": ('{{"k": "{}"}}', "FAKE-BUDDY-0020"),
    "Users/alice/credentials.json": ('{{"client_secret": "{}"}}', "FAKE-GCRED-0021"),
    "Users/alice/.claude/oauth-cache.json": ('{{"refresh": "{}"}}', "FAKE-AIOAUTH-0023"),
    "Users/alice/.config/pip/pip.ini": ("[global]\nindex-url = https://user:{}@pypi.example/simple\n", "FAKE-PIPINI-0024"),
}
NPMRC_VALUE = "FAKE-NPMRC-0007"
ALL_FAKES = (*SECRET_VALUES, NPMRC_VALUE, *(value for _template, value in FAKE_VALUES.values()))


def build_credential_tree(root: Path) -> None:
    build_windows_image(root)
    for relative, (template, value) in FAKE_VALUES.items():
        write(root / relative, template.format(value))
    write(root / "Users/alice/.npmrc", f"//registry.npmjs.org/:_authToken={NPMRC_VALUE}\nregistry=https://registry.npmjs.org/\n")
    write(root / "Users/alice/Documents/notes.json", json.dumps({"memo": NORMAL_VALUE}))
    write(root / "Users/alice/Documents/secret plan.txt", f"plan {NORMAL_VALUE}")


def fake_hits_in_files(folder: Path) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for value in ALL_FAKES:
            if value.encode() in data or value.encode("utf-16-le") in data:
                hits.setdefault(value, []).append(str(path.relative_to(folder)))
    return hits


def fake_hits_in_db(path: Path) -> dict[str, list[str]]:
    hits: dict[str, set[str]] = {}
    from rapidtriage.core.case_db.schema import register_case_db_functions

    connection = sqlite3.connect(path)
    register_case_db_functions(connection)  # the compressed-artifact view decodes blobs with these
    try:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")]
        for table in tables:
            for row in connection.execute(f'SELECT * FROM "{table}"'):
                text = " ".join(item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item) for item in row)
                for value in ALL_FAKES:
                    if value in text:
                        hits.setdefault(value, set()).add(table)
    finally:
        connection.close()
    return {value: sorted(tables) for value, tables in hits.items()}


class CredentialFileClassificationTest(unittest.TestCase):
    def test_reasons(self) -> None:
        cases = {
            "C:/Users/a/.claude/.credentials.json": "catalog-credential",
            "/home/b/.codex/auth.json": "catalog-credential",
            "C:/Users/a/.codex/mcp-oauth-locks/l.json": "catalog-credential",
            "C:/Users/a/.openclaw/credentials/x.json": "catalog-credential",
            "C:/Users/a/.cache/huggingface/token": "catalog-credential",
            "C:/Users/a/.codex/.sandbox-secrets/s.json": "credential-folder",
            "C:/Users/a/.netrc": "credential-name",
            "C:/Users/a/.git-credentials": "credential-name",
            "C:/Users/a/.aws/credentials": "credential-name",
            "C:/Users/a/.azure/accessTokens.json": "credential-name",
            "C:/Users/a/.docker/config.json": "credential-name",
            "C:/Users/a/.claude/buddy-tokens.json": "credential-name",
            "C:/Users/a/.gemini/jetski-standalone-oauth-token": "credential-name",
            "secret:github": "credential-name",
            "C:/U/a/AppData/Local/Google/Chrome/User Data/Default/Login Data": "browser-credential-store",
            "C:/U/a/AppData/Local/Google/Chrome/User Data/Default/Cookies": "browser-credential-store",
            "C:/U/a/AppData/Local/Google/Chrome/User Data/Default/Web Data": "browser-credential-store",
            "D:/keys/server.pem": "private-key",
            "C:/Users/a/.ssh/id_ed25519": "private-key",
            "C:/Users/a/.claude/oauth-cache.json": "ai-tool-credential-name",
        }
        for path, reason in cases.items():
            self.assertEqual(credential_file_reason(path, sniff=False), reason, path)
        for path in (
            "C:/Users/a/Documents/secret plan.docx",  # broad name rule only inside AI tool folders
            "C:/Users/a/Documents/notes.json",
            "C:/Users/a/.claude/settings.json",
            "C:/Users/a/.claude/tokenizer.json",
            "C:/Users/a/.npmrc",  # kept, values masked
            "C:/Users/a/.docker/daemon.json",
        ):
            self.assertEqual(credential_file_reason(path, sniff=False), "", path)

    def test_keynote_key_is_not_a_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            keynote = Path(temp) / "deck.key"
            with zipfile.ZipFile(keynote, "w") as archive:
                archive.writestr("Index.zip", b"x")
            private = Path(temp) / "server.key"
            private.write_text("-----BEGIN PRIVATE KEY-----\nx\n", encoding="utf-8")
            self.assertEqual(credential_file_reason(keynote), "")
            self.assertEqual(credential_file_reason(private), "private-key")

    def test_npmrc_values_masked(self) -> None:
        text = f"//registry.npmjs.org/:_authToken={NPMRC_VALUE}\n_auth=dXNlcjpwYXNz\nalways-auth=true\nregistry=https://u:pw@h/\n"
        masked = redact_credential_text(Path("C:/Users/a/.npmrc"), text)
        self.assertNotIn(NPMRC_VALUE, masked)
        self.assertNotIn("dXNlcjpwYXNz", masked)
        self.assertNotIn("u:pw@", masked)
        self.assertIn("always-auth=true", masked)
        self.assertEqual(redact_credential_text(Path("memo.txt"), "password=1234"), "password=1234")


class CredentialFilePipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from rapidtriage.core.run import run_triage_mode
        from rapidtriage.core.search_index.build import build_search_index

        cls._temp = tempfile.TemporaryDirectory()
        base = Path(cls._temp.name)
        cls.root = base / "ev"
        cls.out = base / "out"
        cls.index = base / "scratch-v4.db"
        build_credential_tree(cls.root)
        cls.summary = run_triage_mode(cls.root, mode="seizure", output_dir=cls.out, read_only=True)
        build_search_index(cls.out, cls.summary, run_id="cred", index_path=cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp.cleanup()

    def test_no_fake_value_in_output_folder(self) -> None:
        self.assertEqual(fake_hits_in_files(self.out), {})

    def test_no_fake_value_in_any_case_db_table(self) -> None:
        self.assertEqual(fake_hits_in_db(self.out / "rapidtriage-case.db"), {})

    def test_no_fake_value_in_v4_index(self) -> None:
        self.assertEqual(fake_hits_in_db(self.index), {})
        data = self.index.read_bytes()
        for value in ALL_FAKES:
            self.assertNotIn(value.encode(), data, value)

    def test_unified_search_finds_name_not_value(self) -> None:
        from rapidtriage.core.search import run_unified_search

        by_name = run_unified_search(self.summary, ["credentials.json"])
        documents = {Path(str(match.get("path"))).name for match in by_name["matches"] if match.get("source") == "documents"}
        self.assertIn(".credentials.json", documents)
        for value in (SECRET_VALUES[0], "FAKE-GCRED-0021", "FAKE-DOCKER-0012"):
            self.assertEqual(run_unified_search(self.summary, [value])["matches"], [], value)

    def test_name_in_case_db_and_v4(self) -> None:
        connection = sqlite3.connect(self.out / "rapidtriage-case.db")
        try:
            count = connection.execute(
                "SELECT count(*) FROM indexed_document_fts WHERE indexed_document_fts MATCH '\"credentials\"'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertGreaterEqual(count, 2)
        connection = sqlite3.connect(self.index)
        try:
            rows = connection.execute("SELECT text FROM search_doc WHERE path_fold LIKE '%/.claude/.credentials.json'").fetchall()
        finally:
            connection.close()
        self.assertTrue(rows)

    def test_normal_json_document_still_indexed(self) -> None:
        connection = sqlite3.connect(self.out / "rapidtriage-case.db")
        try:
            bodies = connection.execute("SELECT count(*) FROM indexed_document WHERE body LIKE ?", (f"%{NORMAL_VALUE}%",)).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(bodies, 2)  # notes.json + "secret plan.txt" (outside AI tool folders)
        connection = sqlite3.connect(self.index)
        try:
            self.assertGreaterEqual(connection.execute("SELECT count(*) FROM search_doc WHERE text LIKE ?", (f"%{NORMAL_VALUE}%",)).fetchone()[0], 2)
        finally:
            connection.close()
        index = json.loads((self.out / "rapidtriage-docs-index.json").read_text(encoding="utf-8"))
        self.assertIn(NORMAL_VALUE.casefold(), index["terms"])

    def test_docs_rows_and_run_disclosure(self) -> None:
        docs = json.loads((self.out / "rapidtriage-docs.json").read_text(encoding="utf-8"))
        rows = docs["credential_files"]
        names = {Path(row["path"]).name for row in rows}
        self.assertTrue(
            {".credentials.json", "auth.json", ".netrc", "id_rsa", "Web Data", "Login Data", "config.json", "token"} <= names, names
        )
        self.assertNotIn(".npmrc", names)
        for row in rows:
            self.assertEqual(row["record_type"], CREDENTIAL_FILE_RECORD_TYPE)
            self.assertEqual(row["coverage_status"], BODY_WITHHELD)
            self.assertTrue(row["reason"])
            self.assertIn("size", row)
            self.assertIn("modified_at", row)
        candidate = next(item for item in docs["candidates"] if item["path"].endswith(".credentials.json"))
        self.assertEqual(candidate["text_status"], BODY_WITHHELD)
        count = docs["summary"]["credential_files"]["count"]
        self.assertEqual(count, len(rows))
        note = f"자격 증명 파일 {count}건 — 본문 미수집"
        self.assertEqual(self.summary["disclosures"]["credential_files"]["note"], note)
        docs_step = next(step for step in self.summary["steps"] if step["name"] == "docs")
        self.assertIn(note, docs_step["warning_messages"])
        self.assertIn(note, (self.out / "rapidtriage-run-report.md").read_text(encoding="utf-8"))


class CredentialFileExtractAndViewerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.base = Path(self._temp.name)
        self.root = self.base / "ev"
        build_credential_tree(self.root)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_docs_and_files_extract_skip_credential_files(self) -> None:
        from rapidtriage.core.docs import run_docs_search
        from rapidtriage.core.extract import run_extract

        payload = run_docs_search(self.root, ["x"])
        # docs-extract copies ``results``: offer every credential file plus one ordinary document.
        payload["results"] = [{"path": item["path"], "kind": "json"} for item in payload["credential_files"]]
        payload["results"].append({"path": str(self.root / "Users/alice/Documents/notes.json"), "kind": "json"})
        result = run_extract(self.base / "docs.json", self.base / "extract", payload=payload)
        skipped = {Path(str(entry["original_path"])).name: entry for entry in result["skipped"]}
        self.assertEqual(len(skipped), len(payload["credential_files"]))
        for name in (".credentials.json", "auth.json", "credentials.json", "Web Data"):
            self.assertEqual(skipped[name]["reason"], "credential-file", name)
            self.assertEqual(skipped[name]["coverage_status"], BODY_WITHHELD)
            self.assertNotIn("sha256", skipped[name])
        self.assertEqual(fake_hits_in_files(self.base / "extract"), {})
        extracted = {Path(str(entry["original_path"])).name for entry in result["entries"]}
        self.assertIn("notes.json", extracted)

    def test_source_viewer_and_source_read_withhold(self) -> None:
        from rapidtriage.api.app import build_source_preview, build_source_search
        from rapidtriage.core.source_reader import (
            build_archived_source_preview,
            build_source_read_preview,
        )

        for relative in (
            "Users/alice/.claude/.credentials.json",
            "Users/alice/.netrc",
            "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
        ):
            path = self.root / relative
            preview = build_source_preview("run", path)
            self.assertEqual(preview["preview_type"], "withheld", relative)
            self.assertEqual(preview["coverage_status"], BODY_WITHHELD)
            self.assertEqual(fake_hits_in_text(json.dumps(preview, ensure_ascii=False)), [], relative)
            search = build_source_search(path, ["FAKE", "SYNTHETIC"])
            self.assertFalse(search["searchable"])
            self.assertEqual(search["matches"], [])
            read = build_source_read_preview(path, max_chars=1000, hex_bytes=256)
            self.assertEqual(read["preview_type"], "withheld")
            self.assertEqual(fake_hits_in_text(json.dumps(read, ensure_ascii=False)), [])
        npmrc = build_source_preview("run", self.root / "Users/alice/.npmrc")
        self.assertEqual(npmrc["preview_type"], "text")
        self.assertNotIn(NPMRC_VALUE, npmrc["text"])
        archive = self.base / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr(".codex/auth.json", json.dumps({"k": SECRET_VALUES[1]}))
        preview, entry = build_archived_source_preview(archive, entry_name=".codex/auth.json", max_chars=1000, hex_bytes=256)
        self.assertEqual(preview["preview_type"], "withheld")
        self.assertEqual(entry["entry_hashes"], {})
        self.assertEqual(fake_hits_in_text(json.dumps(preview, ensure_ascii=False)), [])

    def test_v4_body_fallbacks_and_ocr_sidecar(self) -> None:
        from rapidtriage.core.docs import extract_text
        from rapidtriage.core.ocr_queue import load_ocr_sidecar_with_metadata
        from rapidtriage.core.search_index.build import (
            extract_document_body,
            load_document_bodies,
        )

        path = self.root / "Users/alice/.claude/.credentials.json"
        body, cut = extract_document_body(str(path), "json") or ("", True)
        self.assertFalse(cut)
        self.assertIn(".credentials.json", body)
        self.assertEqual(fake_hits_in_text(body), [])
        self.assertEqual(fake_hits_in_text(extract_text(path, "json")), [])
        # A case DB written before this policy still holds the body: the v4 build swaps it for the name.
        db = self.base / "old-case.db"
        connection = sqlite3.connect(db)
        connection.executescript(
            "CREATE TABLE file_record (id INTEGER PRIMARY KEY, path TEXT);"
            "CREATE TABLE indexed_document (file_record_id INTEGER, body TEXT, source_type TEXT);"
        )
        connection.execute("INSERT INTO file_record VALUES (1, ?)", (str(path),))
        connection.execute("INSERT INTO indexed_document VALUES (1, ?, 'document')", (SECRET_VALUES[0],))
        connection.commit()
        connection.close()
        bodies = load_document_bodies(db)
        self.assertEqual(fake_hits_in_text(json.dumps(bodies)), [])
        image = self.root / "Users/alice/.claude/oauth-token.png"
        write(image, "png")
        write(image.with_name(image.name + ".ocr.txt"), SECRET_VALUES[2])
        self.assertEqual(load_ocr_sidecar_with_metadata(image), {})


def fake_hits_in_text(text: str) -> list[str]:
    return [value for value in ALL_FAKES if value in text]


if __name__ == "__main__":
    unittest.main()
