"""T-007: additive HTTP error envelope (r8-contracts D.7), no paths in 500 bodies, security headers."""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HAS_FASTAPI = True
try:
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.errors import (
        KNOWN_DETAILS,
        KNOWN_PREFIXES,
        envelope_fields,
    )
from rapidtriage.core.error_codes import ERROR_CODES
from rapidtriage.core.jobs import RunJobStore

TOKEN = "rapidtriage-envelope-token"
HANGUL_RE = re.compile(r"[가-힣]")
# A Windows drive path or a user home folder must never reach a 5xx body.
PATH_RE = re.compile(r"[A-Za-z]:[\\/]|\\Users\\|/Users/|/home/", re.IGNORECASE)
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


def _client(app, *, token: str | None = TOKEN, **kwargs) -> TestClient:
    headers = {"X-RapidTriage-Token": token} if token else {}
    return TestClient(app, headers=headers, **kwargs)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ErrorEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(RunJobStore(), auth_token=TOKEN)
        self.client = _client(self.app)

    def assertEnvelope(self, response, status: int, code: str | None = None) -> dict:
        self.assertEqual(response.status_code, status, response.text)
        body = response.json()
        self.assertIn("detail", body)
        for key in ("code", "message", "hint"):
            self.assertIsInstance(body.get(key), str, key)
        self.assertIn(body["code"], ERROR_CODES)
        self.assertRegex(body["message"], HANGUL_RE)
        self.assertRegex(body["hint"], HANGUL_RE)
        if code is not None:
            self.assertEqual(body["code"], code)
        return body

    def assertSecurityHeaders(self, response) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(response.headers.get(name), value, name)

    # -- middleware answers (4 sites) ------------------------------------------------------------
    def test_missing_token_keeps_detail_and_adds_korean_envelope(self) -> None:
        response = _client(self.app, token=None).get("/api/runs")
        body = self.assertEnvelope(response, 401, "UNAUTHORIZED")
        self.assertEqual(body["detail"], "missing or invalid RapidTriage auth token")
        self.assertSecurityHeaders(response)

    def test_query_token_is_refused_in_korean(self) -> None:
        body = self.assertEnvelope(self.client.get("/api/runs", params={"token": TOKEN}), 401, "UNAUTHORIZED")
        self.assertEqual(body["detail"], "query token authentication is disabled; use X-RapidTriage-Token header")
        self.assertIn("X-RapidTriage-Token", body["hint"])

    def test_host_and_origin_refusals(self) -> None:
        host = self.client.get("/api/health", headers={"Host": "attacker.example"})
        self.assertEqual(self.assertEnvelope(host, 403, "FORBIDDEN")["detail"], "RapidTriage API host is not allowed")
        origin = self.client.post("/api/runs", json={}, headers={"Origin": "http://attacker.example"})
        self.assertEqual(self.assertEnvelope(origin, 403, "FORBIDDEN")["detail"], "RapidTriage API origin is not allowed")

    # -- HTTPException / validation -------------------------------------------------------------
    def test_korean_string_detail_is_the_message(self) -> None:
        body = self.assertEnvelope(self.client.get("/api/runs/no-such-run"), 404, "RUN_NOT_FOUND")
        self.assertEqual(body["detail"], "런을 찾을 수 없습니다")
        self.assertEqual(body["message"], body["detail"])

    def test_unknown_route_uses_status_default(self) -> None:
        body = self.assertEnvelope(self.client.get("/api/no-such-endpoint"), 404, "NOT_FOUND")
        self.assertEqual(body["detail"], "Not Found")
        self.assertEnvelope(self.client.delete("/api/health"), 405, "METHOD_NOT_ALLOWED")

    def test_validation_list_detail_stays_a_list(self) -> None:
        response = self.client.post("/api/runs", json={"mode": 7})
        body = self.assertEnvelope(response, 422, "VALIDATION_FAILED")
        self.assertIsInstance(body["detail"], list)
        self.assertTrue(all("msg" in item for item in body["detail"]))

    def test_structured_detail_code_wins(self) -> None:
        self.assertEqual(
            envelope_fields(422, {"code": "OUTPUT_DIR_REQUIRED", "message": "출력 폴더를 지정하세요"}),
            {
                "code": "OUTPUT_DIR_REQUIRED",
                "message": "출력 폴더를 지정하세요",
                "hint": ERROR_CODES["OUTPUT_DIR_REQUIRED"].hint_ko,
            },
        )
        unknown = envelope_fields(409, {"code": "NOT_A_REGISTERED_CODE", "message": "english"})
        self.assertEqual(unknown["code"], "CONFLICT")
        self.assertRegex(unknown["message"], HANGUL_RE)

    def test_route_literals_get_codes_from_the_table(self) -> None:
        @self.app.get("/api/_t007/literal")
        def literal() -> None:
            raise HTTPException(status_code=400, detail="sort requires exactly one kind")

        @self.app.get("/api/_t007/core-text")
        def core_text() -> None:
            raise HTTPException(status_code=409, detail="some core RuntimeError text")

        body = self.assertEnvelope(self.client.get("/api/_t007/literal"), 400, "BAD_REQUEST")
        self.assertEqual(body["detail"], "sort requires exactly one kind")
        self.assertIn("kind", body["message"])
        core = self.assertEnvelope(self.client.get("/api/_t007/core-text"), 409, "CONFLICT")
        self.assertEqual(core["detail"], "some core RuntimeError text")
        self.assertEqual(core["message"], ERROR_CODES["CONFLICT"].message_ko)

    def test_case_run_without_output_maps_to_output_dir_required(self) -> None:
        from rapidtriage.api.app.routes_cases import CASE_RUN_NEEDS_OUTPUT

        fields = envelope_fields(422, CASE_RUN_NEEDS_OUTPUT)
        self.assertEqual(fields["code"], "OUTPUT_DIR_REQUIRED")
        self.assertEqual(fields["message"], CASE_RUN_NEEDS_OUTPUT)

    def test_direct_json_error_responses_are_enveloped_too(self) -> None:
        @self.app.get("/api/_t007/direct")
        def direct() -> JSONResponse:
            return JSONResponse(status_code=400, content={"detail": "질의 3번째 글자: 따옴표", "position": 3})

        @self.app.get("/api/_t007/has-message")
        def has_message() -> JSONResponse:
            return JSONResponse(status_code=400, content={"detail": "x", "message": "기존 문장"})

        body = self.assertEnvelope(self.client.get("/api/_t007/direct"), 400, "BAD_REQUEST")
        self.assertEqual(body["position"], 3)
        self.assertEqual(body["message"], "질의 3번째 글자: 따옴표")
        kept = self.client.get("/api/_t007/has-message").json()
        self.assertEqual(kept["message"], "기존 문장")
        self.assertEqual(kept["code"], "BAD_REQUEST")

    def test_every_known_literal_has_a_registered_code_and_korean_text(self) -> None:
        # Prefix entries are probed with a tail (the value or exception text an f-string appends).
        entries = list(KNOWN_DETAILS.items()) + [(prefix + "x", entry) for prefix, entry in KNOWN_PREFIXES]
        self.assertGreaterEqual(len(entries), 36)
        for detail, entry in entries:
            with self.subTest(detail=detail):
                self.assertIn(entry.code, ERROR_CODES)
                fields = envelope_fields(ERROR_CODES[entry.code].http_status or 400, detail)
                self.assertEqual(fields["code"], entry.code)
                self.assertRegex(fields["message"], HANGUL_RE)
                self.assertRegex(fields["hint"], HANGUL_RE)

    # -- 500 --------------------------------------------------------------------------------------
    def test_internal_error_body_has_crash_id_but_no_path(self) -> None:
        @self.app.get("/api/_t007/boom")
        def boom() -> None:
            raise RuntimeError(r"failed at C:\Users\examiner\case\secret.db")

        @self.app.get("/api/_t007/http500")
        def http500() -> None:
            try:
                raise OSError(r"permission denied: D:\evidence\run-out\notes.json")
            except OSError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RAPIDTRIAGE_CRASH_LOG_DIR": tmp}):
            for path in ("/api/_t007/boom", "/api/_t007/http500"):
                with self.subTest(path=path), self.assertLogs("rapidtriage.api", level="ERROR") as logs:
                    response = self.client.get(path)
                    body = self.assertEnvelope(response, 500, "INTERNAL_ERROR")
                    self.assertNotIn("crash_report", body)
                    self.assertTrue(body["crash_id"].startswith("crash-"))
                    self.assertNotRegex(response.text, PATH_RE)
                    self.assertNotIn("secret", response.text)
                    self.assertTrue((Path(tmp) / f"{body['crash_id']}.json").is_file())
                    self.assertIn(body["crash_id"], "\n".join(logs.output))
                    self.assertSecurityHeaders(response)

    # -- security headers -------------------------------------------------------------------------
    def test_security_headers_on_success_and_console(self) -> None:
        self.assertSecurityHeaders(self.client.get("/api/health"))
        console = self.client.get("/")
        if console.status_code == 200:
            self.assertSecurityHeaders(console)
            self.assertIn("text/html", console.headers["content-type"])


if __name__ == "__main__":
    unittest.main()
