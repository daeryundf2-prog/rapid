from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from rapidtriage.cli import run_web_server
from rapidtriage.core.cloud_api import (
    CloudApiCollectionError,
    fetch_cloud_api_page,
    run_cloud_api_collection,
    strip_credential_headers,
    url_origin,
    validate_hop_url,
)

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

REPO_ROOT = Path(__file__).resolve().parents[1]
TOKEN_ENV_KEYS = ("RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH")


@contextlib.contextmanager
def _clean_token_env(**overrides):
    saved = {key: os.environ.get(key) for key in TOKEN_ENV_KEYS}
    for key in TOKEN_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key in TOKEN_ENV_KEYS:
            if saved[key] is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved[key]


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    recorded: ClassVar[list[dict[str, object]]] = []
    next_url = ""
    redirect_to = ""
    body = b'{"items": []}'

    def do_GET(self):
        type(self).recorded.append(
            {"path": self.path, "headers": {key: value for key, value in self.headers.items()}}
        )
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            return
        payload = self.body
        if self.next_url:
            payload = json.dumps({"items": [], "next": self.next_url}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:
        return


def _start_server(**handler_attrs):
    handler = type("RecordedHandler", (_RecordingHandler,), {"recorded": [], **handler_attrs})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, handler


class Stage4MetricEscapingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node is required for JavaScript escaping checks")
    def test_metric_escapes_imported_markup_but_renders_numbers(self) -> None:
        script = (
            'import { metric } from "./rapidtriage/web/static/app_utils.js";\n'
            'const hostile = metric("count", "<img src=x onerror=alert(1)>");\n'
            'const numeric = metric("files", 1234);\n'
            'if (hostile.includes("<img")) { throw new Error("unescaped metric value"); }\n'
            'if (!hostile.includes("&lt;img")) { throw new Error("markup not rendered as text"); }\n'
            'if (!numeric.includes("<b>1234</b>")) { throw new Error("number rendering changed"); }\n'
        )
        result = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class Stage4AuthConflictTests(unittest.TestCase):
    def test_remote_rejects_disable_auth_environment(self) -> None:
        with _clean_token_env(RAPIDTRIAGE_DISABLE_AUTH="1"):
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True, auth_token="t")
        self.assertIn("RAPIDTRIAGE_DISABLE_AUTH", str(raised.exception))

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required for create_app checks")
    def test_create_app_rejects_disable_flag_with_explicit_token(self) -> None:
        from rapidtriage.api.app import create_app
        from rapidtriage.core.jobs import RunJobStore

        with _clean_token_env():
            with self.assertRaises(RuntimeError) as raised:
                create_app(RunJobStore(), auth_token="token", require_auth=False)
        self.assertIn("conflicting authentication settings", str(raised.exception))

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required for create_app checks")
    def test_create_app_rejects_disable_env_with_token_env(self) -> None:
        from rapidtriage.api.app import create_app
        from rapidtriage.core.jobs import RunJobStore

        with _clean_token_env(RAPIDTRIAGE_DISABLE_AUTH="1", RAPIDTRIAGE_AUTH_TOKEN="env-token"):
            with self.assertRaises(RuntimeError) as raised:
                create_app(RunJobStore())
        self.assertIn("conflicting authentication settings", str(raised.exception))

    def test_allow_remote_without_auth_still_runs_when_explicitly_requested(self) -> None:
        captured: dict[str, object] = {}
        fake_uvicorn = types.SimpleNamespace(run=lambda *_a, **k: captured.update(kwargs=k))
        with _clean_token_env():
            with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = run_web_server("0.0.0.0", 8899, allow_remote_without_auth=True)
        self.assertEqual(result, 0)


class Stage4HopValidationTests(unittest.TestCase):
    def test_https_to_http_downgrade_rejected(self) -> None:
        with self.assertRaises(CloudApiCollectionError):
            validate_hop_url(
                "http://evil.example/collect",
                current_url="https://api.example.com/items",
                allow_insecure_http=True,
            )

    def test_same_scheme_and_https_hops_allowed(self) -> None:
        validate_hop_url(
            "https://api.example.com/items?page=2",
            current_url="https://api.example.com/items",
            allow_insecure_http=False,
        )
        validate_hop_url(
            "http://127.0.0.1:8765/items?page=2",
            current_url="http://127.0.0.1:8765/items",
            allow_insecure_http=False,
        )

    def test_http_to_remote_http_requires_insecure_flag(self) -> None:
        with self.assertRaises(CloudApiCollectionError):
            validate_hop_url(
                "http://remote.example/items",
                current_url="http://127.0.0.1:8765/items",
                allow_insecure_http=False,
            )

    def test_strip_credential_headers_removes_secret_bearing_names(self) -> None:
        stripped = strip_credential_headers(
            {
                "Authorization": "Bearer secret",
                "X-Api-Key": "key",
                "api-key": "key2",
                "Accept": "application/json",
            }
        )
        self.assertEqual(stripped, {"Accept": "application/json"})

    def test_url_origin_distinguishes_ports(self) -> None:
        self.assertNotEqual(
            url_origin("http://127.0.0.1:1111/a"),
            url_origin("http://127.0.0.1:2222/a"),
        )


class Stage4PaginationCredentialTests(unittest.TestCase):
    def test_cross_origin_pagination_never_receives_credential_headers(self) -> None:
        server_b, handler_b = _start_server()
        try:
            next_url = f"http://127.0.0.1:{server_b.server_port}/page2"
            server_a, _handler_a = _start_server(next_url=next_url)
            try:
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    manifest = root / "manifest.json"
                    manifest.write_text(
                        json.dumps(
                            {
                                "requests": [
                                    {
                                        "name": "paged",
                                        "url": f"http://127.0.0.1:{server_a.server_port}/first",
                                        "headers": {"Authorization": "Bearer super-secret"},
                                        "pagination": {
                                            "mode": "next_link_field",
                                            "next_link_field": "next",
                                            "max_pages": 3,
                                        },
                                    }
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )
                    payload = run_cloud_api_collection(
                        manifest,
                        output_dir=root / "out",
                    )
            finally:
                server_a.shutdown()
                server_a.server_close()
        finally:
            server_b.shutdown()
            server_b.server_close()

        self.assertTrue(handler_b.recorded, "cross-origin page was never requested")
        for record in handler_b.recorded:
            header_names = {key.lower() for key in record["headers"]}
            self.assertNotIn("authorization", header_names)
            self.assertNotIn("x-api-key", header_names)
        profile = payload["requests"][0]["pagination_execution_profile"]
        self.assertEqual(profile["cross_origin_hop_count"], 1)
        self.assertIs(profile["credential_headers_stripped_cross_origin"], True)
        self.assertEqual(profile["status"], "complete")

    def test_same_origin_pagination_keeps_credential_headers(self) -> None:
        server, handler = _start_server()
        try:
            next_url = f"http://127.0.0.1:{server.server_port}/page2"
            handler.next_url = next_url
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest = root / "manifest.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "requests": [
                                {
                                    "name": "paged",
                                    "url": f"http://127.0.0.1:{server.server_port}/first",
                                    "headers": {"Authorization": "Bearer keep-me"},
                                    "pagination": {
                                        "mode": "next_link_field",
                                        "next_link_field": "next",
                                        "max_pages": 3,
                                    },
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                run_cloud_api_collection(manifest, output_dir=root / "out")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(len(handler.recorded), 2)
        for record in handler.recorded:
            self.assertEqual(record["headers"].get("Authorization"), "Bearer keep-me")

    def test_cross_origin_redirect_strips_credential_headers(self) -> None:
        server_b, handler_b = _start_server()
        try:
            redirect_to = f"http://127.0.0.1:{server_b.server_port}/final"
            server_a, _handler_a = _start_server(redirect_to=redirect_to)
            try:
                with tempfile.TemporaryDirectory() as temp:
                    result = fetch_cloud_api_page(
                        index=1,
                        name="redirect-test",
                        method="GET",
                        url=f"http://127.0.0.1:{server_a.server_port}/start",
                        headers={"Authorization": "Bearer redirect-secret"},
                        request_body=None,
                        responses_dir=Path(temp),
                        timeout_seconds=5,
                        max_response_bytes=10000,
                        max_attempts=1,
                        retry_statuses=set(),
                        backoff_seconds=0,
                        page_number=1,
                    )
            finally:
                server_a.shutdown()
                server_a.server_close()
        finally:
            server_b.shutdown()
            server_b.server_close()

        self.assertEqual(result.get("status"), 200)
        self.assertTrue(handler_b.recorded)
        header_names = {key.lower() for key in handler_b.recorded[0]["headers"]}
        self.assertNotIn("authorization", header_names)


if __name__ == "__main__":
    unittest.main()
