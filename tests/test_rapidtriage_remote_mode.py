from __future__ import annotations

import contextlib
import io
import os
import sys
import types
import unittest
from unittest.mock import patch

from rapidtriage.cli import build_parser, main, run_web_server

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


def _fake_uvicorn(captured: dict[str, object]) -> types.SimpleNamespace:
    return types.SimpleNamespace(run=lambda *args, **kwargs: captured.update({"args": args, "kwargs": kwargs}))


class RemoteModeFlagTests(unittest.TestCase):
    def test_parser_accepts_remote_and_token_alias(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["web", "--remote", "--token", "abc123"])
        self.assertTrue(args.remote)
        self.assertEqual(args.auth_token, "abc123")

    def test_remote_without_token_errors(self) -> None:
        with _clean_token_env():
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True)
        self.assertIn("--remote requires an API token", str(raised.exception))

    def test_remote_without_token_cli_errors(self) -> None:
        stderr = io.StringIO()
        with _clean_token_env():
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(["web", "--remote", "--host", "0.0.0.0"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--remote requires an API token", stderr.getvalue())

    def test_remote_with_token_keeps_auth_on(self) -> None:
        captured: dict[str, object] = {}
        stderr = io.StringIO()
        with _clean_token_env():
            with patch.dict(sys.modules, {"uvicorn": _fake_uvicorn(captured)}):
                with contextlib.redirect_stderr(stderr):
                    result = run_web_server("0.0.0.0", 8899, remote=True, auth_token="remote-token")
            self.assertEqual(result, 0)
            self.assertEqual(captured["kwargs"]["host"], "0.0.0.0")
            self.assertEqual(os.environ.get("RAPIDTRIAGE_AUTH_TOKEN"), "remote-token")
            self.assertNotIn("RAPIDTRIAGE_DISABLE_AUTH", os.environ)
        warning = stderr.getvalue()
        self.assertIn("WARNING", warning)
        self.assertIn("reverse proxy", warning)
        self.assertNotIn("DISABLED", warning)

    def test_remote_token_from_env(self) -> None:
        captured: dict[str, object] = {}
        with _clean_token_env(RAPIDTRIAGE_TOKEN="env-remote-token"):
            with patch.dict(sys.modules, {"uvicorn": _fake_uvicorn(captured)}):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = run_web_server("0.0.0.0", 8899, remote=True)
            self.assertEqual(result, 0)
            self.assertEqual(os.environ.get("RAPIDTRIAGE_AUTH_TOKEN"), "env-remote-token")

    def test_remote_rejects_allow_remote_without_auth(self) -> None:
        with _clean_token_env():
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True, allow_remote_without_auth=True)
        self.assertIn("mutually exclusive", str(raised.exception))

    def test_default_refusal_unchanged_without_remote(self) -> None:
        with _clean_token_env():
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899)
        self.assertIn("non-localhost", str(raised.exception))

    def test_loopback_remote_still_requires_token(self) -> None:
        with _clean_token_env():
            with self.assertRaises(RuntimeError):
                run_web_server("127.0.0.1", 8899, remote=True)
        captured: dict[str, object] = {}
        with _clean_token_env():
            with patch.dict(sys.modules, {"uvicorn": _fake_uvicorn(captured)}):
                result = run_web_server("127.0.0.1", 8899, remote=True, auth_token="t")
            self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
