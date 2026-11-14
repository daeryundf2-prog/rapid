"""R8 T-112: `rapidtriage web --read-only` / `--no-browser`, token handling and remote TLS.

* ``--read-only`` (``RAPIDTRIAGE_READ_ONLY``): every state-changing ``/api`` request answers 409
  ``RUN_READ_ONLY`` with ``readonly_reason: SERVER_READ_ONLY`` (the run query POSTs and the path
  pre-checks still answer), and the run folders the server knows are held read-only so nothing is
  written into them;
* the browser opens only for a loopback server on an interactive terminal outside CI, never with
  ``--no-browser`` / ``RAPIDTRIAGE_NO_BROWSER`` / ``--read-only``;
* the token: ``RAPIDTRIAGE_AUTH_TOKEN`` (older alias ``RAPIDTRIAGE_TOKEN``) in every mode; a
  generated token reaches only an interactive terminal;
* ``--remote`` without ``--ssl-certfile/--ssl-keyfile`` exits 2 with a Korean message unless
  ``--allow-plain-http``; the TLS files reach uvicorn.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.cli import build_parser, main, run_web_server
from rapidtriage.cli import web as web_module

ENV_KEYS = (
    "RAPIDTRIAGE_TOKEN",
    "RAPIDTRIAGE_AUTH_TOKEN",
    "RAPIDTRIAGE_DISABLE_AUTH",
    "RAPIDTRIAGE_NO_BROWSER",
    "RAPIDTRIAGE_READ_ONLY",
    "RAPIDTRIAGE_REMOTE",
    "RAPIDTRIAGE_BROWSE_ROOTS",
    "CI",
)


@contextlib.contextmanager
def clean_env(**overrides: str):
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key in ENV_KEYS:
            if saved[key] is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved[key]


class FakeUvicorn:
    def __init__(self) -> None:
        self.kwargs: dict[str, object] = {}
        self.env: dict[str, str | None] = {}

    def module(self) -> types.SimpleNamespace:
        def run(*_args, **kwargs) -> None:
            self.kwargs = kwargs
            self.env = {key: os.environ.get(key) for key in ENV_KEYS}

        return types.SimpleNamespace(run=run)


def serve(*args, interactive: bool = False, **kwargs) -> tuple[FakeUvicorn, str, str, list[str]]:
    """Run ``run_web_server`` against a fake uvicorn; returns (fake, stdout, stderr, opened URLs)."""
    fake = FakeUvicorn()
    stdout, stderr = io.StringIO(), io.StringIO()
    opened: list[str] = []

    class Timer:
        def __init__(self, _delay: float, callback) -> None:
            self.callback = callback

        def start(self) -> None:
            self.callback()

    with patch.dict(sys.modules, {"uvicorn": fake.module()}), \
            patch.object(web_module, "interactive_terminal", return_value=interactive), \
            patch("threading.Timer", Timer), patch("webbrowser.open", opened.append), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = run_web_server(*args, **kwargs)
    assert result == 0
    return fake, stdout.getvalue(), stderr.getvalue(), opened


class ParserTests(unittest.TestCase):
    def test_new_flags_parse(self) -> None:
        args = build_parser().parse_args(
            ["web", "--read-only", "--no-browser", "--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem", "--allow-plain-http"]
        )
        self.assertTrue(args.read_only)
        self.assertTrue(args.no_browser)
        self.assertEqual((args.ssl_certfile, args.ssl_keyfile), ("c.pem", "k.pem"))
        self.assertTrue(args.allow_plain_http)
        defaults = build_parser().parse_args(["web"])
        self.assertFalse(defaults.read_only or defaults.no_browser or defaults.allow_plain_http)
        self.assertIsNone(defaults.ssl_certfile)

    def test_help_names_the_flags(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit):
            main(["web", "--help"])
        for flag in ("--read-only", "--no-browser", "--ssl-certfile", "--ssl-keyfile", "--allow-plain-http"):
            self.assertIn(flag, stdout.getvalue())
        self.assertIn("RAPIDTRIAGE_AUTH_TOKEN", stdout.getvalue())


class TokenTests(unittest.TestCase):
    def test_loopback_honours_the_old_token_alias(self) -> None:
        with clean_env(RAPIDTRIAGE_TOKEN="alias-token"):
            fake, stdout, _, _ = serve("127.0.0.1", 8899)
        self.assertEqual(fake.env["RAPIDTRIAGE_AUTH_TOKEN"], "alias-token")
        self.assertNotIn("alias-token", stdout)

    def test_auth_token_variable_wins_over_the_alias(self) -> None:
        with clean_env(RAPIDTRIAGE_TOKEN="alias-token", RAPIDTRIAGE_AUTH_TOKEN="main-token"):
            fake, _, _, _ = serve("127.0.0.1", 8899)
        self.assertEqual(fake.env["RAPIDTRIAGE_AUTH_TOKEN"], "main-token")

    def test_generated_token_is_not_printed_to_non_interactive_output(self) -> None:
        with clean_env():
            fake, stdout, stderr, _ = serve("127.0.0.1", 8899)
            token = fake.env["RAPIDTRIAGE_AUTH_TOKEN"]
        self.assertTrue(token)
        self.assertNotIn(token, stdout + stderr)
        self.assertNotIn("#token=", stdout)
        self.assertIn("RAPIDTRIAGE_AUTH_TOKEN", stdout)

    def test_generated_token_url_reaches_an_interactive_terminal_once(self) -> None:
        with clean_env(RAPIDTRIAGE_NO_BROWSER="1"):
            fake, stdout, _, _ = serve("127.0.0.1", 8899, interactive=True)
            token = fake.env["RAPIDTRIAGE_AUTH_TOKEN"]
        self.assertEqual(stdout.count(token), 1)
        self.assertIn(f"http://127.0.0.1:8899/#token={token}", stdout)

    def test_interactive_terminal_is_false_in_ci_and_for_pipes(self) -> None:
        with clean_env(CI="true"):
            self.assertFalse(web_module.interactive_terminal())
        with clean_env(), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(web_module.interactive_terminal())


class BrowserTests(unittest.TestCase):
    def test_interactive_loopback_opens_the_browser(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            _, _, _, opened = serve("127.0.0.1", 8899, interactive=True)
        self.assertEqual(opened, ["http://127.0.0.1:8899/#token=t"])

    def test_browser_stays_closed(self) -> None:
        cases = (
            ("non-interactive", {}, {}, False),
            ("--no-browser", {}, {"no_browser": True}, True),
            ("RAPIDTRIAGE_NO_BROWSER", {"RAPIDTRIAGE_NO_BROWSER": "1"}, {}, True),
            ("--read-only", {}, {"read_only": True}, True),
        )
        for label, env, kwargs, interactive in cases:
            with self.subTest(label):
                with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t", **env):
                    _, _, _, opened = serve("127.0.0.1", 8899, interactive=interactive, **kwargs)
                self.assertEqual(opened, [])


class ReadOnlySwitchTests(unittest.TestCase):
    def test_read_only_reaches_the_app_and_is_restored(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            fake, stdout, _, _ = serve("127.0.0.1", 8899, read_only=True)
            self.assertNotIn("RAPIDTRIAGE_READ_ONLY", os.environ)
        self.assertEqual(fake.env["RAPIDTRIAGE_READ_ONLY"], "1")
        self.assertIn("SERVER_READ_ONLY", stdout)

    def test_cli_passes_read_only(self) -> None:
        fake = FakeUvicorn()
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"), patch.dict(sys.modules, {"uvicorn": fake.module()}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["web", "--read-only", "--no-browser", "--port", "8899"]), 0)
        self.assertEqual(fake.env["RAPIDTRIAGE_READ_ONLY"], "1")


class RemoteTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cert = Path(tmp.name) / "cert.pem"
        self.key = Path(tmp.name) / "key.pem"
        self.cert.write_text("cert", encoding="utf-8")
        self.key.write_text("key", encoding="utf-8")

    def test_remote_without_tls_is_refused_in_korean(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True)
        self.assertIn("TLS", str(raised.exception))
        self.assertIn("--allow-plain-http", str(raised.exception))
        self.assertIn("인증서", str(raised.exception))

    def test_remote_without_tls_cli_exits_2(self) -> None:
        stderr = io.StringIO()
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["web", "--remote", "--host", "0.0.0.0", "--port", "8899"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--allow-plain-http", stderr.getvalue())

    def test_allow_plain_http_starts_with_a_warning(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            fake, _, stderr, _ = serve("0.0.0.0", 8899, remote=True, allow_plain_http=True)
        self.assertNotIn("ssl_certfile", fake.kwargs)
        self.assertIn("plaintext", stderr)

    def test_tls_files_reach_uvicorn(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            fake, stdout, stderr, _ = serve(
                "0.0.0.0", 8899, remote=True, ssl_certfile=str(self.cert), ssl_keyfile=str(self.key)
            )
        self.assertEqual(fake.kwargs["ssl_certfile"], str(self.cert.resolve()))
        self.assertEqual(fake.kwargs["ssl_keyfile"], str(self.key.resolve()))
        self.assertIn("https://0.0.0.0:8899", stdout)
        self.assertNotIn("plaintext", stderr)

    def test_tls_file_errors(self) -> None:
        with clean_env(RAPIDTRIAGE_AUTH_TOKEN="t"):
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True, ssl_certfile=str(self.cert))
            self.assertIn("함께", str(raised.exception))
            with self.assertRaises(RuntimeError) as raised:
                run_web_server(
                    "0.0.0.0", 8899, remote=True, ssl_certfile=str(self.cert), ssl_keyfile=str(self.key) + ".missing"
                )
            self.assertIn("--ssl-keyfile", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
