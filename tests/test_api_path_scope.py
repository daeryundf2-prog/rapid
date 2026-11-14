"""R8 T-031 (3): ``GET /api/browse`` path scope per server mode.

* loopback (local) server: the whole disk, as before — the analyst picks evidence anywhere.
* ``--remote`` server: only inside the ``--browse-root`` set (default: the run folders the server
  knows + home); anything else is 403 ``PATH_OUTSIDE_ALLOWED_ROOT`` with a Korean message.
* ``scope=analysis-*`` keeps its own run-scoped behaviour.
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

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.cli import build_parser, run_web_server
from rapidtriage.core.error_codes import ERROR_CODES
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest

TOKEN = "t031-browse-token"
ENV_KEYS = ("RAPIDTRIAGE_REMOTE", "RAPIDTRIAGE_BROWSE_ROOTS", "RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH")


@contextlib.contextmanager
def clean_env(**overrides: str):
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class BrowseScopeApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.inside = base / "browse-root"
        (self.inside / "case-a").mkdir(parents=True)
        (self.inside / "case-a" / "disk.E01").write_bytes(b"x")
        self.outside = base / "elsewhere"
        self.outside.mkdir()
        (self.outside / "secret-folder").mkdir()
        env = clean_env()
        env.__enter__()
        self.addCleanup(env.__exit__, None, None, None)

    def client(self, **kwargs: object) -> TestClient:
        app = create_app(RunJobStore(), auth_token=TOKEN, **kwargs)
        return TestClient(app, headers={"X-RapidTriage-Token": TOKEN})

    def browse(self, client: TestClient, path: Path | str | None = None, **params: object):
        if path is not None:
            params["path"] = str(path)
        return client.get("/api/browse", params=params)

    def assert_outside(self, response) -> None:
        self.assertEqual(response.status_code, 403, response.text)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "PATH_OUTSIDE_ALLOWED_ROOT")
        self.assertRegex(detail["message"], "[가-힣]")  # Korean sentence for the analyst

    # -- the three modes (acceptance 3/3) ------------------------------------------------------

    def test_loopback_server_lists_the_whole_disk(self) -> None:
        client = self.client()
        response = self.browse(client, self.outside)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["browse_mode"], "local")
        self.assertIn("secret-folder", {entry["name"] for entry in body["entries"]})
        self.assertEqual(self.browse(client).json()["path"], str(Path.home()))

    def test_remote_server_lists_inside_its_browse_roots(self) -> None:
        client = self.client(browse_remote=True, browse_roots=[self.inside])
        response = self.browse(client, self.inside / "case-a")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["browse_mode"], "remote")
        self.assertEqual({entry["name"] for entry in body["entries"]}, {"disk.E01"})
        self.assertEqual(body["parent"], str(self.inside))
        self.assertEqual(body["roots"], [str(self.inside)])
        at_root = self.browse(client, self.inside).json()
        self.assertIsNone(at_root["parent"], "the up button stops at a browse root")
        # No path: the first root (home is not a root here), never the whole disk.
        self.assertEqual(self.browse(client).json()["path"], str(self.inside))

    def test_remote_server_refuses_paths_outside_its_browse_roots(self) -> None:
        client = self.client(browse_remote=True, browse_roots=[self.inside])
        for path in (
            self.outside,
            self.inside.parent,
            self.inside / ".." / "elsewhere",  # lexical escape
            Path(self.inside.anchor),  # drive / filesystem root
        ):
            with self.subTest(path=str(path)):
                self.assert_outside(self.browse(client, path))

    # -- remote details -------------------------------------------------------------------------

    def test_remote_refuses_a_link_that_leaves_the_roots(self) -> None:
        link = self.inside / "jump"
        try:
            if os.name == "nt":
                import _winapi

                _winapi.CreateJunction(str(self.outside), str(link))  # no privilege needed
            else:
                link.symlink_to(self.outside, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("links are not available to this user")
        client = self.client(browse_remote=True, browse_roots=[self.inside])
        self.assert_outside(self.browse(client, link))

    def test_remote_default_roots_are_known_run_folders_and_home(self) -> None:
        store = RunJobStore()
        run_folder = self.outside / "run-output"
        run_folder.mkdir()
        store._jobs["r1"] = RunJob(  # register without starting a worker
            run_id="r1", request=RunRequest(root=str(self.inside), mode="fraud", output_dir=str(run_folder)), status="failed"
        )
        client = TestClient(create_app(store, auth_token=TOKEN, browse_remote=True), headers={"X-RapidTriage-Token": TOKEN})
        self.assertEqual(self.browse(client, run_folder).status_code, 200)
        self.assertEqual(self.browse(client, Path.home()).status_code, 200)
        self.assertEqual(self.browse(client).json()["path"], str(Path.home()))
        # Anything else (here the filesystem root above home) is outside.
        self.assert_outside(self.browse(client, Path(Path.home().anchor)))

    def test_remote_mode_and_roots_come_from_the_environment(self) -> None:
        with clean_env(RAPIDTRIAGE_REMOTE="1", RAPIDTRIAGE_BROWSE_ROOTS=str(self.inside)):
            client = self.client()
        self.assertEqual(self.browse(client, self.inside).status_code, 200)
        self.assert_outside(self.browse(client, self.outside))

    def test_remote_with_no_usable_root_fails_closed(self) -> None:
        with clean_env(RAPIDTRIAGE_REMOTE="1", RAPIDTRIAGE_BROWSE_ROOTS="relative/only"):
            client = self.client()
        self.assert_outside(self.browse(client))
        self.assert_outside(self.browse(client, Path.home()))

    def test_analysis_scope_is_unchanged_on_a_remote_server(self) -> None:
        client = self.client(browse_remote=True, browse_roots=[self.inside])
        response = self.browse(client, scope="analysis-input")
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("run_id", response.text)

    def test_error_code_is_registered(self) -> None:
        self.assertEqual(ERROR_CODES["PATH_OUTSIDE_ALLOWED_ROOT"].http_status, 403)


class BrowseRootCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()

    def test_parser_accepts_repeatable_browse_root(self) -> None:
        args = build_parser().parse_args(["web", "--remote", "--browse-root", "a", "--browse-root", "b"])
        self.assertEqual(args.browse_roots, ["a", "b"])

    def test_remote_server_passes_browse_roots_to_the_app(self) -> None:
        seen: dict[str, object] = {}

        def fake_run(*_args, **_kwargs) -> None:
            seen["remote"] = os.environ.get("RAPIDTRIAGE_REMOTE")
            seen["roots"] = os.environ.get("RAPIDTRIAGE_BROWSE_ROOTS")

        with clean_env():
            with patch.dict(sys.modules, {"uvicorn": types.SimpleNamespace(run=fake_run)}):
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    result = run_web_server(
                        "0.0.0.0", 8899, remote=True, auth_token="t", browse_roots=[str(self.root)], allow_plain_http=True
                    )
            self.assertEqual(result, 0)
            self.assertEqual(seen, {"remote": "1", "roots": str(self.root)})
            # Restored after the server stops: no leak into this process.
            self.assertNotIn("RAPIDTRIAGE_REMOTE", os.environ)
            self.assertNotIn("RAPIDTRIAGE_BROWSE_ROOTS", os.environ)

    def test_loopback_server_rejects_browse_root(self) -> None:
        with clean_env():
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("127.0.0.1", 8899, browse_roots=[str(self.root)])
        self.assertIn("--browse-root", str(raised.exception))

    def test_missing_browse_root_is_rejected(self) -> None:
        with clean_env():
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8899, remote=True, auth_token="t", browse_roots=[str(self.root / "missing")])
        self.assertIn("not an existing folder", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
