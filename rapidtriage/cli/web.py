"""Entry points for the rapidtriage local web UI server."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path

from .helpers import add_web_arguments


def build_web_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapidtriage-web",
        description="Start the local rapidtriage web UI and API server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage-web
              rapidtriage-web --host 127.0.0.1 --port 8765
            """
        ),
    )
    add_web_arguments(parser)
    return parser


def run_web_server(
    host: str,
    port: int,
    reload: bool = False,
    auth_token: str | None = None,
    allow_remote_without_auth: bool = False,
    crash_log_dir: str | None = None,
) -> int:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in loopback_hosts and not auth_token and not allow_remote_without_auth:
        raise RuntimeError(
            "Refusing to bind RapidTriage to a non-localhost interface without --auth-token. "
            "Use --auth-token or --allow-remote-without-auth if you understand the risk."
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("rapidtriage web requires the 'web' extra: pip install 'dashcam-tools[web]'") from exc
    if not auth_token and not allow_remote_without_auth:
        import secrets

        auth_token = os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or secrets.token_urlsafe(32)
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
        print("RapidTriage API token required for /api routes.")
        print(f"Set browser localStorage key rapidtriage.authToken to: {auth_token}")
    if allow_remote_without_auth:
        # uvicorn re-imports `rapidtriage.api.app:app` (module-scope
        # `app = create_app()`), so auth cannot be passed as an explicit flag;
        # the environment variable is the only channel that reaches it.
        os.environ["RAPIDTRIAGE_DISABLE_AUTH"] = "1"
        if host not in loopback_hosts:
            print(
                "WARNING: RapidTriage API authentication is DISABLED while binding to "
                f"non-loopback host {host}:{port}. Any client that can reach this port "
                "can read evidence metadata, run scans, and write case databases. "
                "Use --auth-token unless you fully control the network segment.",
                file=sys.stderr,
            )
    print(f"Starting rapidtriage web UI at http://{host}:{port}")
    if auth_token:
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
    if crash_log_dir:
        os.environ["RAPIDTRIAGE_CRASH_LOG_DIR"] = str(Path(crash_log_dir).expanduser().resolve())
    uvicorn.run("rapidtriage.api.app:app", host=host, port=port, reload=reload)
    return 0


def web_main(argv=None) -> int:
    parser = build_web_parser()
    args = parser.parse_args(argv)
    try:
        return run_web_server(
            args.host,
            args.port,
            args.reload,
            args.auth_token,
            args.allow_remote_without_auth,
            args.crash_log_dir,
        )
    except RuntimeError as exc:
        parser.error(str(exc))
    return 2

__all__ = ["build_web_parser", "run_web_server", "web_main"]
