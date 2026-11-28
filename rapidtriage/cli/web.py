"""Entry points for the rapidtriage local web UI server."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path

from ..core.local_paths import (
    ANALYSIS_OUTPUT_ROOTS_ENV,
    ANALYSIS_ROOTS_ENV,
    configured_root_entries,
    overlapping_roots,
)
from ..core.user_tokens import TOKENS_FILE_ENV, configured_tokens_file, load_user_tokens
from .helpers import add_web_arguments

try:
    import resource
except ImportError:  # Windows: no RLIMIT_NOFILE
    resource = None

#: Soft open-file limit asked for at start (audit GAP-10): macOS terminals often start at 256,
#: and about 245 idle connections then stalled the server for every client.
OPEN_FILES_TARGET = 8192
LIMIT_CONCURRENCY_ENV = "RAPIDTRIAGE_LIMIT_CONCURRENCY"
#: Concurrent connections + requests before uvicorn answers 503; at most half the open-file limit.
DEFAULT_LIMIT_CONCURRENCY = 1000
KEEP_ALIVE_SECONDS = 5
#: In-flight requests get this long after SIGTERM / Ctrl-C before uvicorn cancels them.
GRACEFUL_SHUTDOWN_SECONDS = 10


def raise_open_file_limit() -> tuple[int, int] | None:
    """Raise the soft ``RLIMIT_NOFILE`` toward the hard limit (at most ``OPEN_FILES_TARGET``).

    Returns ``(before, now)`` soft limits, or ``None`` where unknown (Windows, unlimited).
    A refused raise is ignored: the server starts with the limit it has.
    """
    if resource is None:
        return None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        return None
    if soft == resource.RLIM_INFINITY:
        return None
    wanted = OPEN_FILES_TARGET if hard == resource.RLIM_INFINITY else min(OPEN_FILES_TARGET, hard)
    if soft >= wanted:
        return soft, soft
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    except (OSError, ValueError):
        return soft, soft
    return soft, wanted


def server_limit_concurrency(open_files: int | None) -> int:
    """``RAPIDTRIAGE_LIMIT_CONCURRENCY`` (a positive integer), else the default capped at half ``open_files``."""
    raw = os.environ.get(LIMIT_CONCURRENCY_ENV, "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    if open_files is None:
        return DEFAULT_LIMIT_CONCURRENCY
    return max(16, min(DEFAULT_LIMIT_CONCURRENCY, open_files // 2))


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
              rapidtriage-web --remote --host 0.0.0.0 --token <token>
            """
        ),
    )
    add_web_arguments(parser)
    return parser


def require_server_roots(reason: str) -> None:
    """Refuse to start unless both server root lists are set and no evidence root overlaps an output root.

    Any client that can reach a non-loopback (or ``--remote``) server must stay
    inside them: without them a token holder (or anyone, with
    ``--allow-remote-without-auth``) runs and reads any server path as evidence
    through source-file and writes output anywhere (R1, R10), and the picker lists
    the whole server file system (R2). An output root that is, contains, or lies in
    an evidence root puts run output inside the evidence.
    """
    entries = {env: configured_root_entries(env) for env in (ANALYSIS_ROOTS_ENV, ANALYSIS_OUTPUT_ROOTS_ENV)}
    missing = [env for env, values in entries.items() if not values]
    if missing:
        raise RuntimeError(
            f"{reason} requires server roots: set {' and '.join(missing)} "
            "(os.pathsep-separated absolute local folders: evidence inputs / run outputs)."
        )
    overlaps = overlapping_roots(entries[ANALYSIS_ROOTS_ENV], entries[ANALYSIS_OUTPUT_ROOTS_ENV])
    if overlaps:
        listed = "; ".join(f"{evidence} <-> {output}" for evidence, output in overlaps)
        raise RuntimeError(
            f"{reason}: {ANALYSIS_OUTPUT_ROOTS_ENV} must not be, contain, or lie inside a "
            f"{ANALYSIS_ROOTS_ENV} folder (run output would land in evidence): {listed}"
        )


def run_web_server(
    host: str,
    port: int,
    reload: bool = False,
    auth_token: str | None = None,
    allow_remote_without_auth: bool = False,
    crash_log_dir: str | None = None,
    remote: bool = False,
) -> int:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if remote and allow_remote_without_auth:
        raise RuntimeError("--remote and --allow-remote-without-auth are mutually exclusive: --remote keeps API auth on.")
    disable_auth = os.environ.get("RAPIDTRIAGE_DISABLE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    if remote and disable_auth:
        raise RuntimeError(
            "--remote requires API authentication but RAPIDTRIAGE_DISABLE_AUTH is set. "
            "Unset RAPIDTRIAGE_DISABLE_AUTH or drop --remote; refusing to weaken authentication silently."
        )
    if disable_auth and auth_token:
        raise RuntimeError(
            "conflicting authentication settings: RAPIDTRIAGE_DISABLE_AUTH cannot be combined with "
            "--auth-token; refusing to weaken authentication silently."
        )
    tokens_path = configured_tokens_file()
    if tokens_path is not None:
        # Per-user tokens name who acts on every API call; a shared token or no-auth beside
        # them would let someone act unattributed. Only a count is printed, never the file.
        if disable_auth or allow_remote_without_auth:
            raise RuntimeError(
                f"{TOKENS_FILE_ENV} needs API authentication: drop RAPIDTRIAGE_DISABLE_AUTH / --allow-remote-without-auth."
            )
        if auth_token or os.environ.get("RAPIDTRIAGE_TOKEN") or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN"):
            raise RuntimeError(
                f"{TOKENS_FILE_ENV} replaces the single API token: drop --token/--auth-token "
                "and RAPIDTRIAGE_TOKEN / RAPIDTRIAGE_AUTH_TOKEN."
            )
        users = load_user_tokens(tokens_path)
        # The uvicorn-imported app reads the same file whatever its working directory.
        os.environ[TOKENS_FILE_ENV] = str(tokens_path.resolve())
        print(
            f"RapidTriage API: per-user tokens for {len(users.entries)} users; "
            "each person opens the console with their own token.",
            flush=True,
        )
        for warning in users.warnings:
            print(f"WARNING: {warning}", file=sys.stderr, flush=True)
    if remote and tokens_path is None:
        # --remote is the supported non-loopback path: a token is mandatory so
        # /api auth and the Host/Origin gates stay on. RAPIDTRIAGE_TOKEN is the
        # documented env source; RAPIDTRIAGE_AUTH_TOKEN is accepted as the
        # channel the server process actually reads.
        auth_token = auth_token or os.environ.get("RAPIDTRIAGE_TOKEN") or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN")
        if not auth_token:
            raise RuntimeError(
                "--remote requires an API token: pass --token (or --auth-token), "
                f"set RAPIDTRIAGE_TOKEN / RAPIDTRIAGE_AUTH_TOKEN, or give per-user tokens in {TOKENS_FILE_ENV}."
            )
    elif host not in loopback_hosts and not auth_token and tokens_path is None and not allow_remote_without_auth:
        raise RuntimeError(
            "Refusing to bind RapidTriage to a non-localhost interface without --auth-token. "
            "Use --auth-token, --remote with a token, or --allow-remote-without-auth if you understand the risk."
        )
    if remote or host not in loopback_hosts:
        require_server_roots("--remote" if remote else f"binding to non-loopback host {host}")
    if remote and host not in loopback_hosts:
        print(
            "WARNING: RapidTriage remote mode is localhost-tool-grade: API token auth and "
            f"Host/Origin gates stay on for {host}:{port}, but traffic is plaintext HTTP. "
            "Put a TLS-terminating reverse proxy in front for real remote access, and set "
            "RAPIDTRIAGE_ALLOWED_HOSTS to the serving hostname so Host checks pass.",
            file=sys.stderr,
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("rapidtriage web requires the 'web' extra: pip install 'rapidtriage[web]'") from exc
    if disable_auth:
        os.environ.pop("RAPIDTRIAGE_AUTH_TOKEN", None)
        print("RapidTriage API authentication DISABLED for this local session.", flush=True)
    elif not auth_token and tokens_path is None and not allow_remote_without_auth:
        import secrets

        auth_token = os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or secrets.token_urlsafe(32)
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
        print("RapidTriage API token required for /api routes.", flush=True)
        print(flush=True)
        url_host = f"[{host}]" if ":" in host else host
        print(f"    Open this URL in your browser:  http://{url_host}:{port}/#token={auth_token}", flush=True)
        print(flush=True)
        print(f"(or paste this token into the console token field / localStorage rapidtriage.authToken: {auth_token})", flush=True)
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
    print(f"Starting rapidtriage web UI at http://{host}:{port}", flush=True)
    if auth_token:
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
    if crash_log_dir:
        os.environ["RAPIDTRIAGE_CRASH_LOG_DIR"] = str(Path(crash_log_dir).expanduser().resolve())
    no_browser = os.environ.get("RAPIDTRIAGE_NO_BROWSER", "").strip().lower() in {"1", "true", "yes", "on"}
    if host in loopback_hosts and not reload and not no_browser:
        # First-run friction: open the console automatically. The #token=
        # fragment is never sent over the wire; the page reads it once,
        # stores it, and strips it from the address bar.
        import threading
        import webbrowser

        fragment = f"/#token={auth_token}" if auth_token else ""
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{port}{fragment}")).start()
    limits = raise_open_file_limit()
    limit_concurrency = server_limit_concurrency(limits[1] if limits else None)
    if limits is not None:
        before, now = limits
        raised = f" (raised from {before})" if now > before else ""
        print(
            f"Open-file limit {now}{raised}; at most {limit_concurrency} concurrent connections "
            f"(503 beyond; {LIMIT_CONCURRENCY_ENV}).",
            flush=True,
        )
        if now <= 1024:
            print(
                f"Open-file limit is only {now}: for many LAN clients raise it before starting "
                "(`ulimit -n 4096`, or LimitNOFILE for a service).",
                flush=True,
            )
    uvicorn.run(
        "rapidtriage.api.app:app",
        host=host,
        port=port,
        reload=reload,
        limit_concurrency=limit_concurrency,
        timeout_keep_alive=KEEP_ALIVE_SECONDS,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
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
            remote=args.remote,
        )
    except RuntimeError as exc:
        parser.error(str(exc))
    return 2

__all__ = ["build_web_parser", "run_web_server", "web_main"]
