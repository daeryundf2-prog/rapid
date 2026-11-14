"""Entry points for the rapidtriage local web UI server."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path

from .helpers import add_web_arguments

TRUTHY = frozenset({"1", "true", "yes", "on"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
# T-112: uvicorn re-imports ``rapidtriage.api.app:app``, so ``--read-only`` reaches create_app
# only through this environment variable (restored once the server stops).
READ_ONLY_ENV = "RAPIDTRIAGE_READ_ONLY"
TLS_REQUIRED_MESSAGE = (
    "--remote는 TLS 없이 시작하지 않습니다(토큰과 증거가 평문으로 오갑니다). "
    "--ssl-certfile과 --ssl-keyfile로 인증서를 주거나, TLS를 끝내는 리버스 프록시 뒤에서 띄운다면 "
    "--allow-plain-http를 붙이세요."
)


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
              rapidtriage-web --read-only --no-browser
              rapidtriage-web --remote --host 0.0.0.0 --ssl-certfile cert.pem --ssl-keyfile key.pem
            """
        ),
    )
    add_web_arguments(parser)
    return parser


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in TRUTHY


def interactive_terminal() -> bool:
    """Whether stdout is an interactive terminal outside CI (T-112: token URL and browser only then)."""
    if _truthy_env("CI"):
        return False
    isatty = getattr(sys.stdout, "isatty", None)
    try:
        return bool(isatty and isatty())
    except (OSError, ValueError):
        return False


def _tls_files(ssl_certfile: str | None, ssl_keyfile: str | None) -> dict[str, str]:
    """uvicorn ``ssl_certfile``/``ssl_keyfile`` keyword arguments (empty without TLS)."""
    if not ssl_certfile and not ssl_keyfile:
        return {}
    if not (ssl_certfile and ssl_keyfile):
        raise RuntimeError("--ssl-certfile과 --ssl-keyfile은 함께 지정해야 합니다.")
    files: dict[str, str] = {}
    for option, raw in (("--ssl-certfile", ssl_certfile), ("--ssl-keyfile", ssl_keyfile)):
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise RuntimeError(f"{option} 파일이 없습니다: {raw}")
        files[option[2:].replace("-", "_")] = str(path)
    return files


def run_web_server(
    host: str,
    port: int,
    reload: bool = False,
    auth_token: str | None = None,
    allow_remote_without_auth: bool = False,
    crash_log_dir: str | None = None,
    remote: bool = False,
    browse_roots: list[str] | None = None,
    *,
    read_only: bool = False,
    no_browser: bool = False,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
    allow_plain_http: bool = False,
) -> int:
    loopback_hosts = LOOPBACK_HOSTS
    # T-031: a remote (or non-loopback) server's /api/browse lists only inside the browse roots.
    remote_browse = remote or host not in loopback_hosts
    if browse_roots and not remote_browse:
        raise RuntimeError(
            "--browse-root applies only to a --remote or non-loopback server; "
            "a loopback server's picker lists the whole disk."
        )
    resolved_browse_roots: list[str] = []
    for raw_root in browse_roots or ():
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            raise RuntimeError(f"--browse-root is not an existing folder: {raw_root}")
        resolved_browse_roots.append(str(root))
    tls = _tls_files(ssl_certfile, ssl_keyfile)
    if remote and allow_remote_without_auth:
        raise RuntimeError("--remote and --allow-remote-without-auth are mutually exclusive: --remote keeps API auth on.")
    disable_auth = _truthy_env("RAPIDTRIAGE_DISABLE_AUTH")
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
    if not disable_auth and not allow_remote_without_auth:
        # T-112: RAPIDTRIAGE_AUTH_TOKEN is the token variable (the one the server process reads);
        # RAPIDTRIAGE_TOKEN is its older alias. Every mode honours both, loopback included.
        auth_token = auth_token or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or os.environ.get("RAPIDTRIAGE_TOKEN")
    if remote and not auth_token:
        # --remote is the supported non-loopback path: a token is mandatory so
        # /api auth and the Host/Origin gates stay on.
        raise RuntimeError(
            "--remote requires an API token: pass --token (or --auth-token) "
            "or set RAPIDTRIAGE_AUTH_TOKEN (older alias RAPIDTRIAGE_TOKEN)."
        )
    if not remote and host not in loopback_hosts and not auth_token and not allow_remote_without_auth:
        raise RuntimeError(
            "Refusing to bind RapidTriage to a non-localhost interface without --auth-token. "
            "Use --auth-token, --remote with a token, or --allow-remote-without-auth if you understand the risk."
        )
    if remote and not tls and not allow_plain_http:
        raise RuntimeError(TLS_REQUIRED_MESSAGE)
    if remote and not tls and host not in loopback_hosts:
        print(
            "WARNING: RapidTriage remote mode is serving plaintext HTTP (--allow-plain-http): API token "
            f"auth and Host/Origin gates stay on for {host}:{port}, but put a TLS-terminating reverse "
            "proxy in front for real remote access, and set RAPIDTRIAGE_ALLOWED_HOSTS to the serving "
            "hostname so Host checks pass.",
            file=sys.stderr,
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("rapidtriage web requires the 'web' extra: pip install 'rapidtriage[web]'") from exc
    interactive = interactive_terminal()
    scheme = "https" if tls else "http"
    url_host = f"[{host}]" if ":" in host else host
    if disable_auth:
        os.environ.pop("RAPIDTRIAGE_AUTH_TOKEN", None)
        print("RapidTriage API authentication DISABLED for this local session.", flush=True)
    elif not auth_token and not allow_remote_without_auth:
        import secrets

        auth_token = secrets.token_urlsafe(32)
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
        print("RapidTriage API token required for /api routes.", flush=True)
        if interactive:
            # T-112: the token reaches only an interactive terminal — never a log file, a pipe or
            # CI output. The #token= fragment is never sent over the wire; the page reads it once,
            # stores it, and strips it from the address bar. (T-351 replaces this line.)
            print(flush=True)
            print(f"    Open this URL in your browser:  {scheme}://{url_host}:{port}/#token={auth_token}", flush=True)
            print(flush=True)
        else:
            print(
                "The generated token is not printed to non-interactive output. Set RAPIDTRIAGE_AUTH_TOKEN "
                "before starting the server to know the token.",
                flush=True,
            )
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
    print(f"Starting rapidtriage web UI at {scheme}://{url_host}:{port}", flush=True)
    if read_only:
        print(
            "Read-only server: state-changing API requests are refused (409 RUN_READ_ONLY, "
            "readonly_reason SERVER_READ_ONLY) and nothing is written into a result folder.",
            flush=True,
        )
    if auth_token:
        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
    if crash_log_dir:
        os.environ["RAPIDTRIAGE_CRASH_LOG_DIR"] = str(Path(crash_log_dir).expanduser().resolve())
    # Same channel as auth: uvicorn re-imports `rapidtriage.api.app:app`, so the browse scope and
    # the read-only switch reach create_app only through the environment (restored once the
    # server stops).
    server_env = {"RAPIDTRIAGE_REMOTE": "1"} if remote_browse else {}
    if resolved_browse_roots:
        server_env["RAPIDTRIAGE_BROWSE_ROOTS"] = os.pathsep.join(resolved_browse_roots)
    if read_only:
        server_env[READ_ONLY_ENV] = "1"
    saved_server_env = {key: os.environ.get(key) for key in server_env}
    os.environ.update(server_env)
    # D27 / T-112: open the console only for a loopback server on an interactive terminal outside
    # CI — never with --read-only, --no-browser or RAPIDTRIAGE_NO_BROWSER=1.
    no_browser = no_browser or _truthy_env("RAPIDTRIAGE_NO_BROWSER")
    if host in loopback_hosts and not reload and not no_browser and not read_only and interactive:
        import threading
        import webbrowser

        fragment = f"/#token={auth_token}" if auth_token else ""
        threading.Timer(1.2, lambda: webbrowser.open(f"{scheme}://{url_host}:{port}{fragment}")).start()
    try:
        uvicorn.run("rapidtriage.api.app:app", host=host, port=port, reload=reload, **tls)
    finally:
        for key, value in saved_server_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
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
            browse_roots=args.browse_roots,
            read_only=args.read_only,
            no_browser=args.no_browser,
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
            allow_plain_http=args.allow_plain_http,
        )
    except RuntimeError as exc:
        parser.error(str(exc))
    return 2

__all__ = ["build_web_parser", "run_web_server", "web_main"]
