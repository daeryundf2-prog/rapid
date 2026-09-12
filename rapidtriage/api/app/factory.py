from __future__ import annotations

import os
import secrets
from collections.abc import Iterable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ...core.case_db import open_case_database
from ...core.crash import write_crash_report
from ...core.jobs import RunJobStore, default_job_store
from .constants import MUTATING_METHODS
from .helpers import (
    allowed_api_hosts,
    request_host,
    resolve_case_catalog_path,
    resolve_case_db_path,
    truthy_env,
)
from .routes_case_db import build_case_db_router
from .routes_media import build_media_router
from .routes_meta import build_meta_router
from .routes_reports import build_reports_router
from .routes_runs import build_runs_router
from .routes_search import build_search_router


def create_app(
    job_store: RunJobStore | None = None,
    auth_token: str | None = None,
    require_auth: bool | None = None,
    case_db_roots: Iterable[str | Path] | None = None,
) -> FastAPI:
    store = job_store or default_job_store
    api = FastAPI(title="rapidtriage local API", version="0.2.0")
    static_dir = Path(__file__).resolve().parent.parent.parent / "web" / "static"
    auth_disabled = truthy_env("RAPIDTRIAGE_DISABLE_AUTH") or require_auth is False
    configured_token = auth_token or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or ""
    expected_token = "" if auth_disabled else configured_token or secrets.token_urlsafe(32)
    api.state.auth_required = bool(expected_token)
    api.state.auth_token = expected_token
    configured_case_db_roots = frozenset(case_db_roots or ())
    api.state.case_db_roots = configured_case_db_roots

    def open_request_case_database(raw_path: str | Path):
        database_path = resolve_case_db_path(store, raw_path, configured_case_db_roots)
        return open_case_database(database_path)

    def resolve_request_catalog_path(raw_path: str | Path) -> Path:
        return resolve_case_catalog_path(store, raw_path, configured_case_db_roots)

    @api.middleware("http")
    async def require_auth_token(request: Request, call_next):
        try:
            if request.url.path.startswith("/api"):
                host = request_host(request.headers.get("host"))
                allowed_hosts = allowed_api_hosts()
                if host and host not in allowed_hosts:
                    return JSONResponse(status_code=403, content={"detail": "RapidTriage API host is not allowed"})
                origin = request.headers.get("origin")
                if origin and request.method.upper() in MUTATING_METHODS:
                    origin_host = request_host(origin.split("//", 1)[-1])
                    if origin_host and origin_host not in allowed_hosts:
                        return JSONResponse(status_code=403, content={"detail": "RapidTriage API origin is not allowed"})
            if expected_token and request.url.path.startswith("/api"):
                if "token" in request.query_params:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "query token authentication is disabled; use X-RapidTriage-Token header"},
                    )
                supplied = request.headers.get("X-RapidTriage-Token")
                if supplied is None or not secrets.compare_digest(supplied, expected_token):
                    return JSONResponse(status_code=401, content={"detail": "missing or invalid RapidTriage auth token"})
            return await call_next(request)
        except Exception as exc:
            report = write_crash_report(
                exc,
                context={
                    "component": "web-api",
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "internal RapidTriage error; local crash report written",
                    "crash_id": report["crash_id"],
                    "crash_report": report["path"],
                },
            )

    api.include_router(build_meta_router())
    api.include_router(build_case_db_router(store, open_request_case_database, resolve_request_catalog_path))
    api.include_router(build_runs_router(store))
    api.include_router(build_media_router(store))
    api.include_router(build_search_router(store))
    api.include_router(build_reports_router(store))

    if static_dir.is_dir():
        api.mount("/assets", StaticFiles(directory=static_dir), name="rapidtriage-assets")

        @api.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(static_dir / "index.html")

        @api.get("/favicon.ico", include_in_schema=False)
        def favicon() -> FileResponse:
            return FileResponse(static_dir / "favicon.svg", media_type="image/svg+xml")

    return api


app = create_app()
