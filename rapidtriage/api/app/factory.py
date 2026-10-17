from __future__ import annotations

import os
import re
import secrets
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ...core.case_db import open_case_database
from ...core.crash import write_crash_report
from ...core.jobs import RunJobStore, default_job_store
from .analyses import ANALYSIS_RUNNER, COMPLETION_HOOKS
from .constants import MUTATING_METHODS
from .helpers import (
    allowed_api_hosts,
    request_host,
    resolve_case_catalog_path,
    resolve_case_db_path,
    truthy_env,
)
from .routes_analyses import build_analyses_router, korean_body_errors
from .routes_case_db import build_case_db_router
from .routes_derived import build_derived_router
from .routes_flags import build_flags_router
from .routes_ioc import build_ioc_router
from .routes_media import build_media_router
from .routes_meta import build_meta_router
from .routes_reports import build_reports_router
from .routes_review_tools import build_review_tools_router
from .routes_runs import build_runs_router
from .routes_search import build_search_router
from .routes_search_index import build_search_index_router
from .search_index_service import (
    auto_build_on_completion,
    auto_incremental_after_analysis,
)

ANALYSIS_POST_PATH = re.compile(r"/api/runs/[^/]+/analyses")
# Review-tool bodies (AXIOM E3) also get Korean 422 messages.
REVIEW_TOOL_BODY_PATH = re.compile(r"/api/cases/[^/]+/(tags(/[^/]+)?|histogram-baselines)")


def _without_surrogates(value: object) -> object:
    """``value`` with lone surrogates backslash-escaped so the JSON response can be encoded."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, list):
        return [_without_surrogates(item) for item in value]
    if isinstance(value, dict):
        return {str(_without_surrogates(key)): _without_surrogates(item) for key, item in value.items()}
    return value


def create_app(
    job_store: RunJobStore | None = None,
    auth_token: str | None = None,
    require_auth: bool | None = None,
    case_db_roots: Iterable[str | Path] | None = None,
    auto_search_index: bool = False,
) -> FastAPI:
    store = job_store or default_job_store
    # Identifies this app's analyses in the process-wide runner.
    analysis_owner = object()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        # Shutdown: cancel this app's running analyses at their next unit, drop its queued ones.
        ANALYSIS_RUNNER.shutdown(owner=analysis_owner)

    api = FastAPI(title="rapidtriage local API", version="0.2.0", lifespan=lifespan)
    api.state.analysis_owner = analysis_owner
    if auto_search_index:
        # Search index (plan search §0 결정 1): full build when a run completes, incremental
        # update when another analysis completes. The served app (module-level ``app``)
        # turns this on; embedded/test apps opt in. Named hook: a later app replaces it.
        store.set_completion_hook(
            "search-index", lambda run_store, job: auto_build_on_completion(run_store, job, owner=analysis_owner)
        )
        if auto_incremental_after_analysis not in COMPLETION_HOOKS:
            COMPLETION_HOOKS.append(auto_incremental_after_analysis)

    @api.exception_handler(RequestValidationError)
    async def korean_analysis_body_errors(request: Request, exc: RequestValidationError):
        """Malformed ``POST /analyses`` bodies get Korean 422 messages; other routes keep FastAPI's."""
        if REVIEW_TOOL_BODY_PATH.fullmatch(request.url.path):
            return JSONResponse(status_code=422, content={"detail": korean_body_errors(exc.errors())})
        if request.method == "POST" and ANALYSIS_POST_PATH.fullmatch(request.url.path):
            return JSONResponse(status_code=422, content={"detail": korean_body_errors(exc.errors())})
        try:
            return await request_validation_exception_handler(request, exc)
        except UnicodeEncodeError:
            # A lone surrogate in the body (valid JSON escape, invalid text) must stay a 422, not a 500.
            return JSONResponse(status_code=422, content={"detail": _without_surrogates(jsonable_encoder(exc.errors()))})
    static_dir = Path(__file__).resolve().parent.parent.parent / "web" / "static"
    auth_disabled = truthy_env("RAPIDTRIAGE_DISABLE_AUTH") or require_auth is False
    if auth_disabled and (auth_token or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN")):
        raise RuntimeError(
            "conflicting authentication settings: RAPIDTRIAGE_DISABLE_AUTH/require_auth=False "
            "cannot be combined with an explicit auth token; refusing to weaken authentication silently"
        )
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

    api.include_router(build_meta_router(store))
    api.include_router(build_case_db_router(store, open_request_case_database, resolve_request_catalog_path))
    api.include_router(build_runs_router(store))
    api.include_router(build_flags_router(store))
    api.include_router(build_derived_router(store))
    api.include_router(build_analyses_router(store, owner=analysis_owner))
    api.include_router(build_ioc_router(store))
    api.include_router(build_media_router(store))
    api.include_router(build_search_router(store))
    api.include_router(build_search_index_router(store, owner=analysis_owner))
    api.include_router(build_reports_router(store))
    api.include_router(build_review_tools_router(store, open_request_case_database))

    if static_dir.is_dir():
        api.mount("/assets", StaticFiles(directory=static_dir), name="rapidtriage-assets")

        v2_dir = static_dir / "v2"
        if v2_dir.is_dir():
            api.mount("/v2", StaticFiles(directory=v2_dir, html=True), name="rapidtriage-v2")

        # RAPIDTRIAGE_CONSOLE=v2 (default): v2 bundle at "/", v1 console kept at "/legacy" for one release.
        # RAPIDTRIAGE_CONSOLE=v1: legacy v1 console at "/", v2 bundle at "/v2".
        console_mode = (os.environ.get("RAPIDTRIAGE_CONSOLE") or "v2").strip().lower()
        if console_mode not in {"v1", "v2"}:
            raise RuntimeError(f"RAPIDTRIAGE_CONSOLE must be 'v1' or 'v2', got {console_mode!r}")
        if console_mode == "v2" and v2_dir.is_dir():
            api.mount("/legacy", StaticFiles(directory=static_dir, html=True), name="rapidtriage-legacy")
            root_index = v2_dir / "index.html"
        else:
            root_index = static_dir / "index.html"

        @api.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(root_index)

        @api.get("/favicon.ico", include_in_schema=False)
        def favicon() -> FileResponse:
            return FileResponse(static_dir / "favicon.svg", media_type="image/svg+xml")

    return api


app = create_app()
