"""Request body size cap (remote-use audit GAP-6).

Every route used to read its whole body into memory before validating it, so a
few large JSON bodies could exhaust the server's memory. ``RequestBodyLimit``
answers 413 before the app reads anything when ``Content-Length`` is over the
cap, and counts the bytes of a body without one (chunked) as the app reads them:
past the cap the app sees the client disconnect, its own answer is dropped and
the client gets 413. (An exception raised from ``receive`` would reach the route
wrapped in an exception group by the ``BaseHTTPMiddleware`` layers.)
"""

from __future__ import annotations

import os

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ...core.search_index.hashsets import MAX_UPLOAD_BYTES

MAX_BODY_BYTES_ENV = "RAPIDTRIAGE_MAX_BODY_BYTES"
DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024
#: ``POST /api/hash-sets`` enforces its own 50 MB cap (plus multipart framing) with its own message.
HASH_SET_UPLOAD_PATH = "/api/hash-sets"
HASH_SET_UPLOAD_MAX_BYTES = MAX_UPLOAD_BYTES + 1024 * 1024


def max_body_bytes() -> int:
    """``RAPIDTRIAGE_MAX_BODY_BYTES`` (a positive integer; unset or invalid -> ``DEFAULT_MAX_BODY_BYTES``)."""
    raw = os.environ.get(MAX_BODY_BYTES_ENV, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_MAX_BODY_BYTES


def too_large_detail(limit: int) -> str:
    return f"요청 본문이 너무 큽니다(최대 {limit:,} bytes, {MAX_BODY_BYTES_ENV})"


class RequestBodyLimit:
    """413 for a request body over ``max_bytes`` (``POST /api/hash-sets``: ``upload_max_bytes``)."""

    def __init__(self, app: ASGIApp, *, max_bytes: int, upload_max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.upload_max_bytes = max(max_bytes, upload_max_bytes or 0)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        upload = scope["method"] == "POST" and scope["path"] == HASH_SET_UPLOAD_PATH
        limit = self.upload_max_bytes if upload else self.max_bytes
        declared = Headers(scope=scope).get("content-length", "").strip()
        if declared.isdigit() and int(declared) > limit:
            await JSONResponse(status_code=413, content={"detail": too_large_detail(limit)})(scope, receive, send)
            return
        received = 0
        too_large = False
        response_started = False

        async def counted_receive() -> Message:
            nonlocal received, too_large
            if too_large:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if too_large and not response_started:
                return  # the app's answer to the cut-off body; the 413 below replaces it
            response_started = response_started or message["type"] == "http.response.start"
            await send(message)

        await self.app(scope, counted_receive, guarded_send)
        if too_large and not response_started:
            await JSONResponse(status_code=413, content={"detail": too_large_detail(limit)})(scope, receive, send)
