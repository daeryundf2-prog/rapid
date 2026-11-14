"""HTTP error envelope (R8 T-007, r8-contracts D.7) and response security headers.

Every 4xx/5xx JSON body keeps its existing keys untouched (``detail`` keeps its type and value:
string, 422 list or ``{code, message}`` object) and gains three top-level keys:

* ``code`` — a stable code from ``rapidtriage/core/error_codes.py`` only. Decision order:
  (1) ``detail`` is an object with a ``code``; (2) the literal table below (English route
  literals and a few shared Korean sentences); (3) the status default.
* ``message`` — a Korean sentence: the table's sentence, the ``detail`` string itself when it is
  already Korean, else the code's sentence (an English core exception text stays in ``detail``).
* ``hint`` — the next action, in Korean.

Route files are not edited (396 ``HTTPException(`` sites): the handlers here do the work in one
place. A 5xx body never carries exception text or a filesystem path — only ``crash_id``; the
crash report path goes to the server log.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.utils import is_body_allowed_for_status_code
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ...core.crash import write_crash_report
from ...core.error_codes import ERROR_CODES, default_code_for_status

LOGGER = logging.getLogger("rapidtriage.api")
HANGUL_RE = re.compile(r"[가-힣]")

#: The ``detail`` every 5xx body carries (kept from the pre-T-007 body for old clients).
INTERNAL_ERROR_DETAIL = "internal RapidTriage error; local crash report written"

# Status defaults this module emits (self-named so the code-table scanner sees them).
BAD_REQUEST = "BAD_REQUEST"
UNAUTHORIZED = "UNAUTHORIZED"
FORBIDDEN = "FORBIDDEN"
NOT_FOUND = "NOT_FOUND"
CONFLICT = "CONFLICT"
UNSUPPORTED_MEDIA = "UNSUPPORTED_MEDIA"
VALIDATION_FAILED = "VALIDATION_FAILED"
INTERNAL_ERROR = "INTERNAL_ERROR"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
TIME_BUDGET_EXCEEDED = "TIME_BUDGET_EXCEEDED"
PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
RANGE_NOT_SATISFIABLE = "RANGE_NOT_SATISFIABLE"
TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"

#: Statuses outside ``STATUS_DEFAULT_CODES`` (the table keeps 503 → ``INTERNAL_ERROR`` generic).
EXTRA_STATUS_CODES = {503: SERVICE_UNAVAILABLE}

#: Headers on every response (T-007 v3). The console is never framed, sniffed or referred.
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
)


@dataclass(frozen=True)
class LiteralError:
    """What one known ``detail`` sentence means: a code, a Korean sentence and (optional) hint."""

    code: str
    message: str = ""
    hint: str = ""


def _known(*, code: str, message: str = "", hint: str = "") -> LiteralError:
    return LiteralError(code=code, message=message, hint=hint)


_TOKEN_HINT = "처음부터 다시 조회하세요"
_PREVIEW_HINT = "다른 보기(16진수·텍스트)로 여세요"

#: Exact ``detail`` strings → code / Korean sentence / hint. English literals come from the API
#: routes and middleware; Korean ones only where a specific code applies.
KNOWN_DETAILS: dict[str, LiteralError] = {
    # middleware (factory.require_auth_token)
    "RapidTriage API host is not allowed": _known(
        code=FORBIDDEN, message="허용되지 않은 호스트 이름으로 API에 접근했습니다",
        hint="서버가 알려 준 주소(127.0.0.1 또는 localhost)로 콘솔을 여세요"),
    "RapidTriage API origin is not allowed": _known(
        code=FORBIDDEN, message="허용되지 않은 출처(Origin)에서 보낸 요청입니다",
        hint="서버가 알려 준 주소에서 연 콘솔로만 요청하세요"),
    "query token authentication is disabled; use X-RapidTriage-Token header": _known(
        code=UNAUTHORIZED, message="주소의 token 인자로는 인증할 수 없습니다",
        hint="X-RapidTriage-Token 헤더로 토큰을 보내세요"),
    "missing or invalid RapidTriage auth token": _known(code=UNAUTHORIZED),
    INTERNAL_ERROR_DETAIL: _known(code=INTERNAL_ERROR),
    # Starlette / FastAPI defaults
    "Not Found": _known(code=NOT_FOUND),
    "Method Not Allowed": _known(code=METHOD_NOT_ALLOWED),
    # runs ("런을 찾을 수 없습니다" is helpers.get_job's 404)
    "런을 찾을 수 없습니다": _known(code="RUN_NOT_FOUND"),
    "run has no outputs": _known(code="RUN_NOT_FINISHED", message="런에 아직 출력이 없습니다"),
    "run has no output directory yet": _known(code="RUN_NOT_FINISHED", message="런 출력 폴더가 아직 없습니다"),
    "run summary does not include output_dir": _known(
        code=CONFLICT, message="런 요약에 출력 폴더(output_dir)가 없습니다",
        hint="결과 폴더를 확인하거나 런을 다시 처리하세요"),
    "extract not found": _known(code=NOT_FOUND, message="추출 결과를 찾지 못했습니다",
                                hint="추출 목록을 새로 고친 뒤 다시 고르세요"),
    "invalid extract name": _known(code=BAD_REQUEST, message="추출 이름이 올바르지 않습니다",
                                   hint="추출 목록에서 이름을 다시 고르세요"),
    "extract is larger than the 2 GB zip limit": _known(
        code=PAYLOAD_TOO_LARGE, message="추출 결과가 ZIP 한도(2 GB)보다 큽니다",
        hint="추출 폴더에서 파일을 직접 복사하세요"),
    "output_name may only contain letters, digits, '.', '_' and '-'": _known(
        code=BAD_REQUEST, message="output_name에는 영문자·숫자·'.'·'_'·'-'만 쓸 수 있습니다"),
    "sort requires exactly one kind": _known(
        code=BAD_REQUEST, message="정렬하려면 종류(kind)를 하나만 지정하세요", hint="kind를 하나로 좁힌 뒤 정렬하세요"),
    "order must be asc or desc": _known(
        code=BAD_REQUEST, message="order는 asc(오름차순) 또는 desc(내림차순)여야 합니다"),
    "invalid pagination cursor": _known(code=BAD_REQUEST, message="페이지 커서가 올바르지 않습니다",
                                        hint="첫 페이지부터 다시 조회하세요"),
    "unsupported case report format": _known(
        code=NOT_FOUND, message="지원하지 않는 케이스 보고서 형식입니다", hint="보고서 형식 목록에서 다시 고르세요"),
    # source search / viewers
    "at least one keyword is required": _known(code=BAD_REQUEST, message="검색어를 하나 이상 입력하세요"),
    "resume tokens are not supported for ZIP entry source-search": _known(
        code=BAD_REQUEST, message="ZIP 내부 항목 검색에서는 이어보기 토큰을 쓸 수 없습니다", hint=_TOKEN_HINT),
    "invalid file_resume_token": _known(code=BAD_REQUEST, message="이어보기 토큰(file_resume_token)이 올바르지 않습니다",
                                        hint=_TOKEN_HINT),
    "invalid file_resume_token profile": _known(
        code=BAD_REQUEST, message="이어보기 토큰(file_resume_token)의 검색 설정이 올바르지 않습니다", hint=_TOKEN_HINT),
    "file_resume_token is missing resume state": _known(
        code=BAD_REQUEST, message="이어보기 토큰(file_resume_token)에 이어볼 위치가 없습니다", hint=_TOKEN_HINT),
    "file_resume_token does not match source file": _known(
        code=BAD_REQUEST, message="이어보기 토큰(file_resume_token)이 원본 파일과 맞지 않습니다", hint=_TOKEN_HINT),
    "file_resume_token does not match keywords": _known(
        code=BAD_REQUEST, message="이어보기 토큰(file_resume_token)이 검색어와 맞지 않습니다", hint=_TOKEN_HINT),
    "invalid sqlite_resume_token": _known(
        code=BAD_REQUEST, message="이어보기 토큰(sqlite_resume_token)이 올바르지 않습니다", hint=_TOKEN_HINT),
    "invalid sqlite_resume_token profile": _known(
        code=BAD_REQUEST, message="이어보기 토큰(sqlite_resume_token)의 검색 설정이 올바르지 않습니다", hint=_TOKEN_HINT),
    "sqlite_resume_token is missing resume state": _known(
        code=BAD_REQUEST, message="이어보기 토큰(sqlite_resume_token)에 이어볼 위치가 없습니다", hint=_TOKEN_HINT),
    "sqlite_resume_token does not match source file": _known(
        code=BAD_REQUEST, message="이어보기 토큰(sqlite_resume_token)이 원본 파일과 맞지 않습니다", hint=_TOKEN_HINT),
    "sqlite_resume_token does not match keywords": _known(
        code=BAD_REQUEST, message="이어보기 토큰(sqlite_resume_token)이 검색어와 맞지 않습니다", hint=_TOKEN_HINT),
    "source file is not readable": _known(code=NOT_FOUND, message="원본 파일을 읽을 수 없습니다",
                                          hint="증거가 연결돼 있는지, 원본 경로가 바뀌지 않았는지 확인하세요"),
    "offset is outside the source file": _known(code=RANGE_NOT_SATISFIABLE),
    "source file is not a supported SQLite database": _known(
        code=BAD_REQUEST, message="SQLite 데이터베이스로 열 수 없는 파일입니다", hint=_PREVIEW_HINT),
    "table not found in SQLite database": _known(code=NOT_FOUND, message="SQLite 데이터베이스에서 표를 찾지 못했습니다",
                                                 hint="표 목록에서 다시 고르세요"),
    "table has no readable columns": _known(code=BAD_REQUEST, message="표에 읽을 수 있는 열이 없습니다",
                                            hint="다른 표를 고르세요"),
    "where_column is not a column in the selected table": _known(
        code=BAD_REQUEST, message="where_column이 선택한 표의 열이 아닙니다", hint="표의 열 목록에서 고르세요"),
    "where_column and where_contains must be provided together": _known(
        code=BAD_REQUEST, message="where_column과 where_contains는 함께 지정해야 합니다"),
    "order_by is not a column in the selected table": _known(
        code=BAD_REQUEST, message="order_by가 선택한 표의 열이 아닙니다", hint="표의 열 목록에서 고르세요"),
    "source file is not a supported image preview": _known(
        code=BAD_REQUEST, message="이미지 미리보기를 지원하지 않는 파일입니다", hint=_PREVIEW_HINT),
    "source file is not a supported audio/video preview": _known(
        code=BAD_REQUEST, message="오디오·비디오 미리보기를 지원하지 않는 파일입니다", hint=_PREVIEW_HINT),
    "source file is not a supported EML/MBOX email preview": _known(
        code=BAD_REQUEST, message="EML·MBOX 메일 미리보기를 지원하지 않는 파일입니다", hint=_PREVIEW_HINT),
    "source file is not a supported image": _known(
        code=UNSUPPORTED_MEDIA, message="지원하지 않는 이미지 형식입니다", hint=_PREVIEW_HINT),
    "source file could not be decoded as an image": _known(
        code=UNSUPPORTED_MEDIA, message="이미지로 해석하지 못한 파일입니다", hint=_PREVIEW_HINT),
    "source image has too many pixels for a thumbnail": _known(
        code=PAYLOAD_TOO_LARGE, message="픽셀 수가 너무 많아 썸네일을 만들지 않았습니다", hint="원본 보기로 여세요"),
    "source image is too large for a thumbnail": _known(
        code=PAYLOAD_TOO_LARGE, message="이미지 파일이 너무 커서 썸네일을 만들지 않았습니다", hint="원본 보기로 여세요"),
    "thumbnail support requires Pillow": _known(
        code=SERVICE_UNAVAILABLE, message="썸네일 구성 요소(Pillow)가 없어 썸네일을 만들 수 없습니다",
        hint="Pillow를 설치한 뒤 서버를 다시 시작하세요"),
    "sidecar_index not found": _known(code=NOT_FOUND, message="부속 파일(sidecar_index)을 찾지 못했습니다"),
    "cue_index not found": _known(code=NOT_FOUND, message="자막 항목(cue_index)을 찾지 못했습니다"),
    "attachment_index not found": _known(code=NOT_FOUND, message="첨부 파일(attachment_index)을 찾지 못했습니다"),
    "message_index not found": _known(code=NOT_FOUND, message="메일(message_index)을 찾지 못했습니다"),
}

#: ``detail`` prefixes (f-string details whose tail is a value or an exception text).
KNOWN_PREFIXES: tuple[tuple[str, LiteralError], ...] = (
    ("path is outside the run's allowed source roots: ", _known(code="PATH_OUTSIDE_ALLOWED_ROOT")),
    ("unsupported bookmark source: ", _known(code=BAD_REQUEST, message="지원하지 않는 북마크 출처입니다")),
    ("failed to build OCR/translation review: ", _known(
        code=BAD_REQUEST, message="OCR·번역 검토 정보를 만들지 못했습니다", hint=_PREVIEW_HINT)),
    ("SQLite table page failed: ", _known(code=BAD_REQUEST, message="SQLite 표를 읽지 못했습니다", hint=_PREVIEW_HINT)),
    ("Email attachment package failed: ", _known(
        code=BAD_REQUEST, message="메일 첨부 파일 묶음을 만들지 못했습니다", hint=_PREVIEW_HINT)),
)


def _register_shared_korean() -> None:
    """Korean ``detail`` sentences that carry a specific code (owner default: case-run output)."""
    from .routes_cases import CASE_RUN_NEEDS_OUTPUT

    KNOWN_DETAILS.setdefault(CASE_RUN_NEEDS_OUTPUT, _known(code="OUTPUT_DIR_REQUIRED"))


def status_code_for(status: int) -> str:
    return EXTRA_STATUS_CODES.get(status) or default_code_for_status(status)


def _has_hangul(value: object) -> bool:
    return isinstance(value, str) and bool(HANGUL_RE.search(value))


def _known_detail(detail: str) -> LiteralError | None:
    known = KNOWN_DETAILS.get(detail)
    if known is not None:
        return known
    for prefix, entry in KNOWN_PREFIXES:
        if detail.startswith(prefix):
            return entry
    return None


def envelope_fields(status: int, detail: object) -> dict[str, str]:
    """``{code, message, hint}`` for an error ``detail`` answered with ``status`` (D.7)."""
    code = ""
    message = ""
    hint = ""
    if isinstance(detail, Mapping):
        raw_code = detail.get("code")
        if isinstance(raw_code, str) and raw_code in ERROR_CODES:
            code = raw_code
        if _has_hangul(detail.get("message")):
            message = str(detail["message"])
        if _has_hangul(detail.get("hint")):
            hint = str(detail["hint"])
    elif isinstance(detail, str):
        known = _known_detail(detail)
        if known is not None:
            code, message, hint = known.code, known.message, known.hint
        if not message and _has_hangul(detail):
            message = detail
    elif isinstance(detail, list):
        for item in detail:
            if isinstance(item, Mapping) and _has_hangul(item.get("msg")):
                message = str(item["msg"])
                break
    if not code or code not in ERROR_CODES:
        code = status_code_for(status)
    row = ERROR_CODES[code]
    return {"code": code, "message": message or row.message_ko, "hint": hint or row.hint_ko}


def error_body(status: int, content: Mapping[str, object]) -> dict[str, object]:
    """``content`` with the envelope keys added; keys already in ``content`` are never replaced."""
    body = dict(content)
    for key, value in envelope_fields(status, content.get("detail")).items():
        body.setdefault(key, value)
    return body


def error_response(
    status: int, detail: object, *, headers: Mapping[str, str] | None = None, **extra: object
) -> JSONResponse:
    """A 4xx/5xx JSON response ``{"detail": detail, **extra, code, message, hint}``."""
    return JSONResponse(status_code=status, content=error_body(status, {"detail": detail, **extra}), headers=headers)


def crash_response(exc: BaseException, request: Request) -> JSONResponse:
    """500 for an unexpected failure: crash report on disk, ``crash_id`` only in the body."""
    try:
        report = write_crash_report(
            exc, context={"component": "web-api", "method": request.method, "path": request.url.path}
        )
    except Exception:
        LOGGER.exception("RapidTriage API error while writing a crash report for %s %s", request.method, request.url.path)
        return error_response(500, INTERNAL_ERROR_DETAIL)
    LOGGER.error(
        "RapidTriage API internal error %s on %s %s; crash report: %s",
        report["crash_id"], request.method, request.url.path, report["path"],
    )
    return error_response(500, INTERNAL_ERROR_DETAIL, crash_id=report["crash_id"])


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    if exc.status_code == 500:
        # ``HTTPException(500, detail=str(exc))``: the text may hold paths — log it, never send it.
        return crash_response(exc.__cause__ or exc.__context__ or exc, request)
    return error_response(exc.status_code, exc.detail, headers=headers)


def validation_error_response(detail: object) -> JSONResponse:
    """422 for a request validation error (``detail`` is the list FastAPI or the Korean labeller made)."""
    return error_response(422, detail)


def validation_errors_detail(exc: RequestValidationError) -> object:
    return jsonable_encoder(exc.errors())


def install_error_envelope(app: FastAPI) -> None:
    """Register the ``HTTPException`` handler and the fallback envelope + security header layers."""
    _register_shared_korean()
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_middleware(ErrorEnvelopeMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)


class SecurityHeadersMiddleware:
    """Adds ``SECURITY_HEADERS`` to every HTTP response that does not set them itself."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers += [(name, value) for name, value in SECURITY_HEADERS if name not in present]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class ErrorEnvelopeMiddleware:
    """Adds the envelope to JSON error bodies built outside the handlers (a route returning
    ``JSONResponse(status_code=4xx)`` itself). Bodies that already carry ``code`` pass unchanged."""

    MAX_BODY = 1 << 20

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start: Message | None = None
        chunks: list[bytes] = []

        async def send_enveloped(message: Message) -> None:
            nonlocal start
            if message["type"] == "http.response.start":
                status = int(message["status"])
                content_type = dict(message.get("headers", [])).get(b"content-type", b"")
                if status >= 400 and content_type.startswith(b"application/json"):
                    start = message
                    return
                await send(message)
                return
            if start is None or message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False) and sum(map(len, chunks)) <= self.MAX_BODY:
                return
            body = b"".join(chunks)
            if not message.get("more_body", False):
                body = _enveloped_body(int(start["status"]), body)
            headers = [(name, value) for name, value in start.get("headers", []) if name.lower() != b"content-length"]
            if not message.get("more_body", False):
                headers.append((b"content-length", str(len(body)).encode("latin-1")))
            await send({**start, "headers": headers})
            await send({"type": "http.response.body", "body": body, "more_body": message.get("more_body", False)})
            start = None
            chunks.clear()

        await self.app(scope, receive, send_enveloped)


def _enveloped_body(status: int, body: bytes) -> bytes:
    try:
        content = json.loads(body)
    except ValueError:
        return body
    if not isinstance(content, dict) or "code" in content or "detail" not in content:
        return body
    return JSONResponse(status_code=status, content=error_body(status, content)).body
