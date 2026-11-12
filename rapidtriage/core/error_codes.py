"""Single source of the stable error codes shared by the HTTP server and the CLI (R8 T-162).

Every code a RapidTriage response, CLI envelope or list ``notice`` may carry is one row here:
HTTP status, CLI exit code, category, a Korean sentence, a Korean hint (the next action) and an
English short label. ``docs/api-error-codes.md`` is generated from this table
(``python -m rapidtriage.core.error_codes --write docs/api-error-codes.md``) and
``tests/test_error_codes.py`` keeps the two in sync.

Rules (r8-contracts D.7 / D.8):

* A code string, once shipped, never changes or disappears — rows are only added.
* ``state="active"``: the code is already emitted by ``rapidtriage/`` (the test finds its literal).
  ``state="reserved"``: registered for an upcoming task (``owner``) or for the front end only.
* CLI exit codes follow D.8 (0 ok / 1 failure / 2 usage / 3 partial / 4 target missing). Until
  T-249 the CLI still exits 2 for most failures; ``exit_code`` is the target value.
* ``http_status=None`` means the code never sets a status line by itself (a body field, a list
  ``notice``, a ``readonly_reason`` value, a CLI-only or front-end-only code).

This module is data only: it imports nothing from ``rapidtriage`` and rewires no handler.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Surface = Literal["http", "body", "notice", "readonly_reason", "cli", "frontend"]
State = Literal["active", "reserved"]


@dataclass(frozen=True)
class ErrorCode:
    code: str
    http_status: int | None
    exit_code: int | None
    category: str
    surface: Surface
    state: State
    message_ko: str
    hint_ko: str
    short_en: str
    owner: str = ""


def _e(
    code: str,
    http_status: int | None,
    exit_code: int | None,
    category: str,
    surface: Surface,
    state: State,
    message_ko: str,
    hint_ko: str,
    short_en: str,
    owner: str = "",
) -> ErrorCode:
    return ErrorCode(code, http_status, exit_code, category, surface, state, message_ko, hint_ko, short_en, owner)


#: Category labels in the order the generated document lists them.
CATEGORIES: dict[str, str] = {
    "output": "출력 위치 보호",
    "path": "경로·접근 제한",
    "sample": "연습 샘플",
    "import": "결과 가져오기",
    "run": "런 상태",
    "export": "내보내기",
    "case": "케이스",
    "list": "목록 부분 결과",
    "request": "요청 공통(상태 코드 기본값)",
    "network": "네트워크(프런트 전용)",
}

_ROWS: tuple[ErrorCode, ...] = (
    # -- output guard (core/output_guard.py, api 422 / CLI parser error) --------------------------
    _e("OUTPUT_INSIDE_EVIDENCE", 422, 2, "output", "http", "active",
       "출력 위치가 증거 경로 안(또는 증거와 같은 경로)입니다. 증거에는 아무것도 쓰지 않습니다",
       "증거 밖의 출력 폴더를 지정하세요", "Output folder is inside the evidence"),
    _e("EVIDENCE_INSIDE_OUTPUT", 422, 2, "output", "http", "active",
       "증거가 출력 폴더 안에 있습니다. 출력 폴더는 덮어쓰기·정리 대상이라 증거를 담을 수 없습니다",
       "증거를 담지 않은 다른 출력 폴더를 지정하세요", "Evidence is inside the output folder"),
    _e("OUTPUT_DIR_REQUIRED", 422, 2, "output", "http", "active",
       "출력 폴더가 지정되지 않았습니다. 원본 증거 옆이나 증거 폴더 안에는 런 출력을 만들지 않습니다",
       "증거 밖의 출력 폴더를 지정하세요", "Output folder is required"),
    _e("OUTPUT_DIR_BUSY", 409, 1, "output", "http", "reserved",
       "같은 출력 폴더를 쓰는 런이 대기·실행 중입니다",
       "그 런이 끝나기를 기다리거나 다른 출력 폴더를 지정하세요", "Output folder is in use by another run",
       "T-007"),
    # -- path / access ----------------------------------------------------------------------------
    _e("PATH_OUTSIDE_ALLOWED_ROOT", 403, 1, "path", "http", "active",
       "요청한 경로가 서버가 허용한 위치 밖입니다",
       "허용된 위치(서버 설정) 아래의 경로를 지정하세요", "Path is outside the allowed root"),
    _e("CREDENTIAL_FILE_WITHHELD", 403, 1, "path", "http", "active",
       "자격 증명·비밀 파일이라 원본 내려받기·미리보기를 제공하지 않습니다",
       "파일 메타데이터와 보고서의 가린 값만 확인하세요", "Credential file content is withheld"),
    _e("SERVER_READ_ONLY", None, None, "path", "readonly_reason", "reserved",
       "서버가 읽기 전용으로 실행 중이라 이 결과에 쓰지 않습니다",
       "쓰기가 필요하면 읽기 전용 설정 없이 서버를 다시 시작하세요", "Server is read-only", "T-007"),
    # -- practice sample (core/sample_case.py) ----------------------------------------------------
    _e("SAMPLE_DIR_NOT_EMPTY", 409, 1, "sample", "http", "active",
       "샘플 폴더가 이미 있고 비어 있지 않습니다(덮어쓰기 꺼짐)",
       "덮어쓰기를 켜거나 다른 샘플 폴더를 지정하세요", "Sample folder is not empty"),
    _e("SAMPLE_DIR_NOT_SAMPLE", 409, 1, "sample", "http", "active",
       "샘플 폴더가 아닌 폴더(또는 링크)라서 지우지 않았습니다",
       "RapidTriage가 만든 샘플 폴더나 빈 폴더를 지정하세요", "Folder is not a RapidTriage sample"),
    _e("SAMPLE_DIR_HAS_OTHER_FILES", 409, 1, "sample", "http", "active",
       "샘플 폴더에 샘플이 만들지 않은 파일이 있어 지우지 않았습니다",
       "다른 파일을 옮기거나 빈 폴더를 지정하세요", "Sample folder holds other files"),
    _e("SAMPLE_CASE_FAILED", 400, 1, "sample", "http", "active",
       "연습 샘플을 만들거나 처리하지 못했습니다",
       "메시지의 원인을 확인한 뒤 다시 시도하세요", "Sample case failed"),
    # -- run import (core/jobs.py) ----------------------------------------------------------------
    _e("IMPORT_SUMMARY_INVALID", 400, 1, "import", "http", "active",
       "가져올 결과 폴더의 실행 요약 JSON이 올바르지 않습니다",
       "RapidTriage가 만든 결과 폴더인지 확인하세요", "Run summary is invalid"),
    _e("IMPORT_OUTPUT_OUTSIDE_FOLDER", 400, 1, "import", "http", "active",
       "실행 요약의 산출물 경로가 가져오는 결과 폴더 밖을 가리킵니다",
       "결과 폴더를 통째로 옮긴 원본인지 확인하세요", "Run output path escapes the folder"),
    # -- run state --------------------------------------------------------------------------------
    _e("RUN_READ_ONLY", 409, 1, "run", "http", "active",
       "읽기 전용으로 연 결과입니다(결과 폴더가 증거 안에 있음). 이 결과 폴더에는 아무것도 쓰지 않습니다",
       "결과 폴더를 증거 밖으로 옮긴 뒤 다시 가져오세요", "Run is read-only"),
    _e("RUN_NOT_FOUND", 404, 4, "run", "http", "reserved",
       "해당 런을 찾지 못했습니다", "런 목록에서 런 ID를 확인하세요", "Run not found", "T-007·T-160"),
    _e("RUN_NOT_FINISHED", 409, 1, "run", "http", "reserved",
       "런이 아직 끝나지 않았습니다", "런이 끝난 뒤 다시 시도하세요", "Run has not finished", "T-007·T-160"),
    # -- export -----------------------------------------------------------------------------------
    _e("EXPORT_NOT_WRITTEN", 404, 4, "export", "http", "active",
       "저장된 내보내기 결과가 없습니다",
       "먼저 내보내기(또는 zip 만들기)를 실행하세요", "Export has not been written"),
    # -- case -------------------------------------------------------------------------------------
    _e("CASE_DB_UNREADABLE", None, 1, "case", "body", "active",
       "케이스 DB를 읽지 못했습니다",
       "케이스 DB 파일의 위치·권한을 확인하세요(검토 표시는 비어 보일 수 있습니다)", "Case DB is unreadable"),
    _e("CASE_JSON_UNREADABLE", None, 1, "case", "body", "active",
       "검토 목록 파일(rapidtriage-case.json)을 읽지 못했습니다",
       "파일이 손상되지 않았는지 확인하세요", "Case review JSON is unreadable"),
    _e("CASE_NOT_FOUND", 404, 4, "case", "http", "reserved",
       "해당 케이스를 찾지 못했습니다", "케이스 목록에서 케이스 ID를 확인하세요", "Case not found", "T-007·T-160"),
    _e("REVIEW_CONFLICT", 409, 1, "case", "http", "reserved",
       "다른 검토자가 먼저 같은 항목의 검토 표시를 바꿨습니다",
       "목록을 새로 고친 뒤 다시 표시하세요", "Review mark changed concurrently", "T-007"),
    # -- list partial results (notice) ------------------------------------------------------------
    _e("SCAN_BUDGET_STOPPED", None, 3, "list", "notice", "reserved",
       "확인 한도에 도달해 목록 일부만 확인했습니다",
       "필터를 좁히거나 검색 색인을 만든 뒤 다시 조회하세요", "Scan budget reached", "T-007"),
    _e("TOTAL_NOT_COUNTED", None, 3, "list", "notice", "reserved",
       "전체 건수를 세지 않았습니다(표시한 수는 최소값입니다)",
       "정확한 건수가 필요하면 필터를 좁혀 다시 조회하세요", "Total was not counted", "T-007"),
    # -- request defaults by HTTP status (T-007 decision step 3) ----------------------------------
    _e("BAD_REQUEST", 400, 2, "request", "http", "reserved",
       "요청 내용이 올바르지 않습니다", "입력값을 확인한 뒤 다시 시도하세요", "Bad request", "T-007"),
    _e("UNAUTHORIZED", 401, 1, "request", "http", "reserved",
       "인증 토큰이 없거나 맞지 않습니다", "콘솔을 서버가 알려 준 주소로 다시 여세요", "Unauthorized", "T-007"),
    _e("FORBIDDEN", 403, 1, "request", "http", "reserved",
       "이 요청은 허용되지 않습니다", "허용된 주소·경로에서 다시 시도하세요", "Forbidden", "T-007"),
    _e("NOT_FOUND", 404, 4, "request", "http", "reserved",
       "요청한 대상을 찾지 못했습니다", "주소나 ID를 확인하세요", "Not found", "T-007"),
    _e("CONFLICT", 409, 1, "request", "http", "reserved",
       "현재 상태와 맞지 않아 요청을 처리하지 못했습니다", "상태를 새로 고친 뒤 다시 시도하세요", "Conflict", "T-007"),
    _e("UNSUPPORTED_MEDIA", 415, 2, "request", "http", "reserved",
       "지원하지 않는 요청 형식입니다", "JSON 본문(application/json)으로 보내세요", "Unsupported media type", "T-007"),
    _e("VALIDATION_FAILED", 422, 2, "request", "http", "reserved",
       "입력값 검사를 통과하지 못했습니다", "표시된 항목을 고친 뒤 다시 시도하세요", "Validation failed", "T-007"),
    _e("INTERNAL_ERROR", 500, 1, "request", "http", "reserved",
       "서버 내부 오류가 발생했습니다", "오류 ID(crash_id)를 기록해 관리자에게 알리세요", "Internal error", "T-007"),
    _e("USAGE_ERROR", None, 2, "request", "cli", "reserved",
       "명령 사용법이 올바르지 않습니다", "--help로 사용법을 확인하세요", "Usage error", "T-160"),
    # -- network (front end only: client.ts api()) ------------------------------------------------
    _e("NETWORK_UNREACHABLE", None, None, "network", "frontend", "reserved",
       "서버에 연결하지 못했습니다", "서버가 실행 중인지 확인한 뒤 다시 시도하세요", "Server unreachable", "T-007"),
    _e("REQUEST_TIMEOUT", None, None, "network", "frontend", "reserved",
       "응답 시간이 초과되었습니다", "잠시 뒤 다시 시도하세요", "Request timed out", "T-007"),
    _e("REQUEST_ABORTED", None, None, "network", "frontend", "reserved",
       "요청이 중단되었습니다", "필요하면 다시 시도하세요", "Request aborted", "T-007"),
)

ERROR_CODES: dict[str, ErrorCode] = {row.code: row for row in _ROWS}

#: Default ``code`` per HTTP status when nothing more specific applies (r8-contracts D.7 step 3).
STATUS_DEFAULT_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    415: "UNSUPPORTED_MEDIA",
    422: "VALIDATION_FAILED",
    500: "INTERNAL_ERROR",
}


def get(code: str) -> ErrorCode:
    """Return the registered row for ``code`` (``KeyError`` for an unregistered code)."""
    return ERROR_CODES[code]


def default_code_for_status(status: int) -> str:
    """Fallback code for an HTTP status (``INTERNAL_ERROR`` for 5xx, ``BAD_REQUEST`` for other 4xx)."""
    if status in STATUS_DEFAULT_CODES:
        return STATUS_DEFAULT_CODES[status]
    return "INTERNAL_ERROR" if status >= 500 else "BAD_REQUEST"


def _cell(value: object) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|")


def render_markdown() -> str:
    """Render ``docs/api-error-codes.md`` (LF, trailing newline) from the table."""
    lines = [
        "# RapidTriage 오류 코드표",
        "",
        "<!-- 생성물: 직접 고치지 마세요. 원본은 rapidtriage/core/error_codes.py 입니다. -->",
        "<!-- 갱신: python -m rapidtriage.core.error_codes --write docs/api-error-codes.md -->",
        "",
        "서버(HTTP 오류 본문의 `code`)와 CLI(`_envelope.errors[].code`)가 같은 표를 씁니다(r8 계약 D.7·D.8).",
        "코드 문자열은 한 번 내보내면 바꾸거나 지우지 않습니다(추가만).",
        "",
        "- **상태**: `active` = 지금 코드에서 내보냄, `reserved` = 예약(담당 과제가 연결하거나 프런트 전용).",
        "- **노출**: `http` 오류 응답 · `body` 응답 본문 필드 · `notice` 목록 부분 결과 · "
        "`readonly_reason` 읽기 전용 사유 · `cli` CLI 전용 · `frontend` 프런트 전용.",
        "- **종료 코드**(CLI): 0 성공 / 1 실패 / 2 사용법 / 3 부분 성공 / 4 대상 없음. "
        "T-249 전까지 CLI는 대부분 2로 끝나며, 표의 값은 목표값입니다.",
        "",
        f"코드 {len(_ROWS)}종 (active {sum(r.state == 'active' for r in _ROWS)} · "
        f"reserved {sum(r.state == 'reserved' for r in _ROWS)}).",
    ]
    for category, label in CATEGORIES.items():
        rows = [row for row in _ROWS if row.category == category]
        if not rows:
            continue
        lines += [
            "",
            f"## {label} (`{category}`)",
            "",
            "| 코드 | HTTP | 종료 | 노출 | 상태 | 문장 | 힌트 | English |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for row in rows:
            state = row.state if not row.owner else f"{row.state} ({row.owner})"
            cells = [
                f"`{row.code}`",
                _cell(row.http_status),
                _cell(row.exit_code),
                row.surface,
                _cell(state),
                _cell(row.message_ko),
                _cell(row.hint_ko),
                _cell(row.short_en),
            ]
            lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RapidTriage error code table (docs generator)")
    parser.add_argument("--write", metavar="PATH", help="write the Markdown table to PATH (LF)")
    parser.add_argument("--check", metavar="PATH", help="exit 1 when PATH differs from the table")
    args = parser.parse_args(argv)
    text = render_markdown()
    if args.check:
        current = Path(args.check).read_bytes().decode("utf-8") if Path(args.check).is_file() else ""
        if current != text:
            print(f"{args.check} is out of date; run --write {args.check}", file=sys.stderr)
            return 1
        return 0
    if args.write:
        Path(args.write).write_bytes(text.encode("utf-8"))
        return 0
    sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
