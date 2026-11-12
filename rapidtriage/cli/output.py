"""Shared CLI JSON output helpers: one additive ``_envelope`` key (D.8 / D71).

Every ``--json`` payload keeps its current top-level keys untouched and gains
exactly one extra key, ``_envelope``. Existing keys such as ``doctor``'s
``status: "warn"`` or ``plugins``'s ``errors: []`` therefore keep their meaning;
envelope metadata never shares a key with command data.

This module only provides the helpers (T-160). Commands are migrated to
``emit``/``fail`` later (T-111, T-246, T-247); exit-code migration away from
``2`` for failures is T-249.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections.abc import Iterable, Mapping
from typing import NoReturn, TextIO

from .. import __version__

ENVELOPE_KEY = "_envelope"
SCHEMA = "rapidtriage.cli.v1"

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_NOT_FOUND = 4
# Phase 1 of the exit-code migration (D.8): failures keep exiting 2, as the
# current ``parser.error`` paths do, until T-249 moves them to 1/4.
TRANSITIONAL_FAIL_EXIT_CODE = EXIT_USAGE

STATUSES = ("ok", "partial", "error")
DEFAULT_BUDGET_BYTES = 32 * 1024
STDERR_LINE_MAX_BYTES = 200

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PROCESS_STARTED = time.monotonic()


def _elapsed_ms(started: float | None) -> int:
    origin = _PROCESS_STARTED if started is None else started
    return max(0, int((time.monotonic() - origin) * 1000))


def _validate_code(code: str) -> str:
    # TODO(T-162): resolve codes against rapidtriage/core/error_codes.py once the
    # shared server/CLI code table lands; until then accept any UPPER_SNAKE code.
    if not isinstance(code, str) or not _CODE_RE.match(code):
        raise ValueError(f"error code must be UPPER_SNAKE_CASE, got {code!r}")
    return code


def _issue(code: str, message: str, hint: str | None = None) -> dict[str, str]:
    item = {"code": _validate_code(code), "message": str(message)}
    if hint:
        item["hint"] = str(hint)
    return item


def _normalize_issues(items: Iterable[Mapping[str, object]] | None) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for item in items or ():
        hint = item.get("hint")
        normalized.append(_issue(str(item.get("code", "")), str(item.get("message", "")), str(hint) if hint else None))
    return normalized


def build_envelope(
    *,
    command: str,
    status: str = "ok",
    exit_code: int = EXIT_OK,
    started: float | None = None,
    truncated: bool = False,
    warnings: Iterable[Mapping[str, object]] | None = None,
    errors: Iterable[Mapping[str, object]] | None = None,
    full_output: str | None = None,
) -> dict[str, object]:
    """Return the ``_envelope`` value. ``started`` is a ``time.monotonic()`` stamp."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
    envelope: dict[str, object] = {
        "schema": SCHEMA,
        "command": str(command),
        "status": status,
        "exit_code": int(exit_code),
        "tool_version": __version__,
        "elapsed_ms": _elapsed_ms(started),
        "truncated": bool(truncated),
        "warnings": _normalize_issues(warnings),
        "errors": _normalize_issues(errors),
    }
    if full_output:
        envelope["full_output"] = str(full_output)
    return envelope


def with_envelope(payload: Mapping[str, object], envelope: Mapping[str, object]) -> dict[str, object]:
    """Copy ``payload`` and add the single ``_envelope`` key; existing keys are never renamed."""
    if ENVELOPE_KEY in payload:
        raise ValueError(f"payload already carries {ENVELOPE_KEY!r}")
    result = dict(payload)
    result[ENVELOPE_KEY] = dict(envelope)
    return result


def _dumps(payload: Mapping[str, object]) -> str:
    # Same formatting as the existing ``print(json.dumps(..., ensure_ascii=False, indent=2))`` calls.
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _size(payload: Mapping[str, object]) -> int:
    return len(_dumps(payload).encode("utf-8"))


def apply_budget(payload: Mapping[str, object], budget_bytes: int) -> tuple[dict[str, object], bool]:
    """Shorten top-level lists until the serialized payload fits ``budget_bytes``.

    Only list lengths change; the top-level key set stays identical. Returns the
    (possibly copied) payload and whether anything was cut.
    """
    result = dict(payload)
    if _size(result) <= budget_bytes:
        return result, False
    truncated = False
    while _size(result) > budget_bytes:
        lists = [(key, value) for key, value in result.items() if isinstance(value, list) and value]
        if not lists:
            break
        key, value = max(lists, key=lambda kv: len(_dumps({"v": kv[1]})))
        result[key] = value[: len(value) // 2]
        truncated = True
    return result, truncated


def emit(
    payload: Mapping[str, object],
    *,
    command: str,
    status: str = "ok",
    exit_code: int = EXIT_OK,
    started: float | None = None,
    warnings: Iterable[Mapping[str, object]] | None = None,
    errors: Iterable[Mapping[str, object]] | None = None,
    budget_bytes: int | None = None,
    full_output: str | None = None,
    stream: TextIO | None = None,
) -> dict[str, object]:
    """Print ``payload`` plus one ``_envelope`` key as JSON and return what was printed.

    ``budget_bytes`` (e.g. ``DEFAULT_BUDGET_BYTES``) opts into list truncation;
    ``None`` keeps today's full output. ``full_output`` names the file that holds
    the untruncated result.
    """
    body = dict(payload)
    truncated = False
    if budget_bytes is not None:
        body, truncated = apply_budget(body, budget_bytes)
    envelope = build_envelope(
        command=command,
        status=status,
        exit_code=exit_code,
        started=started,
        truncated=truncated,
        warnings=warnings,
        errors=errors,
        full_output=full_output if truncated else None,
    )
    result = with_envelope(body, envelope)
    print(_dumps(result), file=stream if stream is not None else sys.stdout)
    return result


def _clip_bytes(text: str, limit: int) -> str:
    line = " ".join(str(text).split())
    encoded = line.encode("utf-8")
    if len(encoded) <= limit:
        return line
    ellipsis = "…"
    room = limit - len(ellipsis.encode("utf-8"))
    return encoded[:room].decode("utf-8", errors="ignore") + ellipsis


def stderr_line(code: str, message: str) -> str:
    """One ``CODE: message`` line, whitespace-collapsed, at most 200 UTF-8 bytes."""
    return _clip_bytes(f"{_validate_code(code)}: {message}", STDERR_LINE_MAX_BYTES)


def fail(
    code: str,
    message: str,
    *,
    command: str,
    json_mode: bool,
    hint: str | None = None,
    payload: Mapping[str, object] | None = None,
    exit_code: int = TRANSITIONAL_FAIL_EXIT_CODE,
    started: float | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> NoReturn:
    """Report a failure and exit.

    With ``json_mode`` one JSON document (``_envelope.status == "error"``) goes to
    stdout. In both modes stderr gets exactly one line (``CODE: <Korean message>``,
    at most 200 bytes) and no usage text. Raises ``SystemExit(exit_code)``.
    """
    issue = _issue(code, message, hint)
    if json_mode:
        envelope = build_envelope(command=command, status="error", exit_code=exit_code, started=started, errors=[issue])
        result = with_envelope(payload or {}, envelope)
        print(_dumps(result), file=stdout if stdout is not None else sys.stdout)
    print(stderr_line(code, message), file=stderr if stderr is not None else sys.stderr)
    raise SystemExit(exit_code)
