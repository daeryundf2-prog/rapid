"""Shared output fields for AI transcripts. Only selected evidence fields reach a row."""
from __future__ import annotations

import datetime as dt
import json
import math
import re
import shlex
from dataclasses import dataclass, field

from ..core.filetime import unix_to_iso
from ..core.models import ArtifactRecord
from .url_redaction import REDACTED_VALUE, redact_url

TEXT_LIMIT = 8192
# Authorization and cookie headers: every scheme (Bearer, Basic, Token, Digest, ...) and the
# whole value to the end of the line or closing quote, including quoted Digest parameters.
_HEADER = re.compile(
    r"""(?im)(?P<label>\b(?:proxy-)?(?:authorization|set-cookie|cookie)\b["']?\s*[:=]\s*)"""
    r"""(?:"(?:\\.|[^"\\\r\n])*"|'[^'\r\n]*'|(?:[^\r\n"']|"[^"\r\n]*")+)"""
)
# Mask named assignments (including quoted values), option arguments and bearer tokens.
_SECRET = re.compile(
    r"""(?ix)(?P<label>\b(?:[\w.-]{0,64}[_-])?(?:api[_-]?key|(?:access|secret|private)[_-]key|token|secret|password|"""
    r"""passwd|authorization|credential)s?["']?\s*(?:[:=]\s*|\s+)(?:bearer\s+|basic\s+)?|\b(?:bearer|basic)\s+)"""
    r"""(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s,;}"']+)"""
)
_TOKEN = re.compile(
    r"\b(?:sk-[\w-]{12,}|gh[pousr]_[\w]{12,}|github_pat_[\w]+|xox[baprs]-[\w-]+|AIza[\w-]{20,}|glpat-[\w-]{20,}"
    r"|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|(?:AKIA|ASIA)[0-9A-Z]{16}|eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*)"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL)
# RFC 3339 date-time only: no week dates, basic format, space separator or local wall time.
_RFC3339 = re.compile(r"(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})")


def clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = redact_url(_PRIVATE_KEY.sub(REDACTED_VALUE, value))
    text = _HEADER.sub(lambda m: m["label"] + REDACTED_VALUE, text)
    text = _SECRET.sub(lambda m: m["label"] + REDACTED_VALUE, text)
    return _TOKEN.sub(REDACTED_VALUE, text)[:TEXT_LIMIT].encode("utf-8", "replace").decode()


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def items(value: object) -> list:
    return value if isinstance(value, list) else []


def content(value: object) -> str:
    if isinstance(value, str):
        return value
    return "\n".join(
        part if isinstance(part, str) else part["text"]
        for part in items(value)
        if isinstance(part, str) or isinstance(mapping(part).get("text"), str)
    )


def utc(raw: object, unit: str) -> str | None:
    """RFC 3339 text with an explicit offset, or integer-exact epoch ``s``/``ms`` -> ISO UTC (``+00:00``).

    Fraction digits are kept as recorded (padded to microseconds; nanoseconds are not rounded).
    Anything else, including a wall time without an offset, returns ``None``.
    """
    if isinstance(raw, str):
        match = _RFC3339.fullmatch(raw)
        if not match:
            return None
        date, clock, fraction, zone = match.groups()
        try:
            instant = dt.datetime.fromisoformat(f"{date}T{clock}{'+00:00' if zone in 'Zz' else zone}")
            base = instant.astimezone(dt.timezone.utc).isoformat()[:19]
        except (ValueError, OverflowError):
            return None
        digits = (fraction or "").ljust(6, "0")
        digits = digits[:6] + digits[6:].rstrip("0")
        return f"{base}{'.' + digits if int(digits) else ''}+00:00"
    if type(raw) in (int, float) and unit in ("s", "ms") and math.isfinite(raw):
        return unix_to_iso(raw, unit=unit)
    return None


@dataclass
class Source:
    kind: str
    path: str
    agent: str
    location: dict = field(default_factory=dict)
    session: str = ""
    cwd: str = ""
    model: str = ""
    version: str = ""
    app_version: str = ""

    def row(self, category, *, role="", timestamp=None, unit="", text="", model="", **fields):
        flags = ["schema-version-not-validated"]
        # No layout version is inferred from field shapes: an unrecorded version stays empty and flagged.
        if not (isinstance(self.version, str) and self.version) and not (
                isinstance(self.app_version, str) and self.app_version):
            flags.append("version-unknown")
        normalized = utc(timestamp, unit)
        if timestamp is not None and normalized is None:
            flags.append("timestamp-not-normalized")
        if isinstance(text, str) and len(text) > TEXT_LIMIT:
            flags.append("text-length-limit")
        raw = clean(timestamp) if isinstance(timestamp, str) else None
        if type(timestamp) is int or (type(timestamp) is float and math.isfinite(timestamp)):
            raw = timestamp
        details = {
            "parser": self.kind, "parser_version": "1", "agent": self.agent,
            "source_path": self.path, **self.location, "session_id": clean(self.session),
            "role": clean(role), "cwd": clean(self.cwd), "model": clean(model or self.model),
            "timestamp_raw": raw, "timestamp_utc": normalized, "text": clean(text),
            "tool_name": "", "command_line": "", "file_paths": [],
            "schema_version": clean(self.version), "app_version": clean(self.app_version), "flags": flags, "validation_required": True,
        }
        for key, value in fields.items():
            if key in ("env_names", "file_paths") and isinstance(value, list):
                details[key] = [clean(v) for v in value[:64] if isinstance(v, str)]
                if len(value) > 64:
                    flags.append("list-length-limit")
            else:
                details[key] = value if key == "damaged_count" else clean(value)
                if isinstance(value, str) and len(value) > TEXT_LIMIT and "text-length-limit" not in flags:
                    flags.append("text-length-limit")
        return ArtifactRecord(self.kind, "agent-" + category, self.path, category != "parse-note", details)

    def note(self, reason, **fields):
        row = self.row("parse-note", reason=reason, **fields)
        if fields.get("damaged_count") or reason in ("source-unreadable", "invalid-document", "invalid-editor-json"):
            row.details["parser_error"] = True
        return row


def tool(src, name, arguments, *, call_id="", timestamp=None, unit="", model="", patch=None):
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, RecursionError):
            yield src.note("invalid-tool-arguments", call_id=call_id)
    args = mapping(arguments)
    paths = []
    for key in ("path", "file_path", "filePath", "relativeWorkspacePath", "absolute_path", "paths", "file_paths"):
        value = args.get(key)
        paths.extend([value] if isinstance(value, str) else items(value))
    if isinstance(patch, str):
        paths.extend(re.findall(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): ([^\r\n]+)", patch, re.MULTILINE))
    command = args.get("command", args.get("cmd", ""))
    if isinstance(command, list):
        command = shlex.join([v for v in command if isinstance(v, str)])
    yield src.row("tool-call", role="assistant", timestamp=timestamp, unit=unit, model=model,
                  tool_name=name, call_id=call_id, file_paths=paths, command_line=command)
