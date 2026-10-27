"""Masking for every text field an AI agent adapter emits (R7 AI plan §3.2 common rules).

Two passes, in this order:

1. :func:`mask_api_keys` - API key / token *values* recognised by their vendor prefix
   (``sk-ant-``, ``sk-proj-``, ``sk-``, ``AIza``, ``hf_``, ``ghp_``, ``github_pat_``, ``xai-``,
   ``gsk_``, ``AKIA``), ``Authorization: Bearer`` values, ``*_API_KEY=`` / ``*_TOKEN=`` style
   environment assignments and JSON ``"token": "..."`` pairs. A key becomes
   ``<prefix>[가림:<sha256 12 hex>]`` so the same key can still be matched across rows
   without storing it. This is the one function the later swap to the Stage 3 lane B
   ``core/search_index/patterns.py`` replaces.
2. :func:`redact_secret_text` (``artifacts/url_redaction.py``) - credential query values,
   URL userinfo and bare ``password=`` style arguments.

:func:`mask_email` keeps only an email's domain and a hash of the local part (account rows,
claude-swap file names).
"""

from __future__ import annotations

import hashlib
import re

from ..url_redaction import REDACTED_VALUE, redact_secret_text

API_KEY_PREFIXES: tuple[str, ...] = ("sk-ant-", "sk-proj-", "sk-", "AIza", "hf_", "ghp_", "github_pat_", "xai-", "gsk_", "AKIA")

# Longest prefix first so ``sk-ant-`` / ``sk-proj-`` win over ``sk-``. The body length floors keep
# ordinary words (``sk-learn``, ``hf_hub``) readable.
_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"(?P<prefix>sk-ant-|sk-proj-|github_pat_|sk-|AIza|hf_|ghp_|xai-|gsk_|AKIA)"
    r"(?P<body>[A-Za-z0-9_\-]{12,})"
)
_KEY_MIN_BODY = {"sk-": 16, "AKIA": 16, "AIza": 20}
_BEARER_RE = re.compile(r"(?i)(?P<lead>\bbearer\s+)(?P<value>[A-Za-z0-9._~+/=\-]{12,})")
_ENV_ASSIGN_RE = re.compile(
    r"(?i)(?P<key>\b[A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|ACCESS_KEY)[A-Z0-9_]*)"
    r"(?P<sep>\s*=\s*)"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;]+)"
)
_JSON_SECRET_RE = re.compile(
    r"(?i)(?P<key>\"(?:[a-z0-9_]*(?:token|secret|password|api_?key|apikey|authorization|credential)[a-z0-9_]*)\"\s*:\s*)"
    r"\"(?P<value>[^\"\n]{4,})\""
)
_PLAIN_VALUES = frozenset({"true", "false", "null", "none", "yes", "no"})
_EMAIL_RE = re.compile(r"(?P<local>[A-Za-z0-9._%+\-]{1,64})@(?P<domain>[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def short_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:length]


def _mask(prefix: str, value: str) -> str:
    return f"{prefix}[가림:{short_hash(value)}]"


def _replace_key(match: re.Match[str]) -> str:
    prefix, body = match.group("prefix"), match.group("body")
    if len(body) < _KEY_MIN_BODY.get(prefix, 12):
        return match.group(0)
    return _mask(prefix, prefix + body)


def _replace_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    bare = value.strip("\"'")
    if not bare or "[가림" in bare or bare.startswith("$") or bare.isdigit() or bare.lower() in _PLAIN_VALUES:
        return match.group(0)
    return f"{match.group('key')}{match.group('sep')}{_mask('', bare)}"


def mask_api_keys(text: str) -> str:
    """Hash+mask API key values, bearer tokens and secret-named assignments in ``text``."""
    if not text:
        return text
    text = _KEY_RE.sub(_replace_key, text)
    text = _BEARER_RE.sub(lambda m: f"{m.group('lead')}{_mask('', m.group('value'))}", text)
    text = _JSON_SECRET_RE.sub(lambda m: f"{m.group('key')}\"{_mask('', m.group('value'))}\"", text)
    return _ENV_ASSIGN_RE.sub(_replace_assignment, text)


def redact_text(value: object) -> object:
    """Both passes for one value; non-strings pass through unchanged."""
    if not isinstance(value, str) or not value:
        return value
    return redact_secret_text(mask_api_keys(value))


def redact_str(value: object) -> str:
    """:func:`redact_text` for a value rendered as text (``None`` -> ``""``)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    out = redact_text(text)
    return out if isinstance(out, str) else text


def cap_text(value: object, max_bytes: int) -> tuple[str, bool, int]:
    """Redact then cap ``value`` at ``max_bytes`` UTF-8 bytes: ``(text, truncated, original_bytes)``.

    Very long values are pre-cut to 4x the cap before masking (a key straddling that cut can only
    sit past the final cap, which is dropped anyway)."""
    if value is None:
        return "", False, 0
    text = value if isinstance(value, str) else str(value)
    original = len(text.encode("utf-8", "surrogatepass"))
    if original > max_bytes * 4:
        text = text[: max_bytes * 4]
    text = redact_str(text)
    data = text.encode("utf-8", "surrogatepass")
    if len(data) <= max_bytes and original <= max_bytes * 4:
        return text, False, original
    return data[:max_bytes].decode("utf-8", "ignore"), True, original


def mask_email(value: object) -> tuple[str, str]:
    """``(email_domain, local_part_hash)`` of the first address in ``value`` (``("", "")`` if none)."""
    if not isinstance(value, str):
        return "", ""
    match = _EMAIL_RE.search(value)
    if match is None:
        return "", ""
    return match.group("domain").lower(), short_hash(match.group("local").lower())


def mask_emails_in(value: str) -> str:
    """Every address in ``value`` -> ``u-<hash>@domain`` (file names and log lines that embed emails)."""
    return _EMAIL_RE.sub(lambda m: f"u-{short_hash(m.group('local').lower(), 8)}@{m.group('domain').lower()}", value)


__all__ = [
    "API_KEY_PREFIXES",
    "REDACTED_VALUE",
    "cap_text",
    "mask_api_keys",
    "mask_email",
    "mask_emails_in",
    "redact_str",
    "redact_text",
    "short_hash",
]
