"""Credential / secret files: their bodies are never indexed, extracted or previewed (R7 fix).

A file is a *credential file* when its path matches one of (first match wins, the reason code
is kept on the row):

* ``catalog-credential`` — an AI tool catalog credential path (``core/ai_catalog`` templates with
  ``credential=True``: ``~/.claude/.credentials.json``, ``~/.codex/auth.json``,
  ``~/.codex/mcp-oauth-locks`` …), matched as a path suffix or as a parent folder;
* ``credential-folder`` — any file below ``.sandbox-secrets`` or ``mcp-oauth-locks``;
* ``credential-name`` — a general credential file name: ``.credentials.json``, ``auth.json``,
  ``credentials``(``.json``), ``.netrc``, ``.pypirc``, ``.git-credentials``, ``buddy-tokens.json``,
  ``jetski-standalone-oauth-token``, ``secret:*``, ``.docker/config.json``, ``.azure/*token*``;
* ``browser-credential-store`` — Chromium ``Login Data`` / ``Cookies`` / ``Web Data`` (+ journals);
* ``private-key`` — ``*.pem``, ``*.key`` (not a Keynote ZIP) and ``id_rsa*`` / ``id_ed25519*`` …;
* ``ai-tool-credential-name`` — :func:`~rapidtriage.core.ai_catalog.is_credential_name`
  (``*token*``, ``*oauth*``, ``*secret*`` …) for a file below an AI tool home folder
  (``~/.claude``, ``~/.codex``, ``~/.gemini`` … from the catalog). Outside those folders the
  broad name rule is not used, so an ordinary document called ``secret plan.docx`` keeps its text.

Text-ingesting paths (docs stage / docs index / case DB / search index v4 / docs-extract and
files-extract / source viewer / OCR sidecars) replace the body with :func:`credential_index_text`
(file name + path only, so a name search still finds the file) and the docs stage lists every
credential file as a ``credential-file`` row (path / size / mtime / reason,
``coverage_status: body-withheld``). Token-bearing configs that are not withheld (``.npmrc``,
``.yarnrc``, ``pip.ini`` …) pass through :func:`redact_credential_text`.
"""

from __future__ import annotations

import datetime as dt
import os
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

from .ai_catalog.profiles import is_credential_name

__all__ = [
    "BODY_WITHHELD",
    "CREDENTIAL_EXTRACTION_METHOD",
    "CREDENTIAL_FILE_RECORD_TYPE",
    "CredentialFileLog",
    "credential_disclosure_note",
    "credential_file_reason",
    "credential_index_text",
    "credential_withheld_preview",
    "credential_withheld_reason_text",
    "redact_credential_text",
]

CREDENTIAL_FILE_RECORD_TYPE = "credential-file"
# ``coverage_status`` of a credential-file row and ``text_status`` of its document candidate.
BODY_WITHHELD = "body-withheld"
CREDENTIAL_EXTRACTION_METHOD = "credential-file"
CREDENTIAL_ROW_LIMIT = 5_000

_CREDENTIAL_NAMES = frozenset(
    {
        ".credentials.json",
        "auth.json",
        "credentials",
        "credentials.json",
        ".netrc",
        "_netrc",
        ".pypirc",
        ".git-credentials",
        "buddy-tokens.json",
        "jetski-standalone-oauth-token",
    }
)
_BROWSER_STORE_NAMES = frozenset(
    {
        "login data",
        "login data-journal",
        "login data for account",
        "login data for account-journal",
        "cookies",
        "cookies-journal",
        "web data",
        "web data-journal",
    }
)
_SECRET_FOLDERS = frozenset({".sandbox-secrets", "mcp-oauth-locks"})
_SSH_IDENTITY_RE = re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)")
_PRIVATE_KEY_SUFFIXES = (".pem", ".key")
# Folders that hold tool data without being one tool's own folder (never an "AI tool root").
_NOT_AI_ROOTS = frozenset({".cache", ".config", ".local", ".aws"})
# Token-bearing configs that stay indexed with their secret values masked.
_TOKEN_CONFIG_NAMES = frozenset({".npmrc", "npmrc", ".yarnrc", ".yarnrc.yml", "pip.ini", "pip.conf"})
_TOKEN_CONFIG_LINE = re.compile(
    r"(?im)^(\s*(?:[^\s=:#;]*:)?(?:_authtoken|_auth|_password|npmauthtoken|npmauthident|password|token)\s*[=:]\s*).+$"
)
_MASK = "(값 — 저장하지 않음)"


@lru_cache(maxsize=1)
def _catalog_rules() -> tuple[tuple[tuple[str, ...], ...], frozenset[str]]:
    """``(credential path patterns, AI tool home folder names)`` from the AI catalog (lower-case)."""
    try:
        from .ai_catalog.catalog import catalog_home_roots, load_catalog

        catalog = load_catalog()
    except Exception:  # a broken catalog never stops text policy: the name lists still apply
        return (), frozenset()
    patterns: set[tuple[str, ...]] = set()
    for tool in catalog.tools:
        for template in tool.credential_paths:
            parts = tuple(part.lower() for part in template.relative_parts)
            if parts and not set(parts[0]) & set("*?["):
                patterns.add(parts)
    roots = {
        name
        for name in catalog_home_roots(catalog)
        if name not in _NOT_AI_ROOTS and not name.startswith("..") and not set(name) & set("{}*?[")
        and not re.search(r"\.(?:json|ya?ml|toml)$", name)
    }
    return tuple(sorted(patterns)), frozenset(roots)


def _split_parts(path: str | os.PathLike[str]) -> list[str]:
    return [part for part in re.split(r"[\\/]+", os.fspath(path).lower()) if part]


def _matches_pattern(parts: list[str], pattern: tuple[str, ...]) -> bool:
    width = len(pattern)
    first = pattern[0]
    for start in range(len(parts) - width + 1):
        if parts[start] != first:
            continue
        if all(fnmatchcase(parts[start + offset], pattern[offset]) for offset in range(1, width)):
            return True
    return False


@lru_cache(maxsize=8192)
def _dir_context(dir_key: str) -> tuple[str, bool, tuple[str, ...], str]:
    """``(folder reason, below an AI tool root, file-name globs of catalog patterns whose folder
    part ends this folder, parent name)`` — computed once per folder."""
    parts = _split_parts(dir_key)
    patterns, ai_roots = _catalog_rules()
    folder_reason = ""
    if any(_matches_pattern(parts, pattern) for pattern in patterns):
        folder_reason = "catalog-credential"  # a catalog credential folder (``~/.openclaw/credentials``)
    elif any(part in _SECRET_FOLDERS for part in parts):
        folder_reason = "credential-folder"
    name_globs: list[str] = []
    for pattern in patterns:
        head = pattern[:-1]
        if len(head) > len(parts):
            continue
        tail = parts[len(parts) - len(head) :]
        if all(fnmatchcase(part, glob) for part, glob in zip(tail, head)):
            name_globs.append(pattern[-1])
    in_ai_root = bool(set(parts) & ai_roots)
    return folder_reason, in_ai_root, tuple(name_globs), parts[-1] if parts else ""


def _is_keynote(path: str | os.PathLike[str]) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"PK\x03\x04"
    except OSError:
        return os.path.isdir(path)  # a Keynote bundle folder


def credential_file_reason(
    path: str | os.PathLike[str],
    *,
    name: str | None = None,
    directory: str | None = None,
    sniff: bool = True,
) -> str:
    """Reason code when ``path`` is a credential file (body never indexed), else ``""``.

    Directory walks pass ``name`` and ``directory`` (the walk's ``dirpath``) so the folder part is
    split once per folder; ``sniff=False`` skips the one content check (``*.key`` Keynote ZIP)."""
    text = os.fspath(path)
    if not text:
        return ""
    if name is None or directory is None:
        base, _sep, tail = text.replace("\\", "/").rpartition("/")
        lowered = (name if name is not None else tail).lower()
    else:
        base, lowered = directory, name.lower()
    if not lowered:
        return ""
    folder_reason, in_ai_root, name_globs, parent = _dir_context(base)
    if name_globs and any(fnmatchcase(lowered, glob) for glob in name_globs):
        return "catalog-credential"
    if folder_reason:
        return folder_reason
    if lowered in _CREDENTIAL_NAMES or lowered.startswith("secret:"):
        return "credential-name"
    if (parent == ".docker" and lowered == "config.json") or (parent == ".azure" and "token" in lowered):
        return "credential-name"
    if lowered in _BROWSER_STORE_NAMES:
        return "browser-credential-store"
    if _SSH_IDENTITY_RE.match(lowered) or lowered.endswith(".pem"):
        return "private-key"
    if lowered.endswith(".key") and not (sniff and _is_keynote(text)):
        return "private-key"
    if in_ai_root and is_credential_name(lowered):
        return "ai-tool-credential-name"
    return ""


def credential_index_text(path: str | os.PathLike[str]) -> str:
    """What a credential file contributes to text indexes: its name and path, never its body."""
    text = os.fspath(path)
    name = re.split(r"[\\/]", text)[-1]
    return f"{name}\n{text}"


def credential_withheld_reason_text(reason: str) -> str:
    return f"자격 증명 파일 — 본문 미수집 ({reason})"


def redact_credential_text(path: str | os.PathLike[str], text: str) -> str:
    """Mask token / password values of token-bearing configs (``.npmrc`` ``_authToken=`` …);
    other files are returned unchanged."""
    if not text:
        return text
    name = re.split(r"[\\/]", os.fspath(path))[-1].lower()
    if name not in _TOKEN_CONFIG_NAMES:
        return text
    # Lazy: ``rapidtriage.artifacts`` imports the providers, some of which import core modules.
    from ..artifacts.url_redaction import redact_secret_text

    masked = _TOKEN_CONFIG_LINE.sub(lambda match: f"{match.group(1)}{_MASK}", text)
    return str(redact_secret_text(masked))


def credential_withheld_preview(reason: str) -> dict[str, object]:
    """Source-viewer / source-read payload for a credential file: no text, no hex, no hash."""
    return {
        "preview_type": "withheld",
        "strategy": CREDENTIAL_EXTRACTION_METHOD,
        "text": "",
        "truncated": False,
        "coverage_status": BODY_WITHHELD,
        "credential_reason": reason,
        "message": credential_withheld_reason_text(reason),
    }


def credential_disclosure_note(count: int) -> str:
    return f"자격 증명 파일 {count}건 — 본문 미수집"


@dataclass
class CredentialFileLog:
    """``credential-file`` rows of one scan (bounded) plus the full count."""

    rows: list[dict[str, object]] = field(default_factory=list)
    count: int = 0
    reason_counts: Counter[str] = field(default_factory=Counter)
    limit: int = CREDENTIAL_ROW_LIMIT

    def add(self, path: str | os.PathLike[str], reason: str, *, size: int | None = None, modified_at: str | None = None) -> None:
        self.count += 1
        self.reason_counts[reason] += 1
        if len(self.rows) >= self.limit:
            return
        if size is None or modified_at is None:
            try:
                stat = os.stat(path)
                size = stat.st_size if size is None else size
                if modified_at is None:
                    modified_at = dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat()
            except OSError:
                pass
        self.rows.append(
            {
                "record_type": CREDENTIAL_FILE_RECORD_TYPE,
                "path": os.fspath(path),
                "name": Path(path).name,
                "size": size,
                "modified_at": modified_at,
                "reason": reason,
                "coverage_status": BODY_WITHHELD,
                "value_collected": False,
            }
        )

    def disclosure(self) -> dict[str, object]:
        return {
            "count": self.count,
            "coverage_status": BODY_WITHHELD,
            "reason_counts": dict(sorted(self.reason_counts.items())),
            "rows_truncated": self.count > len(self.rows),
            "note": credential_disclosure_note(self.count),
        }


def credential_disclosure_from_summary(summary: Mapping[str, object]) -> dict[str, object] | None:
    """The docs summary's ``credential_files`` disclosure when it lists at least one file."""
    value = summary.get("credential_files")
    if isinstance(value, Mapping) and int(value.get("count") or 0) > 0:
        return dict(value)
    return None
