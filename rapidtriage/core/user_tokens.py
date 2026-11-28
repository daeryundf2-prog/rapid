"""Per-user API tokens (``RAPIDTRIAGE_TOKENS_FILE``): the token a request carries names who acts.

The file holds one ``name=token`` per line; blank lines and lines starting with ``#`` are
skipped. A name starting with ``agent:`` is an AI agent's own token. Only SHA-256 digests of
the tokens are kept in memory, every request is compared against all of them in constant
time, and no error message, log line or response ever carries a token (errors name the line).
The server re-reads the file when it changes (:class:`TokenFileWatch`), so adding a person or
revoking a token needs no restart.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)

TOKENS_FILE_ENV = "RAPIDTRIAGE_TOKENS_FILE"
#: Same bound as the action API's ``actor.name``.
ACTOR_NAME_MAX = 120
AGENT_PREFIX = "agent:"
#: Shorter tokens load with a warning (``secrets.token_urlsafe(18)`` gives 24 characters).
TOKEN_MIN_LENGTH = 24
#: ``kim=abc # laptop``: the ``#`` and what follows are part of the token (warned, not refused).
TRAILING_COMMENT = re.compile(r"\s#")


class UserTokenFileError(RuntimeError):
    """The tokens file cannot be used; the message never contains a token."""


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()


@dataclass(frozen=True)
class UserTokens:
    #: ``(sha256(token), name)`` per user, file order.
    entries: tuple[tuple[bytes, str], ...]
    #: Things to fix that do not stop the server (file mode, short tokens); never a token or name.
    warnings: tuple[str, ...] = ()

    def actor_for(self, supplied: str) -> str | None:
        """Name of the user whose token is ``supplied`` (``None``: no user has it).

        Every entry is compared (no early exit) on fixed-length digests, so neither the
        matching position nor the token lengths show in the timing.
        """
        digest = _digest(supplied)
        found: str | None = None
        for token_digest, name in self.entries:
            if hmac.compare_digest(digest, token_digest) and found is None:
                found = name
        return found


def configured_tokens_file(explicit: str | Path | None = None) -> Path | None:
    raw = str(explicit) if explicit else os.environ.get(TOKENS_FILE_ENV, "").strip()
    return Path(raw).expanduser() if raw else None


def load_user_tokens(path: Path) -> UserTokens:
    """Parse ``path``; refuses empty names or tokens, repeated names or tokens, and an empty file.

    A UTF-8 BOM (Windows Notepad) is skipped. A name cannot hold ``@``: the action API writes
    a person's agent as ``agent:<name>@<person>``. A file other accounts can read (POSIX),
    tokens shorter than :data:`TOKEN_MIN_LENGTH` and tokens holding a ``" #"`` (a trailing
    comment that became part of the token) are reported in ``warnings``.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
        mode = stat.S_IMODE(path.stat().st_mode)
    except (OSError, UnicodeDecodeError) as exc:
        raise UserTokenFileError(f"{TOKENS_FILE_ENV} cannot be read ({type(exc).__name__})") from None
    entries: list[tuple[bytes, str]] = []
    names: dict[str, int] = {}
    tokens: dict[bytes, int] = {}
    short: list[int] = []
    commented: list[int] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, token = line.partition("=")
        name, token = name.strip(), token.strip()
        if not separator or not name or not token:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: expected 'name=token'")
        if len(name) > ACTOR_NAME_MAX or any(not char.isprintable() for char in name):
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: a name is at most {ACTOR_NAME_MAX} printable characters")
        if "@" in name:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: a name cannot contain '@' (agent:<name>@<person> uses it)")
        if name.casefold().startswith(AGENT_PREFIX) and not name[len(AGENT_PREFIX):].strip():
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: 'agent:' needs an agent name after it")
        if name.casefold() in names:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: the name repeats line {names[name.casefold()]}")
        digest = _digest(token)
        if digest in tokens:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: the token repeats line {tokens[digest]}")
        if len(token) < TOKEN_MIN_LENGTH:
            short.append(number)
        if TRAILING_COMMENT.search(token):
            commented.append(number)
        names[name.casefold()] = number
        tokens[digest] = number
        entries.append((digest, name))
    if not entries:
        raise UserTokenFileError(f"{TOKENS_FILE_ENV} has no 'name=token' line")
    warnings: list[str] = []
    if os.name == "posix" and mode & 0o077:
        warnings.append(f"{TOKENS_FILE_ENV} can be read by other accounts (mode {mode:o}); restrict it with chmod 600")
    if short:
        lines = ", ".join(str(number) for number in short)
        warnings.append(f"{TOKENS_FILE_ENV} line(s) {lines}: tokens shorter than {TOKEN_MIN_LENGTH} characters are easy to guess")
    if commented:
        lines = ", ".join(str(number) for number in commented)
        warnings.append(
            f"{TOKENS_FILE_ENV} line(s) {lines}: the token contains ' #'; a '#' after a token is part of the token "
            "(put comments on their own line)"
        )
    return UserTokens(tuple(entries), tuple(warnings))


def _file_signature(path: Path) -> tuple[int, int, int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    return (info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino)


class TokenFileWatch:
    """The tokens file as the server uses it: re-read when its mtime, size or inode changes.

    A changed file is validated like at start. When the new content cannot be used (bad
    line, unreadable, deleted) the last good set stays in force and a warning is logged
    (the message names a line, never a token); a fixed file is picked up on the next request.
    Removing a person's line revokes their token from the next request on.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._signature = _file_signature(path)
        #: Raises :class:`UserTokenFileError` at start: the server refuses a bad file.
        self._tokens = load_user_tokens(path)

    @property
    def tokens(self) -> UserTokens:
        signature = _file_signature(self._path)
        if signature != self._signature:
            with self._lock:
                if signature != self._signature:
                    self._reload(signature)
        return self._tokens

    def _reload(self, signature: tuple[int, int, int, int] | None) -> None:
        self._signature = signature
        try:
            tokens = load_user_tokens(self._path)
        except UserTokenFileError as exc:
            LOGGER.warning("%s; keeping the previous tokens (%d users)", exc, len(self._tokens.entries))
            return
        self._tokens = tokens
        LOGGER.warning("%s changed: per-user tokens reloaded for %d users", TOKENS_FILE_ENV, len(tokens.entries))
        for warning in tokens.warnings:
            LOGGER.warning("%s", warning)

    def actor_for(self, supplied: str) -> str | None:
        return self.tokens.actor_for(supplied)
