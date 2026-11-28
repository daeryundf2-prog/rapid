"""Per-user API tokens (``RAPIDTRIAGE_TOKENS_FILE``): the token a request carries names who acts.

The file holds one ``name=token`` per line; blank lines and lines starting with ``#`` are
skipped. A name starting with ``agent:`` is an AI agent's own token. Only SHA-256 digests of
the tokens are kept in memory, every request is compared against all of them in constant
time, and no error message, log line or response ever carries a token (errors name the line).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

TOKENS_FILE_ENV = "RAPIDTRIAGE_TOKENS_FILE"
#: Same bound as the action API's ``actor.name``.
ACTOR_NAME_MAX = 120
AGENT_PREFIX = "agent:"


class UserTokenFileError(RuntimeError):
    """The tokens file cannot be used; the message never contains a token."""


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()


@dataclass(frozen=True)
class UserTokens:
    #: ``(sha256(token), name)`` per user, file order.
    entries: tuple[tuple[bytes, str], ...]

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
    """Parse ``path``; refuses empty names or tokens, repeated names or tokens, and an empty file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UserTokenFileError(f"{TOKENS_FILE_ENV} cannot be read ({type(exc).__name__})") from None
    entries: list[tuple[bytes, str]] = []
    names: dict[str, int] = {}
    tokens: dict[bytes, int] = {}
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
        if name.casefold().startswith(AGENT_PREFIX) and not name[len(AGENT_PREFIX):].strip():
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: 'agent:' needs an agent name after it")
        if name.casefold() in names:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: the name repeats line {names[name.casefold()]}")
        digest = _digest(token)
        if digest in tokens:
            raise UserTokenFileError(f"{TOKENS_FILE_ENV} line {number}: the token repeats line {tokens[digest]}")
        names[name.casefold()] = number
        tokens[digest] = number
        entries.append((digest, name))
    if not entries:
        raise UserTokenFileError(f"{TOKENS_FILE_ENV} has no 'name=token' line")
    return UserTokens(tuple(entries))
