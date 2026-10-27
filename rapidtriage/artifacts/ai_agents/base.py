"""Shared AI-agent interface (R7 stage 3.5, lane A) — FROZEN for lane B.

Lane B's session adapters (``artifacts/ai_agents/adapters/*.py``) code against the names in this
module only. Changing a signature here is a cross-lane change: add, never rename or remove.

Contract
--------
* :class:`EvidenceProfile` — one user profile root of the evidence (``Users/<u>``, ``/home/<u>``,
  ``/Users/<u>`` or the evidence root itself when it *is* a home folder). ``os`` is
  ``windows`` / ``macos`` / ``linux`` / ``unknown``.
* :class:`AiAgentAdapter` — ``name`` (adapter id, e.g. ``claude_code``), ``tool`` (catalog tool id,
  e.g. ``claude-code``; see :func:`rapidtriage.core.ai_catalog.load_catalog`),
  ``detect(roots, os_hint) -> list[Found]`` and ``collect(found, limits) -> Iterator[AiRow]``.
  ``detect`` must only stat/list; ``collect`` reads within :class:`AiLimits`.
* :class:`AiRow` — one output row. ``to_record()`` turns it into the run's ``ArtifactRecord``
  (``details`` = the fixed envelope keys below + ``payload``).
* :func:`register_adapter` — adapters register at import time of
  ``rapidtriage.artifacts.ai_agents.adapters``; the ``ai-agent`` provider runs every registered
  adapter after the catalog presence scan. One adapter failing yields an ``ai-agent-parse-error``
  row; the provider continues.

Secret policy (applies to every adapter): never put the contents or a hash of a credential file
in a row. Paths whose name matches :func:`is_credential_name` (or that the catalog lists as
credentials) produce only ``ai-credential-presence`` rows (path / size / mtime).
"""

from __future__ import annotations

import abc
import datetime as dt
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from ...core.models import ArtifactRecord

__all__ = [
    "AI_ARTIFACT_TYPES",
    "AI_PROVIDER_NAME",
    "AI_PROVIDER_PARSER_VERSION",
    "COVERAGE_STATUSES",
    "INSTALL_KINDS",
    "AiAgentAdapter",
    "AiLimits",
    "AiRow",
    "EvidenceProfile",
    "Found",
    "clear_adapters",
    "is_credential_name",
    "mtime_iso",
    "profile_account_key",
    "register_adapter",
    "registered_adapters",
    "unregister_adapter",
]

AI_PROVIDER_NAME = "ai-agents"
AI_PROVIDER_PARSER_VERSION = "ai-agents-v1"

# Every artifact_type the ai-agent kind may emit (lane A rows + lane B session rows, plan §3.3).
AI_ARTIFACT_TYPES: tuple[str, ...] = (
    # lane A
    "ai-tool-presence",
    "ai-credential-presence",
    "unknown-ai-tool-candidate",
    "ai-model-file",
    # lane B (session adapters)
    "ai-agent-session",
    "ai-agent-message",
    "ai-agent-tool-call",
    "ai-agent-file-touch",
    "ai-mcp-server",
    "ai-instruction-file",
    "ai-account",
    "ai-code-attribution",
    "ai-usage-stat",
    # either lane: a source that could not be read (the run continues)
    "ai-agent-parse-error",
)
INSTALL_KINDS: tuple[str, ...] = ("path", "npm-global", "pip", "winget", "msix", "vscode-extension", "execution")
# ``coverage_status`` values (catalog ``conf`` / ``local_verification``, plan §3.2).
COVERAGE_STATUSES: tuple[str, ...] = (
    "local-verified",
    "official",
    "third-party",
    "inferred",
    "unverified",
    "schema-not-validated",
)

# File names that are credentials or session secrets wherever they appear under an AI tool root.
# ``tokenizer*`` (model vocabularies) is excluded explicitly.
_CREDENTIAL_NAME_RE = re.compile(
    r"(token|oauth|secret|credential|\.creds|cookies$|^auth\.json$|\.pem$|\.key$|^id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$|keychain|\.enc$)",
    re.IGNORECASE,
)
_NOT_CREDENTIAL_NAME_RE = re.compile(r"^tokeniz|tokens?[-_]?(?:count|usage|stats?)|^token[-_]?usage", re.IGNORECASE)


def is_credential_name(name: str) -> bool:
    """True for a file / folder name that holds (or names) a credential: ``*token*``, ``*oauth*``,
    ``*secret*``, ``*credential*``, ``Cookies``, ``auth.json``, ``*.pem``/``*.key``, SSH identities,
    ``*.enc`` backups. Model tokenizers and token *counters* are not credentials."""
    text = str(name or "").strip()
    if not text or _NOT_CREDENTIAL_NAME_RE.search(text):
        return False
    return bool(_CREDENTIAL_NAME_RE.search(text))


def mtime_iso(path: Path) -> str:
    """``st_mtime`` as ISO 8601 UTC (``+00:00``), ``""`` when the path cannot be stat'ed."""
    try:
        stamp = path.stat().st_mtime
    except OSError:
        return ""
    try:
        return dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass(frozen=True)
class EvidenceProfile:
    """One user profile (home) inside the evidence."""

    home: Path
    user: str
    os: str = "unknown"  # windows | macos | linux | unknown
    # Evidence root holding ``Users`` / ``home`` (system paths such as ``Program Files`` or
    # ``/usr/lib`` resolve against it); ``None`` when the evidence root is a bare home folder.
    system_root: Path | None = None

    @property
    def label(self) -> str:
        names = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}
        return f"{self.user} ({names[self.os]})" if self.os in names else self.user


def profile_account_key(profile: EvidenceProfile | None, *parts: str) -> str:
    """``<os user>[/<tool account>…]`` — the per-row ``account_key`` convention (plan §3.2)."""
    pieces = [profile.user if profile is not None else ""]
    pieces.extend(str(part) for part in parts if str(part or "").strip())
    return "/".join(piece for piece in pieces if piece)


@dataclass(frozen=True)
class Found:
    """A tool data location an adapter found during ``detect``."""

    adapter: str
    tool: str  # catalog tool id
    path: Path
    profile: EvidenceProfile | None = None
    account_key: str = ""
    profile_label: str = ""
    extra: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class AiLimits:
    """Read limits (plan §3.2 공통 규칙). Exceeding one sets ``truncated`` on the row."""

    max_messages_per_session: int = 2000
    max_message_bytes: int = 16 * 1024
    max_tool_calls_per_session: int = 5000
    max_adapter_read_bytes: int = 200 * 1024 * 1024
    # SQLite databases above this size are read for metadata tables only (reason recorded).
    max_sqlite_bytes: int = 1024 * 1024 * 1024
    # Run option ``ai_bodies``: message text included (masked) when True, metadata only otherwise.
    include_bodies: bool = True
    # Run option ``ai_hash_dbs``: hash large AI databases (off by default; DBs are never copied).
    hash_large_dbs: bool = False


@dataclass
class AiRow:
    """One ai-agent output row. ``payload`` holds the type-specific fields of plan §3.3."""

    artifact_type: str
    tool: str
    account_key: str = ""
    profile_label: str = ""
    path: str = ""
    timestamp: str = ""  # primary ISO 8601 UTC time of the row (``""`` = none)
    timestamp_kind: str = ""  # e.g. modified / started / message / executed
    started_at: str = ""
    ended_at: str = ""
    modified_at: str = ""
    payload: dict[str, object] = field(default_factory=dict)
    coverage_status: str = ""
    truncated: bool = False
    truncated_fields: tuple[str, ...] = ()
    tool_label: str = ""
    user: str = ""
    parser: str = ""

    def to_record(self, *, provider_name: str = AI_PROVIDER_NAME) -> ArtifactRecord:
        details: dict[str, object] = {
            "parser": self.parser or provider_name,
            "parser_version": AI_PROVIDER_PARSER_VERSION,
            "recovery_method": "parsed",
            "coverage_status": self.coverage_status,
            "tool": self.tool,
            "tool_label": self.tool_label or self.tool,
            "account_key": self.account_key,
            "profile_label": self.profile_label,
            "user": self.user,
            "source_path": self.path,
            "timestamp": self.timestamp or None,
            "timestamp_kind": self.timestamp_kind if self.timestamp else "",
            "timestamp_timezone": "UTC" if self.timestamp else "",
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "modified_at": self.modified_at,
            "truncated": bool(self.truncated),
            "truncated_fields": list(self.truncated_fields),
        }
        for key, value in self.payload.items():
            if key not in details:
                details[key] = value
        return ArtifactRecord(
            provider=provider_name,
            artifact_type=self.artifact_type,
            path=self.path,
            supported=True,
            details=details,
        )


class AiAgentAdapter(abc.ABC):
    """Session adapter for one AI tool (lane B). Stateless; one instance serves every profile."""

    name: ClassVar[str] = ""  # adapter id, e.g. "claude_code"
    tool: ClassVar[str] = ""  # catalog tool id, e.g. "claude-code"

    @abc.abstractmethod
    def detect(self, roots: Sequence[EvidenceProfile], os_hint: str = "") -> list[Found]:
        """Locate this tool's data under each profile (stat/list only, no content reads)."""

    @abc.abstractmethod
    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        """Rows for one ``Found`` location, honouring ``limits``."""


_ADAPTERS: dict[str, AiAgentAdapter] = {}
_ADAPTERS_LOCK = threading.Lock()


def register_adapter(adapter: AiAgentAdapter | type[AiAgentAdapter]) -> AiAgentAdapter:
    """Register an adapter (class or instance) under its ``name``; a duplicate name raises."""
    instance = adapter() if isinstance(adapter, type) else adapter
    if not isinstance(instance, AiAgentAdapter):
        raise TypeError(f"not an AiAgentAdapter: {adapter!r}")
    name = str(instance.name or "").strip()
    if not name or not str(instance.tool or "").strip():
        raise ValueError("AiAgentAdapter needs a non-empty name and catalog tool id")
    with _ADAPTERS_LOCK:
        if name in _ADAPTERS and _ADAPTERS[name] is not instance:
            raise ValueError(f"AI agent adapter already registered: {name}")
        _ADAPTERS[name] = instance
    return instance


def unregister_adapter(name: str) -> None:
    with _ADAPTERS_LOCK:
        _ADAPTERS.pop(name, None)


def clear_adapters() -> None:
    with _ADAPTERS_LOCK:
        _ADAPTERS.clear()


def registered_adapters() -> list[AiAgentAdapter]:
    """Registered adapters in name order (deterministic row order)."""
    with _ADAPTERS_LOCK:
        return [_ADAPTERS[name] for name in sorted(_ADAPTERS)]
