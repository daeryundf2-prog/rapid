"""Evidence profile and credential-name rule shared by the AI catalog and the ai-agent kind.

Re-exported unchanged by :mod:`rapidtriage.artifacts.ai_agents.base` (the frozen adapter
interface); kept here so ``core.ai_catalog`` never imports the ``artifacts`` package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["EvidenceProfile", "is_credential_name"]

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
