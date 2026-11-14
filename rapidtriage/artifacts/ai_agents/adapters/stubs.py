"""Presence-only adapters for tools whose session stores were not validated on real data
(R7 AI plan §3.2 table row "copilot, windsurf, devin, opencode, aider, goose, cline…").

Each stub lists its known locations below a profile, and for every one that exists emits one
``ai-tool-presence`` row (file count, total size, newest file mtime as a row field, a version when
a ``package.json`` / ``version`` file states one) with ``coverage_status=schema-not-validated``.
No content is parsed. Files whose names are credentials (lane A ``is_credential_name``) become
``ai-credential-presence`` rows (stat only).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path

from ._common import (
    COVERAGE_NOT_VALIDATED,
    RowContext,
    credential_row,
    iso_from_epoch,
    iter_profiles,
    make_found,
    summary_row,
    walk_files,
)
from ._iface import (
    AiAgentAdapter,
    AiLimits,
    AiRow,
    Found,
    is_credential_name,
    register_adapter,
)

MAX_STUB_FILES = 5_000
# Plain names that hold tokens in these tools (GitHub Copilot ``hosts.json`` / ``apps.json``).
STUB_CREDENTIAL_NAMES = frozenset({"hosts.json", "apps.json"})

# name -> (catalog tool id, label, home-relative candidate locations)
STUBS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "copilot": ("github-copilot-cli", "GitHub Copilot CLI", (".copilot",)),
    "github_copilot": ("github-copilot", "GitHub Copilot", (".config/github-copilot", "AppData/Local/github-copilot")),
    "windsurf": ("windsurf", "Windsurf", (".codeium/windsurf", ".windsurf", "AppData/Roaming/Windsurf", "Library/Application Support/Windsurf", ".config/Windsurf")),
    "devin": ("devin", "Devin", (".devin", ".devin-shared", "AppData/Roaming/Devin", "AppData/Local/devin")),
    "opencode": ("opencode", "OpenCode", (".local/share/opencode", ".config/opencode", ".opencode")),
    "aider": ("aider", "Aider", (".aider.chat.history.md", ".aider.input.history", ".aider.conf.yml", ".aider")),
    "goose": ("goose", "Goose", (".config/goose", ".local/share/goose", "AppData/Roaming/Block/goose")),
    "cline": (
        "cline",
        "Cline",
        (
            "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev",
            "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev",
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev",
            "AppData/Roaming/Cursor/User/globalStorage/saoudrizwan.claude-dev",
        ),
    ),
}


def _version(path: Path) -> str:
    for candidate in (path / "package.json", path / "version", path / "VERSION"):
        try:
            if candidate.is_file() and candidate.stat().st_size <= 256 * 1024:
                text = candidate.read_text(encoding="utf-8", errors="replace")
                if candidate.name == "package.json":
                    data = json.loads(text)
                    return str(data.get("version") or "") if isinstance(data, dict) else ""
                return text.strip()[:64]
        except (OSError, ValueError):
            continue
    return ""


class _PresenceStub(AiAgentAdapter):
    """One stub per tool; ``name`` / ``tool`` / locations come from :data:`STUBS`."""

    label = ""
    locations: tuple[str, ...] = ()

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        found: list[Found] = []
        for profile in iter_profiles(roots, os_hint):
            hits = [profile.home / rel for rel in self.locations if (profile.home / rel).exists()]
            if hits:
                found.append(make_found(self, profile, hits[0], locations=hits))
        return found

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        ctx = RowContext(self, self.label, found, limits, coverage=COVERAGE_NOT_VALIDATED)
        for location in found.extra.get("locations") or [found.path]:  # type: ignore[union-attr]
            files = [location] if location.is_file() else list(walk_files(location, limit=MAX_STUB_FILES + 1))
            total, newest = 0, 0.0
            for path in files[:MAX_STUB_FILES]:
                try:
                    st = path.stat()
                except OSError:
                    continue
                total += st.st_size
                newest = max(newest, st.st_mtime)
                if is_credential_name(path.name) or path.name in STUB_CREDENTIAL_NAMES:
                    yield credential_row(ctx, path, "credential-file")
            yield ctx.row(
                "ai-tool-presence",
                location,
                presence_kind="tool-data",
                file_count=min(len(files), MAX_STUB_FILES),
                file_count_capped=len(files) > MAX_STUB_FILES,
                total_bytes=total,
                newest_file_mtime=iso_from_epoch(newest) if newest else "",
                version=_version(location) if location.is_dir() else "",
                parser_status="presence-only: session store layout not validated on real data",
            )
        yield summary_row(ctx, found.path, locations=len(found.extra.get("locations") or []))  # type: ignore[arg-type]


def _make(name: str, tool: str, label: str, locations: tuple[str, ...]) -> type[_PresenceStub]:
    return type(f"{name.title()}PresenceAdapter", (_PresenceStub,), {"name": f"stub_{name}", "tool": tool, "label": label, "locations": locations, "__module__": __name__})


STUB_ADAPTERS: dict[str, type[_PresenceStub]] = {name: _make(name, *spec) for name, spec in STUBS.items()}
for _cls in STUB_ADAPTERS.values():
    register_adapter(_cls)
