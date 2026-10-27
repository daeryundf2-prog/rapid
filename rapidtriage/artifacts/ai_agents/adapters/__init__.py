"""R7 AI lane B session adapters. Importing this package registers every adapter with lane A's
registry (``ai_agents/base.py`` :func:`register_adapter`)."""

from __future__ import annotations

from . import (
    antigravity,
    claude_code,
    claude_desktop,
    claude_swap,
    codex,
    cursor,
    gemini_cli,
    kiro,
    omo,
    stubs,
    zcode,
)

ADAPTER_MODULES = (antigravity, claude_code, claude_desktop, claude_swap, codex, cursor, gemini_cli, kiro, omo, stubs, zcode)

__all__ = ["ADAPTER_MODULES"]
