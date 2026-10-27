"""R7 AI lane B session adapters. Importing this package registers every adapter with lane A's
registry (``ai_agents/base.py`` :func:`register_adapter`)."""

from __future__ import annotations

from . import antigravity, claude_code, codex, cursor, kiro, omo, zcode

ADAPTER_MODULES = (antigravity, claude_code, codex, cursor, kiro, omo, zcode)

__all__ = ["ADAPTER_MODULES"]
