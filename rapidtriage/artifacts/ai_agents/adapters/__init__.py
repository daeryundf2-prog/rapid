"""R7 AI lane B session adapters. Importing this package registers every adapter with lane A's
registry (``ai_agents/base.py`` :func:`register_adapter`)."""

from __future__ import annotations

from . import claude_code

ADAPTER_MODULES = (claude_code,)

__all__ = ["ADAPTER_MODULES"]
