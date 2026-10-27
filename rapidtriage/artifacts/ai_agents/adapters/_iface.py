"""Lane B import seam: the shared adapter interface frozen by lane A (``ai_agents/base.py``)."""

from __future__ import annotations

from ..base import (
    AiAgentAdapter,
    AiLimits,
    AiRow,
    EvidenceProfile,
    Found,
    is_credential_name,
    profile_account_key,
    register_adapter,
    registered_adapters,
)

__all__ = [
    "AiAgentAdapter",
    "AiLimits",
    "AiRow",
    "EvidenceProfile",
    "Found",
    "is_credential_name",
    "profile_account_key",
    "register_adapter",
    "registered_adapters",
]
