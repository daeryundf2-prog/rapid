"""AI tool catalog — single source for AI tool paths, domains, binaries and installs (R7 §3.1)."""

from __future__ import annotations

from .catalog import (
    CATALOG_DATA_DIR,
    CATALOG_FILES,
    AiCatalog,
    AiTool,
    ExpandedPath,
    PathTemplate,
    ai_service_tokens,
    catalog_domain_pairs,
    domains,
    enumerate_profiles,
    execution_names,
    expand_paths,
    expand_template,
    key_prefixes,
    load_catalog,
    normalize_confidence,
)
from .profiles import EvidenceProfile, is_credential_name

__all__ = [
    "CATALOG_DATA_DIR",
    "CATALOG_FILES",
    "AiCatalog",
    "AiTool",
    "EvidenceProfile",
    "ExpandedPath",
    "PathTemplate",
    "ai_service_tokens",
    "catalog_domain_pairs",
    "domains",
    "enumerate_profiles",
    "execution_names",
    "expand_paths",
    "expand_template",
    "is_credential_name",
    "key_prefixes",
    "load_catalog",
    "normalize_confidence",
]
