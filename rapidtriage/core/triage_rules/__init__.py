"""Triage-flag rule library (plan viewer-families-2026-10-15 §3.1).

``catalog/*.yaml`` holds the families (core/aux grid columns) and the rule
metadata (grade, Korean label/rationale/false-positive note, sources,
version, status, params); one module per family group implements the rules
(:func:`base.register`). :func:`engine.run_triage_flags` runs them over a run
output.
"""

from __future__ import annotations

from . import (  # noqa: F401  (imports register the rule implementations)
    accounts,
    antiforensics,
    archives,
    browser,
    cloud,
    documents,
    email,
    eventlog,
    execution,
    generic,
    lnk,
    media,
    messenger,
    mobile,
    ntfs,
    rdp,
    registry,
    usb,
)
from .base import (
    GRADE_RANK,
    GRADES,
    RULE_CLASSES,
    FlagContext,
    RowView,
    Rule,
    RuleResult,
)
from .catalog import Catalog, CatalogError, RuleSpec, load_catalog

__all__ = [
    "GRADES",
    "GRADE_RANK",
    "RULE_CLASSES",
    "Catalog",
    "CatalogError",
    "FlagContext",
    "RowView",
    "Rule",
    "RuleResult",
    "RuleSpec",
    "load_catalog",
]
