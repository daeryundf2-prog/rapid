"""통합 보기: derived cross-artifact tables built from the catalogue's semantic column tags (plan axiom-adoption §3.2)."""

from .engine import TABLE_LABELS, TABLES, run_derived
from .stage import DERIVED_ANALYSIS_KIND, run_derived_stage

__all__ = ["DERIVED_ANALYSIS_KIND", "TABLES", "TABLE_LABELS", "run_derived", "run_derived_stage"]
