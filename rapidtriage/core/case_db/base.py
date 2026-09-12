"""Case DB error types and record model."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

__all__ = [
    "CaseDatabaseError",
    "CaseRecord",
    "default_citation_prefix",
    "normalize_identifier",
    "now_iso",
]

class CaseDatabaseError(ValueError):
    """Raised when a case database operation is invalid."""


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    name: str
    description: str
    examiner: str
    organization: str
    case_root: str
    citation_prefix: str
    status: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "description": self.description,
            "examiner": self.examiner,
            "organization": self.organization,
            "case_root": self.case_root,
            "citation_prefix": self.citation_prefix,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_identifier(value: str, *, fallback: str) -> str:
    normalized = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in value.strip())
    normalized = "-".join(part for part in normalized.split("-") if part)
    return normalized or fallback


def default_citation_prefix(case_id: str) -> str:
    normalized = normalize_identifier(case_id.upper(), fallback="CASE")
    return normalized[:40]
