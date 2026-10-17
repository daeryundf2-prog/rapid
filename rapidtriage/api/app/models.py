from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ...core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ...core.sample_case import (
    DEFAULT_SAMPLE_MODE,
)


class RunCreateRequest(BaseModel):
    root: str = Field(..., min_length=1)
    mode: str = Field(..., min_length=1)
    output_dir: str | None = None
    input_kind: str | None = None
    rules: str | None = None
    dry_run: bool = False
    read_only: bool = False
    max_extract_size_bytes: int = 0
    max_file_count: int = 0
    memory_cap_bytes: int = 0
    e01_partition_start_sector: int | None = None
    overwrite: bool = False
    resume: bool = False
    extract: bool = False
    known_good_hash_feeds: list[str] = Field(default_factory=list)
    hide_known_good: bool = False
    known_good_max_hash_bytes: int = Field(DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES, ge=0)
    wait: bool = False


class RunExtractRow(BaseModel):
    path: str = Field(..., min_length=1)
    locator: str | None = None


class RunExtractRequest(BaseModel):
    rows: list[RunExtractRow] = Field(..., min_length=1, max_length=500)
    output_name: str | None = Field(default=None, max_length=64)


class RunImportRequest(BaseModel):
    output_dir: str = Field(..., min_length=1)


class SampleCaseRunRequest(BaseModel):
    output_dir: str | None = None
    mode: str = DEFAULT_SAMPLE_MODE
    overwrite: bool = True
    read_only: bool = True


class BookmarkCreateRequest(BaseModel):
    source: str = Field(..., min_length=1)
    pointer: str = Field(..., min_length=1)
    bookmark_id: str | None = None
    tag: str | None = None
    tags: list[str] | None = None
    remove_tags: list[str] | None = None
    note: str | None = None
    case_id: str | None = None
    title: str | None = None
    review_status: str | None = None
    include_in_report: bool | None = None


class CaseReportCreateRequest(BaseModel):
    template: str = "legal-handoff"
    title: str | None = None
    case_number: str | None = None
    investigator: str | None = None
    organization: str | None = None
    requester: str | None = None
    scope: str | None = None
    conclusion: str | None = None
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class ReviewerBundleCreateRequest(BaseModel):
    title: str | None = None
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class CaseDbImportRunRequest(BaseModel):
    database: str = Field(..., min_length=1)
    run_output: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: str | None = None


class RunCaseDbEnsureRequest(BaseModel):
    database: str | None = None
    case_id: str | None = None
    name: str | None = None


class CaseDbSearchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    keywords: list[str] = Field(..., min_length=1)
    limit: int = Field(100, ge=1, le=1000)
    cursor: str | None = None
    sources: list[str] | None = None
    metadata_filters: list[str] | None = None
    review_status: str | None = None
    verification_status: str | None = None
    save_as: str | None = None
    keyword_packs: list[str] | None = None


class CaseDbReviewRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    target_type: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    status: str | None = None
    verification_status: str | None = None
    tags: list[str] | None = None
    note: str | None = None
    reviewer: str | None = None
    assignee: str | None = None
    priority: str | None = None
    due_at: str | None = None
    include_in_report: bool | None = None


class CaseDbReviewBatchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    # Each target is ``{target_type, target_id}`` (case-DB row) or a run-output
    # locator ``{collection, kind?, locator}`` resolved against ``run_id``.
    targets: list[dict[str, str]] = Field(..., min_length=1)
    run_id: str | None = None
    # Merged into each target's existing tags (``tags`` replaces them).
    add_tags: list[str] | None = None
    status: str | None = None
    verification_status: str | None = None
    tags: list[str] | None = None
    note: str | None = None
    reviewer: str | None = None
    assignee: str | None = None
    priority: str | None = None
    due_at: str | None = None
    include_in_report: bool | None = None


class CaseDbReportExportRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class CaseDbSavedSearchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    keywords: list[str] = Field(..., min_length=1)
    limit: int = Field(100, ge=1, le=1000)
    sources: list[str] | None = None
    metadata_filters: list[str] | None = None
    review_status: str | None = None
    verification_status: str | None = None
    created_by: str = ""


class CaseDbSavedSearchListRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)


class CaseCatalogAddRunRequest(BaseModel):
    catalog: str | None = None
    run_output: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: str | None = None
    description: str = ""
    examiner: str = ""
    organization: str = ""


class EvidenceIdentifyRequest(BaseModel):
    path: str = Field(..., min_length=1)


class CollectPlanRequest(BaseModel):
    root: str = Field(..., min_length=1)
    profile: str = "intrusion"
    input_kind: str | None = None


class RunCaseNotesRequest(BaseModel):
    examiner: str = Field("", max_length=200)
    summary: str = Field("", max_length=20000)


# --- case intake (AXIOM adoption E1) -----------------------------------------


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_number: str = Field(..., min_length=1, max_length=100)
    name: str = Field("", max_length=200)
    case_type: str = Field("", max_length=100)
    examiner: str = Field("", max_length=200)
    requester: str = Field("", max_length=200)
    organization: str = Field("", max_length=200)
    description: str = Field("", max_length=4000)
    case_root: str = Field("", max_length=1024)


class CasePatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_number: str | None = Field(None, min_length=1, max_length=100)
    name: str | None = Field(None, max_length=200)
    case_type: str | None = Field(None, max_length=100)
    examiner: str | None = Field(None, max_length=200)
    requester: str | None = Field(None, max_length=200)
    organization: str | None = Field(None, max_length=200)
    description: str | None = Field(None, max_length=4000)
    status: Literal["open", "closed"] | None = None
    actor: str = Field("", max_length=200)


class CaseEvidenceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_number: str = Field(..., min_length=1, max_length=50)
    display_name: str = Field("", max_length=200)
    source_type: Literal["e01", "folder", "export", "mobile"]
    path: str = Field(..., min_length=1, max_length=4096)
    verify_hash: bool = False
    expected_hash: str = Field("", max_length=128)
    actor: str = Field("", max_length=200)


class CaseRunCreateRequest(RunCreateRequest):
    """``POST /api/runs`` body + the case evidence the run processes (root defaults to its path)."""

    root: str = ""
    evidence_citation_id: str = Field(..., min_length=1, max_length=120)
    actor: str = Field("", max_length=200)


class CaseRunLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., min_length=1, max_length=64)
    evidence_citation_id: str | None = Field(None, max_length=120)
    evidence_number: str | None = Field(None, max_length=50)
    actor: str = Field("", max_length=200)


class CaseNoteCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=10000)
    author: str = Field("", max_length=200)
