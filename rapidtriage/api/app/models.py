from __future__ import annotations
import base64
import binascii
import contextlib
import datetime as dt
import email
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import struct
import wave
from collections.abc import Mapping, MutableMapping, Sequence
from email import policy
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree as ET
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ...core.case_db import CaseDatabaseError, open_case_database
from ...core.case_report import (
    build_case_report_markdown,
    case_report_export_paths,
    write_case_report_exports,
)
from ...core.collect_plan import (
    CollectPlanError,
    build_collect_plan,
    supported_collect_profiles,
)
from ...core.columnar_store import query_columnar_artifact_records
from ...core.commercial_readiness import (
    CommercialReadinessError,
    build_commercial_readiness_report,
)
from ...core.crash import (
    export_crash_report_bundle,
    list_crash_reports,
    read_crash_report,
    write_crash_report,
)
from ...core.docs import SUPPORTED_DOC_EXTS, TEXT_EXTS, extract_text, query_docs_index
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.hash_cache import hash_cache_assessment
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    default_job_store,
    is_relative_to,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ...core.large_case_controls import build_source_search_full_cursor_contract
from ...core.ocr_queue import (
    OcrQueueError,
    build_ocr_queue,
    build_ocr_queue_report_grade_validation_plan,
)
from ...core.run import RunModeError
from ...core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from ...core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ...core.search import SearchError, run_unified_search
from ...core.source_paths import (
    candidate_source_paths,
    source_path_resolution_diagnostics,
)
from ...core.source_reader import (
    SourceReadError,
    build_source_locator,
    parse_archived_source_request,
)
from ...core.source_reader import (
    build_archived_source_preview as build_archived_source_read_preview,
)
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from ...core.submission import build_submission_manifest, compute_hashes
from ...core.visible_capabilities import build_visible_capability_response



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
    known_good_hash_feeds: list[str] = Field(default_factory=list)
    hide_known_good: bool = False
    known_good_max_hash_bytes: int = Field(DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES, ge=0)
    wait: bool = False


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
    targets: list[dict[str, str]] = Field(..., min_length=1)
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
