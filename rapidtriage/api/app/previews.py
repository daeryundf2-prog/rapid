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

from .constants import (
    JSON_PREVIEW_ITEM_LIMIT,
    STRUCTURED_PREVIEW_MAX_BYTES,
    XML_PREVIEW_NODE_LIMIT,
)
from .helpers import (
    safe_read_text,
)
from .viewer_core import (
    structured_viewer_metadata,
)


def write_json_file(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_json_preview(source_path: Path, suffix: str) -> dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"JSON preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("json", "bounded-json-parse", "capped"),
            "json": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
        if suffix == ".json":
            data = json.loads(text)
            preview = summarize_json_value(data)
            formatted = json.dumps(data, ensure_ascii=False, indent=2)
            item_count = json_item_count(data)
        else:
            rows = []
            errors = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                if len(rows) >= JSON_PREVIEW_ITEM_LIMIT:
                    break
                try:
                    rows.append({"line": line_number, "value": summarize_json_value(json.loads(line))})
                except json.JSONDecodeError as exc:
                    errors.append({"line": line_number, "error": str(exc)})
            preview = {"type": "jsonl", "rows": rows, "errors": errors[:5]}
            formatted = "\n".join(text.splitlines()[:JSON_PREVIEW_ITEM_LIMIT])
            item_count = len(rows)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "preview_type": "text",
            "message": f"JSON parse failed, showing text fallback: {exc}",
            "text": safe_read_text(source_path, max_chars=20000),
            "truncated": source_path.stat().st_size > 20000,
            "viewer_metadata": structured_viewer_metadata("json", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "json",
        "message": "JSON structured preview is available.",
        "text": formatted[:20000],
        "truncated": len(formatted) > 20000,
        "viewer_metadata": structured_viewer_metadata("json", "bounded-json-parse", "available"),
        "json": {
            "summary": preview,
            "item_count": item_count,
            "item_limit": JSON_PREVIEW_ITEM_LIMIT,
            "truncated": item_count >= JSON_PREVIEW_ITEM_LIMIT,
        },
    }


def build_json_preview_from_text(text: str, suffix: str) -> dict[str, object]:
    try:
        if suffix == ".json":
            data = json.loads(text)
            preview = summarize_json_value(data)
            formatted = json.dumps(data, ensure_ascii=False, indent=2)
            item_count = json_item_count(data)
        else:
            rows = []
            errors = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                if len(rows) >= JSON_PREVIEW_ITEM_LIMIT:
                    break
                try:
                    rows.append({"line": line_number, "value": summarize_json_value(json.loads(line))})
                except json.JSONDecodeError as exc:
                    errors.append({"line": line_number, "error": str(exc)})
            preview = {"type": "jsonl", "rows": rows, "errors": errors[:5]}
            formatted = "\n".join(text.splitlines()[:JSON_PREVIEW_ITEM_LIMIT])
            item_count = len(rows)
    except json.JSONDecodeError as exc:
        return {
            "preview_type": "text",
            "message": f"JSON parse failed, showing text fallback: {exc}",
            "text": text[:20000],
            "truncated": len(text) > 20000,
            "viewer_metadata": structured_viewer_metadata("json", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "json",
        "message": "JSON structured preview is available from a ZIP entry.",
        "text": formatted[:20000],
        "truncated": len(formatted) > 20000,
        "viewer_metadata": structured_viewer_metadata("json", "bounded-zip-entry-json-parse", "available"),
        "json": {
            "summary": preview,
            "item_count": item_count,
            "item_limit": JSON_PREVIEW_ITEM_LIMIT,
            "truncated": item_count >= JSON_PREVIEW_ITEM_LIMIT,
        },
    }


def summarize_json_value(value: object, *, depth: int = 0) -> object:
    if depth >= 3:
        if isinstance(value, dict):
            return {"type": "object", "keys": len(value)}
        if isinstance(value, list):
            return {"type": "array", "items": len(value)}
        return value
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": list(value.keys())[:JSON_PREVIEW_ITEM_LIMIT],
            "sample": {str(key): summarize_json_value(item, depth=depth + 1) for key, item in list(value.items())[:10]},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "items": len(value),
            "sample": [summarize_json_value(item, depth=depth + 1) for item in value[:10]],
        }
    return value


def json_item_count(value: object) -> int:
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 1


def build_xml_preview(source_path: Path) -> dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"XML preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "capped"),
            "xml": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
        root = safe_xml_fromstring(text.encode("utf-8", errors="replace"))
        nodes = summarize_xml_nodes(root)
    except (OSError, ET.ParseError, UnsafeXmlError) as exc:
        return {
            "preview_type": "text",
            "message": f"XML parse failed, showing text fallback: {exc}",
            "text": safe_read_text(source_path, max_chars=20000),
            "truncated": source_path.stat().st_size > 20000,
            "viewer_metadata": structured_viewer_metadata("xml", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "xml",
        "message": "XML structured preview is available.",
        "text": text[:20000],
        "truncated": len(text) > 20000,
        "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "available"),
        "xml": {
            "root_tag": local_xml_name(root.tag),
            "root_attributes": dict(root.attrib),
            "nodes": nodes,
            "node_limit": XML_PREVIEW_NODE_LIMIT,
            "truncated": len(nodes) >= XML_PREVIEW_NODE_LIMIT,
        },
    }


def summarize_xml_nodes(root: ET.Element) -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    stack: list[tuple[ET.Element, str, int]] = [(root, "/" + local_xml_name(root.tag), 0)]
    while stack and len(nodes) < XML_PREVIEW_NODE_LIMIT:
        node, path, depth = stack.pop()
        text = " ".join((node.text or "").split())
        nodes.append(
            {
                "path": path,
                "tag": local_xml_name(node.tag),
                "depth": depth,
                "attributes": dict(list(node.attrib.items())[:10]),
                "text": text[:240],
                "child_count": len(list(node)),
            }
        )
        children = list(node)
        for index, child in reversed(list(enumerate(children[:20], start=1))):
            stack.append((child, f"{path}/{local_xml_name(child.tag)}[{index}]", depth + 1))
    return nodes


def local_xml_name(value: str) -> str:
    return value.rsplit("}", 1)[-1] if "}" in value else value
