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
    MEDIA_CUE_EXPORT_MAX_CHARS,
    MEDIA_TRANSCRIPT_PREVIEW_CHARS,
    MEDIA_TRANSCRIPT_REPORT_GRADE_BLOCKERS,
    MEDIA_TRANSCRIPT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    MEDIA_TRANSCRIPT_SUFFIXES,
    MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
    MEDIA_TRANSCRIPT_TRUSTED_TOOLS,
    SOURCE_VIEWER_VERSION,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .helpers import (
    _media_transcript_diff_key,
    _media_transcript_diff_values,
    optional_int_for_api,
    stable_payload_sha256,
)
from .viewer_core import (
    build_viewer_trusted_diff_result,
    viewer_workflow_commercial_uplift_evidence,
    viewer_workflow_reportability_decision,
)


def build_media_transcript_trusted_diff(
    rapid_sidecars: Sequence[Mapping[str, object]],
    trusted_sidecars: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "media-transcript-trusted-cue-diff",
) -> dict[str, object]:
    rapid_index = {_media_transcript_diff_key(row): _media_transcript_diff_values(row) for row in rapid_sidecars}
    trusted_index = {_media_transcript_diff_key(row): _media_transcript_diff_values(row) for row in trusted_sidecars}
    return build_viewer_trusted_diff_result(
        profile_version="media-transcript-trusted-cue-diff-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=MEDIA_TRANSCRIPT_TRUSTED_TOOLS,
        blocker_id=MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
        compare_fields=("sha256", "cue_count", "cues_sha256", "preview_sha256"),
    )


def media_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
    transcript_manifest: Mapping[str, object] | None = None,
    cue_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if metadata:
        satisfied.append("media metadata extracted")
    try:
        source_size = source_path.stat().st_size
    except OSError:
        source_size = 0
    if source_size <= 128 * 1024 * 1024:
        satisfied.append("source hashes captured")
    if sidecars:
        satisfied.append("transcript sidecars imported")
    if any(item.get("cues") for item in sidecars):
        satisfied.append("cue timestamps preserved")
    transcript_manifest = transcript_manifest if isinstance(transcript_manifest, Mapping) else {}
    if transcript_manifest.get("manifest_hash"):
        satisfied.append("media transcript source manifest")
    if transcript_manifest.get("cue_hash_count"):
        satisfied.append("transcript cue hashes")
    cue_manifest = cue_manifest if isinstance(cue_manifest, Mapping) else {}
    if cue_manifest.get("manifest_hash"):
        satisfied.append("media cue proof manifest")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("media transcript report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("media transcript report-grade ready slots")
    satisfied.append("playback/transcript verification warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted transcript cue/alignment diff pass")
    return [
        build_accuracy_gate(
            57,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"transcript_sidecar_count:{len(sidecars)}",
                f"media_transcript_manifest_hash:{transcript_manifest.get('manifest_hash', '')}",
                f"media_cue_manifest_hash:{cue_manifest.get('manifest_hash', '')}",
                f"media_transcript_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"media_transcript_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"media_transcript_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def build_media_transcript_report_grade_validation_plan(
    *,
    context: str,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
    source_hashes: Mapping[str, object] | None = None,
    transcript_manifest: Mapping[str, object] | None = None,
    cue_manifest: Mapping[str, object] | None = None,
    cue_package_profile: Mapping[str, object] | None = None,
    copy_safe_citation_ready: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_hashes = source_hashes if isinstance(source_hashes, Mapping) else {}
    transcript_manifest = transcript_manifest if isinstance(transcript_manifest, Mapping) else {}
    cue_manifest = cue_manifest if isinstance(cue_manifest, Mapping) else {}
    cue_package_profile = cue_package_profile if isinstance(cue_package_profile, Mapping) else {}
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    sidecar_count = len(sidecars)
    cue_count = sum(len(item.get("cues") or []) for item in sidecars)
    transcript_manifest_hash = str(transcript_manifest.get("manifest_hash") or "")
    cue_manifest_hash = str(cue_manifest.get("manifest_hash") or "")
    sidecar_row_hash_count = int(transcript_manifest.get("sidecar_row_hash_count") or 0)
    transcript_cue_hash_count = int(transcript_manifest.get("cue_hash_count") or 0)
    cue_profile_count = int(cue_package_profile.get("cue_count") or 0)
    cue_row = cue_manifest.get("cue") if isinstance(cue_manifest.get("cue"), Mapping) else {}
    source_sha256 = str(source_hashes.get("sha256") or cue_row.get("source_sha256") or "")
    validation_slots = [
        slot(
            "media-metadata-and-source-hash",
            ready=bool(metadata) and (bool(source_sha256) or source_path.exists()),
            evidence=(
                f"metadata_keys={sorted(str(key) for key in metadata.keys())} "
                f"source_sha256={source_sha256} source_exists={source_path.exists()}"
            ),
            blocker_id="media-metadata-and-source-hash-required",
            operator_action="Capture bounded media metadata and source hashes before transcript review.",
        ),
        slot(
            "media-transcript-sidecar-import",
            ready=sidecar_count > 0,
            evidence=f"sidecar_count={sidecar_count}",
            blocker_id="media-transcript-sidecar-import-required",
            operator_action="Import adjacent transcript sidecars or attach a trusted transcript export.",
        ),
        slot(
            "media-cue-timestamp-preservation",
            ready=cue_count > 0 or bool(cue_manifest_hash),
            evidence=f"cue_count={cue_count} cue_manifest_hash={cue_manifest_hash}",
            blocker_id="media-cue-timestamp-preservation-required",
            operator_action="Preserve cue start/end timestamps and text hashes for citation.",
        ),
        slot(
            "media-transcript-or-cue-manifest-hashes",
            ready=(bool(transcript_manifest_hash) and (sidecar_row_hash_count > 0 or transcript_cue_hash_count > 0))
            or bool(cue_manifest_hash),
            evidence=(
                f"transcript_manifest_hash={transcript_manifest_hash} sidecar_row_hash_count={sidecar_row_hash_count} "
                f"transcript_cue_hash_count={transcript_cue_hash_count} cue_manifest_hash={cue_manifest_hash}"
            ),
            blocker_id="media-transcript-or-cue-manifest-hashes-required",
            operator_action="Attach transcript/cue manifests with row hashes for reproducible review.",
        ),
        slot(
            "media-cue-package-or-profile",
            ready=cue_profile_count > 0 or bool(cue_manifest_hash),
            evidence=f"cue_profile_count={cue_profile_count} cue_manifest_hash={cue_manifest_hash}",
            blocker_id="media-cue-package-or-profile-required",
            operator_action="Expose a bounded cue package/profile before report handoff.",
        ),
        slot(
            "media-copy-safe-citation-or-warning",
            ready=copy_safe_citation_ready or bool(cue_package_profile) or bool(transcript_manifest_hash),
            evidence=(
                f"copy_safe_citation_ready={copy_safe_citation_ready} "
                f"cue_package_profile={bool(cue_package_profile)} transcript_manifest_hash={transcript_manifest_hash}"
            ),
            blocker_id="media-copy-safe-citation-or-warning-required",
            operator_action="Emit copy-safe cue citation text or a warning-backed cue profile.",
        ),
        slot(
            "media-safe-playback-sandbox",
            ready=False,
            evidence="safe_playback_sandbox=false",
            blocker_id="safe-playback-sandbox-required",
            operator_action="Add safe playback/waveform preview sandboxing and browser-test active media handling.",
        ),
        slot(
            "media-asr-execution-or-alignment",
            ready=False,
            evidence="asr_execution_or_alignment=false",
            blocker_id="asr-execution-or-alignment-required",
            operator_action="Run ASR or manual cue alignment validation with tool/version logs.",
        ),
        slot(
            "media-waveform-thumbnail-preview",
            ready=False,
            evidence="waveform_thumbnail_preview=false",
            blocker_id="waveform-thumbnail-preview-required",
            operator_action="Generate bounded waveform/video thumbnail previews without executing untrusted active content.",
        ),
        slot(
            "media-trusted-transcript-cue-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing trusted transcript cue/alignment manifest diff.",
        ),
        slot(
            "media-transcript-alignment-corpus",
            ready=False,
            evidence="transcript_alignment_corpus=false",
            blocker_id="transcript-alignment-corpus-required",
            operator_action="Validate cue parsing and alignment against a known-answer transcript/media corpus.",
        ),
        slot(
            "media-selected-cue-report-export",
            ready=False,
            evidence="selected_cue_report_export_integration=false",
            blocker_id="selected-cue-report-export-integration-required",
            operator_action="Wire selected cue packages into report/exhibit exports with manifest hashes.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": MEDIA_TRANSCRIPT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 57,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["media"],
        "batch_id": "commercial-uplift-056-060",
        "selected_track": "media-transcript-review-report-validation",
        "context": context,
        "path": str(source_path),
        "source_sha256": source_sha256,
        "metadata_sha256": stable_payload_sha256(dict(metadata)),
        "sidecar_count": sidecar_count,
        "cue_count": cue_count,
        "transcript_manifest_hash": transcript_manifest_hash,
        "cue_manifest_hash": cue_manifest_hash,
        "sidecar_row_hash_count": sidecar_row_hash_count,
        "transcript_cue_hash_count": transcript_cue_hash_count,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MEDIA_TRANSCRIPT_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage web -> source-preview for an audio/video source",
            "GET /api/runs/<run_id>/source-media-cue?path=<path>&sidecar_index=<n>&cue_index=<n>",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 57 --json",
        ],
        "report_guidance": {
            "allowed_use": "media-transcript-sidecar-triage-pivot",
            "forbidden_claim": "safe playback, ASR, waveform, or transcript-alignment-complete analysis",
            "required_disclaimer": (
                "Media transcript output is bounded sidecar/cue metadata until safe playback sandboxing, ASR/manual "
                "alignment evidence, waveform/thumbnail previews, trusted cue diffs, alignment corpus validation, "
                "and selected-cue report export integration are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_media_preview(source_path: Path, *, mime_type: str, run_id: str | None = None) -> dict[str, object]:
    sidecars = collect_media_transcript_sidecars(source_path)
    metadata: dict[str, object] = {
        "duration_seconds": None,
        "audio_channels": None,
        "sample_rate": None,
        "frame_count": None,
    }
    if source_path.suffix.lower() == ".wav":
        metadata.update(read_wav_metadata(source_path))
    source_hashes = compute_hashes(source_path) if source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    transcript_manifest = build_media_transcript_manifest(
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        source_hashes=source_hashes,
    )
    transcript_text = "\n\n".join(str(item.get("preview") or "") for item in sidecars)
    trusted_diff = {
        "status": "missing",
        "blocker_id": MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
        "required_tools": sorted(MEDIA_TRANSCRIPT_TRUSTED_TOOLS),
    }
    cue_package_profile = media_cue_package_profile(run_id=run_id, source_path=source_path, sidecars=sidecars)
    validation_plan = build_media_transcript_report_grade_validation_plan(
        context="media-preview",
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        source_hashes=source_hashes,
        transcript_manifest=transcript_manifest,
        cue_package_profile=cue_package_profile,
        trusted_diff=trusted_diff,
    )
    core_accuracy_gates = media_viewer_core_accuracy_gates(
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        transcript_manifest=transcript_manifest,
        trusted_diff=trusted_diff,
        validation_plan=validation_plan,
    )
    return {
        "preview_type": "media",
        "message": "Media metadata preview is available.",
        "text": transcript_text[:20000],
        "truncated": any(bool(item.get("truncated")) for item in sidecars),
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or mime_type,
            "strategy": "bounded-media-metadata",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.media",
            "parser_version": SOURCE_VIEWER_VERSION,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        },
        "media": {
            "mime_type": mime_type,
            "metadata": metadata,
            "source_hashes": source_hashes,
            "review": {
                "playback_sandbox": "not-played-or-transcoded-inline",
                "transcript_alignment": "sidecar-cue-based" if any(item.get("cues") for item in sidecars) else "not-available",
                "report_selection_hint": "Cite transcript cue timestamps only after verifying them against the original media.",
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
                "transcript_sidecar_verification_required": True,
                "cue_navigation_available": any(item.get("cues") for item in sidecars),
            },
            "transcript_sidecar_count": len(sidecars),
            "transcript_sidecars": sidecars,
            "media_transcript_manifest": transcript_manifest,
            "media_transcript_manifest_hash": transcript_manifest["manifest_hash"],
            "media_transcript_report_grade_validation_plan": validation_plan,
            "media_transcript_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "cue_package_profile": cue_package_profile,
            "media_transcript_assessment": media_transcript_assessment(sidecars=sidecars),
            "core_accuracy_gates": core_accuracy_gates,
            "trusted_media_transcript_diff": trusted_diff,
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=57,
                component="video-audio-preview-and-transcript",
                core_accuracy_gates=core_accuracy_gates,
                blockers=[
                    "media-playback-and-transcoding-not-performed-inline",
                    "automatic-speech-recognition-not-executed-by-viewer",
                    "transcript-sidecar-alignment-must-be-verified-against-original-media",
                    "selected-cue-report-export-not-implemented",
                    MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[
                    f"source_path:{source_path}",
                    f"transcript_sidecar_count:{len(sidecars)}",
                    f"media_transcript_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                ],
                controls={
                    "source_hashes_captured": source_path.stat().st_size <= 128 * 1024 * 1024,
                    "transcript_sidecar_count": len(sidecars),
                    "cue_count": sum(len(item.get("cues") or []) for item in sidecars),
                    "playback_executed_inline": False,
                    "asr_executed_inline": False,
                    "selected_cue_export": True,
                    "max_cue_export_chars": MEDIA_CUE_EXPORT_MAX_CHARS,
                    "media_transcript_manifest_hash": transcript_manifest["manifest_hash"],
                    "transcript_sidecar_row_hash_count": transcript_manifest["sidecar_row_hash_count"],
                    "transcript_cue_hash_count": transcript_manifest["cue_hash_count"],
                    "media_transcript_report_grade_validation_plan_present": bool(validation_plan.get("validation_plan_sha256")),
                    "media_transcript_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or ""),
                    "media_transcript_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                    "media_transcript_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
                },
            ),
            "limitations": [
                "Media playback/transcoding is not performed by the local viewer.",
                "Transcript sidecars are imported as review aids and must be verified against the original media.",
            ],
        },
}


def build_media_transcript_manifest(
    *,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
    source_hashes: Mapping[str, object],
) -> dict[str, object]:
    sidecar_entries = []
    cue_hash_count = 0
    for sidecar_index, sidecar in enumerate(sidecars, start=1):
        cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
        cue_entries = []
        for cue_index, cue in enumerate(cues, start=1):
            if not isinstance(cue, Mapping):
                continue
            cue_core = {
                "cue_index": cue_index,
                "start": str(cue.get("start") or ""),
                "end": str(cue.get("end") or ""),
                "text_sha256": str(cue.get("text_sha256") or ""),
            }
            cue_hash = str(cue.get("cue_hash") or stable_payload_sha256(cue_core))
            cue_entries.append({**cue_core, "cue_hash": cue_hash})
            cue_hash_count += 1
        sidecar_core = {
            "sidecar_index": sidecar_index,
            "path": str(sidecar.get("path") or ""),
            "name": str(sidecar.get("name") or ""),
            "size": optional_int_for_api(sidecar.get("size")),
            "modified_at": str(sidecar.get("modified_at") or ""),
            "sha256": str(sidecar.get("sha256") or ""),
            "cue_count": optional_int_for_api(sidecar.get("cue_count")) or len(cue_entries),
            "preview_sha256": hashlib.sha256(str(sidecar.get("preview") or "").encode("utf-8", errors="replace")).hexdigest()
            if sidecar.get("preview")
            else "",
            "validation_status": str(sidecar.get("validation_status") or ""),
            "cues": cue_entries,
        }
        sidecar_entries.append({**sidecar_core, "sidecar_row_hash": stable_payload_sha256(sidecar_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "media-transcript-source-manifest-v1",
        "item_number": 57,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "path": str(source_path),
        "name": source_path.name,
        "source_format": source_path.suffix.lower().lstrip("."),
        "source_hashes": dict(source_hashes),
        "metadata_sha256": stable_payload_sha256(dict(metadata)),
        "sidecar_count": len(sidecar_entries),
        "sidecar_row_hash_count": sum(1 for item in sidecar_entries if item.get("sidecar_row_hash")),
        "cue_hash_count": cue_hash_count,
        "source_viewer_locator": {
            "viewer": "source-media-transcript",
            "path": str(source_path),
            "open_action": "open-media-transcript-review",
        },
        "sidecars": sidecar_entries,
        "blockers": [
            "trusted-transcript-cue-alignment-diff-required-before-court-use",
            "safe-playback-or-asr-alignment-not-validated",
            "waveform-thumbnail-preview-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def media_transcript_assessment(*, sidecars: list[dict[str, object]]) -> dict[str, object]:
    return {
        "component": "video-audio-preview-and-transcript",
        "status": "sidecar-transcript-available" if sidecars else "metadata-only",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "ready_for_court_report": False,
        "cue_count": sum(len(item.get("cues") or []) for item in sidecars),
        "blockers": [
            "media-playback-and-transcoding-not-performed-inline",
            "automatic-speech-recognition-not-executed-by-viewer",
            "transcript-sidecar-alignment-must-be-verified-against-original-media",
        ],
    }


def media_cue_package_profile(*, run_id: str | None, source_path: Path, sidecars: Sequence[Mapping[str, object]]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    cue_links = []
    for sidecar_index, sidecar in enumerate(sidecars, start=1):
        cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
        for cue_index, cue in enumerate(cues, start=1):
            if not isinstance(cue, Mapping):
                continue
            cue_links.append(
                {
                    "sidecar_index": sidecar_index,
                    "cue_index": cue_index,
                    "sidecar_name": str(sidecar.get("name") or ""),
                    "start": str(cue.get("start") or ""),
                    "end": str(cue.get("end") or ""),
                    "text_sha256": str(cue.get("text_sha256") or ""),
                    "package_url": (
                        f"/api/runs/{run_id}/source-media-cue?path={quoted_path}&sidecar_index={sidecar_index}&cue_index={cue_index}"
                        if run_id
                        else None
                    ),
                }
            )
    return {
        "profile_version": "media-cue-package-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "endpoint": "/api/runs/{run_id}/source-media-cue",
        "cue_count": len(cue_links),
        "links": cue_links[:50],
        "max_cue_export_chars": MEDIA_CUE_EXPORT_MAX_CHARS,
        "supports_timestamp_citation": True,
        "supports_source_hash_reference": True,
        "playback_executed_inline": False,
        "asr_executed_inline": False,
        "report_use_warning": "Verify cue timestamps against playback or a trusted transcript alignment export before report-grade use.",
    }


def build_media_cue_package(
    *,
    run_id: str,
    source_path: Path,
    sidecar_index: int,
    cue_index: int,
    include_source_hashes: bool,
) -> dict[str, object]:
    sidecars = collect_media_transcript_sidecars(source_path)
    if sidecar_index > len(sidecars):
        raise HTTPException(status_code=404, detail="sidecar_index not found")
    sidecar = sidecars[sidecar_index - 1]
    cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
    if cue_index > len(cues):
        raise HTTPException(status_code=404, detail="cue_index not found")
    cue = cues[cue_index - 1]
    if not isinstance(cue, Mapping):
        raise HTTPException(status_code=404, detail="cue_index not found")
    cue_text = str(cue.get("text") or "")[:MEDIA_CUE_EXPORT_MAX_CHARS]
    cue_sha256 = hashlib.sha256(cue_text.encode("utf-8", errors="replace")).hexdigest() if cue_text else ""
    source_hashes = compute_hashes(source_path) if include_source_hashes and source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{sidecar.get('path')}|{sidecar_index}|{cue_index}|{cue.get('start')}|{cue.get('end')}|{cue_sha256}".encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()[:16]
    cue_proof_manifest = build_media_cue_proof_manifest(
        run_id=run_id,
        source_path=source_path,
        sidecar=sidecar,
        cue=cue,
        sidecar_index=sidecar_index,
        cue_index=cue_index,
        citation_id=citation_id,
        cue_text=cue_text,
        source_hashes=source_hashes,
    )
    metadata: dict[str, object] = {
        "duration_seconds": None,
        "audio_channels": None,
        "sample_rate": None,
        "frame_count": None,
    }
    if source_path.suffix.lower() == ".wav":
        metadata.update(read_wav_metadata(source_path))
    validation_plan = build_media_transcript_report_grade_validation_plan(
        context="media-cue-package",
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        source_hashes=source_hashes,
        cue_manifest=cue_proof_manifest,
        copy_safe_citation_ready=True,
    )
    core_accuracy_gates = media_viewer_core_accuracy_gates(
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        cue_manifest=cue_proof_manifest,
        validation_plan=validation_plan,
    )
    return {
        "command": "source-media-cue",
        "profile_version": "media-cue-citation-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "sidecar_index": sidecar_index,
        "cue_index": cue_index,
        "sidecar_path": str(sidecar.get("path") or ""),
        "sidecar_name": str(sidecar.get("name") or ""),
        "sidecar_sha256": str(sidecar.get("sha256") or ""),
        "start": str(cue.get("start") or ""),
        "end": str(cue.get("end") or ""),
        "text": cue_text,
        "text_sha256": cue_sha256,
        "truncated": len(str(cue.get("text") or "")) > MEDIA_CUE_EXPORT_MAX_CHARS,
        "source_hashes": source_hashes,
        "source_hash_status": "computed" if source_hashes else "available-on-demand",
        "media_cue_proof_manifest": cue_proof_manifest,
        "media_cue_proof_manifest_hash": cue_proof_manifest["manifest_hash"],
        "media_transcript_report_grade_validation_plan": validation_plan,
        "media_transcript_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "core_accuracy_gates": core_accuracy_gates,
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; sidecar={sidecar.get('name', '')}; cue={cue_index}; "
                f"time={cue.get('start', '')}-{cue.get('end', '')}; text_sha256={cue_sha256}; citation_id={citation_id}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=57,
            component="media-cue-citation-package",
            blockers=[
                "trusted-transcript-cue-alignment-diff-required-before-court-use",
                "manual-playback-or-asr-alignment-review-required",
                "waveform-thumbnail-preview-not-implemented",
            ],
            controls={
                "cue_timestamp_citation": True,
                "cue_text_hash": bool(cue_sha256),
                "source_hashes_included": bool(source_hashes),
                "playback_executed_inline": False,
                "asr_executed_inline": False,
                "media_transcript_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "media_transcript_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "media_transcript_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def build_media_cue_proof_manifest(
    *,
    run_id: str,
    source_path: Path,
    sidecar: Mapping[str, object],
    cue: Mapping[str, object],
    sidecar_index: int,
    cue_index: int,
    citation_id: str,
    cue_text: str,
    source_hashes: Mapping[str, object],
) -> dict[str, object]:
    cue_core = {
        "sidecar_index": sidecar_index,
        "cue_index": cue_index,
        "start": str(cue.get("start") or ""),
        "end": str(cue.get("end") or ""),
        "text_sha256": hashlib.sha256(cue_text.encode("utf-8", errors="replace")).hexdigest() if cue_text else "",
        "sidecar_sha256": str(sidecar.get("sha256") or ""),
        "source_sha256": str(source_hashes.get("sha256") or ""),
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "media-cue-proof-manifest-v1",
        "item_number": 57,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "run_id": run_id,
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "sidecar_path": str(sidecar.get("path") or ""),
        "sidecar_name": str(sidecar.get("name") or ""),
        "source_hashes": dict(source_hashes),
        "cue": {**cue_core, "cue_hash": str(cue.get("cue_hash") or stable_payload_sha256(cue_core))},
        "source_viewer_locator": {
            "viewer": "source-media-cue",
            "path": str(source_path),
            "sidecar_index": sidecar_index,
            "cue_index": cue_index,
            "open_action": "open-media-cue-citation",
        },
        "blockers": [
            "trusted-transcript-cue-alignment-diff-required-before-court-use",
            "manual-playback-or-asr-alignment-review-required",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def collect_media_transcript_sidecars(source_path: Path) -> list[dict[str, object]]:
    candidates: list[Path] = []
    for suffix in MEDIA_TRANSCRIPT_SUFFIXES:
        candidates.append(source_path.with_suffix(source_path.suffix + suffix))
        candidates.append(source_path.with_suffix(suffix))
    output = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
            stat = candidate.stat()
        except OSError:
            continue
        cues = parse_transcript_cues(text)
        output.append(
            {
                "path": str(candidate),
                "name": candidate.name,
                "size": stat.st_size,
                "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
                "sha256": compute_hashes(candidate)["sha256"] if stat.st_size <= 20 * 1024 * 1024 else "",
                "preview": text[:MEDIA_TRANSCRIPT_PREVIEW_CHARS],
                "cues": cues,
                "cue_count": len(cues),
                "truncated": len(text) > MEDIA_TRANSCRIPT_PREVIEW_CHARS,
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
                "validation_status": "sidecar-review-required",
                "report_use": "review-aid-until-verified-against-original-media",
            }
        )
    return output


def parse_transcript_cues(text: str, *, limit: int = 20) -> list[dict[str, object]]:
    cues: list[dict[str, object]] = []
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    index = 0
    while index < len(lines) and len(cues) < limit:
        line = lines[index]
        if "-->" not in line:
            index += 1
            continue
        start, end = [part.strip() for part in line.split("-->", 1)]
        cue_lines: list[str] = []
        index += 1
        while index < len(lines) and lines[index]:
            cue_lines.append(lines[index])
            index += 1
        text_value = " ".join(cue_lines).strip()
        cues.append(
            {
                "start": start,
                "end": end,
                "text": text_value[:500],
                "text_sha256": hashlib.sha256(text_value.encode("utf-8", errors="replace")).hexdigest() if text_value else "",
                "cue_hash": stable_payload_sha256(
                    {
                        "start": start,
                        "end": end,
                        "text_sha256": hashlib.sha256(text_value.encode("utf-8", errors="replace")).hexdigest() if text_value else "",
                    }
                ),
            }
        )
        index += 1
    return cues


def read_wav_metadata(source_path: Path) -> dict[str, object]:
    try:
        with wave.open(str(source_path), "rb") as wav_file:
            frames = wav_file.getnframes()
            rate = wav_file.getframerate()
            return {
                "duration_seconds": round(frames / rate, 3) if rate else None,
                "audio_channels": wav_file.getnchannels(),
                "sample_rate": rate,
                "frame_count": frames,
            }
    except (OSError, wave.Error):
        return {}
