from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.ocr_queue import (
    OcrQueueError,
    build_ocr_queue,
    build_ocr_queue_report_grade_validation_plan,
)
from ...core.submission import compute_hashes
from .constants import (
    IMAGE_GALLERY_DEFAULT_LIMIT,
    IMAGE_GALLERY_MAX_ITEMS,
    IMAGE_GALLERY_REPORT_GRADE_BLOCKERS,
    IMAGE_GALLERY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    IMAGE_GALLERY_TRUSTED_DIFF_BLOCKER,
    SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
    SOURCE_OCR_TRANSLATION_MAX_CHARS,
    SOURCE_VIEWER_VERSION,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .helpers import (
    is_image_preview_candidate,
    optional_int_for_api,
    stable_payload_sha256,
    stable_source_queue_id,
)
from .viewer_core import (
    viewer_workflow_commercial_uplift_evidence,
    viewer_workflow_reportability_decision,
)


def build_image_preview(source_path: Path, *, image_url: str, run_id: str | None = None) -> dict[str, object]:
    try:
        from ...artifacts.media import build_image_record

        artifact = build_image_record(source_path)
        details = artifact.details
        thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), dict) else {}
        gallery_page = image_gallery_page_profile(run_id=run_id, source_path=source_path, details=details)
        ocr_queue_page = source_ocr_queue_profile(run_id=run_id, source_path=source_path)
        translation_review = source_ocr_translation_profile(run_id=run_id, source_path=source_path, details=details)
        gallery_manifest = details.get("image_gallery_manifest") if isinstance(details.get("image_gallery_manifest"), dict) else {}
        validation_plan = build_image_gallery_report_grade_validation_plan(
            context="image-preview",
            source_path=source_path,
            details=details,
            gallery_manifest=gallery_manifest,
            gallery_page_profile=gallery_page,
        )
        core_accuracy_gates = image_viewer_core_accuracy_gates(
            source_path=source_path,
            details=details,
            gallery_manifest=gallery_manifest,
            validation_plan=validation_plan,
        )
        image_payload = {
            "decoded": bool(details.get("decoded")),
            "width": details.get("width"),
            "height": details.get("height"),
            "channel_count": details.get("channel_count"),
            "hashes": details.get("hashes") if isinstance(details.get("hashes"), dict) else {},
            "perceptual_hash": str(details.get("perceptual_hash") or ""),
            "similarity_bucket": str(details.get("similarity_bucket") or ""),
            "visual_classification": details.get("visual_classification") if isinstance(details.get("visual_classification"), dict) else {},
            "thumbnail_preview": thumbnail,
            "ocr_plan": details.get("ocr_plan") if isinstance(details.get("ocr_plan"), dict) else {},
            "translation_plan": details.get("translation_plan") if isinstance(details.get("translation_plan"), dict) else {},
            "ocr_sidecar": details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), dict) else {},
            "translation_sidecar": details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), dict) else {},
            "ocr_queue_profile": ocr_queue_page,
            "korean_ocr_translation_profile": translation_review,
            "korean_ocr_translation_report_grade_validation_plan": details.get(
                "korean_ocr_translation_report_grade_validation_plan"
            )
            if isinstance(details.get("korean_ocr_translation_report_grade_validation_plan"), dict)
            else {},
            "korean_ocr_translation_report_grade_validation_plan_hash": str(
                details.get("korean_ocr_translation_report_grade_validation_plan_hash") or ""
            ),
            "gallery_review": {
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
                "tag_suggestions": image_tag_suggestions(details),
                "report_selection_hint": "Use review marks to include the image after verifying source hashes and context.",
                "similarity_bucket_key": str(details.get("similarity_bucket") or ""),
                "compare_ready": bool(details.get("perceptual_hash")),
                "gallery_page_url": gallery_page.get("default_page_url"),
            },
            "gallery_page_profile": gallery_page,
            "image_gallery_manifest": gallery_manifest,
            "image_gallery_manifest_hash": str(gallery_manifest.get("manifest_hash") or ""),
            "gallery_review_assessment": image_gallery_review_assessment(details),
            "image_gallery_report_grade_validation_plan": validation_plan,
            "image_gallery_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "core_accuracy_gates": core_accuracy_gates,
            "commercial_uplift_evidence": image_viewer_commercial_uplift_evidence(
                source_path=source_path,
                details=details,
                gallery_manifest=gallery_manifest,
                validation_plan=validation_plan,
            ),
            "ocr_queue_assessment": details.get("ocr_queue_assessment") if isinstance(details.get("ocr_queue_assessment"), dict) else {},
            "korean_ocr_translation_workflow": details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), dict) else {},
        }
    except Exception as exc:
        validation_plan = build_image_gallery_report_grade_validation_plan(
            context="image-preview-error",
            source_path=source_path,
            details={},
            gallery_manifest={},
            gallery_page_profile=image_gallery_page_profile(run_id=run_id, source_path=source_path, details={}),
        )
        core_accuracy_gates = image_viewer_core_accuracy_gates(
            source_path=source_path,
            details={},
            validation_plan=validation_plan,
        )
        image_payload = {
            "decoded": False,
            "error": str(exc),
            "hashes": {},
            "gallery_review": {
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
                "tag_suggestions": ["image-review-needed"],
                "report_selection_hint": "Open the authoritative image and compute hashes before report use.",
                "similarity_bucket_key": "",
                "compare_ready": False,
            },
            "gallery_page_profile": image_gallery_page_profile(run_id=run_id, source_path=source_path, details={}),
            "image_gallery_manifest": {},
            "image_gallery_manifest_hash": "",
            "ocr_queue_profile": source_ocr_queue_profile(run_id=run_id, source_path=source_path),
            "korean_ocr_translation_profile": source_ocr_translation_profile(run_id=run_id, source_path=source_path, details={}),
            "gallery_review_assessment": image_gallery_review_assessment({}),
            "image_gallery_report_grade_validation_plan": validation_plan,
            "image_gallery_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "core_accuracy_gates": core_accuracy_gates,
            "commercial_uplift_evidence": image_viewer_commercial_uplift_evidence(
                source_path=source_path,
                details={},
                validation_plan=validation_plan,
            ),
        }
    return {
        "preview_type": "image",
        "image_url": image_url,
        "message": "Image preview and gallery review metadata are available.",
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or "image",
            "strategy": "image-gallery-preview",
            "preview_status": "available" if image_payload.get("decoded") else "metadata-only",
            "parser": "rapidtriage.source-viewer.image-gallery",
            "parser_version": SOURCE_VIEWER_VERSION,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"], VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        },
        "image": image_payload,
    }


def image_gallery_review_assessment(details: Mapping[str, object]) -> dict[str, object]:
    return {
        "component": "image-gallery-review-mode",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "ready_for_court_report": False,
        "supports": [
            "thumbnail-preview",
            "similarity-bucket",
            "ocr-sidecar-status",
            "translation-sidecar-status",
            "report-selection-hint",
        ],
        "blockers": [
            "dedicated-large-gallery-virtualization-and-bulk-tagging-remain-limited",
            "similarity-is-perceptual-hash-bucket-not-ml-validated",
            "deepfake-and-sensitive-media-classification-not-implemented",
        ],
        "source_perceptual_hash_present": bool(details.get("perceptual_hash")),
    }


def image_gallery_page_profile(*, run_id: str | None, source_path: Path, details: Mapping[str, object]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    bucket = str(details.get("similarity_bucket") or "")
    default_page_url = (
        f"/api/runs/{run_id}/source-image-gallery?path={quoted_path}&offset=0&limit={IMAGE_GALLERY_DEFAULT_LIMIT}"
        if run_id
        else None
    )
    bucket_page_url = (
        f"{default_page_url}&similarity_bucket={quote(bucket)}"
        if default_page_url and bucket
        else None
    )
    return {
        "profile_version": "image-gallery-page-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "endpoint": "/api/runs/{run_id}/source-image-gallery",
        "default_page_url": default_page_url,
        "bucket_page_url": bucket_page_url,
        "anchor_similarity_bucket": bucket,
        "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
        "default_limit": IMAGE_GALLERY_DEFAULT_LIMIT,
        "supports_folder_gallery_page": True,
        "supports_similarity_bucket_filter": True,
        "supports_keyboard_triage_metadata": True,
        "persistent_tags": False,
        "report_use_warning": "Treat perceptual buckets and tags as triage hints until validated against a trusted image gallery manifest.",
    }


def source_ocr_queue_profile(*, run_id: str | None, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    queue_url = (
        f"/api/runs/{run_id}/source-ocr-queue?path={quoted_path}&max_items={SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS}"
        if run_id
        else None
    )
    return {
        "profile_version": "source-ocr-queue-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "endpoint": "/api/runs/{run_id}/source-ocr-queue",
        "default_queue_url": queue_url,
        "scope": "anchor-image-parent-folder",
        "max_default_items": SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
        "supports_sidecar_inventory": True,
        "supports_retry_failure_projection": True,
        "case_db_persistence": False,
        "native_ocr_execution": False,
        "report_use_warning": "Queue state coordinates OCR work; attach sidecar hashes and engine logs before report-grade OCR claims.",
    }


def source_ocr_translation_profile(*, run_id: str | None, source_path: Path, details: Mapping[str, object]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    review_url = (
        f"/api/runs/{run_id}/source-ocr-translation?path={quoted_path}&include_text=true"
        if run_id
        else None
    )
    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), Mapping) else {}
    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), Mapping) else {}
    workflow = details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), Mapping) else {}
    return {
        "profile_version": "source-ocr-translation-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "endpoint": "/api/runs/{run_id}/source-ocr-translation",
        "default_review_url": review_url,
        "has_ocr_sidecar": bool(ocr_sidecar),
        "has_translation_sidecar": bool(translation_sidecar),
        "korean_detected_or_expected": bool(workflow.get("korean_detected_or_expected")),
        "supports_side_by_side_review": True,
        "preserves_original_image": True,
        "max_text_chars": SOURCE_OCR_TRANSLATION_MAX_CHARS,
        "native_korean_ocr_execution": False,
        "machine_translation_execution": False,
        "certified_translation": False,
        "report_use_warning": "Use this side-by-side OCR/translation review as triage until Korean OCR calibration and certified translation evidence are attached.",
    }


def build_source_ocr_queue(*, run_id: str, anchor_path: Path, max_items: int, retry_failures: bool) -> dict[str, object]:
    try:
        queue = build_ocr_queue(anchor_path.parent, max_items=max_items, retry_failures=retry_failures)
    except OcrQueueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    items = queue.get("items") if isinstance(queue.get("items"), list) else []
    anchor_id = hashlib.sha256(str(anchor_path.resolve()).encode("utf-8", errors="replace")).hexdigest()[:16]
    queue["profile_version"] = "source-ocr-queue-page-v1"
    queue["run_id"] = run_id
    queue["anchor_path"] = str(anchor_path)
    queue["anchor_name"] = anchor_path.name
    queue["anchor_queue_id"] = stable_source_queue_id(anchor_path)
    queue["viewer_context"] = {
        "profile_version": "source-ocr-queue-viewer-context-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "anchor_id": anchor_id,
        "scope": "parent-folder",
        "item_count": len(items),
        "retry_failures": retry_failures,
        "case_db_persistence": False,
        "native_ocr_execution": False,
        "work_queue_controls": {
            "max_items": max_items,
            "bounded_folder_scan": True,
            "sidecar_hashes_preserved": True,
            "engine_logs_required_for_report": True,
        },
        "review_actions": [
            "open sidecar text next to source image",
            "run external OCR engine outside RapidTriage and preserve logs",
            "rebuild queue with retry_failures after failed engine runs",
            "mark OCR-derived evidence only after source and sidecar hashes are verified",
        ],
    }
    page_manifest = build_source_ocr_queue_page_manifest(
        run_id=run_id,
        anchor_path=anchor_path,
        queue=queue,
        items=items,
    )
    queue["source_ocr_queue_page_manifest"] = page_manifest
    queue["source_ocr_queue_page_manifest_hash"] = page_manifest["manifest_hash"]
    page_validation_plan = build_ocr_queue_report_grade_validation_plan(
        context="source-ocr-queue-page",
        root=Path(str(queue.get("root") or anchor_path.parent)),
        items=items,
        queue_manifest=queue.get("ocr_queue_manifest") if isinstance(queue.get("ocr_queue_manifest"), Mapping) else {},
        page_manifest=page_manifest,
        trusted_diffs=queue.get("trusted_ocr_queue_diffs") if isinstance(queue.get("trusted_ocr_queue_diffs"), Mapping) else {},
    )
    queue["source_ocr_queue_report_grade_validation_plan"] = page_validation_plan
    queue["source_ocr_queue_report_grade_validation_plan_hash"] = page_validation_plan["validation_plan_sha256"]
    if isinstance(queue.get("commercial_uplift_evidence"), dict):
        controls = queue["commercial_uplift_evidence"]["large_data_controls"]
        controls["source_ocr_queue_page_manifest_hash"] = page_manifest["manifest_hash"]
        controls["source_ocr_queue_report_grade_validation_plan_hash"] = page_validation_plan["validation_plan_sha256"]
        controls["source_ocr_queue_report_grade_ready_slot_count"] = page_validation_plan["ready_slot_count"]
        controls["source_ocr_queue_report_grade_blocking_slot_count"] = page_validation_plan["blocking_slot_count"]
    queue["copy_safe_citation"] = {
        "text": (
            f"OCR queue scope={anchor_path.parent.name}; anchor={anchor_path.name}; "
            f"candidate_count={queue.get('summary', {}).get('candidate_count', 0)}; anchor_queue_id={queue['anchor_queue_id']}"
        ),
        "redacts_full_path": True,
    }
    return queue


def build_source_ocr_queue_page_manifest(
    *,
    run_id: str,
    anchor_path: Path,
    queue: Mapping[str, object],
    items: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    item_rows = []
    for index, item in enumerate(items, start=1):
        item_manifest = item.get("ocr_queue_item_manifest") if isinstance(item.get("ocr_queue_item_manifest"), Mapping) else {}
        row_core = {
            "index": index,
            "queue_id": str(item.get("queue_id") or ""),
            "source_path": str(item.get("source_path") or ""),
            "source_name": str(item.get("source_name") or ""),
            "status": str(item.get("status") or ""),
            "language_hint": str(item.get("language_hint") or ""),
            "source_sha256": str(item.get("source_sha256") or ""),
            "item_manifest_hash": str(item_manifest.get("manifest_hash") or item.get("ocr_queue_item_manifest_hash") or ""),
        }
        item_rows.append({**row_core, "page_row_hash": stable_payload_sha256(row_core)})
    queue_manifest = queue.get("ocr_queue_manifest") if isinstance(queue.get("ocr_queue_manifest"), Mapping) else {}
    manifest_core: dict[str, object] = {
        "manifest_version": "source-ocr-queue-page-manifest-v1",
        "item_numbers": [58, 59],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "run_id": run_id,
        "anchor_path": str(anchor_path),
        "anchor_name": anchor_path.name,
        "root": str(queue.get("root") or anchor_path.parent),
        "candidate_count": len(item_rows),
        "summary": queue.get("summary") if isinstance(queue.get("summary"), Mapping) else {},
        "ocr_queue_manifest_hash": str(queue_manifest.get("manifest_hash") or queue.get("ocr_queue_manifest_hash") or ""),
        "page_row_hash_count": sum(1 for item in item_rows if item.get("page_row_hash")),
        "source_viewer_locator": {
            "viewer": "source-ocr-queue-page",
            "path": str(anchor_path),
            "run_id": run_id,
            "open_action": "open-source-ocr-queue-page",
        },
        "items": item_rows,
        "blockers": [
            "native-ocr-engine-execution-not-implemented",
            "browser-editable-queue-state-not-persisted",
            "case-db-ocr-job-persistence-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_source_ocr_translation_package(*, run_id: str, source_path: Path, include_text: bool) -> dict[str, object]:
    try:
        from ...artifacts.media import (
            build_image_record,
            build_korean_ocr_translation_report_grade_validation_plan,
        )

        details = build_image_record(source_path).details
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to build OCR/translation review: {exc}") from exc
    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), Mapping) else {}
    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), Mapping) else {}
    workflow = details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), Mapping) else {}
    ocr_text = str(ocr_sidecar.get("text") or "")
    translation_text = str(translation_sidecar.get("text") or "")
    ocr_text_bounded = ocr_text[:SOURCE_OCR_TRANSLATION_MAX_CHARS]
    translation_text_bounded = translation_text[:SOURCE_OCR_TRANSLATION_MAX_CHARS]
    side_by_side_review = [
        build_ocr_translation_review_side(
            role="ocr-source",
            label="Original OCR text",
            language_hint=str(ocr_sidecar.get("language_hint") or "unknown"),
            sidecar=ocr_sidecar,
            text=ocr_text_bounded,
            include_text=include_text,
            original_length=len(ocr_text),
        ),
        build_ocr_translation_review_side(
            role="translation-target",
            label="Translation sidecar text",
            language_hint=str(translation_sidecar.get("target_language") or "en"),
            sidecar=translation_sidecar,
            text=translation_text_bounded,
            include_text=include_text,
            original_length=len(translation_text),
        ),
    ]
    source_hashes = compute_hashes(source_path) if source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    review_manifest = build_ocr_translation_review_manifest(
        run_id=run_id,
        source_path=source_path,
        source_hashes=source_hashes,
        side_by_side_review=side_by_side_review,
        workflow=workflow,
    )
    trusted_diffs = details.get("media_trusted_diffs") if isinstance(details.get("media_trusted_diffs"), Mapping) else {}
    validation_plan = build_korean_ocr_translation_report_grade_validation_plan(
        context="source-ocr-translation-review",
        source_path=source_path,
        source_hashes=source_hashes,
        workflow=workflow,
        ocr_sidecar=ocr_sidecar,
        translation_sidecar=translation_sidecar,
        review_manifest=review_manifest,
        trusted_diffs=trusted_diffs,
    )
    core_gates = [
        gate
        for gate in details.get("core_accuracy_gates", [])
        if isinstance(gate, Mapping) and str(gate.get("gap_id")) == VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]
    ]
    if not core_gates:
        core_gates = [
            build_accuracy_gate(
                59,
                satisfied_checks=[
                    "Korean language hinting" if workflow.get("language_hints") else "workflow profile emitted",
                    "translation sidecar import" if translation_sidecar else "translation requirement disclosed",
                    "human translation validation warning",
                ],
                evidence_refs=[
                    f"source_path:{source_path}",
                    f"ocr_sidecar:{ocr_sidecar.get('source_path', '')}",
                    f"translation_sidecar:{translation_sidecar.get('source_path', '')}",
                ],
            )
        ]
    core_gates = augment_ocr_translation_core_gates(core_gates, review_manifest, validation_plan=validation_plan)
    commercial_uplift = (
        dict(details.get("commercial_uplift_evidence"))
        if isinstance(details.get("commercial_uplift_evidence"), Mapping)
        else {}
    )
    if commercial_uplift:
        controls = (
            dict(commercial_uplift.get("large_data_controls"))
            if isinstance(commercial_uplift.get("large_data_controls"), Mapping)
            else {}
        )
        controls["source_ocr_translation_report_grade_validation_plan_hash"] = validation_plan["validation_plan_sha256"]
        controls["source_ocr_translation_report_grade_ready_slot_count"] = validation_plan["ready_slot_count"]
        controls["source_ocr_translation_report_grade_blocking_slot_count"] = validation_plan["blocking_slot_count"]
        commercial_uplift["large_data_controls"] = controls
    return {
        "command": "source-ocr-translation",
        "profile_version": "source-ocr-translation-review-v1",
        "run_id": run_id,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "summary": {
            "ocr_sidecar_present": bool(ocr_sidecar),
            "translation_sidecar_present": bool(translation_sidecar),
            "korean_detected_or_expected": bool(workflow.get("korean_detected_or_expected")),
            "translation_required": bool(workflow.get("translation_required")),
            "text_included": include_text,
            "ready_for_court_report": False,
        },
        "side_by_side_review": side_by_side_review,
        "source_ocr_translation_review_manifest": review_manifest,
        "source_ocr_translation_review_manifest_hash": review_manifest["manifest_hash"],
        "source_ocr_translation_report_grade_validation_plan": validation_plan,
        "source_ocr_translation_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "review_profile": {
            "status": "side-by-side-review-ready" if ocr_sidecar or translation_sidecar else "ocr-and-translation-sidecars-missing",
            "supports_side_by_side_review": True,
            "preserves_original_image": True,
            "max_text_chars_per_side": SOURCE_OCR_TRANSLATION_MAX_CHARS,
            "native_korean_ocr_execution": False,
            "machine_translation_execution": False,
            "certified_translation": False,
            "required_before_report": [
                "attach OCR engine name/version/language-pack logs",
                "human-review Korean OCR text against the original image",
                "attach certified translation or reviewer signoff before citing translated text",
                "compare against trusted Korean OCR/translation review diff evidence",
            ],
            "report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
            "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        },
        "workflow": workflow,
        "core_accuracy_gates": core_gates,
        "commercial_uplift_evidence": commercial_uplift,
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=59,
            component="korean-ocr-translation-review",
            blockers=[
                "built-in-korean-ocr-execution-not-implemented",
                "machine-translation-worker-not-implemented",
                "certified-translation-review-required",
                "trusted-korean-ocr-translation-review-diff-required",
            ],
            controls={
                "side_by_side_review": True,
                "ocr_sidecar_present": bool(ocr_sidecar),
                "translation_sidecar_present": bool(translation_sidecar),
                "native_korean_ocr_execution": False,
                "machine_translation_execution": False,
                "review_manifest_hash": review_manifest["manifest_hash"],
                "report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
        "copy_safe_citation": {
            "text": (
                f"Korean OCR/translation review source={source_path.name}; "
                f"ocr_sha256={ocr_sidecar.get('source_sha256', '')}; "
                f"translation_sha256={translation_sidecar.get('source_sha256', '')}"
            ),
            "redacts_full_path": True,
        },
    }


def augment_ocr_translation_core_gates(
    core_gates: Sequence[Mapping[str, object]],
    review_manifest: Mapping[str, object],
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    output: list[dict[str, object]] = []
    for gate in core_gates:
        copied = dict(gate)
        satisfied = list(copied.get("satisfied_checks") or [])
        evidence_refs = list(copied.get("evidence_refs") or [])
        if review_manifest.get("manifest_hash") and "OCR/translation review manifest" not in satisfied:
            satisfied.append("OCR/translation review manifest")
            evidence_refs.append(f"ocr_translation_review_manifest_hash:{review_manifest.get('manifest_hash')}")
        if review_manifest.get("review_side_hash_count") and "side-by-side review row hashes" not in satisfied:
            satisfied.append("side-by-side review row hashes")
        if isinstance(review_manifest.get("source_viewer_locator"), Mapping) and "source viewer locator emitted" not in satisfied:
            satisfied.append("source viewer locator emitted")
        if validation_plan.get("validation_plan_sha256") and "Korean OCR/translation report-grade validation plan" not in satisfied:
            satisfied.append("Korean OCR/translation report-grade validation plan")
            evidence_refs.append(
                f"korean_ocr_translation_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256')}"
            )
        if int(validation_plan.get("ready_slot_count") or 0) >= 6 and "Korean OCR/translation ready slots" not in satisfied:
            satisfied.append("Korean OCR/translation ready slots")
        copied["satisfied_checks"] = satisfied
        copied["evidence_refs"] = evidence_refs
        output.append(copied)
    return output


def build_ocr_translation_review_manifest(
    *,
    run_id: str,
    source_path: Path,
    source_hashes: Mapping[str, object],
    side_by_side_review: Sequence[Mapping[str, object]],
    workflow: Mapping[str, object],
) -> dict[str, object]:
    side_entries = []
    for index, side in enumerate(side_by_side_review, start=1):
        side_core = {
            "index": index,
            "role": str(side.get("role") or ""),
            "label": str(side.get("label") or ""),
            "language_hint": str(side.get("language_hint") or ""),
            "sidecar_path": str(side.get("sidecar_path") or ""),
            "sidecar_name": str(side.get("sidecar_name") or ""),
            "sidecar_sha256": str(side.get("sidecar_sha256") or ""),
            "text_sha256": str(side.get("text_sha256") or ""),
            "character_count": optional_int_for_api(side.get("character_count")),
            "text_included": bool(side.get("text_included")),
            "truncated": bool(side.get("truncated")),
        }
        side_entries.append({**side_core, "review_side_hash": stable_payload_sha256(side_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "source-ocr-translation-review-manifest-v1",
        "item_number": 59,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "run_id": run_id,
        "path": str(source_path),
        "name": source_path.name,
        "source_hashes": dict(source_hashes),
        "workflow_sha256": stable_payload_sha256(dict(workflow)),
        "review_side_count": len(side_entries),
        "review_side_hash_count": sum(1 for item in side_entries if item.get("review_side_hash")),
        "source_viewer_locator": {
            "viewer": "source-ocr-translation-review",
            "path": str(source_path),
            "run_id": run_id,
            "open_action": "open-ocr-translation-side-by-side-review",
        },
        "sides": side_entries,
        "blockers": [
            "trusted-korean-ocr-translation-review-diff-required",
            "built-in-korean-ocr-execution-not-implemented",
            "certified-translation-review-required",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_ocr_translation_review_side(
    *,
    role: str,
    label: str,
    language_hint: str,
    sidecar: Mapping[str, object],
    text: str,
    include_text: bool,
    original_length: int,
) -> dict[str, object]:
    return {
        "role": role,
        "label": label,
        "language_hint": language_hint,
        "sidecar_path": str(sidecar.get("source_path") or ""),
        "sidecar_name": Path(str(sidecar.get("source_path") or "")).name if sidecar.get("source_path") else "",
        "sidecar_sha256": str(sidecar.get("source_sha256") or ""),
        "text_sha256": str(sidecar.get("text_sha256") or ""),
        "character_count": int(sidecar.get("character_count") or original_length),
        "quality_metrics": sidecar.get("quality_metrics") if isinstance(sidecar.get("quality_metrics"), Mapping) else {},
        "truncated": bool(sidecar.get("truncated")) or original_length > SOURCE_OCR_TRANSLATION_MAX_CHARS,
        "text": text if include_text else "",
        "text_included": include_text,
    }


def build_image_gallery_page(
    *,
    run_id: str,
    anchor_path: Path,
    offset: int,
    limit: int,
    similarity_bucket: str | None,
) -> dict[str, object]:
    candidates = sorted(
        [path for path in anchor_path.parent.iterdir() if path.is_file() and is_image_preview_candidate(path)],
        key=lambda item: item.name.lower(),
    )
    items = []
    for path in candidates[: max(IMAGE_GALLERY_MAX_ITEMS * 2, limit + offset)]:
        summary = image_gallery_item_summary(run_id=run_id, path=path, anchor_path=anchor_path)
        if similarity_bucket and summary.get("similarity_bucket") != similarity_bucket:
            continue
        items.append(summary)
        if len(items) >= IMAGE_GALLERY_MAX_ITEMS:
            break
    total = len(items)
    page_items = items[offset : offset + limit]
    next_offset = offset + len(page_items)
    bucket_counts: dict[str, int] = {}
    for item in items:
        bucket = str(item.get("similarity_bucket") or "unknown")
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
    gallery_manifest = build_image_gallery_page_manifest(
        anchor_path=anchor_path,
        items=page_items,
        offset=offset,
        limit=limit,
        total=total,
        similarity_bucket=similarity_bucket,
        bucket_counts=bucket_counts,
    )
    page_controls = {
        "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
        "bounded_folder_scan": True,
        "inline_originals_not_copied": True,
        "thumbnail_metadata_only": True,
        "keyboard_triage": True,
        "persistent_tags": False,
    }
    page_details = image_gallery_page_details_for_validation(page_items)
    validation_plan = build_image_gallery_report_grade_validation_plan(
        context="image-gallery-page",
        source_path=anchor_path,
        details=page_details,
        page_manifest=gallery_manifest,
        page_items=page_items,
        page_controls=page_controls,
    )
    core_accuracy_gates = image_viewer_core_accuracy_gates(
        source_path=anchor_path,
        details=page_details,
        gallery_manifest=gallery_manifest,
        validation_plan=validation_plan,
    )
    return {
        "command": "source-image-gallery",
        "profile_version": "image-gallery-page-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "anchor_path": str(anchor_path),
        "anchor_name": anchor_path.name,
        "offset": offset,
        "limit": limit,
        "returned": len(page_items),
        "total": total,
        "has_next": next_offset < total,
        "next_offset": next_offset if next_offset < total else None,
        "similarity_bucket_filter": similarity_bucket or "",
        "bucket_counts": bucket_counts,
        "image_gallery_page_manifest": gallery_manifest,
        "image_gallery_page_manifest_hash": gallery_manifest["manifest_hash"],
        "image_gallery_report_grade_validation_plan": validation_plan,
        "image_gallery_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "core_accuracy_gates": core_accuracy_gates,
        "items": page_items,
        "large_data_controls": {
            **page_controls,
            "image_gallery_page_manifest_hash": gallery_manifest["manifest_hash"],
            "image_row_hash_count": gallery_manifest["image_row_hash_count"],
            "image_gallery_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "image_gallery_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
            "image_gallery_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        },
        "keyboard_triage": {
            "suggested_shortcuts": ["left/right: move image", "r: mark relevant", "x: reject", "i: include in report"],
            "state_persistence": "requires-case-review-mark",
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=56,
            component="image-gallery-page",
            blockers=[
                "trusted-image-gallery-manifest-diff-required-before-court-use",
                "persistent-gallery-tags-not-implemented",
                "ml-similarity-and-sensitive-media-classifier-not-validated",
            ],
            controls={
                "bounded_gallery_page": True,
                "similarity_bucket_filter": bool(similarity_bucket),
                "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
                "persistent_tags": False,
                "image_gallery_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "image_gallery_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "image_gallery_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def image_gallery_item_summary(*, run_id: str, path: Path, anchor_path: Path) -> dict[str, object]:
    try:
        from ...artifacts.media import build_image_record

        details = build_image_record(path).details
    except Exception as exc:
        details = {"decoded": False, "error": str(exc), "hashes": compute_hashes(path) if path.is_file() else {}}
    thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), Mapping) else {}
    hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
    bucket = str(details.get("similarity_bucket") or "")
    return {
        "path": str(path),
        "name": path.name,
        "is_anchor": path == anchor_path,
        "size": path.stat().st_size if path.exists() else 0,
        "width": details.get("width"),
        "height": details.get("height"),
        "decoded": bool(details.get("decoded")),
        "sha256": str(hashes.get("sha256") or ""),
        "perceptual_hash": str(details.get("perceptual_hash") or ""),
        "similarity_bucket": bucket,
        "thumbnail_available": bool(thumbnail.get("available")),
        "thumbnail_sha256": str(thumbnail.get("sha256") or ""),
        "tag_suggestions": image_tag_suggestions(details),
        "preview_url": f"/api/runs/{run_id}/source-preview?path={quote(str(path))}",
        "source_url": f"/api/runs/{run_id}/source-file?path={quote(str(path))}",
        "copy_safe_citation": (
            f"Source={path.name}; sha256={hashes.get('sha256', '')}; "
            f"dimensions={details.get('width', '')}x{details.get('height', '')}; bucket={bucket}"
        ),
    }


def build_image_gallery_page_manifest(
    *,
    anchor_path: Path,
    items: Sequence[Mapping[str, object]],
    offset: int,
    limit: int,
    total: int,
    similarity_bucket: str | None,
    bucket_counts: Mapping[str, int],
) -> dict[str, object]:
    item_entries: list[dict[str, object]] = []
    for item in items:
        item_core = {
            "path": str(item.get("path") or ""),
            "name": str(item.get("name") or ""),
            "is_anchor": bool(item.get("is_anchor")),
            "size": item.get("size"),
            "width": item.get("width"),
            "height": item.get("height"),
            "sha256": str(item.get("sha256") or ""),
            "perceptual_hash": str(item.get("perceptual_hash") or ""),
            "similarity_bucket": str(item.get("similarity_bucket") or ""),
            "thumbnail_sha256": str(item.get("thumbnail_sha256") or ""),
            "tag_suggestions": list(item.get("tag_suggestions") or []),
        }
        item_entries.append({**item_core, "image_row_hash": stable_payload_sha256(item_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "image-gallery-page-manifest-v1",
        "item_number": 56,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "anchor_path": str(anchor_path),
        "offset": offset,
        "limit": limit,
        "total": total,
        "returned": len(item_entries),
        "similarity_bucket_filter": similarity_bucket or "",
        "bucket_counts": dict(sorted(bucket_counts.items())),
        "image_row_hash_count": sum(1 for item in item_entries if item.get("image_row_hash")),
        "source_viewer_locator": {
            "viewer": "source-image-gallery-page",
            "path": str(anchor_path),
            "offset": offset,
            "limit": limit,
            "similarity_bucket": similarity_bucket or "",
            "open_action": "open-image-gallery-page",
        },
        "items": item_entries,
        "blockers": [
            "trusted-image-gallery-manifest-diff-required-before-court-use",
            "persistent-gallery-tags-not-implemented",
            "ml-similarity-and-sensitive-media-classifier-not-validated",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def image_gallery_page_details_for_validation(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    first_hash = next((str(item.get("sha256") or "") for item in items if item.get("sha256")), "")
    first_bucket = next((str(item.get("similarity_bucket") or "") for item in items if item.get("similarity_bucket")), "")
    thumbnail_ready = any(bool(item.get("thumbnail_available")) or item.get("decoded") is not None for item in items)
    return {
        "decoded": any(bool(item.get("decoded")) for item in items) if items else False,
        "width": next((item.get("width") for item in items if item.get("width") is not None), None),
        "height": next((item.get("height") for item in items if item.get("height") is not None), None),
        "hashes": {"sha256": first_hash} if first_hash else {},
        "similarity_bucket": first_bucket,
        "thumbnail_preview": {"available": thumbnail_ready} if items else {},
        "gallery_review_mode": bool(items),
        "tag_suggestions": next((list(item.get("tag_suggestions") or []) for item in items if item.get("tag_suggestions")), []),
    }


def build_image_gallery_report_grade_validation_plan(
    *,
    context: str,
    source_path: Path,
    details: Mapping[str, object],
    gallery_manifest: Mapping[str, object] | None = None,
    page_manifest: Mapping[str, object] | None = None,
    page_items: Sequence[Mapping[str, object]] | None = None,
    gallery_page_profile: Mapping[str, object] | None = None,
    page_controls: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    gallery_manifest = gallery_manifest if isinstance(gallery_manifest, Mapping) else {}
    page_manifest = page_manifest if isinstance(page_manifest, Mapping) else {}
    page_items = list(page_items or [])
    gallery_page_profile = gallery_page_profile if isinstance(gallery_page_profile, Mapping) else {}
    page_controls = page_controls if isinstance(page_controls, Mapping) else {}
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

    hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
    source_sha256 = str(hashes.get("sha256") or "")
    page_sha_count = sum(1 for item in page_items if item.get("sha256"))
    source_manifest_hash = str(gallery_manifest.get("manifest_hash") or "")
    source_row_hash = str(gallery_manifest.get("image_row_hash") or "")
    page_manifest_hash = str(page_manifest.get("manifest_hash") or "")
    page_row_hash_count = int(page_manifest.get("image_row_hash_count") or 0)
    similarity_bucket = str(details.get("similarity_bucket") or "")
    page_similarity_count = sum(1 for item in page_items if item.get("similarity_bucket"))
    tag_suggestions = details.get("tag_suggestions") if isinstance(details.get("tag_suggestions"), Sequence) else []
    validation_slots = [
        slot(
            "image-metadata-and-source-hash",
            ready=bool(source_sha256) or page_sha_count > 0 or details.get("width") is not None,
            evidence=f"source_sha256={source_sha256} page_sha_count={page_sha_count} width={details.get('width', '')}",
            blocker_id="image-metadata-and-source-hash-required",
            operator_action="Capture image dimensions and source hashes before gallery review.",
        ),
        slot(
            "image-thumbnail-or-preview-metadata",
            ready=bool(details.get("thumbnail_preview")) or details.get("decoded") is not None or any(item.get("thumbnail_available") for item in page_items),
            evidence=(
                f"thumbnail_preview={bool(details.get('thumbnail_preview'))} decoded_present={details.get('decoded') is not None} "
                f"page_thumbnail_count={sum(1 for item in page_items if item.get('thumbnail_available'))}"
            ),
            blocker_id="image-thumbnail-or-preview-metadata-required",
            operator_action="Emit thumbnail or preview metadata for each reviewable image row.",
        ),
        slot(
            "image-perceptual-bucket",
            ready=bool(similarity_bucket) or page_similarity_count > 0,
            evidence=f"similarity_bucket={similarity_bucket} page_similarity_count={page_similarity_count}",
            blocker_id="image-perceptual-bucket-required",
            operator_action="Compute a perceptual triage bucket before image comparison review.",
        ),
        slot(
            "image-source-or-page-manifest-hashes",
            ready=(bool(source_manifest_hash) and bool(source_row_hash)) or (bool(page_manifest_hash) and page_row_hash_count > 0),
            evidence=(
                f"source_manifest_hash={source_manifest_hash} source_row_hash={source_row_hash} "
                f"page_manifest_hash={page_manifest_hash} page_row_hash_count={page_row_hash_count}"
            ),
            blocker_id="image-source-or-page-manifest-hashes-required",
            operator_action="Attach source/page manifests with row hashes for report reproducibility.",
        ),
        slot(
            "image-bounded-gallery-page-or-profile",
            ready=bool(page_manifest_hash)
            or bool(gallery_page_profile.get("supports_folder_gallery_page"))
            or bool(page_controls.get("bounded_folder_scan")),
            evidence=(
                f"page_manifest_hash={page_manifest_hash} supports_folder_gallery_page={gallery_page_profile.get('supports_folder_gallery_page', False)} "
                f"bounded_folder_scan={page_controls.get('bounded_folder_scan', False)}"
            ),
            blocker_id="image-bounded-gallery-page-or-profile-required",
            operator_action="Expose a bounded gallery page/profile so large folders do not overload the reviewer.",
        ),
        slot(
            "image-tag-report-selection-hints",
            ready=bool(tag_suggestions)
            or bool(details.get("gallery_review_mode"))
            or any(item.get("tag_suggestions") for item in page_items)
            or bool(page_controls.get("keyboard_triage")),
            evidence=(
                f"tag_suggestions={len(tag_suggestions)} page_tag_rows={sum(1 for item in page_items if item.get('tag_suggestions'))} "
                f"keyboard_triage={page_controls.get('keyboard_triage', False)}"
            ),
            blocker_id="image-tag-report-selection-hints-required",
            operator_action="Emit tag/report-selection hints or keyboard-triage metadata for reviewer handoff.",
        ),
        slot(
            "image-dedicated-virtualized-gallery-ui",
            ready=False,
            evidence="dedicated_virtualized_gallery_ui=false",
            blocker_id="dedicated-virtualized-gallery-ui-required",
            operator_action="Build and browser-test a true virtualized grid with persisted viewport and keyboard navigation.",
        ),
        slot(
            "image-persistent-gallery-tags",
            ready=False,
            evidence="persistent_gallery_tags=false",
            blocker_id="persistent-gallery-tags-required",
            operator_action="Persist relevant/rejected/include tags into Case DB review history with audit evidence.",
        ),
        slot(
            "image-ml-visual-similarity-clustering",
            ready=False,
            evidence="ml_visual_similarity_clustering=false",
            blocker_id="ml-visual-similarity-clustering-required",
            operator_action="Validate ML/perceptual clustering against a labeled visual similarity corpus.",
        ),
        slot(
            "image-sensitive-deepfake-classifier-validation",
            ready=False,
            evidence="sensitive_deepfake_classifier_validation=false",
            blocker_id="sensitive-deepfake-classifier-validation-required",
            operator_action="Attach sensitive media and deepfake classifier validation with known-answer false positive/negative rates.",
        ),
        slot(
            "image-trusted-gallery-manifest-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=IMAGE_GALLERY_TRUSTED_DIFF_BLOCKER,
            operator_action="Compare Rapid image gallery manifests against a trusted external manifest before court use.",
        ),
        slot(
            "image-selected-report-export",
            ready=False,
            evidence="selected_image_report_export=false",
            blocker_id="selected-image-report-export-required",
            operator_action="Export selected gallery rows into report/exhibit packages with citation manifests.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": IMAGE_GALLERY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 56,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["gallery"],
        "batch_id": "commercial-uplift-056-060",
        "selected_track": "image-gallery-review-report-validation",
        "context": context,
        "path": str(source_path),
        "source_sha256": source_sha256,
        "source_manifest_hash": source_manifest_hash,
        "source_row_hash": source_row_hash,
        "page_manifest_hash": page_manifest_hash,
        "page_row_hash_count": page_row_hash_count,
        "returned_item_count": len(page_items),
        "page_sha_count": page_sha_count,
        "similarity_bucket": similarity_bucket,
        "page_similarity_count": page_similarity_count,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(IMAGE_GALLERY_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage web -> source-preview for an image source",
            "GET /api/runs/<run_id>/source-image-gallery?path=<path>&offset=<n>&limit=<n>",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 56 --json",
        ],
        "report_guidance": {
            "allowed_use": "image-gallery-metadata-triage-pivot",
            "forbidden_claim": "ML visual similarity, sensitive/deepfake, or selected-image report-complete analysis",
            "required_disclaimer": (
                "Image gallery output is bounded metadata, hash, thumbnail, and perceptual-bucket triage until a "
                "virtualized gallery UI, persisted tags, ML similarity corpus, sensitive/deepfake classifier validation, "
                "trusted image manifest diff, and selected-image report export evidence are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def image_viewer_commercial_uplift_evidence(
    *,
    source_path: Path,
    details: Mapping[str, object],
    gallery_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    gallery_manifest = gallery_manifest if isinstance(gallery_manifest, Mapping) else {}
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else build_image_gallery_report_grade_validation_plan(
        context="image-preview",
        source_path=source_path,
        details=details,
        gallery_manifest=gallery_manifest,
    )
    gates = image_viewer_core_accuracy_gates(
        source_path=source_path,
        details=details,
        gallery_manifest=gallery_manifest,
        validation_plan=validation_plan,
    )
    blockers = [
        "dedicated-large-gallery-virtualization-and-bulk-tagging-remain-limited",
        "similarity-is-perceptual-hash-bucket-not-ml-validated",
        "deepfake-and-sensitive-media-classification-not-implemented",
        "selected-image-report-export-flow-not-complete",
    ]
    return viewer_workflow_commercial_uplift_evidence(
        item_number=56,
        component="image-gallery-review-mode",
        core_accuracy_gates=gates,
        blockers=blockers,
        source_refs=[
            f"source_path:{source_path}",
            f"perceptual_hash:{details.get('perceptual_hash', '')}",
            f"similarity_bucket:{details.get('similarity_bucket', '')}",
            f"image_gallery_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
        ],
        controls={
            "thumbnail_preview": bool(details.get("thumbnail_preview")),
            "perceptual_hash_present": bool(details.get("perceptual_hash")),
            "similarity_bucket_present": bool(details.get("similarity_bucket")),
            "compare_ready": bool(details.get("perceptual_hash")),
            "bounded_gallery_page": True,
            "image_gallery_manifest_present": bool(gallery_manifest.get("manifest_hash")),
            "image_gallery_manifest_hash": str(gallery_manifest.get("manifest_hash") or ""),
            "image_gallery_row_hash": str(gallery_manifest.get("image_row_hash") or ""),
            "image_gallery_report_grade_validation_plan_present": bool(validation_plan.get("validation_plan_sha256")),
            "image_gallery_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or ""),
            "image_gallery_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "image_gallery_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "dedicated_virtualized_gallery": False,
            "persistent_gallery_tags": False,
        },
    )


def image_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    details: Mapping[str, object],
    gallery_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if details.get("width") is not None or details.get("hashes"):
        satisfied.append("image metadata and source hashes")
    if details.get("thumbnail_preview") or details.get("decoded") is not None:
        satisfied.append("thumbnail or preview metadata")
    if details.get("similarity_bucket"):
        satisfied.append("perceptual similarity bucket")
    gallery_manifest = gallery_manifest if isinstance(gallery_manifest, Mapping) else {}
    if gallery_manifest.get("manifest_hash"):
        satisfied.append("image gallery source manifest")
    if gallery_manifest.get("image_row_hash"):
        satisfied.append("image gallery row hash")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("image gallery report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("image gallery report-grade ready slots")
    satisfied.append("tag/report selection hints")
    if not details.get("media_native_capabilities", {}).get("deepfake_detection", False):
        satisfied.append("visual-classifier limitation warning")
    return [
        build_accuracy_gate(
            56,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"perceptual_hash:{details.get('perceptual_hash', '')}",
                f"similarity_bucket:{details.get('similarity_bucket', '')}",
                f"image_gallery_manifest_hash:{gallery_manifest.get('manifest_hash', '')}",
                f"image_gallery_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"image_gallery_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"image_gallery_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
            ],
        )
    ]


def image_tag_suggestions(details: Mapping[str, object]) -> list[str]:
    tags = ["image"]
    classification = details.get("visual_classification") if isinstance(details.get("visual_classification"), Mapping) else {}
    label = str(classification.get("label") or "")
    if label:
        tags.append(label)
    if details.get("ocr_sidecar"):
        tags.append("ocr-sidecar")
    if details.get("similarity_bucket"):
        tags.append("similarity-bucketed")
    if not details.get("decoded"):
        tags.append("decode-warning")
    return tags
