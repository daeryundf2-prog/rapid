from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.media import IMAGE_EXTENSIONS, contains_hangul, language_hint_for_text, ocr_quality_metrics
from .forensic_accuracy import build_accuracy_gate
from .submission import compute_hashes


OCR_QUEUE_SCHEMA_VERSION = 1
OCR_SIDECAR_CANDIDATE_SUFFIXES = (
    ".ocr.txt",
    ".txt",
    ".srt",
    ".vtt",
)
OCR_METADATA_SUFFIXES = (
    ".ocr.json",
    ".ocr.meta.json",
)
TRANSLATION_SIDECAR_SUFFIXES = (
    ".translation.txt",
    ".en.txt",
)
OCR_SIDECAR_MAX_CHARS = 20_000
TRANSLATION_SIDECAR_MAX_CHARS = 20_000
OCR_QUEUE_NATIVE_CAPABILITIES = {
    "retryable_queue_manifest": True,
    "sidecar_import": True,
    "metadata_sidecar_import": True,
    "korean_language_hinting": True,
    "translation_sidecar_import": True,
    "native_ocr_engine_execution": False,
    "native_machine_translation": False,
    "human_translation_certification": False,
}
OCR_QUEUE_REPORT_GRADE_BLOCKERS = [
    "ocr-queue-builds-work-items-but-does-not-run-native-ocr",
    "korean-language-pack-and-ocr-engine-output-require-validation",
    "translation-sidecars-are-review-aids-not-certified-translations",
    "sidecar-provenance-and-hashes-must-be-preserved-for-reporting",
]
OCR_QUEUE_TRUSTED_DIFF_BLOCKERS = {
    58: "ocr-queue-trusted-engine-log-diff-required",
    59: "korean-ocr-translation-trusted-review-diff-required",
}
OCR_QUEUE_TRUSTED_DIFF_CHECKS = {
    58: "trusted OCR queue engine/sidecar diff pass",
    59: "trusted Korean OCR/translation review diff pass",
}
OCR_QUEUE_TRUSTED_TOOLS = {
    "ocr-engine-log",
    "ocr-queue-ground-truth",
    "ocr-sidecar-ground-truth",
    "korean-ocr-review",
    "certified-translation-review",
}


class OcrQueueError(ValueError):
    """Raised when OCR queue generation cannot be completed."""


def build_ocr_queue(
    root: Path,
    *,
    previous_queue: Path | None = None,
    retry_failures: bool = False,
    max_items: int = 0,
) -> dict[str, object]:
    resolved_root = root.expanduser().resolve()
    if not resolved_root.exists():
        raise OcrQueueError(f"root does not exist: {resolved_root}")
    if not resolved_root.is_dir():
        raise OcrQueueError(f"OCR queue root must be a directory: {resolved_root}")

    previous = load_previous_queue(previous_queue) if previous_queue else {}
    previous_by_path = {
        str(item.get("source_path") or ""): item
        for item in previous.get("items", [])
        if isinstance(item, Mapping)
    }
    image_paths = [
        path
        for path in sorted(resolved_root.rglob("*"), key=lambda item: str(item).lower())
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
    ]
    if max_items > 0:
        image_paths = image_paths[:max_items]

    options = {
        "previous_queue": str(previous_queue.expanduser().resolve()) if previous_queue else "",
        "retry_failures": retry_failures,
        "max_items": max_items,
    }
    items = [
        build_ocr_queue_item(path, previous_by_path=previous_by_path, retry_failures=retry_failures)
        for path in image_paths
    ]
    status_counts: dict[str, int] = {}
    language_counts: dict[str, int] = {}
    for item in items:
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        language = str(item.get("language_hint") or "unknown")
        language_counts[language] = language_counts.get(language, 0) + 1
    trusted_diffs = missing_ocr_queue_trusted_diffs()
    queue_manifest = build_ocr_queue_manifest(
        root=resolved_root,
        items=items,
        options=options,
        status_counts=status_counts,
        language_counts=language_counts,
    )
    core_accuracy_gates = ocr_queue_core_accuracy_gates(
        items=items,
        root=resolved_root,
        queue_manifest=queue_manifest,
        trusted_diffs=trusted_diffs,
    )
    return {
        "command": "ocr-queue",
        "schema_version": OCR_QUEUE_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(resolved_root),
        "options": options,
        "summary": {
            "candidate_count": len(items),
            "status_counts": status_counts,
            "language_counts": language_counts,
            "sidecar_imported_count": status_counts.get("sidecar-imported", 0),
            "queued_count": status_counts.get("queued", 0),
            "failed_retry_queued_count": status_counts.get("failed-retry-queued", 0),
            "commercial_gap_ids": ["#58", "#59"],
            "commercial_grade_ready": False,
        },
        "ocr_queue_native_capabilities": dict(OCR_QUEUE_NATIVE_CAPABILITIES),
        "ocr_queue_report_grade_assessment": ocr_queue_report_grade_assessment(),
        "trusted_ocr_queue_diffs": trusted_diffs,
        "ocr_queue_manifest": queue_manifest,
        "ocr_queue_manifest_hash": queue_manifest["manifest_hash"],
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": ocr_queue_commercial_uplift_evidence(
            items=items,
            root=resolved_root,
            queue_manifest=queue_manifest,
            core_accuracy_gates=core_accuracy_gates,
        ),
        "items": items,
        "review_guidance": [
            "Sidecar OCR text is treated as post-acquisition review material; preserve the original sidecar hashes.",
            "Queued items require an external OCR engine run or manual sidecar import before report reliance.",
            "Failed items can be re-queued with --retry-failures after dependency or language-pack remediation.",
        ],
    }


def build_ocr_queue_item(
    path: Path,
    *,
    previous_by_path: Mapping[str, Mapping[str, object]],
    retry_failures: bool,
) -> dict[str, object]:
    resolved = path.resolve()
    previous = previous_by_path.get(str(resolved), {})
    sidecar = load_ocr_sidecar_with_metadata(resolved)
    translation_sidecar = load_translation_sidecar(resolved)
    previous_status = str(previous.get("status") or "")
    if sidecar:
        status = "sidecar-imported"
    elif retry_failures and previous_status in {"failed", "ocr-failed", "dependency-failed"}:
        status = "failed-retry-queued"
    else:
        status = "queued"
    text = str(sidecar.get("text") or "")
    metadata = sidecar.get("metadata") if isinstance(sidecar.get("metadata"), Mapping) else {}
    language_hint = str(metadata.get("language") or sidecar.get("language_hint") or language_hint_for_path_or_text(resolved, text))
    confidence = optional_float(metadata.get("confidence"))
    item_context = {
        "source_path": str(resolved),
        "status": status,
        "sidecar": sidecar,
        "translation_sidecar": translation_sidecar,
        "language_hint": language_hint,
        "confidence": confidence,
        "metadata": metadata,
        "quality_metrics": ocr_quality_metrics(text) if text else {},
    }
    item_gates = ocr_queue_item_core_accuracy_gates(item_context=item_context)
    item = {
        "queue_id": stable_queue_id(resolved),
        "source_path": str(resolved),
        "source_name": resolved.name,
        "source_size": resolved.stat().st_size,
        "source_sha256": compute_hashes(resolved)["sha256"] if resolved.stat().st_size <= 128 * 1024 * 1024 else "",
        "status": status,
        "previous_status": previous_status,
        "attempt_count": int(previous.get("attempt_count") or 0) + (1 if status == "failed-retry-queued" else 0),
        "language_hint": language_hint,
        "confidence": confidence,
        "recommended_languages": recommended_ocr_languages(language_hint),
        "sidecar": sidecar,
        "translation_sidecar": translation_sidecar,
        "translation_status": "sidecar-imported" if translation_sidecar else ("required-not-run" if "ko" in language_hint.lower() else "not-required"),
        "quality_metrics": ocr_quality_metrics(text) if text else {},
        "retryable": status in {"queued", "failed-retry-queued"},
        "validation_status": "review-sidecar-text" if sidecar else "requires-ocr-run",
        "commercial_gap_ids": ["#58", "#59"],
        "core_accuracy_gates": item_gates,
        "commercial_uplift_evidence": ocr_queue_item_commercial_uplift_evidence(
            item_context=item_context,
            core_accuracy_gates=item_gates,
        ),
        "korean_ocr_translation_workflow": {
            "commercial_gap_ids": ["#59"],
            "language_hint": language_hint,
            "recommended_languages": recommended_ocr_languages(language_hint),
            "korean_language_pack_required": any(language == "kor" for language in recommended_ocr_languages(language_hint)),
            "translation_status": "sidecar-imported" if translation_sidecar else ("required-not-run" if "ko" in language_hint.lower() else "not-required"),
            "ready_for_court_report": False,
        },
        "report_grade_assessment": ocr_queue_item_assessment(status=status, language_hint=language_hint),
    }
    item_manifest = build_ocr_queue_item_manifest(item)
    item["ocr_queue_item_manifest"] = item_manifest
    item["ocr_queue_item_manifest_hash"] = item_manifest["manifest_hash"]
    item["commercial_uplift_evidence"]["large_data_controls"]["item_manifest_hash"] = item_manifest["manifest_hash"]
    return item


def build_ocr_queue_manifest(
    *,
    root: Path,
    items: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    status_counts: Mapping[str, int],
    language_counts: Mapping[str, int],
) -> dict[str, object]:
    item_rows = []
    for index, item in enumerate(items, start=1):
        sidecar = item.get("sidecar") if isinstance(item.get("sidecar"), Mapping) else {}
        translation = item.get("translation_sidecar") if isinstance(item.get("translation_sidecar"), Mapping) else {}
        row_core = {
            "index": index,
            "queue_id": str(item.get("queue_id") or ""),
            "source_path": str(item.get("source_path") or ""),
            "source_name": str(item.get("source_name") or ""),
            "source_sha256": str(item.get("source_sha256") or ""),
            "status": str(item.get("status") or ""),
            "language_hint": str(item.get("language_hint") or ""),
            "sidecar_sha256": str(sidecar.get("sha256") or ""),
            "sidecar_text_sha256": str(sidecar.get("text_sha256") or ""),
            "translation_sha256": str(translation.get("sha256") or ""),
            "translation_text_sha256": str(translation.get("text_sha256") or ""),
            "attempt_count": int(item.get("attempt_count") or 0),
        }
        item_rows.append({**row_core, "queue_item_row_hash": stable_payload_sha256(row_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "ocr-queue-source-manifest-v1",
        "item_numbers": [58, 59],
        "commercial_gap_ids": ["#58", "#59"],
        "root": str(root),
        "options": dict(options),
        "candidate_count": len(item_rows),
        "status_counts": dict(sorted(status_counts.items())),
        "language_counts": dict(sorted(language_counts.items())),
        "queue_item_row_hash_count": sum(1 for item in item_rows if item.get("queue_item_row_hash")),
        "source_viewer_locator": {
            "viewer": "source-ocr-queue",
            "root": str(root),
            "open_action": "open-ocr-queue-review",
        },
        "items": item_rows,
        "blockers": [
            "native-ocr-engine-execution-not-implemented",
            "engine-specific-retry-logs-not-attached",
            "case-db-ocr-job-persistence-not-implemented",
            OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[58],
            OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[59],
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_ocr_queue_item_manifest(item: Mapping[str, object]) -> dict[str, object]:
    sidecar = item.get("sidecar") if isinstance(item.get("sidecar"), Mapping) else {}
    translation = item.get("translation_sidecar") if isinstance(item.get("translation_sidecar"), Mapping) else {}
    manifest_core: dict[str, object] = {
        "manifest_version": "ocr-queue-item-manifest-v1",
        "item_numbers": [58, 59],
        "commercial_gap_ids": ["#58", "#59"],
        "queue_id": str(item.get("queue_id") or ""),
        "source_path": str(item.get("source_path") or ""),
        "source_name": str(item.get("source_name") or ""),
        "source_sha256": str(item.get("source_sha256") or ""),
        "status": str(item.get("status") or ""),
        "previous_status": str(item.get("previous_status") or ""),
        "attempt_count": int(item.get("attempt_count") or 0),
        "language_hint": str(item.get("language_hint") or ""),
        "confidence": item.get("confidence"),
        "sidecar": {
            "path": str(sidecar.get("path") or ""),
            "name": str(sidecar.get("name") or ""),
            "sha256": str(sidecar.get("sha256") or ""),
            "text_sha256": str(sidecar.get("text_sha256") or ""),
            "metadata": sidecar.get("metadata") if isinstance(sidecar.get("metadata"), Mapping) else {},
        },
        "translation_sidecar": {
            "path": str(translation.get("path") or ""),
            "name": str(translation.get("name") or ""),
            "sha256": str(translation.get("sha256") or ""),
            "text_sha256": str(translation.get("text_sha256") or ""),
            "target_language": str(translation.get("target_language") or ""),
        },
        "source_viewer_locator": {
            "viewer": "source-ocr-queue-item",
            "path": str(item.get("source_path") or ""),
            "queue_id": str(item.get("queue_id") or ""),
            "open_action": "open-ocr-queue-item-review",
        },
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def ocr_queue_core_accuracy_gates(
    *,
    items: list[dict[str, object]],
    root: Path,
    queue_manifest: Mapping[str, object] | None = None,
    trusted_diffs: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    evidence_refs = [f"root:{root}", f"candidate_count:{len(items)}"]
    queue_manifest = queue_manifest if isinstance(queue_manifest, Mapping) else {}
    if queue_manifest.get("manifest_hash"):
        evidence_refs.append(f"ocr_queue_manifest_hash:{queue_manifest.get('manifest_hash')}")
    trusted_diffs = trusted_diffs if isinstance(trusted_diffs, Mapping) else {}
    for number in (58, 59):
        diff = trusted_diffs.get(str(number)) if isinstance(trusted_diffs.get(str(number)), Mapping) else {}
        evidence_refs.append(f"trusted_diff_{number}_status:{diff.get('status', 'missing')}")
    for item in items[:5]:
        evidence_refs.append(f"source_path:{item.get('source_path', '')}")
        if isinstance(item.get("sidecar"), Mapping) and item["sidecar"].get("sha256"):
            evidence_refs.append(f"sidecar_sha256:{item['sidecar']['sha256']}")

    item58 = []
    if items:
        item58.append("queue item generation")
    if any(isinstance(item.get("sidecar"), Mapping) and item["sidecar"].get("sha256") for item in items):
        item58.append("sidecar import and hashes")
    if any(str(item.get("status")) == "failed-retry-queued" or item.get("previous_status") for item in items):
        item58.append("retry state handling")
    if any(isinstance(item.get("sidecar"), Mapping) and item["sidecar"].get("metadata") for item in items):
        item58.append("engine/metadata preservation")
    if queue_manifest.get("manifest_hash"):
        item58.append("queue manifest hash emitted")
    if queue_manifest.get("queue_item_row_hash_count"):
        item58.append("queue item row hashes")
    if isinstance(queue_manifest.get("source_viewer_locator"), Mapping):
        item58.append("source viewer locator emitted")
    if not OCR_QUEUE_NATIVE_CAPABILITIES["native_ocr_engine_execution"]:
        item58.append("native OCR limitation warning")
    if trusted_ocr_queue_diff_passed(trusted_diffs, 58):
        item58.append(OCR_QUEUE_TRUSTED_DIFF_CHECKS[58])

    item59 = []
    if any("ko" in str(item.get("language_hint", "")).lower() or "kor" in str(item.get("language_hint", "")).lower() for item in items):
        item59.append("Korean language hinting")
    if any(item.get("quality_metrics") for item in items):
        item59.append("OCR quality metrics")
    if any(item.get("translation_sidecar") for item in items):
        item59.append("translation sidecar import")
    if any(item.get("confidence") is not None or (isinstance(item.get("sidecar"), Mapping) and item["sidecar"].get("metadata")) for item in items):
        item59.append("confidence/engine metadata")
    if not OCR_QUEUE_NATIVE_CAPABILITIES["human_translation_certification"]:
        item59.append("human translation validation warning")
    if trusted_ocr_queue_diff_passed(trusted_diffs, 59):
        item59.append(OCR_QUEUE_TRUSTED_DIFF_CHECKS[59])

    return [
        build_accuracy_gate(58, satisfied_checks=item58, evidence_refs=evidence_refs),
        build_accuracy_gate(59, satisfied_checks=item59, evidence_refs=evidence_refs),
    ]


def ocr_queue_commercial_uplift_evidence(
    *,
    items: list[dict[str, object]],
    root: Path,
    queue_manifest: Mapping[str, object] | None = None,
    core_accuracy_gates: list[dict[str, object]],
) -> dict[str, object]:
    passed_by_item = {
        str(gate.get("gap_id")): list(gate.get("satisfied_checks") or [])
        for gate in core_accuracy_gates
        if str(gate.get("gap_id")) in {"#58", "#59"}
    }
    queue_manifest = queue_manifest if isinstance(queue_manifest, Mapping) else {}
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [58, 59],
        "implementation_track": "ocr-queue-korean-translation-gates",
        "source_refs": [f"root:{root}", f"candidate_count:{len(items)}"],
        "reportability_decision": ocr_queue_reportability_decision(
            failed_by_item={
                "#58": [
                    "native-ocr-engine-execution",
                    "engine-specific-retry-logs",
                    "case-db-ocr-job-persistence",
                    OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[58],
                ],
                "#59": [
                    "built-in-korean-ocr-execution",
                    "machine-translation-worker",
                    "certified-translation-workflow",
                    OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[59],
                ],
            },
            item_count=len(items),
            sidecar_imported_count=sum(1 for item in items if str(item.get("status")) == "sidecar-imported"),
        ),
        "passed_validation_check_ids_by_item": passed_by_item,
        "failed_validation_check_ids_by_item": {
            "#58": [
                "native-ocr-engine-execution",
                "engine-specific-retry-logs",
                "case-db-ocr-job-persistence",
                OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[58],
            ],
            "#59": [
                "built-in-korean-ocr-execution",
                "machine-translation-worker",
                "certified-translation-workflow",
                OCR_QUEUE_TRUSTED_DIFF_BLOCKERS[59],
            ],
        },
        "trusted_diffs": missing_ocr_queue_trusted_diffs(),
        "commercial_blockers": list(OCR_QUEUE_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "candidate_count": len(items),
            "sidecar_imported_count": sum(1 for item in items if str(item.get("status")) == "sidecar-imported"),
            "queued_count": sum(1 for item in items if str(item.get("status")) == "queued"),
            "failed_retry_queued_count": sum(1 for item in items if str(item.get("status")) == "failed-retry-queued"),
            "ocr_queue_manifest_hash": str(queue_manifest.get("manifest_hash") or ""),
            "queue_item_row_hash_count": int(queue_manifest.get("queue_item_row_hash_count") or 0),
            "native_ocr_engine_execution": False,
            "case_db_job_persistence": False,
        },
        "reporting_status": "queue-ready-validation-required",
    }


def ocr_queue_item_commercial_uplift_evidence(
    *,
    item_context: Mapping[str, object],
    core_accuracy_gates: list[dict[str, object]],
) -> dict[str, object]:
    passed_by_item = {
        str(gate.get("gap_id")): list(gate.get("satisfied_checks") or [])
        for gate in core_accuracy_gates
        if str(gate.get("gap_id")) in {"#58", "#59"}
    }
    sidecar = item_context.get("sidecar") if isinstance(item_context.get("sidecar"), Mapping) else {}
    translation_sidecar = (
        item_context.get("translation_sidecar")
        if isinstance(item_context.get("translation_sidecar"), Mapping)
        else {}
    )
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [58, 59],
        "implementation_track": "ocr-queue-item-gate",
        "source_refs": [
            f"source_path:{item_context.get('source_path', '')}",
            f"sidecar:{sidecar.get('path', '')}",
            f"translation_sidecar:{translation_sidecar.get('path', '')}",
        ],
        "reportability_decision": ocr_queue_reportability_decision(
            failed_by_item={
                "#58": ["native-ocr-engine-execution"],
                "#59": ["machine-translation-worker", "human-certified-translation"],
            },
            item_count=1,
            sidecar_imported_count=1 if sidecar else 0,
        ),
        "passed_validation_check_ids_by_item": passed_by_item,
        "failed_validation_check_ids_by_item": {
            "#58": ["native-ocr-engine-execution"],
            "#59": ["machine-translation-worker", "human-certified-translation"],
        },
        "commercial_blockers": list(OCR_QUEUE_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "status": str(item_context.get("status") or ""),
            "sidecar_imported": bool(sidecar),
            "translation_sidecar_imported": bool(translation_sidecar),
            "confidence_present": item_context.get("confidence") is not None,
            "quality_metrics_present": bool(item_context.get("quality_metrics")),
            "native_ocr_engine_execution": False,
        },
        "reporting_status": "sidecar-review-required" if sidecar else "ocr-run-required",
    }


def ocr_queue_reportability_decision(
    *,
    failed_by_item: Mapping[str, Sequence[str]],
    item_count: int,
    sidecar_imported_count: int,
) -> dict[str, object]:
    blockers = {f"{item_id}:{check}" for item_id, checks in failed_by_item.items() for check in checks}
    return {
        "profile_version": "ocr-queue-reportability-decision-v1",
        "commercial_gap_ids": ["#58", "#59"],
        "decision": "do-not-report-ocr-or-translation-as-engine-validated",
        "allowed_use": "ocr-sidecar-and-queue-triage-pivot",
        "blockers": sorted(blockers),
        "item_count": item_count,
        "sidecar_imported_count": sidecar_imported_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "execute or attach OCR engine logs, retry history, version capture, and confidence calibration",
            "attach certified Korean OCR/translation review evidence before reporting translated text",
            "persist queue state in Case DB for multi-reviewer long-running workflows",
        ],
    }


def ocr_queue_item_core_accuracy_gates(*, item_context: Mapping[str, object]) -> list[dict[str, object]]:
    sidecar = item_context.get("sidecar") if isinstance(item_context.get("sidecar"), Mapping) else {}
    translation_sidecar = (
        item_context.get("translation_sidecar")
        if isinstance(item_context.get("translation_sidecar"), Mapping)
        else {}
    )
    metadata = item_context.get("metadata") if isinstance(item_context.get("metadata"), Mapping) else {}
    quality_metrics = item_context.get("quality_metrics") if isinstance(item_context.get("quality_metrics"), Mapping) else {}
    return ocr_queue_core_accuracy_gates(
        items=[
            {
                "source_path": item_context.get("source_path", ""),
                "status": item_context.get("status", ""),
                "sidecar": sidecar,
                "translation_sidecar": translation_sidecar,
                "language_hint": item_context.get("language_hint", ""),
                "confidence": item_context.get("confidence"),
                "quality_metrics": quality_metrics,
                "previous_status": "",
            }
        ],
        root=Path(str(item_context.get("source_path") or ".")).parent,
        trusted_diffs=missing_ocr_queue_trusted_diffs(),
    )


def stable_payload_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def missing_ocr_queue_trusted_diffs() -> dict[str, dict[str, object]]:
    return {
        str(number): {
            "status": "missing",
            "blocker_id": blocker,
            "required_tools": sorted(OCR_QUEUE_TRUSTED_TOOLS),
        }
        for number, blocker in OCR_QUEUE_TRUSTED_DIFF_BLOCKERS.items()
    }


def trusted_ocr_queue_diff_passed(trusted_diffs: Mapping[str, object], number: int) -> bool:
    diff = trusted_diffs.get(str(number)) if isinstance(trusted_diffs.get(str(number)), Mapping) else {}
    return diff.get("status") == "pass"


def build_ocr_queue_trusted_diff(
    number: int,
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = OCR_QUEUE_TRUSTED_DIFF_BLOCKERS.get(number, "ocr-queue-trusted-diff-required")
    rapid_index = index_ocr_queue_trusted_rows(number, rapid_rows)
    trusted_index = index_ocr_queue_trusted_rows(number, trusted_rows)
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index) & set(trusted_index)):
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({"row_key": key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
    recognized = trusted_tool.strip().lower().replace(" ", "") in {item.replace(" ", "").lower() for item in OCR_QUEUE_TRUSTED_TOOLS}
    status = "pass" if recognized and rapid_index and trusted_index and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "ocr-queue-trusted-diff-v1",
        "gap_id": f"#{number}",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(set(rapid_index) & set(trusted_index)) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-ocr-output-as-engine-validated-finding",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_ocr_queue_trusted_rows(number: int, rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        key_source = str(row.get("queue_id") or row.get("source_path") or "")
        if not key_source:
            continue
        key = hashlib.sha256(key_source.encode("utf-8", errors="replace")).hexdigest()[:16]
        sidecar = row.get("sidecar") if isinstance(row.get("sidecar"), Mapping) else {}
        translation = row.get("translation_sidecar") if isinstance(row.get("translation_sidecar"), Mapping) else {}
        if number == 58:
            metadata = sidecar.get("metadata") if isinstance(sidecar.get("metadata"), Mapping) else {}
            indexed[key] = {
                "source_sha256": str(row.get("source_sha256") or ""),
                "status": str(row.get("status") or ""),
                "sidecar_sha256": str(sidecar.get("sha256") or ""),
                "text_sha256": str(sidecar.get("text_sha256") or ""),
                "engine": str(metadata.get("engine") or ""),
            }
        else:
            indexed[key] = {
                "language_hint": str(row.get("language_hint") or ""),
                "confidence": str(row.get("confidence") or ""),
                "translation_sha256": str(translation.get("sha256") or ""),
                "translation_text_sha256": str(translation.get("text_sha256") or ""),
            }
    return indexed


def ocr_queue_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "queue-ready-validation-required",
        "commercial_gap_ids": ["#58", "#59"],
        "ready_for_court_report": False,
        "blockers": list(OCR_QUEUE_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Record OCR engine name/version/language packs and preserve OCR/translation sidecar hashes.",
            "Human-verify Korean OCR and translation output before citing text in a report.",
        ],
    }


def ocr_queue_item_assessment(*, status: str, language_hint: str) -> dict[str, object]:
    return {
        "status": "sidecar-review-required" if status == "sidecar-imported" else "ocr-run-required",
        "commercial_gap_ids": ["#58", "#59"],
        "language_hint": language_hint,
        "ready_for_court_report": False,
        "blockers": list(OCR_QUEUE_REPORT_GRADE_BLOCKERS),
    }


def load_ocr_sidecar_with_metadata(path: Path) -> dict[str, object]:
    for candidate in ocr_sidecar_candidates(path):
        if not candidate.is_file():
            continue
        try:
            raw = candidate.read_text(encoding="utf-8", errors="replace")
            stat = candidate.stat()
        except OSError:
            continue
        text = raw[:OCR_SIDECAR_MAX_CHARS]
        metadata = load_ocr_metadata(path, candidate)
        return {
            "path": str(candidate.resolve()),
            "name": candidate.name,
            "size": stat.st_size,
            "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "text": text,
            "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            "language_hint": language_hint_for_text(text),
            "contains_hangul": contains_hangul(text),
            "metadata": metadata,
            "truncated": len(raw) > OCR_SIDECAR_MAX_CHARS,
        }
    return {}


def load_translation_sidecar(path: Path) -> dict[str, object]:
    candidates = [
        path.with_name(f"{path.name}.translation.txt"),
        path.with_name(f"{path.name}.en.txt"),
        path.with_name(f"{path.stem}.translation.txt"),
        path.with_name(f"{path.stem}.en.txt"),
    ]
    candidates.extend(path.with_suffix(suffix) for suffix in TRANSLATION_SIDECAR_SUFFIXES)
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            raw = candidate.read_text(encoding="utf-8", errors="replace")
            stat = candidate.stat()
        except OSError:
            continue
        text = raw[:TRANSLATION_SIDECAR_MAX_CHARS]
        return {
            "path": str(candidate.resolve()),
            "name": candidate.name,
            "size": stat.st_size,
            "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "text": text,
            "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            "source_language": "ko" if contains_hangul(path.name) else "unknown",
            "target_language": "en",
            "quality_metrics": ocr_quality_metrics(text),
            "truncated": len(raw) > TRANSLATION_SIDECAR_MAX_CHARS,
        }
    return {}


def ocr_sidecar_candidates(path: Path) -> list[Path]:
    candidates = [
        path.with_name(f"{path.name}.ocr.txt"),
        path.with_name(f"{path.stem}.ocr.txt"),
    ]
    candidates.extend(path.with_suffix(suffix) for suffix in OCR_SIDECAR_CANDIDATE_SUFFIXES)
    seen: set[Path] = set()
    unique: list[Path] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def load_ocr_metadata(path: Path, sidecar: Path) -> dict[str, object]:
    candidates = [
        sidecar.with_suffix(sidecar.suffix + ".json"),
        path.with_name(f"{path.name}.ocr.json"),
        path.with_name(f"{path.stem}.ocr.json"),
    ]
    candidates.extend(path.with_suffix(suffix) for suffix in OCR_METADATA_SUFFIXES)
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return {
                "path": str(candidate.resolve()),
                "language": str(payload.get("language") or payload.get("language_hint") or ""),
                "confidence": optional_float(payload.get("confidence")),
                "engine": str(payload.get("engine") or ""),
                "engine_version": str(payload.get("engine_version") or payload.get("version") or ""),
            }
    return {}


def load_previous_queue(path: Path | None) -> dict[str, object]:
    if path is None:
        return {}
    try:
        payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OcrQueueError(f"failed to read previous OCR queue: {exc}") from exc
    if not isinstance(payload, dict):
        raise OcrQueueError("previous OCR queue must be a JSON object")
    return payload


def stable_queue_id(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8", errors="replace")).hexdigest()[:16]


def language_hint_for_path_or_text(path: Path, text: str) -> str:
    if text:
        return language_hint_for_text(text)
    return "ko" if contains_hangul(path.name) else "en"


def recommended_ocr_languages(language_hint: str) -> list[str]:
    normalized = language_hint.lower()
    if "ko" in normalized or "kor" in normalized:
        return ["kor", "eng"]
    if normalized in {"unknown", ""}:
        return ["eng"]
    return [normalized]


def optional_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
