from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Mapping

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
    return {
        "command": "ocr-queue",
        "schema_version": OCR_QUEUE_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(resolved_root),
        "options": {
            "previous_queue": str(previous_queue.expanduser().resolve()) if previous_queue else "",
            "retry_failures": retry_failures,
            "max_items": max_items,
        },
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
        "core_accuracy_gates": ocr_queue_core_accuracy_gates(items=items, root=resolved_root),
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
    return {
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
        "core_accuracy_gates": ocr_queue_item_core_accuracy_gates(item_context={
            "source_path": str(resolved),
            "status": status,
            "sidecar": sidecar,
            "translation_sidecar": translation_sidecar,
            "language_hint": language_hint,
            "confidence": confidence,
            "metadata": metadata,
            "quality_metrics": ocr_quality_metrics(text) if text else {},
        }),
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


def ocr_queue_core_accuracy_gates(*, items: list[dict[str, object]], root: Path) -> list[dict[str, object]]:
    evidence_refs = [f"root:{root}", f"candidate_count:{len(items)}"]
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
    if not OCR_QUEUE_NATIVE_CAPABILITIES["native_ocr_engine_execution"]:
        item58.append("native OCR limitation warning")

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

    return [
        build_accuracy_gate(58, satisfied_checks=item58, evidence_refs=evidence_refs),
        build_accuracy_gate(59, satisfied_checks=item59, evidence_refs=evidence_refs),
    ]


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
    )


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
