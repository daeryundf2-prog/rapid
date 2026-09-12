from __future__ import annotations

import importlib
import shutil
from collections.abc import Iterable, Mapping
from pathlib import Path

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "synthetic-media-deepfake-lens-v1"
DEEPFAKE_LENS_MODULE = "deepfake_lens"
DEEPFAKE_LENS_SCAN_JSON_SCHEMA_VERSION = 1
# deepfake_lens.core analyze_file only inspects these formats today; keep the
# local copy so the provider can report coverage even when the optional
# dependency is absent.
SYNTHETIC_MEDIA_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
SYNTHETIC_MEDIA_TEXT_EXTENSIONS = {".txt", ".md"}
SYNTHETIC_MEDIA_MAX_FILES = 512
SYNTHETIC_MEDIA_MAX_FILE_BYTES = 256 * 1024 * 1024
SYNTHETIC_MEDIA_HASH_DEFER_BYTES = 512 * 1024 * 1024
# Bounded-read limits passed through to deepfake_lens.analyze_file.
SYNTHETIC_MEDIA_TEXT_BYTES = 64 * 1024
SYNTHETIC_MEDIA_METADATA_BYTES = 4 * 1024 * 1024
SYNTHETIC_MEDIA_SIGNAL_LIMIT = 25
SYNTHETIC_MEDIA_SCORE_SEMANTICS = "prioritization-score-not-truth-label"
SYNTHETIC_MEDIA_SCORE_GUIDANCE = (
    "deepfake-lens score orders files for examiner review only. It is not an "
    "authenticity verdict and must not be reported as proof that media is or "
    "is not synthetic. Pair with limitations and examiner validation."
)


def deepfake_lens_module():
    """Return the imported deepfake_lens module or None when unavailable."""
    try:
        return importlib.import_module(DEEPFAKE_LENS_MODULE)
    except Exception:
        return None


def deepfake_lens_cli_path() -> str:
    return shutil.which("deepfake-lens") or ""


class SyntheticMediaProvider:
    collector_kind = "synthetic-media"
    name = "synthetic-media-artifacts"
    description = (
        "Optional deepfake-lens screening of image/text evidence; emits "
        "prioritization scores for review ordering, not truth labels"
    )
    target_platform = "any"

    def supported(self) -> bool:
        return deepfake_lens_module() is not None

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        module = deepfake_lens_module()
        if module is None:
            yield build_unavailable_record(root)
            return
        candidates = iter_synthetic_media_candidates(root)
        scanned = 0
        skipped_oversize = 0
        failed = 0
        capped = False
        for path in candidates:
            if scanned + skipped_oversize >= SYNTHETIC_MEDIA_MAX_FILES:
                capped = True
                break
            resolved = path.resolve()
            try:
                size = resolved.stat().st_size
            except OSError:
                size = 0
            if size > SYNTHETIC_MEDIA_MAX_FILE_BYTES:
                skipped_oversize += 1
                continue
            scanned += 1
            record = scan_file_record(module, resolved)
            if record.details.get("scan_status") == "error":
                failed += 1
            yield record
        yield build_scan_summary_record(
            root,
            scanned=scanned,
            skipped_oversize=skipped_oversize,
            failed=failed,
            capped=capped,
        )


def iter_synthetic_media_candidates(root: Path) -> Iterable[Path]:
    suffixes = SYNTHETIC_MEDIA_IMAGE_EXTENSIONS | SYNTHETIC_MEDIA_TEXT_EXTENSIONS
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def scan_file_record(module: object, path: Path) -> ArtifactRecord:
    resolved = path.resolve()
    try:
        stat_result = resolved.stat()
    except OSError as exc:
        return build_error_record(resolved, error=f"{type(exc).__name__}: {exc}")
    try:
        item = module.analyze_file(
            resolved,
            text_bytes=SYNTHETIC_MEDIA_TEXT_BYTES,
            metadata_bytes=SYNTHETIC_MEDIA_METADATA_BYTES,
            pixel_mode="off",
        )
    except Exception as exc:
        return build_error_record(resolved, error=f"{type(exc).__name__}: {exc}")
    payload = scan_item_payload(item)
    return build_scan_record(resolved, stat_size=stat_result.st_size, payload=payload)


def scan_item_payload(item: object) -> dict[str, object]:
    to_json = getattr(item, "to_json", None)
    if callable(to_json):
        payload = to_json()
        if isinstance(payload, Mapping):
            return dict(payload)
    if isinstance(item, Mapping):
        return dict(item)
    return {"status": "error", "error": "unrecognized deepfake_lens analyze_file result"}


def build_scan_record(path: Path, *, stat_size: int, payload: Mapping[str, object]) -> ArtifactRecord:
    result = payload.get("result")
    result_payload = result if isinstance(result, Mapping) else {}
    signals = result_payload.get("signals")
    signal_rows = [dict(row) for row in signals if isinstance(row, Mapping)][:SYNTHETIC_MEDIA_SIGNAL_LIMIT] if isinstance(signals, list) else []
    limitations = result_payload.get("limitations")
    model_analysis = result_payload.get("model_analysis")
    model_payload = model_analysis if isinstance(model_analysis, Mapping) else {}
    status = str(payload.get("status") or "unknown")
    details: dict[str, object] = {
        "parser": "synthetic-media-deepfake-lens",
        "parser_version": PARSER_VERSION,
        "coverage_status": "deepfake-lens-scan",
        "reportability": "triage",
        "source_path": str(path),
        "source_format": path.suffix.lower().lstrip("."),
        "source_size": stat_size,
        "source_hashes": synthetic_media_source_hashes(path, file_size=stat_size),
        "scan_status": status,
        "scan_kind": str(payload.get("kind") or ""),
        "scan_error": str(payload.get("error") or ""),
        "deepfake_lens_schema_version": DEEPFAKE_LENS_SCAN_JSON_SCHEMA_VERSION,
        "deepfake_lens_cli_path": deepfake_lens_cli_path(),
        "score": result_payload.get("score"),
        "band": str(result_payload.get("band") or ""),
        "band_label": str(result_payload.get("band_label") or ""),
        "verdict": str(result_payload.get("verdict") or ""),
        "signals": signal_rows,
        "signal_count": len(signal_rows),
        "limitations": [str(item) for item in limitations] if isinstance(limitations, list) else [],
        "source_guess": dict(result_payload.get("source_guess") or {}) if isinstance(result_payload.get("source_guess"), Mapping) else {},
        "next_checks": [str(item) for item in result_payload.get("next_checks") or []] if isinstance(result_payload.get("next_checks"), list) else [],
        "model_analysis_available": bool(model_payload.get("available")),
        "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
        "score_guidance": SYNTHETIC_MEDIA_SCORE_GUIDANCE,
        "parser_confidence": 0.4,
        "parser_confidence_basis": "optional heuristic screening score; not an authenticity determination",
        "evidence_strength": "triage",
        "validation_required": True,
        "validation_guidance": (
            "Treat score/band as review ordering only. Confirm with examiner review, "
            "trusted-tool comparison, or a validated forensic workflow before reporting."
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "deepfake-lens-heuristic-score-not-validated-forensic-classifier",
            "external-model-sidecar-must-be-pinned-and-provenanced",
            "known-answer-synthetic-media-corpus-required",
        ],
        "raw_result": dict(result_payload),
    }
    return ArtifactRecord(
        provider=SyntheticMediaProvider.name,
        artifact_type=f"synthetic-media-{payload.get('kind') or 'item'}",
        path=str(path),
        supported=True,
        details=details,
    )


def build_error_record(path: Path, *, error: str) -> ArtifactRecord:
    return ArtifactRecord(
        provider=SyntheticMediaProvider.name,
        artifact_type="synthetic-media-scan-error",
        path=str(path),
        supported=True,
        details={
            "parser": "synthetic-media-deepfake-lens",
            "parser_version": PARSER_VERSION,
            "coverage_status": "deepfake-lens-scan-error",
            "reportability": "triage",
            "source_path": str(path),
            "source_format": path.suffix.lower().lstrip("."),
            "scan_status": "error",
            "scan_error": error,
            "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
            "validation_required": True,
        },
    )


def build_unavailable_record(root: Path) -> ArtifactRecord:
    return ArtifactRecord(
        provider=SyntheticMediaProvider.name,
        artifact_type="synthetic-media-scan-status",
        path=str(root.resolve()),
        supported=False,
        details={
            "parser": "synthetic-media-deepfake-lens",
            "parser_version": PARSER_VERSION,
            "coverage_status": "provider-unavailable",
            "reportability": "inventory-only",
            "scan_status": "skipped-optional-dependency",
            "reason": "deepfake_lens python module is not importable in this environment",
            "deepfake_lens_cli_path": deepfake_lens_cli_path(),
            "install_hint": (
                "Install the deepfake-lens toolkit (pip install deepfake-lens or a "
                "checkout on PYTHONPATH) to enable synthetic-media screening."
            ),
            "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
            "validation_required": False,
        },
    )


def build_scan_summary_record(
    root: Path,
    *,
    scanned: int,
    skipped_oversize: int,
    failed: int,
    capped: bool,
) -> ArtifactRecord:
    return ArtifactRecord(
        provider=SyntheticMediaProvider.name,
        artifact_type="synthetic-media-scan-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "synthetic-media-deepfake-lens",
            "parser_version": PARSER_VERSION,
            "coverage_status": "deepfake-lens-scan-summary",
            "reportability": "triage",
            "scan_status": "completed",
            "scan_file_count": scanned,
            "scan_error_count": failed,
            "skipped_oversize_count": skipped_oversize,
            "scan_capped": capped,
            "max_files": SYNTHETIC_MEDIA_MAX_FILES,
            "max_file_bytes": SYNTHETIC_MEDIA_MAX_FILE_BYTES,
            "text_bytes": SYNTHETIC_MEDIA_TEXT_BYTES,
            "metadata_bytes": SYNTHETIC_MEDIA_METADATA_BYTES,
            "deepfake_lens_schema_version": DEEPFAKE_LENS_SCAN_JSON_SCHEMA_VERSION,
            "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
            "score_guidance": SYNTHETIC_MEDIA_SCORE_GUIDANCE,
            "validation_required": True,
        },
    )


def synthetic_media_source_hashes(path: Path, *, file_size: int) -> dict[str, str]:
    if 0 <= file_size <= SYNTHETIC_MEDIA_HASH_DEFER_BYTES:
        try:
            return compute_hashes(path)
        except OSError:
            pass
    return {
        "md5": "",
        "sha1": "",
        "sha256": "",
        "hash_status": "deferred-large-file" if file_size > SYNTHETIC_MEDIA_HASH_DEFER_BYTES else "unavailable",
    }
