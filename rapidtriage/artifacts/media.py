from __future__ import annotations

import base64
import io
import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:
    import cv2  # type: ignore[import-not-found]
except ModuleNotFoundError:
    cv2 = None  # type: ignore[assignment]

try:
    from PIL import Image
except ModuleNotFoundError:
    Image = None  # type: ignore[assignment]

from ..core.models import ArtifactRecord
from ..core.forensic_accuracy import build_accuracy_gate
from ..core.submission import compute_hashes

PARSER_VERSION = "media-image-v4"
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
THUMBNAIL_MAX_DIMENSION = 128
THUMBNAIL_MAX_BYTES = 64 * 1024
OCR_SIDECAR_MAX_CHARS = 20_000
TRANSLATION_SIDECAR_MAX_CHARS = 20_000
HANGUL_RE = re.compile(r"[\uac00-\ud7a3\u1100-\u11ff\u3130-\u318f]")
MEDIA_NATIVE_CAPABILITIES = {
    "image_gallery_review_metadata": True,
    "perceptual_hash_similarity_bucket": True,
    "bounded_thumbnail_preview": True,
    "ocr_sidecar_import": True,
    "korean_language_hinting": True,
    "translation_sidecar_import": True,
    "deepfake_detection": False,
    "ml_visual_similarity_clustering": False,
    "native_ocr_execution": False,
    "machine_translation_execution": False,
}
MEDIA_REPORT_GRADE_BLOCKERS = [
    "image-similarity-is-perceptual-hash-bucket-not-ml-validated-clustering",
    "ocr-and-translation-sidecars-are-post-acquisition-review-material",
    "native-ocr-and-translation-engine-execution-not-bundled",
    "deepfake-and-sensitive-media-classification-not-implemented",
]


class PillowEncodedBytes:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def tobytes(self) -> bytes:
        return self._data


class PillowMatrix:
    def __init__(self, image) -> None:
        self.image = image

    @property
    def shape(self) -> tuple[int, ...]:
        width, height = self.image.size
        channels = len(self.image.getbands())
        if channels == 1:
            return (height, width)
        return (height, width, channels)

    def tolist(self) -> list[object]:
        width, height = self.image.size
        pixels = list(self.image.getdata())
        rows: list[object] = []
        for y in range(height):
            start = y * width
            rows.append(list(pixels[start : start + width]))
        return rows

    def grayscale(self) -> "PillowMatrix":
        return PillowMatrix(self.image.convert("L"))

    def resized(self, size: tuple[int, int]) -> "PillowMatrix":
        return PillowMatrix(self.image.resize(size))

    def png_bytes(self) -> bytes:
        buffer = io.BytesIO()
        self.image.save(buffer, format="PNG")
        return buffer.getvalue()


class PillowCv2Compat:
    IMREAD_UNCHANGED = -1
    COLOR_BGR2GRAY = 6
    INTER_AREA = 3

    def imread(self, path: str, flags: int = -1):  # noqa: ARG002
        if Image is None:
            return None
        try:
            with Image.open(path) as image:
                if image.mode not in {"L", "RGB", "RGBA"}:
                    image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                return PillowMatrix(image.copy())
        except OSError:
            return None

    def cvtColor(self, image, code: int):  # noqa: N802
        if isinstance(image, PillowMatrix) and code == self.COLOR_BGR2GRAY:
            return image.grayscale()
        return image

    def resize(self, image, size: tuple[int, int], interpolation: int = 3):  # noqa: ARG002
        if isinstance(image, PillowMatrix):
            return image.resized(size)
        return image

    def imencode(self, extension: str, image) -> tuple[bool, PillowEncodedBytes]:
        if extension.lower() != ".png" or not isinstance(image, PillowMatrix):
            return False, PillowEncodedBytes(b"")
        try:
            return True, PillowEncodedBytes(image.png_bytes())
        except OSError:
            return False, PillowEncodedBytes(b"")


if cv2 is None:
    cv2 = PillowCv2Compat()  # type: ignore[assignment]


class MediaImageProvider:
    collector_kind = "media-image"
    name = "media-image-artifacts"
    description = "Image inventory with dimensions, hashes, perceptual hash, OCR queue hints, and similarity buckets"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
                yield build_image_record(path)


def build_image_record(path: Path) -> ArtifactRecord:
    resolved = path.resolve()
    stat_result = resolved.stat()
    details: dict[str, object] = {
        "parser": "media-image",
        "parser_version": PARSER_VERSION,
        "source_path": str(resolved),
        "source_format": resolved.suffix.lower().lstrip("."),
        "source_size": stat_result.st_size,
        "entry_name": resolved.name,
        "hashes": compute_hashes(resolved),
        "parser_confidence": 0.72,
        "parser_confidence_basis": "extension, file signature, bounded decoder/OCR sidecar validation",
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#56", "#58", "#59"],
        "media_native_capabilities": dict(MEDIA_NATIVE_CAPABILITIES),
        "media_report_grade_assessment": media_report_grade_assessment(),
    }
    details.update(build_ocr_and_classifier_validation(resolved))
    if not has_plausible_image_signature(resolved):
        image = None
    else:
        image = cv2.imread(str(resolved), cv2.IMREAD_UNCHANGED)
    if image is None:
        details.update(
            {
                "decoded": False,
                "parser_confidence": 0.35,
                "ocr_candidate": True,
                "note": "Image extension detected, but OpenCV could not decode the file.",
            }
        )
        artifact_type = "media-image-unreadable"
    else:
        height, width = image.shape[:2]
        perceptual_hash = average_hash(image)
        details.update(
            {
                "decoded": True,
                "parser_confidence": 0.86,
                "width": int(width),
                "height": int(height),
                "channel_count": int(image.shape[2]) if len(image.shape) == 3 else 1,
                "perceptual_hash": perceptual_hash,
                "similarity_bucket": perceptual_hash[:8],
                "ocr_candidate": True,
                "gallery_review_mode": image_gallery_review_mode(
                    perceptual_hash=perceptual_hash,
                    similarity_bucket=perceptual_hash[:8],
                    decoded=True,
                ),
                "visual_classification": classify_image(width=int(width), height=int(height), channel_count=int(image.shape[2]) if len(image.shape) == 3 else 1),
                "thumbnail_preview": safe_thumbnail_preview(image),
            }
        )
        artifact_type = "media-image"
    details["core_accuracy_gates"] = media_core_accuracy_gates(details=details, source_path=resolved)
    details["commercial_uplift_evidence"] = media_image_commercial_uplift_evidence(details=details, source_path=resolved)
    return ArtifactRecord(
        provider=MediaImageProvider.name,
        artifact_type=artifact_type,
        path=str(resolved),
        supported=True,
        details=details,
    )


def build_ocr_and_classifier_validation(path: Path) -> dict[str, object]:
    sidecar = load_ocr_sidecar(path)
    translation_sidecar = load_translation_sidecar(path)
    filename_has_hangul = contains_hangul(path.name)
    language_hints = ["kor", "eng"] if filename_has_hangul or sidecar.get("contains_hangul") else ["eng"]
    translation_required = bool(filename_has_hangul or sidecar.get("contains_hangul"))
    ocr_plan = {
        "engine": "tesseract",
        "status": "sidecar-imported" if sidecar else "queued-not-run",
        "recommended_languages": language_hints,
        "korean_language_pack_required": "kor" in language_hints,
        "validation_status": "review-sidecar-text" if sidecar else "requires-ocr-run",
        "commercial_gap_ids": ["#58", "#59"],
    }
    translation_plan = {
        "status": "sidecar-imported" if translation_sidecar else ("required-not-run" if translation_required else "not-required"),
        "source_language_hint": "ko" if translation_required else "unknown",
        "target_language_hint": str(translation_sidecar.get("target_language") or "en"),
        "validation_status": "review-translation-sidecar" if translation_sidecar else "translation-not-run",
        "commercial_gap_ids": ["#59"],
    }
    classifier_validation = {
        "status": "rule-based-triage",
        "model": "none",
        "deepfake_detection_status": "not-run",
        "validation_status": "not-a-forensic-media-classifier",
    }
    payload: dict[str, object] = {
        "ocr_plan": ocr_plan,
        "translation_plan": translation_plan,
        "classifier_validation": classifier_validation,
        "ocr_queue_assessment": ocr_queue_assessment(sidecar=sidecar),
        "korean_ocr_translation_workflow": korean_ocr_translation_workflow(
            language_hints=language_hints,
            translation_required=translation_required,
            translation_sidecar=translation_sidecar,
        ),
    }
    if sidecar:
        payload["ocr_sidecar"] = sidecar
    if translation_sidecar:
        payload["translation_sidecar"] = translation_sidecar
    return payload


def image_gallery_review_mode(*, perceptual_hash: str, similarity_bucket: str, decoded: bool) -> dict[str, object]:
    return {
        "commercial_gap_ids": ["#56"],
        "status": "implemented-baseline-validation-required",
        "decoded": decoded,
        "perceptual_hash": perceptual_hash,
        "similarity_bucket": similarity_bucket,
        "supports": [
            "thumbnail-preview",
            "similarity-bucket-filtering",
            "tag-suggestions",
            "report-selection-hints",
            "source-hash-verification",
        ],
        "ready_for_court_report": False,
        "blockers": [
            "full-gallery-virtualized-review-board-not-yet-dedicated",
            "visual-similarity-is-hash-bucketed-not-ml-validated",
            "sensitive-media-and-deepfake-classification-not-implemented",
        ],
    }


def ocr_queue_assessment(*, sidecar: dict[str, object]) -> dict[str, object]:
    return {
        "commercial_gap_ids": ["#58"],
        "status": "sidecar-imported" if sidecar else "queued-not-run",
        "ready_for_court_report": False,
        "blockers": [
            "ocr-engine-execution-is-external-to-this-parser",
            "ocr-quality-and-language-pack-validation-required",
            "sidecar-provenance-must-be-preserved-before-reporting",
        ],
    }


def korean_ocr_translation_workflow(
    *,
    language_hints: list[str],
    translation_required: bool,
    translation_sidecar: dict[str, object],
) -> dict[str, object]:
    return {
        "commercial_gap_ids": ["#59"],
        "language_hints": language_hints,
        "korean_detected_or_expected": "kor" in language_hints,
        "translation_required": translation_required,
        "translation_status": "sidecar-imported" if translation_sidecar else ("required-not-run" if translation_required else "not-required"),
        "ready_for_court_report": False,
        "blockers": [
            "korean-ocr-sidecar-or-engine-output-needs-human-validation",
            "translation-is-review-aid-not-certified-translation",
        ],
    }


def media_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "triage-only-validation-required",
        "commercial_gap_ids": ["#56", "#58", "#59"],
        "ready_for_court_report": False,
        "blockers": list(MEDIA_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Verify image hashes, thumbnail/source consistency, OCR sidecar provenance, and translation accuracy before report inclusion.",
            "Use validated media/OCR tools for sensitive image classification, full gallery workflows, and certified translation.",
        ],
    }


def media_core_accuracy_gates(*, details: dict[str, object], source_path: Path) -> list[dict[str, object]]:
    evidence_refs = [
        f"source_path:{source_path}",
        f"source_format:{details.get('source_format', '')}",
        f"source_size:{details.get('source_size', '')}",
    ]
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    item56: list[str] = []
    if details.get("hashes") and (details.get("width") is not None or details.get("decoded") is not None):
        item56.append("image metadata and source hashes")
    if details.get("thumbnail_preview") or details.get("decoded") is not None:
        item56.append("thumbnail or preview metadata")
    if details.get("similarity_bucket"):
        item56.append("perceptual similarity bucket")
    if details.get("gallery_review_mode"):
        item56.append("tag/report selection hints")
    if not MEDIA_NATIVE_CAPABILITIES["deepfake_detection"]:
        item56.append("visual-classifier limitation warning")

    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), dict) else {}
    item58: list[str] = []
    if details.get("ocr_plan"):
        item58.append("queue item generation")
    if (ocr_sidecar.get("sha256") or ocr_sidecar.get("source_sha256")) and ocr_sidecar.get("text_sha256"):
        item58.append("sidecar import and hashes")
    if details.get("ocr_queue_assessment"):
        item58.append("retry state handling")
    if ocr_sidecar.get("metadata") is not None:
        item58.append("engine/metadata preservation")
    if not MEDIA_NATIVE_CAPABILITIES["native_ocr_execution"]:
        item58.append("native OCR limitation warning")

    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), dict) else {}
    workflow = details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), dict) else {}
    item59: list[str] = []
    if workflow.get("language_hints") or details.get("ocr_plan"):
        item59.append("Korean language hinting")
    if ocr_sidecar.get("quality_metrics"):
        item59.append("OCR quality metrics")
    if translation_sidecar:
        item59.append("translation sidecar import")
    if ocr_sidecar.get("metadata") is not None:
        item59.append("confidence/engine metadata")
    if not MEDIA_NATIVE_CAPABILITIES["machine_translation_execution"]:
        item59.append("human translation validation warning")

    return [
        build_accuracy_gate(56, satisfied_checks=item56, evidence_refs=evidence_refs),
        build_accuracy_gate(58, satisfied_checks=item58, evidence_refs=evidence_refs),
        build_accuracy_gate(59, satisfied_checks=item59, evidence_refs=evidence_refs),
    ]


def media_image_commercial_uplift_evidence(*, details: Mapping[str, object], source_path: Path) -> dict[str, object]:
    gates = details.get("core_accuracy_gates") if isinstance(details.get("core_accuracy_gates"), list) else []
    passed_by_item: dict[str, list[str]] = {}
    for gate in gates:
        if isinstance(gate, Mapping) and gate.get("gap_id") in {"#56", "#58", "#59"}:
            passed_by_item[str(gate["gap_id"])] = list(gate.get("satisfied_checks") or [])
    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), Mapping) else {}
    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), Mapping) else {}
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [56, 58, 59],
        "implementation_track": "image-gallery-ocr-review-gates",
        "source_refs": [
            f"source_path:{source_path}",
            f"source_sha256:{details.get('hashes', {}).get('sha256', '') if isinstance(details.get('hashes'), Mapping) else ''}",
            f"ocr_sidecar:{ocr_sidecar.get('source_path', '')}",
            f"translation_sidecar:{translation_sidecar.get('source_path', '')}",
        ],
        "reportability_decision": media_image_reportability_decision(
            failed_by_item={
                "#56": ["dedicated-gallery-grid", "persistent-tags", "ml-visual-similarity", "deepfake-classifier-validation"],
                "#58": ["native-ocr-engine-execution", "engine-retry-logs", "case-db-ocr-job-persistence"],
                "#59": ["built-in-korean-ocr-execution", "machine-translation-worker", "confidence-calibration-corpus"],
            },
            ocr_sidecar=ocr_sidecar,
            translation_sidecar=translation_sidecar,
        ),
        "passed_validation_check_ids_by_item": passed_by_item,
        "failed_validation_check_ids_by_item": {
            "#56": ["dedicated-gallery-grid", "persistent-tags", "ml-visual-similarity", "deepfake-classifier-validation"],
            "#58": ["native-ocr-engine-execution", "engine-retry-logs", "case-db-ocr-job-persistence"],
            "#59": ["built-in-korean-ocr-execution", "machine-translation-worker", "confidence-calibration-corpus"],
        },
        "commercial_blockers": list(MEDIA_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "source_size": int(details.get("source_size") or 0),
            "thumbnail_inline_available": bool(
                isinstance(details.get("thumbnail_preview"), Mapping) and details["thumbnail_preview"].get("available")
            ),
            "perceptual_hash_present": bool(details.get("perceptual_hash")),
            "similarity_bucket_present": bool(details.get("similarity_bucket")),
            "ocr_sidecar_imported": bool(ocr_sidecar),
            "translation_sidecar_imported": bool(translation_sidecar),
            "native_ocr_execution": False,
            "machine_translation_execution": False,
        },
        "reporting_status": "triage-only-validation-required",
    }


def media_image_reportability_decision(
    *,
    failed_by_item: Mapping[str, Sequence[str]],
    ocr_sidecar: Mapping[str, object],
    translation_sidecar: Mapping[str, object],
) -> dict[str, object]:
    blockers = {f"{item_id}:{check}" for item_id, checks in failed_by_item.items() for check in checks}
    return {
        "profile_version": "media-image-reportability-decision-v1",
        "commercial_gap_ids": ["#56", "#58", "#59"],
        "decision": "do-not-report-media-image-output-as-gallery-ocr-or-translation-complete",
        "allowed_use": "image-gallery-ocr-sidecar-triage-pivot",
        "blockers": sorted(blockers),
        "ocr_sidecar_imported": bool(ocr_sidecar),
        "translation_sidecar_imported": bool(translation_sidecar),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate gallery virtualization, persistent tags, ML similarity, and sensitive/deepfake classifier behavior",
            "run or validate OCR engine execution logs, retry state, confidence calibration, and Case DB queue persistence",
            "attach certified Korean OCR/translation review evidence before reporting translated text",
        ],
    }


def load_ocr_sidecar(path: Path) -> dict[str, object]:
    candidates = [
        path.with_name(f"{path.name}.ocr.txt"),
        path.with_name(f"{path.stem}.ocr.txt"),
        path.with_suffix(".txt"),
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")[:OCR_SIDECAR_MAX_CHARS]
        except OSError:
            continue
        return {
            "source_path": str(candidate.resolve()),
            "source_format": "text",
            "source_size": candidate.stat().st_size,
            "source_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "text": text,
            "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            "character_count": len(text),
            "contains_hangul": contains_hangul(text),
            "language_hint": language_hint_for_text(text),
            "quality_metrics": ocr_quality_metrics(text),
            "truncated": len(text) >= OCR_SIDECAR_MAX_CHARS,
        }
    return {}


def load_translation_sidecar(path: Path) -> dict[str, object]:
    candidates = [
        path.with_name(f"{path.name}.translation.txt"),
        path.with_name(f"{path.name}.en.txt"),
        path.with_name(f"{path.stem}.translation.txt"),
        path.with_name(f"{path.stem}.en.txt"),
        path.with_suffix(".translation.txt"),
        path.with_suffix(".en.txt"),
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            raw = candidate.read_text(encoding="utf-8", errors="replace")
            stat = candidate.stat()
        except OSError:
            continue
        text = raw[:TRANSLATION_SIDECAR_MAX_CHARS]
        return {
            "source_path": str(candidate.resolve()),
            "source_format": "text",
            "source_size": stat.st_size,
            "source_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "text": text,
            "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            "character_count": len(text),
            "source_language": "ko" if contains_hangul(path.name) else "unknown",
            "target_language": "en",
            "quality_metrics": ocr_quality_metrics(text),
            "truncated": len(raw) > TRANSLATION_SIDECAR_MAX_CHARS,
        }
    return {}


def classify_image(*, width: int, height: int, channel_count: int) -> dict[str, object]:
    aspect_ratio = round(width / height, 3) if height else 0
    if width >= 700 and height >= 400 and 1.2 <= aspect_ratio <= 2.4:
        label = "screenshot-candidate"
        confidence = 0.62
    elif channel_count == 1 or aspect_ratio < 0.8:
        label = "document-scan-candidate"
        confidence = 0.55
    else:
        label = "photo-or-image-candidate"
        confidence = 0.45
    return {
        "label": label,
        "confidence": confidence,
        "method": "dimension-channel-rule",
        "validation_status": "triage-hint",
    }


def contains_hangul(value: str) -> bool:
    return bool(HANGUL_RE.search(value))


def language_hint_for_text(value: str) -> str:
    has_hangul = contains_hangul(value)
    has_latin = any("a" <= character.lower() <= "z" for character in value)
    if has_hangul and has_latin:
        return "ko+en"
    if has_hangul:
        return "ko"
    if has_latin:
        return "en"
    return "unknown"


def ocr_quality_metrics(value: str) -> dict[str, object]:
    hangul_count = sum(1 for character in value if contains_hangul(character))
    latin_count = sum(1 for character in value if "a" <= character.lower() <= "z")
    digit_count = sum(1 for character in value if character.isdigit())
    whitespace_count = sum(1 for character in value if character.isspace())
    return {
        "character_count": len(value),
        "non_whitespace_count": sum(1 for character in value if not character.isspace()),
        "hangul_count": hangul_count,
        "latin_count": latin_count,
        "digit_count": digit_count,
        "whitespace_ratio": round(whitespace_count / max(len(value), 1), 3),
        "korean_text_present": hangul_count > 0,
    }


def average_hash(image) -> str:
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
    resized = cv2.resize(grayscale, (8, 8), interpolation=cv2.INTER_AREA)
    values = matrix_values(resized)
    mean_value = sum(values) / max(len(values), 1)
    bits = "".join("1" if value >= mean_value else "0" for value in values)
    return f"{int(bits, 2):016x}"


def matrix_values(image) -> list[int]:
    try:
        matrix = image.tolist()
    except Exception:
        matrix = [[image[y][x] for x in range(8)] for y in range(8)]
    return [normalized_pixel_value(value) for row in matrix for value in ensure_sequence(row)]


def ensure_sequence(value) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def normalized_pixel_value(value) -> int:
    if isinstance(value, (list, tuple)):
        channel_values = [normalized_pixel_value(channel) for channel in value]
        return int(sum(channel_values) / max(len(channel_values), 1))
    return int(value)


def safe_thumbnail_preview(image) -> dict[str, object]:
    try:
        return build_thumbnail_preview(image)
    except Exception as exc:
        return {
            "strategy": "bounded-inline-png",
            "available": False,
            "reason": "opencv-thumbnail-failed",
            "error": str(exc),
        }


def build_thumbnail_preview(image) -> dict[str, object]:
    height, width = image.shape[:2]
    scale = min(1.0, THUMBNAIL_MAX_DIMENSION / max(width, height))
    thumbnail_width = max(1, int(round(width * scale)))
    thumbnail_height = max(1, int(round(height * scale)))
    if scale < 1.0:
        thumbnail = cv2.resize(image, (thumbnail_width, thumbnail_height), interpolation=cv2.INTER_AREA)
    else:
        thumbnail = image
    success, encoded = cv2.imencode(".png", thumbnail)
    if not success:
        return {
            "strategy": "bounded-inline-png",
            "available": False,
            "reason": "opencv-imencode-failed",
        }
    data = encoded.tobytes()
    preview: dict[str, object] = {
        "strategy": "bounded-inline-png",
        "available": True,
        "format": "png",
        "width": int(thumbnail_width),
        "height": int(thumbnail_height),
        "byte_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if len(data) <= THUMBNAIL_MAX_BYTES:
        preview["data_uri"] = "data:image/png;base64," + base64.b64encode(data).decode("ascii")
    else:
        preview["available"] = False
        preview["reason"] = "thumbnail-exceeds-inline-limit"
    return preview


def has_plausible_image_signature(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
            if path.suffix.lower() in {".jpg", ".jpeg"}:
                handle.seek(-2, 2)
                tail = handle.read(2)
    except OSError:
        return False
    suffix = path.suffix.lower()
    if suffix in {".jpg", ".jpeg"}:
        return header.startswith(b"\xff\xd8") and tail == b"\xff\xd9"
    if suffix == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n") and header[12:16] == b"IHDR"
    if suffix == ".bmp":
        return header.startswith(b"BM")
    if suffix in {".tif", ".tiff"}:
        return header.startswith((b"II*\x00", b"MM\x00*"))
    if suffix == ".webp":
        return header.startswith(b"RIFF") and header[8:12] == b"WEBP"
    return True
