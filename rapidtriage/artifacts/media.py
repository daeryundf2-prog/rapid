from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Iterable

import cv2

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "media-image-v3"
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
THUMBNAIL_MAX_DIMENSION = 128
THUMBNAIL_MAX_BYTES = 64 * 1024
OCR_SIDECAR_MAX_CHARS = 20_000
HANGUL_RE = re.compile(r"[\uac00-\ud7a3\u1100-\u11ff\u3130-\u318f]")


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
                "width": int(width),
                "height": int(height),
                "channel_count": int(image.shape[2]) if len(image.shape) == 3 else 1,
                "perceptual_hash": perceptual_hash,
                "similarity_bucket": perceptual_hash[:8],
                "ocr_candidate": True,
                "visual_classification": classify_image(width=int(width), height=int(height), channel_count=int(image.shape[2]) if len(image.shape) == 3 else 1),
                "thumbnail_preview": build_thumbnail_preview(image),
            }
        )
        artifact_type = "media-image"
    return ArtifactRecord(
        provider=MediaImageProvider.name,
        artifact_type=artifact_type,
        path=str(resolved),
        supported=True,
        details=details,
    )


def build_ocr_and_classifier_validation(path: Path) -> dict[str, object]:
    sidecar = load_ocr_sidecar(path)
    filename_has_hangul = contains_hangul(path.name)
    language_hints = ["kor", "eng"] if filename_has_hangul or sidecar.get("contains_hangul") else ["eng"]
    translation_required = bool(filename_has_hangul or sidecar.get("contains_hangul"))
    ocr_plan = {
        "engine": "tesseract",
        "status": "sidecar-imported" if sidecar else "queued-not-run",
        "recommended_languages": language_hints,
        "korean_language_pack_required": "kor" in language_hints,
        "validation_status": "review-sidecar-text" if sidecar else "requires-ocr-run",
    }
    translation_plan = {
        "status": "required-not-run" if translation_required else "not-required",
        "source_language_hint": "ko" if translation_required else "unknown",
        "target_language_hint": "en",
        "validation_status": "translation-not-run",
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
    }
    if sidecar:
        payload["ocr_sidecar"] = sidecar
    return payload


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
            "truncated": len(text) >= OCR_SIDECAR_MAX_CHARS,
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


def average_hash(image) -> str:
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
    resized = cv2.resize(grayscale, (8, 8), interpolation=cv2.INTER_AREA)
    mean_value = resized.mean()
    bits = "".join("1" if value >= mean_value else "0" for value in resized.flatten())
    return f"{int(bits, 2):016x}"


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
