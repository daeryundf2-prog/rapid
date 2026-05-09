from __future__ import annotations

import base64
import io
import hashlib
import json
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
VIDEO_EXTENSIONS = {".mp4", ".mov", ".avi", ".mkv", ".wmv", ".m4v", ".webm", ".3gp"}
AUDIO_EXTENSIONS = {".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".wma", ".amr"}
THUMBNAIL_MAX_DIMENSION = 128
THUMBNAIL_MAX_BYTES = 64 * 1024
OCR_SIDECAR_MAX_CHARS = 20_000
TRANSLATION_SIDECAR_MAX_CHARS = 20_000
CODEC_METADATA_SIDECAR_MAX_BYTES = 2 * 1024 * 1024
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
    "video_audio_inventory": True,
    "transcript_sidecar_import": True,
    "codec_metadata_sidecar_import": True,
    "safe_media_playback": False,
    "waveform_generation": False,
}
MEDIA_REPORT_GRADE_BLOCKERS = [
    "image-similarity-is-perceptual-hash-bucket-not-ml-validated-clustering",
    "ocr-and-translation-sidecars-are-post-acquisition-review-material",
    "native-ocr-and-translation-engine-execution-not-bundled",
    "deepfake-and-sensitive-media-classification-not-implemented",
]
MEDIA_TRUSTED_DIFF_BLOCKERS = {
    56: "image-gallery-trusted-manifest-diff-required",
    58: "ocr-sidecar-trusted-engine-log-diff-required",
    59: "korean-ocr-translation-trusted-review-diff-required",
}
MEDIA_TRUSTED_DIFF_CHECKS = {
    56: "trusted image gallery manifest diff pass",
    58: "trusted OCR engine/sidecar diff pass",
    59: "trusted Korean OCR/translation review diff pass",
}
MEDIA_TRUSTED_TOOLS = {
    "image-gallery-ground-truth",
    "perceptual-hash-manifest",
    "ocr-engine-log",
    "ocr-sidecar-ground-truth",
    "korean-ocr-review",
    "certified-translation-review",
}


def stable_payload_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
            elif path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS:
                yield build_media_av_record(path, media_kind="video")
            elif path.is_file() and path.suffix.lower() in AUDIO_EXTENSIONS:
                yield build_media_av_record(path, media_kind="audio")


def build_media_av_record(path: Path, *, media_kind: str) -> ArtifactRecord:
    resolved = path.resolve()
    stat_result = resolved.stat()
    transcript_sidecars = find_transcript_sidecars(resolved)
    transcript_cues = [cue for sidecar in transcript_sidecars for cue in sidecar.get("cue_samples", [])]
    container_profile = media_container_profile(resolved, media_kind=media_kind)
    preview_sidecars = find_media_preview_sidecars(resolved)
    codec_metadata_sidecars = find_codec_metadata_sidecars(resolved)
    waveform_preview = build_waveform_preview(resolved, container_profile) if media_kind == "audio" else {"status": "not-applicable"}
    details: dict[str, object] = {
        "parser": "media-image",
        "parser_version": PARSER_VERSION,
        "source_path": str(resolved),
        "source_format": resolved.suffix.lower().lstrip("."),
        "source_size": stat_result.st_size,
        "entry_name": resolved.name,
        "media_kind": media_kind,
        "hashes": compute_hashes(resolved),
        "modified_at": stat_result.st_mtime,
        "parser_confidence": 0.62,
        "parser_confidence_basis": "extension and bounded transcript sidecar inventory",
        "coverage_status": "media-file-inventory",
        "container_profile": container_profile,
        "container_parse_status": container_profile.get("parse_status", "unknown"),
        "reportability": "triage",
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#57"],
        "media_native_capabilities": dict(MEDIA_NATIVE_CAPABILITIES),
        "transcript_sidecars": transcript_sidecars,
        "transcript_sidecar_count": len(transcript_sidecars),
        "transcript_cue_sample_count": len(transcript_cues),
        "transcript_cue_samples": transcript_cues[:25],
        "preview_sidecars": preview_sidecars,
        "preview_sidecar_count": len(preview_sidecars),
        "codec_metadata_sidecars": codec_metadata_sidecars,
        "codec_metadata_sidecar_count": len(codec_metadata_sidecars),
        "codec_metadata_summary": codec_metadata_summary(codec_metadata_sidecars),
        "waveform_preview": waveform_preview,
        "preview_workflow": {
            "safe_playback_status": "not-implemented",
            "waveform_status": waveform_preview.get("status", "not-applicable") if media_kind == "audio" else "not-applicable",
            "thumbnail_status": "sidecar-linked" if preview_sidecars else "not-generated",
            "transcript_cue_review_status": "sidecar-only" if transcript_sidecars else "not-available",
            "codec_metadata_status": "sidecar-linked" if codec_metadata_sidecars else "not-available",
        },
        "validation_required": True,
        "validation_guidance": (
            "Video/audio file is inventoried and transcript/codec metadata sidecars are linked when present. Safe playback, waveform/"
            "thumbnail extraction, codec sandboxing, and transcript cue validation are required before report-grade media claims."
        ),
        "commercial_grade_blockers": [
            "safe-media-playback-sandbox-not-implemented",
            "waveform-thumbnail-generation-not-implemented",
            "transcript-cue-known-answer-validation-required",
            "codec-metadata-sidecar-must-be-provenanced-or-regenerated-by-trusted-tool",
        ],
    }
    return ArtifactRecord(
        provider=MediaImageProvider.name,
        artifact_type=f"media-{media_kind}",
        path=str(resolved),
        supported=True,
        details=details,
    )


def media_container_profile(path: Path, *, media_kind: str) -> dict[str, object]:
    blob = read_prefix(path, 4096)
    suffix = path.suffix.lower()
    if media_kind == "audio" and blob.startswith(b"RIFF") and blob[8:12] == b"WAVE":
        return wav_container_profile(blob)
    if media_kind == "video" and len(blob) >= 12 and blob[4:8] == b"ftyp":
        return mp4_container_profile(blob, suffix=suffix)
    return {
        "profile_version": "media-container-profile-v1",
        "media_kind": media_kind,
        "container_hint": suffix.lstrip("."),
        "parse_status": "signature-not-recognized",
        "scan_bytes": len(blob),
    }


def mp4_container_profile(blob: bytes, *, suffix: str) -> dict[str, object]:
    major_brand = blob[8:12].decode("ascii", errors="replace") if len(blob) >= 12 else ""
    compatible_brands: list[str] = []
    for offset in range(16, min(len(blob), 64), 4):
        brand = blob[offset : offset + 4]
        if len(brand) == 4 and all(32 <= byte <= 126 for byte in brand):
            compatible_brands.append(brand.decode("ascii", errors="replace"))
    box_inventory = mp4_box_inventory(blob)
    mvhd_profile = mp4_mvhd_duration_profile(blob)
    return {
        "profile_version": "media-container-profile-v1",
        "media_kind": "video",
        "container_hint": "mp4-family" if suffix in {".mp4", ".m4v", ".mov"} else suffix.lstrip("."),
        "parse_status": "ftyp-header-parsed",
        "major_brand": major_brand,
        "compatible_brands": compatible_brands[:12],
        "box_inventory": box_inventory,
        "box_count": len(box_inventory),
        "mvhd_profile": mvhd_profile,
        "scan_bytes": len(blob),
    }


def mp4_box_inventory(blob: bytes, *, limit: int = 40) -> list[dict[str, object]]:
    boxes: list[dict[str, object]] = []
    offset = 0
    while offset + 8 <= len(blob) and len(boxes) < limit:
        size = int.from_bytes(blob[offset : offset + 4], "big", signed=False)
        box_type = blob[offset + 4 : offset + 8].decode("ascii", errors="replace")
        header_size = 8
        if size == 1 and offset + 16 <= len(blob):
            size = int.from_bytes(blob[offset + 8 : offset + 16], "big", signed=False)
            header_size = 16
        elif size == 0:
            size = len(blob) - offset
        if size < header_size or offset + size > len(blob):
            boxes.append(
                {
                    "offset": offset,
                    "type": box_type,
                    "size": size,
                    "header_size": header_size,
                    "parse_status": "truncated-or-invalid",
                }
            )
            break
        boxes.append(
            {
                "offset": offset,
                "type": box_type,
                "size": size,
                "header_size": header_size,
                "payload_offset": offset + header_size,
                "payload_size": size - header_size,
                "parse_status": "bounded",
            }
        )
        offset += size
    return boxes


def mp4_mvhd_duration_profile(blob: bytes) -> dict[str, object]:
    offset = blob.find(b"mvhd")
    if offset < 4:
        return {"status": "not-found"}
    box_start = offset - 4
    box_size = int.from_bytes(blob[box_start:offset], "big", signed=False)
    if box_size < 24 or box_start + box_size > len(blob):
        return {"status": "truncated-or-invalid", "box_offset": box_start, "box_size": box_size}
    version = blob[offset + 4]
    body = offset + 8
    if version == 0 and body + 16 <= len(blob):
        timescale = int.from_bytes(blob[body + 8 : body + 12], "big", signed=False)
        duration = int.from_bytes(blob[body + 12 : body + 16], "big", signed=False)
    elif version == 1 and body + 28 <= len(blob):
        timescale = int.from_bytes(blob[body + 16 : body + 20], "big", signed=False)
        duration = int.from_bytes(blob[body + 20 : body + 28], "big", signed=False)
    else:
        return {"status": "unsupported-version", "version": version, "box_offset": box_start}
    seconds = round(duration / timescale, 6) if timescale else None
    return {
        "status": "parsed" if seconds is not None else "timescale-zero",
        "box_offset": box_start,
        "box_size": box_size,
        "version": version,
        "timescale": timescale,
        "duration_units": duration,
        "estimated_duration_seconds": seconds,
        "validation_status": "triage-container-metadata",
    }


def wav_container_profile(blob: bytes) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "media-container-profile-v1",
        "media_kind": "audio",
        "container_hint": "wav",
        "parse_status": "riff-wave-header-parsed",
        "scan_bytes": len(blob),
    }
    fmt_offset = blob.find(b"fmt ")
    data_offset = blob.find(b"data")
    if fmt_offset >= 0 and fmt_offset + 24 <= len(blob):
        audio_format = int.from_bytes(blob[fmt_offset + 8 : fmt_offset + 10], "little", signed=False)
        channels = int.from_bytes(blob[fmt_offset + 10 : fmt_offset + 12], "little", signed=False)
        sample_rate = int.from_bytes(blob[fmt_offset + 12 : fmt_offset + 16], "little", signed=False)
        byte_rate = int.from_bytes(blob[fmt_offset + 16 : fmt_offset + 20], "little", signed=False)
        bits_per_sample = int.from_bytes(blob[fmt_offset + 22 : fmt_offset + 24], "little", signed=False)
        profile.update(
            {
                "audio_format": audio_format,
                "channels": channels,
                "sample_rate": sample_rate,
                "byte_rate": byte_rate,
                "bits_per_sample": bits_per_sample,
            }
        )
    if data_offset >= 0 and data_offset + 8 <= len(blob):
        data_size = int.from_bytes(blob[data_offset + 4 : data_offset + 8], "little", signed=False)
        profile["data_size"] = data_size
        byte_rate = profile.get("byte_rate")
        if isinstance(byte_rate, int) and byte_rate > 0:
            profile["estimated_duration_seconds"] = round(data_size / byte_rate, 3)
    return profile


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def find_media_preview_sidecars(path: Path) -> list[dict[str, object]]:
    candidates: list[Path] = []
    for suffix in (".jpg", ".jpeg", ".png", ".webp"):
        candidates.append(path.with_suffix(path.suffix + suffix))
        candidates.append(path.with_suffix(suffix))
        candidates.append(path.parent / f"{path.stem}.thumbnail{suffix}")
        candidates.append(path.parent / f"{path.stem}.poster{suffix}")
    sidecars: list[dict[str, object]] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        image_profile = preview_image_profile(candidate)
        sidecars.append(
            {
                "path": str(candidate.resolve()),
                "source_sha256": compute_hashes(path).get("sha256", ""),
                "sidecar_hashes": compute_hashes(candidate),
                "format": candidate.suffix.lower().lstrip("."),
                "size": candidate.stat().st_size,
                "image_profile": image_profile,
                "validation_status": "sidecar-linked-unvalidated",
            }
        )
    return sidecars


def preview_image_profile(path: Path) -> dict[str, object]:
    profile: dict[str, object] = {
        "decoded": False,
        "width": None,
        "height": None,
        "parse_status": "not-decoded",
    }
    if Image is None:
        profile["parse_status"] = "pillow-unavailable"
        return profile
    try:
        with Image.open(path) as image:
            profile.update(
                {
                    "decoded": True,
                    "width": int(image.width),
                    "height": int(image.height),
                    "mode": image.mode,
                    "parse_status": "decoded",
                }
            )
    except OSError as exc:
        profile["parse_status"] = "decode-failed"
        profile["error"] = str(exc)[:120]
    return profile


def find_codec_metadata_sidecars(path: Path) -> list[dict[str, object]]:
    candidates: list[Path] = []
    for suffix in (".ffprobe.json", ".mediainfo.json", ".media.json", ".codec.json"):
        candidates.append(path.with_suffix(path.suffix + suffix))
        candidates.append(path.with_suffix(suffix))
    sidecars: list[dict[str, object]] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        payload, parse_status, error = read_codec_metadata_payload(candidate)
        sidecar: dict[str, object] = {
            "path": str(candidate.resolve()),
            "source_sha256": compute_hashes(path).get("sha256", ""),
            "sidecar_hashes": compute_hashes(candidate),
            "format": candidate.suffix.lower().lstrip("."),
            "size": candidate.stat().st_size,
            "parse_status": parse_status,
            "validation_status": "sidecar-linked-unvalidated",
            "tool_hint": codec_tool_hint(candidate),
        }
        if error:
            sidecar["error"] = error
        if isinstance(payload, Mapping):
            sidecar["format_profile"] = codec_format_profile(payload)
            sidecar["stream_profiles"] = codec_stream_profiles(payload)
            sidecar["stream_count"] = len(sidecar["stream_profiles"]) if isinstance(sidecar["stream_profiles"], list) else 0
        sidecars.append(sidecar)
    return sidecars


def read_codec_metadata_payload(path: Path) -> tuple[object | None, str, str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, "stat-failed", str(exc)[:120]
    if size > CODEC_METADATA_SIDECAR_MAX_BYTES:
        return None, "too-large", f"metadata sidecar exceeds {CODEC_METADATA_SIDECAR_MAX_BYTES} bytes"
    try:
        with path.open("rb") as handle:
            payload = json.loads(handle.read().decode("utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, "parse-failed", str(exc)[:120]
    return payload, "parsed" if isinstance(payload, Mapping) else "unsupported-json-root", ""


def codec_tool_hint(path: Path) -> str:
    name = path.name.lower()
    if "ffprobe" in name:
        return "ffprobe-json"
    if "mediainfo" in name:
        return "mediainfo-json"
    return "generic-codec-json"


def codec_format_profile(payload: Mapping[str, object]) -> dict[str, object]:
    format_row = payload.get("format") if isinstance(payload.get("format"), Mapping) else {}
    duration = parse_float(format_row.get("duration")) if isinstance(format_row, Mapping) else None
    size = parse_int(format_row.get("size")) if isinstance(format_row, Mapping) else None
    bit_rate = parse_int(format_row.get("bit_rate")) if isinstance(format_row, Mapping) else None
    return {
        "filename": str(format_row.get("filename", ""))[:500] if isinstance(format_row, Mapping) else "",
        "format_name": str(format_row.get("format_name", ""))[:120] if isinstance(format_row, Mapping) else "",
        "format_long_name": str(format_row.get("format_long_name", ""))[:180] if isinstance(format_row, Mapping) else "",
        "duration_seconds": duration,
        "size": size,
        "bit_rate": bit_rate,
    }


def codec_stream_profiles(payload: Mapping[str, object], *, limit: int = 20) -> list[dict[str, object]]:
    streams = payload.get("streams")
    if not isinstance(streams, Sequence) or isinstance(streams, (str, bytes, bytearray)):
        return []
    profiles: list[dict[str, object]] = []
    for stream in streams[:limit]:
        if not isinstance(stream, Mapping):
            continue
        profiles.append(
            {
                "index": parse_int(stream.get("index")),
                "codec_type": str(stream.get("codec_type", ""))[:60],
                "codec_name": str(stream.get("codec_name", ""))[:120],
                "codec_long_name": str(stream.get("codec_long_name", ""))[:180],
                "width": parse_int(stream.get("width")),
                "height": parse_int(stream.get("height")),
                "sample_rate": parse_int(stream.get("sample_rate")),
                "channels": parse_int(stream.get("channels")),
                "duration_seconds": parse_float(stream.get("duration")),
                "bit_rate": parse_int(stream.get("bit_rate")),
            }
        )
    return profiles


def codec_metadata_summary(sidecars: Sequence[Mapping[str, object]]) -> dict[str, object]:
    streams: list[Mapping[str, object]] = []
    duration_candidates: list[float] = []
    tool_hints: list[str] = []
    for sidecar in sidecars:
        tool_hint = sidecar.get("tool_hint")
        if isinstance(tool_hint, str) and tool_hint:
            tool_hints.append(tool_hint)
        format_profile = sidecar.get("format_profile") if isinstance(sidecar.get("format_profile"), Mapping) else {}
        duration = format_profile.get("duration_seconds") if isinstance(format_profile, Mapping) else None
        if isinstance(duration, (int, float)):
            duration_candidates.append(float(duration))
        stream_profiles = sidecar.get("stream_profiles")
        if isinstance(stream_profiles, Sequence) and not isinstance(stream_profiles, (str, bytes, bytearray)):
            streams.extend(stream for stream in stream_profiles if isinstance(stream, Mapping))
    video_streams = [stream for stream in streams if stream.get("codec_type") == "video"]
    audio_streams = [stream for stream in streams if stream.get("codec_type") == "audio"]
    return {
        "status": "sidecar-linked" if sidecars else "not-available",
        "sidecar_count": len(sidecars),
        "tool_hints": sorted(set(tool_hints)),
        "duration_seconds": duration_candidates[0] if duration_candidates else None,
        "stream_count": len(streams),
        "video_stream_count": len(video_streams),
        "audio_stream_count": len(audio_streams),
        "primary_video": dict(video_streams[0]) if video_streams else {},
        "primary_audio": dict(audio_streams[0]) if audio_streams else {},
        "validation_status": "sidecar-linked-unvalidated" if sidecars else "not-available",
    }


def parse_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_float(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 6)
    try:
        return round(float(str(value).strip()), 6)
    except (TypeError, ValueError):
        return None


def build_waveform_preview(path: Path, container_profile: Mapping[str, object], *, bucket_count: int = 32) -> dict[str, object]:
    if container_profile.get("parse_status") != "riff-wave-header-parsed":
        return {"status": "unsupported-container", "bucket_count": 0, "peaks": []}
    if container_profile.get("audio_format") != 1 or container_profile.get("bits_per_sample") != 16:
        return {"status": "unsupported-pcm-format", "bucket_count": 0, "peaks": []}
    blob = read_prefix(path, 256 * 1024)
    data_offset = blob.find(b"data")
    if data_offset < 0 or data_offset + 8 > len(blob):
        return {"status": "data-chunk-not-found", "bucket_count": 0, "peaks": []}
    data_size = int.from_bytes(blob[data_offset + 4 : data_offset + 8], "little", signed=False)
    pcm = blob[data_offset + 8 : min(len(blob), data_offset + 8 + data_size)]
    sample_count = len(pcm) // 2
    if sample_count == 0:
        return {"status": "empty-pcm-sample", "bucket_count": 0, "peaks": []}
    samples = [int.from_bytes(pcm[index : index + 2], "little", signed=True) for index in range(0, len(pcm) - 1, 2)]
    bucket_size = max(1, len(samples) // bucket_count)
    peaks: list[dict[str, object]] = []
    for bucket_index, start in enumerate(range(0, len(samples), bucket_size)):
        if len(peaks) >= bucket_count:
            break
        bucket = samples[start : start + bucket_size]
        if not bucket:
            continue
        peak = max(abs(value) for value in bucket)
        peaks.append(
            {
                "bucket": bucket_index,
                "sample_start": start,
                "sample_end": start + len(bucket) - 1,
                "peak": peak,
                "normalized_peak": round(peak / 32768, 6),
            }
        )
    return {
        "status": "pcm16-peak-preview",
        "bucket_count": len(peaks),
        "sample_count_scanned": len(samples),
        "data_bytes_scanned": len(pcm),
        "peaks": peaks,
        "validation_status": "triage-preview-unvalidated",
    }


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
    details["media_trusted_diffs"] = missing_media_trusted_diffs()
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
    details["image_gallery_manifest"] = build_image_gallery_manifest(details=details, source_path=resolved)
    details["image_gallery_manifest_hash"] = details["image_gallery_manifest"]["manifest_hash"]
    details["core_accuracy_gates"] = media_core_accuracy_gates(details=details, source_path=resolved)
    details["commercial_uplift_evidence"] = media_image_commercial_uplift_evidence(details=details, source_path=resolved)
    return ArtifactRecord(
        provider=MediaImageProvider.name,
        artifact_type=artifact_type,
        path=str(resolved),
        supported=True,
        details=details,
    )


def find_transcript_sidecars(path: Path) -> list[dict[str, object]]:
    candidates: list[Path] = []
    for suffix in (".srt", ".vtt", ".txt", ".transcript.txt"):
        candidates.append(path.with_suffix(path.suffix + suffix))
        candidates.append(path.with_suffix(suffix))
    sidecars: list[dict[str, object]] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        sidecars.append(
            {
                "path": str(candidate.resolve()),
                "source_sha256": compute_hashes(path).get("sha256", ""),
                "sidecar_hashes": compute_hashes(candidate),
                "format": candidate.suffix.lower().lstrip("."),
                "size": candidate.stat().st_size,
                "contains_hangul": contains_hangul(text),
                "preview": text[:500],
                "cue_count": len(parse_transcript_cues(text)),
                "cue_samples": parse_transcript_cues(text)[:10],
                "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                "validation_status": "sidecar-linked-unvalidated",
            }
        )
    return sidecars


TRANSCRIPT_TIME_RE = re.compile(
    r"(?P<start>\d{1,2}:\d{2}(?::\d{2})?[\.,]\d{3})\s*-->\s*(?P<end>\d{1,2}:\d{2}(?::\d{2})?[\.,]\d{3})"
)


def parse_transcript_cues(text: str) -> list[dict[str, str]]:
    cues: list[dict[str, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = TRANSCRIPT_TIME_RE.search(line)
        if not match:
            continue
        cue_lines: list[str] = []
        for candidate in lines[index + 1 : index + 5]:
            if not candidate.strip():
                break
            if TRANSCRIPT_TIME_RE.search(candidate):
                break
            cue_lines.append(candidate.strip())
        cues.append(
            {
                "start": match.group("start").replace(",", "."),
                "end": match.group("end").replace(",", "."),
                "text": " ".join(cue_lines)[:500],
            }
        )
    return cues


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


def build_image_gallery_manifest(*, details: Mapping[str, object], source_path: Path) -> dict[str, object]:
    hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
    thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), Mapping) else {}
    classification = details.get("visual_classification") if isinstance(details.get("visual_classification"), Mapping) else {}
    row_core = {
        "source_path": str(source_path),
        "entry_name": str(details.get("entry_name") or source_path.name),
        "source_format": str(details.get("source_format") or source_path.suffix.lower().lstrip(".")),
        "source_size": details.get("source_size"),
        "decoded": bool(details.get("decoded")),
        "width": details.get("width"),
        "height": details.get("height"),
        "channel_count": details.get("channel_count"),
        "sha256": str(hashes.get("sha256") or ""),
        "perceptual_hash": str(details.get("perceptual_hash") or ""),
        "similarity_bucket": str(details.get("similarity_bucket") or ""),
        "thumbnail_sha256": str(thumbnail.get("sha256") or ""),
        "classification_label": str(classification.get("label") or ""),
        "classification_status": str(classification.get("validation_status") or ""),
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "image-gallery-source-manifest-v1",
        "item_number": 56,
        "commercial_gap_ids": ["#56"],
        "path": str(source_path),
        "source_viewer_locator": {
            "viewer": "source-image-gallery",
            "path": str(source_path),
            "similarity_bucket": row_core["similarity_bucket"],
            "open_action": "open-image-gallery-at-anchor",
        },
        "image_row": row_core,
        "image_row_hash": stable_payload_sha256(row_core),
        "tag_suggestions": image_tag_suggestions(details),
        "report_selection_hint": "Verify source hash, thumbnail consistency, and context before report inclusion.",
        "blockers": [
            "trusted-image-gallery-manifest-diff-required-before-court-use",
            "persistent-gallery-tags-not-implemented",
            "ml-similarity-and-sensitive-media-classifier-not-validated",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


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
    trusted_diffs = details.get("media_trusted_diffs") if isinstance(details.get("media_trusted_diffs"), Mapping) else {}
    for number in (56, 58, 59):
        diff = trusted_diffs.get(str(number)) if isinstance(trusted_diffs.get(str(number)), Mapping) else {}
        evidence_refs.append(f"trusted_diff_{number}_status:{diff.get('status', 'missing')}")

    item56: list[str] = []
    if details.get("hashes") and (details.get("width") is not None or details.get("decoded") is not None):
        item56.append("image metadata and source hashes")
    if details.get("thumbnail_preview") or details.get("decoded") is not None:
        item56.append("thumbnail or preview metadata")
    if details.get("similarity_bucket"):
        item56.append("perceptual similarity bucket")
    if details.get("gallery_review_mode"):
        item56.append("tag/report selection hints")
    gallery_manifest = details.get("image_gallery_manifest") if isinstance(details.get("image_gallery_manifest"), Mapping) else {}
    if gallery_manifest.get("manifest_hash"):
        item56.append("image gallery source manifest")
    if gallery_manifest.get("image_row_hash"):
        item56.append("image gallery row hash")
    if not MEDIA_NATIVE_CAPABILITIES["deepfake_detection"]:
        item56.append("visual-classifier limitation warning")
    if trusted_media_diff_passed(trusted_diffs, 56):
        item56.append(MEDIA_TRUSTED_DIFF_CHECKS[56])

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
    if trusted_media_diff_passed(trusted_diffs, 58):
        item58.append(MEDIA_TRUSTED_DIFF_CHECKS[58])

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
    if trusted_media_diff_passed(trusted_diffs, 59):
        item59.append(MEDIA_TRUSTED_DIFF_CHECKS[59])

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
    trusted_diffs = details.get("media_trusted_diffs") if isinstance(details.get("media_trusted_diffs"), Mapping) else {}
    gallery_manifest = details.get("image_gallery_manifest") if isinstance(details.get("image_gallery_manifest"), Mapping) else {}
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [56, 58, 59],
        "implementation_track": "image-gallery-ocr-review-gates",
        "source_refs": [
            f"source_path:{source_path}",
            f"source_sha256:{details.get('hashes', {}).get('sha256', '') if isinstance(details.get('hashes'), Mapping) else ''}",
            f"image_gallery_manifest_hash:{gallery_manifest.get('manifest_hash', '')}",
            f"ocr_sidecar:{ocr_sidecar.get('source_path', '')}",
            f"translation_sidecar:{translation_sidecar.get('source_path', '')}",
        ],
        "reportability_decision": media_image_reportability_decision(
            failed_by_item={
                "#56": [
                    "dedicated-gallery-grid",
                    "persistent-tags",
                    "ml-visual-similarity",
                    "deepfake-classifier-validation",
                    *([] if trusted_media_diff_passed(trusted_diffs, 56) else [MEDIA_TRUSTED_DIFF_BLOCKERS[56]]),
                ],
                "#58": [
                    "native-ocr-engine-execution",
                    "engine-retry-logs",
                    "case-db-ocr-job-persistence",
                    *([] if trusted_media_diff_passed(trusted_diffs, 58) else [MEDIA_TRUSTED_DIFF_BLOCKERS[58]]),
                ],
                "#59": [
                    "built-in-korean-ocr-execution",
                    "machine-translation-worker",
                    "confidence-calibration-corpus",
                    *([] if trusted_media_diff_passed(trusted_diffs, 59) else [MEDIA_TRUSTED_DIFF_BLOCKERS[59]]),
                ],
            },
            ocr_sidecar=ocr_sidecar,
            translation_sidecar=translation_sidecar,
        ),
        "passed_validation_check_ids_by_item": passed_by_item,
        "failed_validation_check_ids_by_item": {
            "#56": [
                "dedicated-gallery-grid",
                "persistent-tags",
                "ml-visual-similarity",
                "deepfake-classifier-validation",
                *([] if trusted_media_diff_passed(trusted_diffs, 56) else [MEDIA_TRUSTED_DIFF_BLOCKERS[56]]),
            ],
            "#58": [
                "native-ocr-engine-execution",
                "engine-retry-logs",
                "case-db-ocr-job-persistence",
                *([] if trusted_media_diff_passed(trusted_diffs, 58) else [MEDIA_TRUSTED_DIFF_BLOCKERS[58]]),
            ],
            "#59": [
                "built-in-korean-ocr-execution",
                "machine-translation-worker",
                "confidence-calibration-corpus",
                *([] if trusted_media_diff_passed(trusted_diffs, 59) else [MEDIA_TRUSTED_DIFF_BLOCKERS[59]]),
            ],
        },
        "trusted_diffs": dict(trusted_diffs) if trusted_diffs else missing_media_trusted_diffs(),
        "commercial_blockers": list(MEDIA_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "source_size": int(details.get("source_size") or 0),
            "thumbnail_inline_available": bool(
                isinstance(details.get("thumbnail_preview"), Mapping) and details["thumbnail_preview"].get("available")
            ),
            "perceptual_hash_present": bool(details.get("perceptual_hash")),
            "similarity_bucket_present": bool(details.get("similarity_bucket")),
            "image_gallery_manifest_present": bool(gallery_manifest.get("manifest_hash")),
            "image_gallery_manifest_hash": str(gallery_manifest.get("manifest_hash") or ""),
            "image_gallery_row_hash": str(gallery_manifest.get("image_row_hash") or ""),
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


def missing_media_trusted_diffs() -> dict[str, dict[str, object]]:
    return {
        str(number): {
            "status": "missing",
            "blocker_id": blocker,
            "required_tools": sorted(MEDIA_TRUSTED_TOOLS),
        }
        for number, blocker in MEDIA_TRUSTED_DIFF_BLOCKERS.items()
    }


def trusted_media_diff_passed(trusted_diffs: Mapping[str, object], number: int) -> bool:
    diff = trusted_diffs.get(str(number)) if isinstance(trusted_diffs.get(str(number)), Mapping) else {}
    return diff.get("status") == "pass"


def build_media_trusted_diff(
    number: int,
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = MEDIA_TRUSTED_DIFF_BLOCKERS.get(number, "media-trusted-diff-required")
    rapid_index = index_media_trusted_rows(number, rapid_rows)
    trusted_index = index_media_trusted_rows(number, trusted_rows)
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index) & set(trusted_index)):
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({"row_key": key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
    recognized = trusted_tool.strip().lower().replace(" ", "") in {item.replace(" ", "").lower() for item in MEDIA_TRUSTED_TOOLS}
    status = "pass" if recognized and rapid_index and trusted_index and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "media-trusted-diff-v1",
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
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-media-output-as-report-grade-finding",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_media_trusted_rows(number: int, rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        path = str(row.get("source_path") or row.get("path") or "")
        key = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16] if path else str(row.get("entry_name") or row.get("name") or "")
        if not key:
            continue
        if number == 56:
            hashes = row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {}
            indexed[key] = {
                "sha256": str(hashes.get("sha256") or row.get("source_sha256") or ""),
                "width": str(row.get("width") or ""),
                "height": str(row.get("height") or ""),
                "perceptual_hash": str(row.get("perceptual_hash") or ""),
                "similarity_bucket": str(row.get("similarity_bucket") or ""),
            }
        elif number == 58:
            indexed[key] = {
                "source_sha256": str(row.get("source_sha256") or row.get("sha256") or ""),
                "sidecar_sha256": str(row.get("sidecar_sha256") or row.get("sha256") or ""),
                "text_sha256": str(row.get("text_sha256") or ""),
                "engine": str(row.get("engine") or ""),
            }
        else:
            indexed[key] = {
                "language_hint": str(row.get("language_hint") or row.get("source_language") or ""),
                "text_sha256": str(row.get("text_sha256") or ""),
                "translation_sha256": str(row.get("translation_sha256") or row.get("sha256") or ""),
                "review_status": str(row.get("review_status") or row.get("validation_status") or ""),
            }
    return indexed


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
