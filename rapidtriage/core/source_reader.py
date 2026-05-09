from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .docs import SUPPORTED_DOC_EXTS, extract_text
from .search import SearchError, load_run_summary
from .source_paths import resolve_source_path_in_roots
from .submission import compute_hashes

SOURCE_READ_PROFILE_VERSION = "source-read-v1"
DEFAULT_MAX_TEXT_CHARS = 20_000
DEFAULT_MAX_HEX_BYTES = 1024
MAX_SOURCE_READ_TEXT_CHARS = 2_000_000
MAX_SOURCE_READ_HEX_BYTES = 1_048_576


class SourceReadError(ValueError):
    """Raised when a source file cannot be safely read from a completed run."""


def run_source_read(
    run_summary: Mapping[str, object] | Path,
    raw_path: str,
    *,
    include_hashes: bool = False,
    max_chars: int = DEFAULT_MAX_TEXT_CHARS,
    hex_bytes: int = DEFAULT_MAX_HEX_BYTES,
) -> dict[str, object]:
    summary = load_summary_or_raise(run_summary)
    source = summary_source(summary)
    analysis_root = source_analysis_root(source)
    source_path = resolve_source_read_path(raw_path, analysis_root=analysis_root)

    if not source_path.is_file():
        raise SourceReadError(f"source file not found or not a regular file: {source_path}")
    if not is_relative_to(source_path, analysis_root):
        raise SourceReadError(f"source file is outside the run analysis root: {source_path}")

    stat = source_path.stat()
    max_chars = normalize_limit(max_chars, default=DEFAULT_MAX_TEXT_CHARS, maximum=MAX_SOURCE_READ_TEXT_CHARS)
    hex_bytes = normalize_limit(hex_bytes, default=DEFAULT_MAX_HEX_BYTES, maximum=MAX_SOURCE_READ_HEX_BYTES)
    preview = build_source_read_preview(source_path, max_chars=max_chars, hex_bytes=hex_bytes)
    hashes = compute_hashes(source_path) if include_hashes else {}

    return {
        "command": "source-read",
        "profile_version": SOURCE_READ_PROFILE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary") or ""),
        "source": source,
        "analysis_root": str(analysis_root),
        "path": str(source_path),
        "relative_path": str(source_path.relative_to(analysis_root)),
        "name": source_path.name,
        "extension": source_path.suffix.lower(),
        "size": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
        "hashes": hashes,
        "preview": preview,
        "forensic_read_profile": forensic_read_profile(
            source_path=source_path,
            analysis_root=analysis_root,
            preview=preview,
            hashes=hashes,
            include_hashes=include_hashes,
        ),
        "reportability_decision": {
            "decision": "source-preview-is-review-aid-not-standalone-proof",
            "allowed_use": "analyst-source-verification-and-review",
            "required_before_report": [
                "verify source file hash",
                "record review status and note",
                "cite path plus line/offset/table locator where applicable",
                "preserve original evidence image/container provenance",
            ],
        },
    }


def load_summary_or_raise(run_summary: Mapping[str, object] | Path) -> Mapping[str, object]:
    try:
        return load_run_summary(run_summary)
    except SearchError as exc:
        raise SourceReadError(str(exc)) from exc


def summary_source(summary: Mapping[str, object]) -> Mapping[str, object]:
    source = summary.get("source")
    if not isinstance(source, Mapping):
        raise SourceReadError("run summary does not include source.analysis_root")
    return source


def source_analysis_root(source: Mapping[str, object]) -> Path:
    raw = source.get("analysis_root") or source.get("root")
    if not isinstance(raw, str) or not raw:
        raise SourceReadError("run source does not include analysis_root")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise SourceReadError(f"run analysis root does not exist: {root}")
    return root


def resolve_source_read_path(raw_path: str, *, analysis_root: Path) -> Path:
    if not raw_path.strip():
        raise SourceReadError("--path is required")
    return resolve_source_path_in_roots(raw_path, [analysis_root])


def build_source_read_preview(source_path: Path, *, max_chars: int, hex_bytes: int) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
            return text_preview_payload(text, max_chars=max_chars, strategy="document-text-extract")
        except Exception as exc:
            return {
                "preview_type": "error",
                "strategy": "document-text-extract",
                "message": f"text extraction failed: {exc}",
                "truncated": False,
            }

    if source_path.stat().st_size <= max_chars and not is_probably_binary(source_path):
        try:
            text = source_path.read_text(encoding="utf-8", errors="replace")
            return text_preview_payload(text, max_chars=max_chars, strategy="bounded-plain-text")
        except OSError as exc:
            return {
                "preview_type": "error",
                "strategy": "bounded-plain-text",
                "message": f"text read failed: {exc}",
                "truncated": False,
            }

    return hex_preview_payload(source_path, hex_bytes=hex_bytes)


def text_preview_payload(text: str, *, max_chars: int, strategy: str) -> dict[str, object]:
    preview = text[:max_chars]
    return {
        "preview_type": "text",
        "strategy": strategy,
        "text": preview,
        "text_length": len(text),
        "preview_length": len(preview),
        "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "truncated": len(text) > len(preview),
        "line_count": text.count("\n") + (1 if text else 0),
        "message": "Text preview is available.",
    }


def hex_preview_payload(source_path: Path, *, hex_bytes: int) -> dict[str, object]:
    with source_path.open("rb") as handle:
        blob = handle.read(hex_bytes)
    ascii_preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in blob)
    return {
        "preview_type": "hex",
        "strategy": "bounded-hex",
        "offset": 0,
        "byte_count": len(blob),
        "hex": blob.hex(),
        "ascii": ascii_preview,
        "preview_sha256": hashlib.sha256(blob).hexdigest() if blob else "",
        "truncated": source_path.stat().st_size > len(blob),
        "message": "Binary/large-file hex preview is available.",
    }


def forensic_read_profile(
    *,
    source_path: Path,
    analysis_root: Path,
    preview: Mapping[str, object],
    hashes: Mapping[str, str],
    include_hashes: bool,
) -> dict[str, object]:
    return {
        "profile_version": SOURCE_READ_PROFILE_VERSION,
        "read_mode": "read-only-bounded-preview",
        "source_scope": "completed-run-analysis-root",
        "path_inside_analysis_root": is_relative_to(source_path, analysis_root),
        "preview_type": str(preview.get("preview_type") or ""),
        "hashes_computed": bool(hashes),
        "hash_algorithms": sorted(hashes) if hashes else [],
        "hashes_requested": include_hashes,
        "safe_for_large_case": bool(preview.get("truncated")) or source_path.stat().st_size <= DEFAULT_MAX_TEXT_CHARS,
        "limitations": [
            "Preview may be truncated to keep analysis responsive.",
            "Source preview does not replace original evidence image/container provenance.",
            "Binary preview is a bounded hex sample unless a dedicated parser/viewer exists.",
        ],
    }


def normalize_limit(value: int, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed <= 0:
        parsed = default
    return min(parsed, maximum)


def is_probably_binary(source_path: Path, *, sample_size: int = 4096) -> bool:
    try:
        sample = source_path.read_bytes()[:sample_size]
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.08


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def render_source_read_text(payload: Mapping[str, object]) -> str:
    preview = payload.get("preview") if isinstance(payload.get("preview"), Mapping) else {}
    lines = [
        f"Source: {payload.get('relative_path') or payload.get('path')}",
        f"Type: {preview.get('preview_type')}  Size: {payload.get('size')} bytes",
    ]
    hashes = payload.get("hashes") if isinstance(payload.get("hashes"), Mapping) else {}
    if hashes:
        lines.extend(f"{name.upper()}: {value}" for name, value in sorted(hashes.items()))
    if preview.get("preview_type") == "text":
        lines.append("")
        lines.append(str(preview.get("text") or ""))
    elif preview.get("preview_type") == "hex":
        lines.append("")
        lines.append(str(preview.get("hex") or ""))
        lines.append("")
        lines.append(str(preview.get("ascii") or ""))
    else:
        lines.append(str(preview.get("message") or "No preview available."))
    return "\n".join(lines)
