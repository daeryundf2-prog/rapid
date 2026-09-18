from __future__ import annotations

import datetime as dt
import hashlib
import time
from collections.abc import Iterable
from pathlib import Path

from .docs import write_result
from .e01 import (
    build_e01_segment_set_profile,
    discover_e01_segments,
    ewf_segment_number,
    is_e01_path,
    stable_manifest_sha256,
)

E01_STREAMING_HASH_VERSION = "e01-streaming-full-hash-v1"
E01_STREAMING_HASH_CHECKPOINT_VERSION = "e01-streaming-hash-checkpoint-v1"
DEFAULT_E01_HASH_CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_E01_HASH_ALGORITHMS = ("sha256", "sha1", "md5")


class E01StreamingHashError(ValueError):
    """Raised when E01 streaming hash input is invalid."""


def run_e01_streaming_hash(
    *,
    source_path: Path,
    output_dir: Path,
    algorithms: Iterable[str] = DEFAULT_E01_HASH_ALGORITHMS,
    chunk_size: int = DEFAULT_E01_HASH_CHUNK_SIZE,
    checkpoint_interval_bytes: int = 128 * 1024 * 1024,
    overwrite: bool = False,
) -> dict[str, object]:
    source_path = source_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise E01StreamingHashError(f"E01 hash output directory is not empty: {output_dir}")
    if not source_path.is_file():
        raise E01StreamingHashError(f"source image not found: {source_path}")
    if chunk_size <= 0:
        raise E01StreamingHashError("chunk_size must be greater than zero")
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_algorithms = tuple(dict.fromkeys(str(item).lower() for item in algorithms if str(item).strip()))
    if not normalized_algorithms:
        raise E01StreamingHashError("at least one hash algorithm is required")
    try:
        hashers = {name: hashlib.new(name) for name in normalized_algorithms}
    except ValueError as exc:
        raise E01StreamingHashError(str(exc)) from exc

    checkpoint_path = output_dir / "e01-streaming-hash-checkpoint.json"
    json_path = output_dir / "e01-streaming-hash.json"
    markdown_path = output_dir / "e01-streaming-hash.md"
    is_e01 = is_e01_path(source_path)
    segment_profile = build_e01_segment_set_profile(source_path) if is_e01 else {}
    segment_paths = tuple(discover_e01_segments(source_path)) if is_e01 else (source_path,)
    segment_sizes = {path: path.stat().st_size for path in segment_paths}
    segment_set_size = sum(segment_sizes.values())
    stat = source_path.stat()
    started = time.perf_counter()
    bytes_hashed = 0
    checkpoint_count = 0
    next_checkpoint = max(chunk_size, checkpoint_interval_bytes)
    segment_rows: list[dict[str, object]] = []
    for segment_index, segment_path in enumerate(segment_paths):
        segment_hashers = {name: hashlib.new(name) for name in normalized_algorithms}
        segment_bytes = 0
        with segment_path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
                for segment_hasher in segment_hashers.values():
                    segment_hasher.update(chunk)
                bytes_hashed += len(chunk)
                segment_bytes += len(chunk)
                if bytes_hashed >= next_checkpoint:
                    checkpoint_count += 1
                    write_e01_hash_checkpoint(
                        checkpoint_path,
                        source_path=source_path,
                        source_size=stat.st_size,
                        bytes_hashed=bytes_hashed,
                        algorithms=normalized_algorithms,
                        checkpoint_count=checkpoint_count,
                        status="running",
                        segment_set_size=segment_set_size,
                        current_segment=str(segment_path),
                        segments_completed=segment_index,
                    )
                    next_checkpoint += max(chunk_size, checkpoint_interval_bytes)
        segment_rows.append(
            {
                "path": str(segment_path),
                "name": segment_path.name,
                "segment_number": ewf_segment_number(segment_path),
                "size_bytes": segment_sizes[segment_path],
                "bytes_hashed": segment_bytes,
                "digests": {name: hasher.hexdigest() for name, hasher in segment_hashers.items()},
            }
        )
    checkpoint_count += 1
    write_e01_hash_checkpoint(
        checkpoint_path,
        source_path=source_path,
        source_size=stat.st_size,
        bytes_hashed=bytes_hashed,
        algorithms=normalized_algorithms,
        checkpoint_count=checkpoint_count,
        status="complete",
        segment_set_size=segment_set_size,
        current_segment=str(segment_paths[-1]),
        segments_completed=len(segment_paths),
    )
    duration = time.perf_counter() - started
    digest_rows = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    payload_core: dict[str, object] = {
        "command": "e01-streaming-hash",
        "profile_version": E01_STREAMING_HASH_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {
            "path": str(source_path),
            "name": source_path.name,
            "size_bytes": stat.st_size,
            "supported_e01_extension": is_e01,
            "mtime_ns": stat.st_mtime_ns,
        },
        "segment_set_profile": segment_profile,
        "hash_scope": {
            "profile_version": "hash-scope-v1",
            "scope": "ewf-container-segment-bytes" if is_e01 else "file-bytes",
            "claims_decoded_media_hash": False,
            "claims_acquisition_media_hash": False,
            "segment_count": len(segment_paths),
            "coverage": "all-discovered-segments" if len(segment_paths) > 1 else "single-file",
            "aggregate_definition": (
                "digests cover every discovered segment's container bytes concatenated in "
                "discovered segment order"
            ),
            "note": (
                "EWF container bytes include acquisition metadata, checksums, and compression "
                "blocks; these digests do not equal the decoded acquisition-media hash recorded "
                "by the acquisition tool or verified by ewfverify."
            )
            if is_e01
            else (
                "Digests cover the selected file's bytes as stored; they do not decode or verify "
                "any embedded acquisition-media hash."
            ),
        },
        "algorithms": list(normalized_algorithms),
        "digests": digest_rows,
        "segment_digests": segment_rows,
        "segment_set_size_bytes": segment_set_size,
        "bytes_hashed": bytes_hashed,
        "duration_seconds": round(duration, 6),
        "throughput_mb_s": round((bytes_hashed / (1024 * 1024)) / duration, 3) if duration else None,
        "checkpoint": {
            "path": str(checkpoint_path),
            "checkpoint_count": checkpoint_count,
            "checkpoint_interval_bytes": checkpoint_interval_bytes,
            "status": "complete",
        },
        "reportability_decision": {
            "decision": "container-segment-set-hash-computed",
            "allowed_use": "container-file integrity evidence for the on-disk segment set",
            "not_acquisition_media_hash": True,
            "must_compare_against": ["acquisition log hash", "ewfverify transcript", "Sleuth Kit img_cat hash when available"],
        },
        "background_job_ready": True,
        "outputs": {"json": str(json_path), "markdown": str(markdown_path), "checkpoint": str(checkpoint_path)},
    }
    payload = {**payload_core, "manifest_sha256": stable_manifest_sha256(payload_core)}
    write_result(payload, json_path)
    markdown_path.write_text(render_e01_streaming_hash_markdown(payload), encoding="utf-8")
    return payload


def write_e01_hash_checkpoint(
    checkpoint_path: Path,
    *,
    source_path: Path,
    source_size: int,
    bytes_hashed: int,
    algorithms: Iterable[str],
    checkpoint_count: int,
    status: str,
    segment_set_size: int | None = None,
    current_segment: str = "",
    segments_completed: int = 0,
) -> None:
    progress_base = segment_set_size if segment_set_size else source_size
    checkpoint_core = {
        "profile_version": E01_STREAMING_HASH_CHECKPOINT_VERSION,
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_path": str(source_path),
        "source_size_bytes": source_size,
        "segment_set_size_bytes": segment_set_size if segment_set_size is not None else source_size,
        "current_segment": current_segment,
        "segments_completed": segments_completed,
        "bytes_hashed": bytes_hashed,
        "percent_complete": round((bytes_hashed / progress_base) * 100, 6) if progress_base else 0,
        "algorithms": list(algorithms),
        "checkpoint_count": checkpoint_count,
        "status": status,
        "resume_policy": "hash state is not serialized; interrupted jobs restart reading source but preserve last progress evidence",
    }
    payload = {**checkpoint_core, "checkpoint_hash": stable_manifest_sha256(checkpoint_core)}
    write_result(payload, checkpoint_path)


def render_e01_streaming_hash_markdown(payload: dict[str, object]) -> str:
    digests = payload.get("digests") if isinstance(payload.get("digests"), dict) else {}
    scope = payload.get("hash_scope") if isinstance(payload.get("hash_scope"), dict) else {}
    segment_rows = payload.get("segment_digests") if isinstance(payload.get("segment_digests"), list) else []
    lines = [
        "# E01 Streaming Full Hash",
        "",
        f"- Source: `{payload['source']['path']}`",
        f"- Size bytes: `{payload['source']['size_bytes']}`",
        f"- Bytes hashed: `{payload['bytes_hashed']}`",
        f"- Throughput MB/s: `{payload['throughput_mb_s']}`",
        f"- Manifest SHA256: `{payload['manifest_sha256']}`",
        "",
        "## Hash Scope",
        "",
        f"- Scope: `{scope.get('scope', '')}`",
        f"- Coverage: `{scope.get('coverage', '')}`",
        f"- Claims decoded-media hash: `{scope.get('claims_decoded_media_hash', '')}`",
        f"- Note: {scope.get('note', '')}",
        "",
        "## Aggregate Digests",
    ]
    lines.extend(f"- {name}: `{value}`" for name, value in digests.items())
    lines.append("")
    if segment_rows:
        lines.append("## Segment Digests")
        lines.append("")
        for row in segment_rows:
            if not isinstance(row, dict):
                continue
            lines.append(f"### `{row.get('name', '')}`")
            lines.append("")
            lines.append(f"- Path: `{row.get('path', '')}`")
            lines.append(f"- Size bytes: `{row.get('size_bytes', '')}`")
            row_digests = row.get("digests") if isinstance(row.get("digests"), dict) else {}
            lines.extend(f"- {name}: `{value}`" for name, value in row_digests.items())
            lines.append("")
    return "\n".join(lines)
