from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from pathlib import Path
from typing import Iterable

from .docs import write_result
from .e01 import build_e01_segment_set_profile, is_e01_path, stable_manifest_sha256


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
    segment_profile = build_e01_segment_set_profile(source_path) if is_e01_path(source_path) else {}
    stat = source_path.stat()
    started = time.perf_counter()
    bytes_hashed = 0
    checkpoint_count = 0
    next_checkpoint = max(chunk_size, checkpoint_interval_bytes)
    with source_path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
            bytes_hashed += len(chunk)
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
                )
                next_checkpoint += max(chunk_size, checkpoint_interval_bytes)
    checkpoint_count += 1
    write_e01_hash_checkpoint(
        checkpoint_path,
        source_path=source_path,
        source_size=stat.st_size,
        bytes_hashed=bytes_hashed,
        algorithms=normalized_algorithms,
        checkpoint_count=checkpoint_count,
        status="complete",
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
            "supported_e01_extension": is_e01_path(source_path),
            "mtime_ns": stat.st_mtime_ns,
        },
        "segment_set_profile": segment_profile,
        "algorithms": list(normalized_algorithms),
        "digests": digest_rows,
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
            "decision": "full-source-hash-computed",
            "allowed_use": "acquisition/full-image hash evidence",
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
) -> None:
    checkpoint_core = {
        "profile_version": E01_STREAMING_HASH_CHECKPOINT_VERSION,
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_path": str(source_path),
        "source_size_bytes": source_size,
        "bytes_hashed": bytes_hashed,
        "percent_complete": round((bytes_hashed / source_size) * 100, 6) if source_size else 0,
        "algorithms": list(algorithms),
        "checkpoint_count": checkpoint_count,
        "status": status,
        "resume_policy": "hash state is not serialized; interrupted jobs restart reading source but preserve last progress evidence",
    }
    payload = {**checkpoint_core, "checkpoint_hash": stable_manifest_sha256(checkpoint_core)}
    write_result(payload, checkpoint_path)


def render_e01_streaming_hash_markdown(payload: dict[str, object]) -> str:
    digests = payload.get("digests") if isinstance(payload.get("digests"), dict) else {}
    lines = [
        "# E01 Streaming Full Hash",
        "",
        f"- Source: `{payload['source']['path']}`",
        f"- Size bytes: `{payload['source']['size_bytes']}`",
        f"- Bytes hashed: `{payload['bytes_hashed']}`",
        f"- Throughput MB/s: `{payload['throughput_mb_s']}`",
        f"- Manifest SHA256: `{payload['manifest_sha256']}`",
        "",
        "## Digests",
    ]
    lines.extend(f"- {name}: `{value}`" for name, value in digests.items())
    lines.append("")
    return "\n".join(lines)
