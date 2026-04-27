from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .docs import write_result
from .input_root import InputRoot, resolve_input_root


DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CARVE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 250


class CarvingError(RuntimeError):
    """Raised when bounded carving cannot be completed safely."""


@dataclass(frozen=True)
class CarvingSignature:
    kind: str
    extension: str
    start: bytes
    end: bytes | None
    include_end: bool = True


SIGNATURES: tuple[CarvingSignature, ...] = (
    CarvingSignature("jpeg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9"),
    CarvingSignature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    CarvingSignature("pdf", ".pdf", b"%PDF-", b"%%EOF"),
    CarvingSignature("zip", ".zip", b"PK\x03\x04", None),
)


def run_bounded_carving(
    root: InputRoot | Path,
    output_dir: Path,
    *,
    extract: bool = False,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    max_carve_bytes: int = DEFAULT_MAX_CARVE_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    extensions: Sequence[str] | None = None,
) -> dict[str, object]:
    input_root = resolve_input_root(root)
    source_root = input_root.root_path
    if not source_root.exists():
        raise CarvingError(f"carving root does not exist: {source_root}")
    if max_scan_bytes < 1 or max_carve_bytes < 1 or max_candidates < 1:
        raise CarvingError("carving caps must be positive integers")

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    carved_dir = output_dir / "carved"
    if extract:
        carved_dir.mkdir(parents=True, exist_ok=True)

    allowed_extensions = normalize_extensions(extensions)
    entries: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    scanned_files = 0
    scanned_bytes = 0

    for path in iter_carving_sources(source_root):
        if len(entries) >= max_candidates:
            skipped.append({"path": str(path), "reason": "candidate-cap-reached"})
            break
        try:
            stat_result = path.stat()
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"stat-error:{exc}"})
            continue
        if allowed_extensions and path.suffix.lower() not in allowed_extensions:
            continue
        if stat_result.st_size <= 0:
            continue
        read_limit = min(int(stat_result.st_size), max_scan_bytes)
        try:
            with path.open("rb") as handle:
                data = handle.read(read_limit)
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"read-error:{exc}"})
            continue
        scanned_files += 1
        scanned_bytes += len(data)
        entries.extend(
            carve_buffer(
                data,
                source_path=path,
                output_dir=carved_dir,
                extract=extract,
                max_carve_bytes=max_carve_bytes,
                remaining=max_candidates - len(entries),
            )
        )

    payload = {
        "command": "carve",
        "root": str(source_root),
        "input_kind": input_root.kind,
        "generated_at": dt.datetime.now().isoformat(),
        "output_dir": str(output_dir),
        "safety": {
            "extract": extract,
            "max_scan_bytes_per_file": max_scan_bytes,
            "max_carve_bytes": max_carve_bytes,
            "max_candidates": max_candidates,
            "extensions": sorted(allowed_extensions),
        },
        "summary": {
            "scanned_file_count": scanned_files,
            "scanned_byte_count": scanned_bytes,
            "candidate_count": len(entries),
            "extracted_count": sum(1 for entry in entries if entry.get("extracted_path")),
            "skipped_count": len(skipped),
            "kind_counts": count_kinds(entries),
        },
        "entries": entries,
        "skipped": skipped,
    }
    write_result(payload, output_dir / "rapidtriage-carve.json")
    return payload


def carve_buffer(
    data: bytes,
    *,
    source_path: Path,
    output_dir: Path,
    extract: bool,
    max_carve_bytes: int,
    remaining: int,
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for signature in SIGNATURES:
        start_at = 0
        while remaining > 0:
            offset = data.find(signature.start, start_at)
            if offset < 0:
                break
            carved, end_offset, status = carve_candidate(data, offset, signature, max_carve_bytes=max_carve_bytes)
            digest = hashlib.sha256(carved).hexdigest()
            entry = {
                "source_path": str(source_path),
                "kind": signature.kind,
                "extension": signature.extension,
                "offset": offset,
                "end_offset": end_offset,
                "size": len(carved),
                "sha256": digest,
                "status": status,
                "extracted_path": None,
            }
            if extract:
                output_path = output_dir / f"{source_path.stem}-{offset:012x}-{digest[:12]}{signature.extension}"
                output_path.write_bytes(carved)
                entry["extracted_path"] = str(output_path)
            entries.append(entry)
            remaining -= 1
            start_at = max(offset + 1, end_offset)
    return sorted(entries, key=lambda item: (str(item["source_path"]), int(item["offset"])))


def carve_candidate(
    data: bytes,
    offset: int,
    signature: CarvingSignature,
    *,
    max_carve_bytes: int,
) -> tuple[bytes, int, str]:
    max_end = min(len(data), offset + max_carve_bytes)
    if signature.end is None:
        return data[offset:max_end], max_end, "bounded-header-candidate"

    end_at = data.find(signature.end, offset + len(signature.start), max_end)
    if end_at < 0:
        return data[offset:max_end], max_end, "bounded-no-footer"
    end_offset = end_at + len(signature.end) if signature.include_end else end_at
    return data[offset:end_offset], end_offset, "footer-validated"


def iter_carving_sources(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def normalize_extensions(extensions: Sequence[str] | None) -> set[str]:
    if not extensions:
        return set()
    return {item.lower() if item.startswith(".") else f".{item.lower()}" for item in extensions}


def count_kinds(entries: Sequence[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        kind = str(entry.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts
