from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .docs import write_result
from .input_root import InputRoot, resolve_input_root
from .recovery import (
    CANDIDATE_KIND_CARVED,
    CANDIDATE_KIND_PARTIAL_CORRUPT,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    VALIDATION_PARTIAL,
    VALIDATION_REJECTED,
    VALIDATION_UNVERIFIED,
    VALIDATION_VALIDATED,
    build_recovery_record,
    count_candidate_kinds,
)

DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CARVE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 250

# Source files are scanned in bounded windows so multi-GB inputs do not
# load into memory. The overlap carries incomplete headers across chunk
# boundaries; candidates found in the overlap are emitted once by the
# deferral rule in _scan_source.
SCAN_CHUNK_BYTES = 8 * 1024 * 1024
SCAN_OVERLAP_BYTES = 4096

# Bytes probed at a candidate offset for structural header validation.
HEADER_PROBE_BYTES = 512

CARVE_CHECKPOINT_SCHEMA = "carve-checkpoint-v1"
CARVE_CHECKPOINT_NAME = "rapidtriage-carve.checkpoint.json"

STATUS_FOOTER_VALIDATED = "footer-validated"
STATUS_LENGTH_FIELD = "length-field"
STATUS_LENGTH_FIELD_TRUNCATED = "length-field-truncated"
STATUS_BOUNDED_NO_FOOTER = "bounded-no-footer"
STATUS_BOUNDED_HEADER = "bounded-header-candidate"
STATUS_REJECTED = "false-positive-rejected"


class CarvingError(RuntimeError):
    """Raised when bounded carving cannot be completed safely."""


# Validators receive the first HEADER_PROBE_BYTES bytes at the candidate
# offset and return a rejection reason, or None when the structure is
# consistent enough to keep the candidate. Rejected candidates are still
# emitted as ``false-positive-rejected`` rows so the FP decision is
# auditable instead of silent.
def _validate_jpeg(probe: bytes) -> str | None:
    # FF D8 FF <marker>; marker must be a legal JPEG segment marker.
    if len(probe) < 4:
        return "truncated-jpeg-header"
    marker = probe[3]
    if marker in {0x00, 0x01, 0xD8, 0xD9} or 0xE0 <= marker <= 0xEF or 0xC0 <= marker <= 0xFE:
        return None
    return f"invalid-jpeg-marker:0x{marker:02x}"


def _validate_png(probe: bytes) -> str | None:
    # First chunk must be a 13-byte IHDR.
    if len(probe) < 16:
        return "truncated-png-header"
    if probe[8:16] != b"\x00\x00\x00\x0dIHDR":
        return "missing-png-ihdr-chunk"
    return None


def _validate_pdf(probe: bytes) -> str | None:
    if len(probe) < 8:
        return "truncated-pdf-header"
    tail = probe[5:8]
    if not (tail[0:1].isdigit() and tail[1:2] == b"." and tail[2:3].isdigit()):
        return "invalid-pdf-version-marker"
    return None


def _validate_zip(probe: bytes) -> str | None:
    if len(probe) < 10:
        return "truncated-zip-header"
    method = int.from_bytes(probe[8:10], "little")
    # Registered ZIP methods are small integers; arbitrary data matching
    # 'PK\x03\x04' rarely produces a plausible one.
    if method > 99:
        return f"implausible-zip-method:{method}"
    return None


def _sqlite_page_size(probe: bytes) -> int | None:
    if len(probe) < 32:
        return None
    raw = int.from_bytes(probe[16:18], "big")
    size = 65536 if raw == 1 else raw
    if size < 512 or size > 65536 or size & (size - 1):
        return None
    return size


def _validate_sqlite(probe: bytes) -> str | None:
    if len(probe) < 32:
        return "truncated-sqlite-header"
    if _sqlite_page_size(probe) is None:
        return "invalid-sqlite-page-size"
    # File-format write/read versions are 1 (legacy) or 2 (WAL).
    if probe[18] not in (1, 2) or probe[19] not in (1, 2):
        return "invalid-sqlite-format-version"
    # Byte 20 (reserved space) and 21-23 (payload fractions) have fixed ranges.
    if probe[21] != 64 or probe[22] != 32 or probe[23] != 32:
        return "invalid-sqlite-payload-fractions"
    if int.from_bytes(probe[28:32], "big") < 1:
        return "invalid-sqlite-page-count"
    return None


def _sqlite_size_hint(probe: bytes) -> int | None:
    page_size = _sqlite_page_size(probe)
    if page_size is None:
        return None
    page_count = int.from_bytes(probe[28:32], "big")
    if page_count < 1:
        return None
    declared = page_size * page_count
    # The in-header size is only trustworthy when it does not exceed a
    # plausible bound; keep it as a hint, callers still clamp to caps.
    if declared > 64 * 1024 * 1024 * 1024:
        return None
    return declared


def _validate_gif(probe: bytes) -> str | None:
    if len(probe) < 6:
        return "truncated-gif-header"
    if probe[4:6] not in (b"7a", b"9a"):
        return "invalid-gif-version"
    return None


def _validate_7z(probe: bytes) -> str | None:
    if len(probe) < 8:
        return "truncated-7z-header"
    if probe[6] != 0:
        return "invalid-7z-major-version"
    return None


def _validate_rar(probe: bytes) -> str | None:
    if len(probe) < 8:
        return "truncated-rar-header"
    if probe[6:8] not in (b"\x00\x07", b"\x00\x00", b"\x01\x00"):
        return "invalid-rar-version"
    return None


@dataclass(frozen=True)
class CarvingSignature:
    kind: str
    extension: str
    start: bytes
    end: bytes | None
    include_end: bool = True
    validator: Callable[[bytes], str | None] | None = None
    size_hint: Callable[[bytes], int | None] | None = None


SIGNATURES: tuple[CarvingSignature, ...] = (
    CarvingSignature("jpeg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", validator=_validate_jpeg),
    CarvingSignature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", validator=_validate_png),
    CarvingSignature("pdf", ".pdf", b"%PDF-", b"%%EOF", validator=_validate_pdf),
    CarvingSignature("zip", ".zip", b"PK\x03\x04", None, validator=_validate_zip),
    CarvingSignature(
        "sqlite",
        ".sqlite",
        b"SQLite format 3\x00",
        None,
        validator=_validate_sqlite,
        size_hint=_sqlite_size_hint,
    ),
    CarvingSignature("gif", ".gif", b"GIF8", b"\x3b", validator=_validate_gif),
    CarvingSignature("7z", ".7z", b"7z\xbc\xaf\x27\x1c", None, validator=_validate_7z),
    CarvingSignature("rar", ".rar", b"Rar!\x1a\x07", None, validator=_validate_rar),
)

SIGNATURE_KINDS: tuple[str, ...] = tuple(signature.kind for signature in SIGNATURES)


def run_bounded_carving(
    root: InputRoot | Path,
    output_dir: Path,
    *,
    extract: bool = False,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    max_carve_bytes: int = DEFAULT_MAX_CARVE_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    extensions: Sequence[str] | None = None,
    kinds: Sequence[str] | None = None,
    resume: bool = False,
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
    signatures = _select_signatures(kinds)
    fingerprint = _config_fingerprint(
        extract=extract,
        max_scan_bytes=max_scan_bytes,
        max_carve_bytes=max_carve_bytes,
        max_candidates=max_candidates,
        extensions=allowed_extensions,
        signatures=signatures,
    )

    checkpoint_path = output_dir / CARVE_CHECKPOINT_NAME
    completed_sources: set[str] = set()
    entries: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    scanned_files = 0
    scanned_bytes = 0
    resumed = False
    if resume and checkpoint_path.is_file():
        state = _load_checkpoint(checkpoint_path, fingerprint)
        completed_sources = set(state["completed_sources"])
        entries = list(state["entries"])
        skipped = list(state["skipped"])
        scanned_files = int(state["scanned_files"])
        scanned_bytes = int(state["scanned_bytes"])
        resumed = True

    sources = sorted(iter_carving_sources(source_root), key=lambda p: str(p).lower())
    cap_reached = len(entries) >= max_candidates
    for path in sources:
        if cap_reached:
            break
        source_key = _source_key(path, source_root)
        if source_key in completed_sources:
            continue
        try:
            stat_result = path.stat()
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"stat-error:{exc}"})
            completed_sources.add(source_key)
            continue
        if allowed_extensions and path.suffix.lower() not in allowed_extensions:
            completed_sources.add(source_key)
            continue
        if stat_result.st_size <= 0:
            completed_sources.add(source_key)
            continue
        read_limit = min(int(stat_result.st_size), max_scan_bytes)
        try:
            file_entries, file_scanned = _scan_source(
                path,
                read_limit=read_limit,
                source_root=source_root,
                output_dir=carved_dir,
                extract=extract,
                max_carve_bytes=max_carve_bytes,
                remaining=max_candidates - len(entries),
                signatures=signatures,
            )
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"read-error:{exc}"})
            completed_sources.add(source_key)
            continue
        scanned_files += 1
        scanned_bytes += file_scanned
        entries.extend(file_entries)
        completed_sources.add(source_key)
        cap_reached = len(entries) >= max_candidates
        _write_checkpoint(
            checkpoint_path,
            fingerprint,
            completed_sources=completed_sources,
            entries=entries,
            skipped=skipped,
            scanned_files=scanned_files,
            scanned_bytes=scanned_bytes,
        )

    unprocessed = [
        {"path": str(path), "reason": "candidate-cap-reached"}
        for path in sources
        if cap_reached and _source_key(path, source_root) not in completed_sources
    ]
    skipped.extend(unprocessed)

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
            "signature_kinds": [signature.kind for signature in signatures],
            "scan_chunk_bytes": SCAN_CHUNK_BYTES,
            "scan_overlap_bytes": SCAN_OVERLAP_BYTES,
        },
        "summary": {
            "scanned_file_count": scanned_files,
            "scanned_byte_count": scanned_bytes,
            "candidate_count": len(entries),
            "candidate_kind_counts": count_candidate_kinds(entries),
            "extracted_count": sum(1 for entry in entries if entry.get("extracted_path")),
            "rejected_count": sum(1 for entry in entries if entry.get("status") == STATUS_REJECTED),
            "skipped_count": len(skipped),
            "kind_counts": count_kinds(entries),
            "status_counts": count_statuses(entries),
        },
        "resume": {
            "checkpoint_path": str(checkpoint_path),
            "resumed_from_checkpoint": resumed,
            "completed_source_count": len(completed_sources),
        },
        "entries": entries,
        "skipped": skipped,
    }
    write_result(payload, output_dir / "rapidtriage-carve.json")
    _write_checkpoint(
        checkpoint_path,
        fingerprint,
        completed_sources=completed_sources,
        entries=entries,
        skipped=skipped,
        scanned_files=scanned_files,
        scanned_bytes=scanned_bytes,
        complete=True,
    )
    return payload


def _scan_source(
    path: Path,
    *,
    read_limit: int,
    source_root: Path,
    output_dir: Path,
    extract: bool,
    max_carve_bytes: int,
    remaining: int,
    signatures: Sequence[CarvingSignature],
) -> tuple[list[dict[str, object]], int]:
    """Scan one source in overlapping chunks; returns (entries, bytes_scanned).

    Header matches in the final ``SCAN_OVERLAP_BYTES`` of a window are
    deferred to the next window so headers straddling chunk boundaries
    are not missed. Carving itself seeks to the candidate offset and
    reads a bounded window, so footers may live beyond the scan chunk.
    """
    entries: list[dict[str, object]] = []
    scanned = 0
    tail = b""
    base = 0  # file offset of buffer[0]
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(min(SCAN_CHUNK_BYTES, read_limit - scanned))
            if not chunk:
                break
            scanned += len(chunk)
            eof = scanned >= read_limit
            buffer = tail + chunk
            # Matches starting in the last SCAN_OVERLAP_BYTES are deferred
            # to the next window; they reappear inside the next tail and
            # are emitted then. Matches already emitted sit below the
            # previous emit limit, which equals this window's base.
            emit_limit = base + len(buffer) - (0 if eof else SCAN_OVERLAP_BYTES)
            for signature in signatures:
                start_at = 0
                while True:
                    pos = buffer.find(signature.start, start_at)
                    if pos < 0:
                        break
                    offset = base + pos
                    start_at = pos + 1
                    if offset >= emit_limit:
                        continue
                    if len(entries) >= remaining:
                        break
                    entries.append(
                        _build_candidate_entry(
                            handle,
                            path=path,
                            file_size=read_limit,
                            offset=offset,
                            signature=signature,
                            output_dir=output_dir,
                            extract=extract,
                            max_carve_bytes=max_carve_bytes,
                        )
                    )
            tail = buffer[-SCAN_OVERLAP_BYTES:]
            base = base + len(buffer) - len(tail)
            if eof:
                break
    return entries, scanned


def _build_candidate_entry(
    handle,
    *,
    path: Path,
    file_size: int,
    offset: int,
    signature: CarvingSignature,
    output_dir: Path,
    extract: bool,
    max_carve_bytes: int,
) -> dict[str, object]:
    handle.seek(offset)
    window = handle.read(min(max_carve_bytes, file_size - offset))
    rejection = signature.validator(window[:HEADER_PROBE_BYTES]) if signature.validator else None
    entry: dict[str, object] = {
        "source_path": str(path),
        "kind": signature.kind,
        "extension": signature.extension,
        "offset": offset,
        "extracted_path": None,
    }
    if rejection is not None:
        entry.update(
            {
                "end_offset": offset,
                "size": 0,
                "status": STATUS_REJECTED,
                "rejected_reason": rejection,
                "recovery": carved_recovery_record(
                    STATUS_REJECTED,
                    signature=signature,
                    source_path=path,
                    offset=offset,
                    rejection=rejection,
                ),
            }
        )
        return entry
    carved, end_offset, status, boundary_method = carve_candidate(
        window, 0, signature, max_carve_bytes=max_carve_bytes
    )
    digest = hashlib.sha256(carved).hexdigest()
    entry.update(
        {
            "end_offset": offset + end_offset,
            "size": len(carved),
            "sha256": digest,
            "status": status,
            "confidence": _status_confidence(status),
            "recovery": carved_recovery_record(
                status,
                signature=signature,
                source_path=path,
                offset=offset,
                boundary_method=boundary_method,
            ),
        }
    )
    if extract:
        output_path = output_dir / f"{path.stem}-{offset:012x}-{digest[:12]}{signature.extension}"
        output_path.write_bytes(carved)
        entry["extracted_path"] = str(output_path)
    return entry


def _status_confidence(status: str) -> str:
    if status in (STATUS_FOOTER_VALIDATED, STATUS_LENGTH_FIELD):
        return CONFIDENCE_HIGH
    if status == STATUS_LENGTH_FIELD_TRUNCATED:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def carve_buffer(
    data: bytes,
    *,
    source_path: Path,
    output_dir: Path,
    extract: bool,
    max_carve_bytes: int,
    remaining: int,
    signatures: Sequence[CarvingSignature] | None = None,
) -> list[dict[str, object]]:
    """Carve candidates out of an in-memory buffer.

    Kept for callers that already hold bytes (tests, memory dumps). The
    file-scanning path uses ``_scan_source`` so chunk boundaries are
    handled by overlapping windows instead of whole-file reads.
    """
    entries: list[dict[str, object]] = []
    for signature in signatures or SIGNATURES:
        start_at = 0
        while remaining > 0:
            offset = data.find(signature.start, start_at)
            if offset < 0:
                break
            probe = data[offset : offset + HEADER_PROBE_BYTES]
            rejection = signature.validator(probe) if signature.validator else None
            if rejection is not None:
                entry: dict[str, object] = {
                    "source_path": str(source_path),
                    "kind": signature.kind,
                    "extension": signature.extension,
                    "offset": offset,
                    "end_offset": offset,
                    "size": 0,
                    "status": STATUS_REJECTED,
                    "rejected_reason": rejection,
                    "extracted_path": None,
                    "recovery": carved_recovery_record(
                        STATUS_REJECTED,
                        signature=signature,
                        source_path=source_path,
                        offset=offset,
                        rejection=rejection,
                    ),
                }
            else:
                carved, end_offset, status, boundary_method = carve_candidate(
                    data, offset, signature, max_carve_bytes=max_carve_bytes
                )
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
                    "confidence": _status_confidence(status),
                    "extracted_path": None,
                    "recovery": carved_recovery_record(
                        status,
                        signature=signature,
                        source_path=source_path,
                        offset=offset,
                        boundary_method=boundary_method,
                    ),
                }
                if extract:
                    output_path = output_dir / f"{source_path.stem}-{offset:012x}-{digest[:12]}{signature.extension}"
                    output_path.write_bytes(carved)
                    entry["extracted_path"] = str(output_path)
            entries.append(entry)
            remaining -= 1
            start_at = max(offset + 1, int(entry["end_offset"]))
    return sorted(entries, key=lambda item: (str(item["source_path"]), int(item["offset"])))


def carved_recovery_record(
    status: str,
    *,
    signature: CarvingSignature,
    source_path: Path,
    offset: int,
    boundary_method: str | None = None,
    rejection: str | None = None,
) -> dict[str, object]:
    if status == STATUS_REJECTED:
        return build_recovery_record(
            CANDIDATE_KIND_CARVED,
            confidence=CONFIDENCE_LOW,
            validation_status=VALIDATION_REJECTED,
            deletion_state="unallocated-candidate",
            source_path=str(source_path),
            source_offset=offset,
            boundary_method="signature-header",
            signature_type=signature.kind,
            limitation=f"Header signature matched but structural validation rejected the candidate: {rejection}.",
        )
    if status == STATUS_FOOTER_VALIDATED:
        return build_recovery_record(
            CANDIDATE_KIND_CARVED,
            confidence=CONFIDENCE_HIGH,
            validation_status=VALIDATION_VALIDATED,
            deletion_state="unallocated-candidate",
            source_path=str(source_path),
            source_offset=offset,
            boundary_method=boundary_method or "signature-footer",
            signature_type=signature.kind,
            limitation=(
                "Validated at signature level only; internal structure and "
                "content integrity are not verified."
            ),
        )
    if status == STATUS_LENGTH_FIELD:
        return build_recovery_record(
            CANDIDATE_KIND_CARVED,
            confidence=CONFIDENCE_HIGH,
            validation_status=VALIDATION_VALIDATED,
            deletion_state="unallocated-candidate",
            source_path=str(source_path),
            source_offset=offset,
            boundary_method=boundary_method or "length-field",
            signature_type=signature.kind,
            limitation=(
                "Boundary derived from the format's declared length field; "
                "internal page structure is not verified."
            ),
        )
    if status in (STATUS_BOUNDED_NO_FOOTER, STATUS_LENGTH_FIELD_TRUNCATED):
        return build_recovery_record(
            CANDIDATE_KIND_PARTIAL_CORRUPT,
            confidence=CONFIDENCE_MEDIUM if status == STATUS_LENGTH_FIELD_TRUNCATED else CONFIDENCE_LOW,
            validation_status=VALIDATION_PARTIAL,
            deletion_state="unallocated-candidate",
            source_path=str(source_path),
            source_offset=offset,
            boundary_method=boundary_method or "signature-footer",
            signature_type=signature.kind,
            limitation=(
                "Declared length or footer extends beyond the bounded scan "
                "window; the candidate may be truncated or a false positive."
            ),
        )
    return build_recovery_record(
        CANDIDATE_KIND_CARVED,
        confidence=CONFIDENCE_LOW,
        validation_status=VALIDATION_UNVERIFIED,
        deletion_state="unallocated-candidate",
        source_path=str(source_path),
        source_offset=offset,
        boundary_method=boundary_method or "header-only-bounded",
        signature_type=signature.kind,
        limitation=(
            "No footer or length field bounds this format; the candidate "
            "is bounded only by max_carve_bytes and needs manual validation."
        ),
    )


def carve_candidate(
    data: bytes,
    offset: int,
    signature: CarvingSignature,
    *,
    max_carve_bytes: int,
) -> tuple[bytes, int, str, str]:
    """Return (bytes, end_offset, status, boundary_method)."""
    max_end = min(len(data), offset + max_carve_bytes)
    if signature.size_hint is not None:
        declared = signature.size_hint(data[offset : offset + HEADER_PROBE_BYTES])
        if declared is not None:
            hinted_end = offset + declared
            if hinted_end <= max_end:
                return data[offset:hinted_end], hinted_end, STATUS_LENGTH_FIELD, "length-field"
            return data[offset:max_end], max_end, STATUS_LENGTH_FIELD_TRUNCATED, "length-field"
    if signature.end is None:
        return data[offset:max_end], max_end, STATUS_BOUNDED_HEADER, "header-only-bounded"

    end_at = data.find(signature.end, offset + len(signature.start), max_end)
    if end_at < 0:
        return data[offset:max_end], max_end, STATUS_BOUNDED_NO_FOOTER, "signature-footer"
    end_offset = end_at + len(signature.end) if signature.include_end else end_at
    return data[offset:end_offset], end_offset, STATUS_FOOTER_VALIDATED, "signature-footer"


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


def _select_signatures(kinds: Sequence[str] | None) -> list[CarvingSignature]:
    if not kinds:
        return list(SIGNATURES)
    wanted = {str(kind).strip().lower() for kind in kinds if str(kind or "").strip()}
    unknown = wanted - set(SIGNATURE_KINDS)
    if unknown:
        raise CarvingError(
            f"unknown signature kinds: {', '.join(sorted(unknown))} "
            f"(supported: {', '.join(SIGNATURE_KINDS)})"
        )
    return [signature for signature in SIGNATURES if signature.kind in wanted]


def _source_key(path: Path, source_root: Path) -> str:
    try:
        return str(path.relative_to(source_root))
    except ValueError:
        return str(path)


def _config_fingerprint(
    *,
    extract: bool,
    max_scan_bytes: int,
    max_carve_bytes: int,
    max_candidates: int,
    extensions: set[str],
    signatures: Sequence[CarvingSignature],
) -> str:
    material = json.dumps(
        {
            "extract": bool(extract),
            "max_scan_bytes": max_scan_bytes,
            "max_carve_bytes": max_carve_bytes,
            "max_candidates": max_candidates,
            "extensions": sorted(extensions),
            "signature_kinds": [signature.kind for signature in signatures],
            "scan_chunk_bytes": SCAN_CHUNK_BYTES,
            "scan_overlap_bytes": SCAN_OVERLAP_BYTES,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _load_checkpoint(checkpoint_path: Path, fingerprint: str) -> dict[str, object]:
    try:
        state = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CarvingError(
            f"cannot resume: carve checkpoint is unreadable ({exc}); "
            "delete it or rerun without --resume"
        ) from exc
    if state.get("schema") != CARVE_CHECKPOINT_SCHEMA:
        raise CarvingError(
            "cannot resume: carve checkpoint schema mismatch; "
            "delete it or rerun without --resume"
        )
    if state.get("config_fingerprint") != fingerprint:
        raise CarvingError(
            "cannot resume: carving options changed since the checkpoint was "
            "written; delete it or rerun without --resume"
        )
    return state


def _write_checkpoint(
    checkpoint_path: Path,
    fingerprint: str,
    *,
    completed_sources: set[str],
    entries: Sequence[dict[str, object]],
    skipped: Sequence[dict[str, object]],
    scanned_files: int,
    scanned_bytes: int,
    complete: bool = False,
) -> None:
    state = {
        "schema": CARVE_CHECKPOINT_SCHEMA,
        "config_fingerprint": fingerprint,
        "complete": complete,
        "generated_at": dt.datetime.now().isoformat(),
        "completed_sources": sorted(completed_sources),
        "entries": list(entries),
        "skipped": list(skipped),
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
    }
    tmp_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, checkpoint_path)


def count_kinds(entries: Sequence[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        kind = str(entry.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def count_statuses(entries: Sequence[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts
