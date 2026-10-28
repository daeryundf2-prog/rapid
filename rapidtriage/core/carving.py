from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import io
import json
import multiprocessing
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent import futures
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path

from . import carving_formats as formats
from .coverage import record_coverage
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
# Recovery mode lifts the scan cap (all unallocated clusters) and raises the candidate cap.
RECOVERY_MAX_CANDIDATES = 100_000
CARVE_PROCS_ENV = "RAPIDTRIAGE_PARSE_PROCS"
COVERAGE_AREA = "carving"

# Source files are scanned in bounded windows so multi-GB inputs do not
# load into memory. The overlap carries incomplete headers across chunk
# boundaries; candidates found in the overlap are emitted once by the
# deferral rule in _scan_source.
SCAN_CHUNK_BYTES = 8 * 1024 * 1024
SCAN_OVERLAP_BYTES = 4096

# Bytes probed at a candidate offset for structural header validation.
HEADER_PROBE_BYTES = 512
# Walker-based signatures first walk this prefix of their carve window; the full window
# (up to max_carve_bytes) is read only when the prefix walk does not reject the candidate.
PREWALK_BYTES = 64 * 1024
# With ``count_rejected=False`` (API) a signature kind whose rejections in one source exceed
# this is not evaluated again in that source (disclosed in the scan ``stats``).
MAX_UNCOUNTED_REJECTIONS_PER_KIND = 2_000
# Rejections that mean "the bytes after this offset are the same unterminated header block":
# the rejected range is claimed so every following header line is not re-parsed (quadratic).
RANGE_CLAIMING_REJECTIONS = frozenset({"eml-header-unterminated"})
# Internal entry key: end of the range an entry claims (stripped before the entry is emitted).
_CLAIM_END = "_claim_end"

CARVE_CHECKPOINT_SCHEMA = "carve-checkpoint-v1"
CARVE_CHECKPOINT_NAME = "rapidtriage-carve.checkpoint.json"

STATUS_FOOTER_VALIDATED = "footer-validated"
STATUS_LENGTH_FIELD = "length-field"
STATUS_LENGTH_FIELD_TRUNCATED = "length-field-truncated"
STATUS_BOUNDED_NO_FOOTER = "bounded-no-footer"
STATUS_BOUNDED_HEADER = "bounded-header-candidate"
STATUS_REJECTED = "false-positive-rejected"
# Boundary found by a text heuristic (eml: first NUL byte / next message separator).
STATUS_TEXT_BOUNDARY = formats.STATUS_TEXT_BOUNDARY


class CarvingCancelled(RuntimeError):
    """The run's cancel request stopped carving (distinct from a carving failure)."""


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
    # R3 (plan r3-os-depth §3.3). ``anchor``: the pattern sits this many bytes after
    # the file start (``ftyp`` at +4). ``probe_bytes``: header bytes the validator
    # sees. ``max_bytes``: the format's own length bound (``max_carve_bytes`` still
    # caps it). ``walker``: carve window -> ``(length, status, boundary method)`` or
    # a rejection reason. ``group``: an accepted candidate claims ``[offset, end)``
    # so later matches of the same group inside it (ZIP members of a docx, MP3
    # frames after an ID3 tag, the ``Received:`` lines of one message) are not
    # separate candidates; ``claims_range=False`` (generic zip) is suppressed by a
    # claim but never claims. ``fallback`` signatures lose ties at the same offset
    # (a docx is not reported as a zip as well).
    anchor: int = 0
    probe_bytes: int = HEADER_PROBE_BYTES
    max_bytes: int | None = None
    walker: Callable[[bytes], tuple[int, str, str] | str] | None = None
    group: str | None = None
    claims_range: bool = True
    fallback: bool = False


GIB = formats.GIB
MIB = formats.MIB
ZIP_CONTAINER_PROBE_BYTES = 256 * 1024

SIGNATURES: tuple[CarvingSignature, ...] = (
    CarvingSignature("jpeg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", validator=_validate_jpeg),
    CarvingSignature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", validator=_validate_png),
    CarvingSignature("pdf", ".pdf", b"%PDF-", b"%%EOF", validator=_validate_pdf),
    CarvingSignature(
        "zip", ".zip", b"PK\x03\x04", None, validator=_validate_zip, group="zip", claims_range=False, fallback=True
    ),
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
    # R3: audio/video, Office/HWP, e-mail, executables, event logs (validators: carving_formats).
    CarvingSignature(
        "wav", ".wav", b"RIFF", None, validator=formats.validate_wav, walker=formats.walk_wav,
        probe_bytes=1024, max_bytes=4 * GIB + 8,
    ),
    CarvingSignature(
        "mp3", ".mp3", b"ID3", None, validator=formats.validate_mp3_id3, walker=formats.walk_mp3_id3,
        max_bytes=512 * MIB, group="mp3",
    ),
    *(
        CarvingSignature(
            "mp3", ".mp3", sync, None, validator=formats.validate_mp3_sync, walker=formats.walk_mp3_sync,
            probe_bytes=4, max_bytes=512 * MIB, group="mp3",
        )
        for sync in (b"\xff\xfb", b"\xff\xfa", b"\xff\xf3", b"\xff\xf2")
    ),
    CarvingSignature(
        "m4a", ".m4a", b"ftyp", None, anchor=4, validator=formats.validate_m4a, walker=formats.walk_bmff,
        max_bytes=4 * GIB, group="bmff",
    ),
    CarvingSignature(
        "mp4", ".mp4", b"ftyp", None, anchor=4, validator=formats.validate_mp4, walker=formats.walk_bmff,
        max_bytes=16 * GIB, group="bmff",
    ),
    *(
        CarvingSignature(
            kind, f".{kind}", b"PK\x03\x04", None, validator=formats.zip_container_validator(kind),
            walker=formats.walk_zip_container(kind), probe_bytes=ZIP_CONTAINER_PROBE_BYTES, max_bytes=2 * GIB,
            group="zip",
        )
        for kind in ("docx", "xlsx", "pptx", "hwpx")
    ),
    CarvingSignature(
        "hwp", ".hwp", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", None, validator=formats.validate_cfb,
        walker=formats.walk_hwp, max_bytes=2 * GIB,
    ),
    *(
        CarvingSignature(
            "eml", ".eml", start, None, validator=formats.validate_eml, walker=formats.walk_eml,
            probe_bytes=formats.EML_HEADER_MAX, max_bytes=64 * MIB, group="eml",
        )
        for start in (b"Return-Path: ", b"Received: from ", b"Delivered-To: ")
    ),
    CarvingSignature(
        "pe", ".exe", b"MZ", None, validator=formats.validate_pe, walker=formats.walk_pe,
        probe_bytes=formats.PE_PROBE_BYTES, max_bytes=2 * GIB,
    ),
    CarvingSignature(
        "evtx", ".evtx", b"ElfFile\x00", None, validator=formats.validate_evtx, walker=formats.walk_evtx,
        probe_bytes=formats.EVTX_HEADER_BLOCK, max_bytes=4 * GIB,
    ),
)

# Several patterns may share a kind (mp3: ID3 + four frame syncs; eml: three header starts).
SIGNATURE_KINDS: tuple[str, ...] = tuple(dict.fromkeys(signature.kind for signature in SIGNATURES))

# Where a carved candidate of each signature kind belongs in the evidence tree (plan
# r3-os-depth §3.3 "복구됨(카빙)" family nodes): (artifact kind, artifact_type, Korean family).
CARVED_FAMILIES: dict[str, tuple[str, str, str]] = {
    "jpeg": ("media-image", "media-image", "이미지"),
    "png": ("media-image", "media-image", "이미지"),
    "gif": ("media-image", "media-image", "이미지"),
    "wav": ("media-image", "media-audio", "오디오"),
    "mp3": ("media-image", "media-audio", "오디오"),
    "m4a": ("media-image", "media-audio", "오디오"),
    "mp4": ("media-image", "media-video", "동영상"),
    "pdf": ("generic-documents", "document", "문서"),
    "docx": ("generic-documents", "document", "문서"),
    "xlsx": ("generic-documents", "document", "문서"),
    "pptx": ("generic-documents", "document", "문서"),
    "hwp": ("generic-documents", "document", "문서"),
    "hwpx": ("generic-documents", "document", "문서"),
    "zip": ("generic-documents", "archive-file-inventory", "압축"),
    "7z": ("generic-documents", "archive-file-inventory", "압축"),
    "rar": ("generic-documents", "archive-file-inventory", "압축"),
    "sqlite": ("windows-filesystem", "database-file", "데이터베이스"),
    "eml": ("email", "email-message", "이메일"),
    "pe": ("windows-execution", "executable-file", "실행 파일"),
    "evtx": ("eventlog", "eventlog-file", "이벤트 로그"),
}


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
    scan_capped_bytes = 0
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
        if read_limit < int(stat_result.st_size):
            scan_capped_bytes += int(stat_result.st_size)
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
    if scan_capped_bytes:
        record_coverage(COVERAGE_AREA, "scan_bytes_cap", max_scan_bytes, scan_capped_bytes, "bytes")
    if cap_reached:
        record_coverage(COVERAGE_AREA, "candidate_cap", max_candidates, len(entries), "candidates")

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


class _RunView:
    """Read-only file view of the absolute byte range ``[lo, hi)`` of an image reader.

    Carve windows may run past a scan chunk but never past the end of the unallocated run, so a
    candidate never swallows allocated clusters that follow the run."""

    def __init__(self, reader, lo: int, hi: int) -> None:
        self.reader = reader
        self.lo = lo
        self.hi = hi
        self.pos = lo

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = offset if whence == 0 else self.pos + offset
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, size: int = -1) -> bytes:
        if self.pos < self.lo or self.pos >= self.hi:
            return b""
        want = self.hi - self.pos if size is None or size < 0 else min(size, self.hi - self.pos)
        self.reader.seek(self.pos)
        data = self.reader.read(want)
        self.pos += len(data)
        return data


def plan_unallocated_tasks(
    runs: Sequence[tuple[int, int]],
    *,
    partition_offset: int,
    cluster_size: int,
    scan_limit: int | None,
    chunk_bytes: int = SCAN_CHUNK_BYTES,
) -> tuple[list[tuple[int, int, int, int]], bool]:
    """``(run_lo, run_hi, start, emit_end)`` absolute byte tasks of ``chunk_bytes`` over the
    unallocated cluster ``runs`` (``(first cluster, count)``), at most ``scan_limit`` bytes in all
    (``None`` = all). Returns ``(tasks, truncated)``; ``truncated`` is true when the limit stopped it."""
    tasks: list[tuple[int, int, int, int]] = []
    budget = scan_limit
    for first_cluster, count in runs:
        lo = partition_offset + first_cluster * cluster_size
        hi = lo + count * cluster_size
        start = lo
        while start < hi:
            end = min(start + chunk_bytes, hi)
            if budget is not None:
                if budget <= 0:
                    return tasks, True
                if end - start > budget:
                    end = start + budget
            tasks.append((lo, hi, start, end))
            if budget is not None:
                budget -= end - start
            start = end
    return tasks, False


def _scan_unallocated_batch(
    image: str,
    kinds: tuple[str, ...] | None,
    tasks: Sequence[tuple[int, int, int, int]],
    output_dir: str,
    extract: bool,
    max_carve_bytes: int,
    max_candidates: int,
    partition_offset: int,
    cluster_size: int,
) -> tuple[list[dict[str, object]], str | None]:
    """Scan a batch of chunk tasks (runs in a worker process or thread; opens the image itself).

    Entries keep their ``_CLAIM_END`` so the caller can apply range claims across chunks."""
    from .e01_native import EwfSectorReader, NativeImageError, open_image_media

    signatures = _select_signatures(kinds)
    entries: list[dict[str, object]] = []
    image_path = Path(image)
    try:
        with contextlib.ExitStack() as stack:
            try:
                handle, _kind = stack.enter_context(open_image_media(image_path))
            except NativeImageError as exc:
                return entries, str(exc)
            reader = EwfSectorReader(handle)
            counted = 0  # per batch (not per chunk): the worker never builds more than the run cap
            for run_lo, run_hi, start, emit_end in tasks:
                if counted >= max_candidates:
                    break
                view = _RunView(reader, run_lo, run_hi)
                view.seek(start)
                buffer = view.read(min(emit_end + SCAN_OVERLAP_BYTES, run_hi) - start)
                claims = _Claims()
                probes: dict[tuple[int, int], bytes] = {}
                for offset, _tie, index in _buffer_matches(buffer, start, signatures):
                    if offset < start or offset >= emit_end:
                        continue
                    if counted >= max_candidates:
                        break
                    signature = signatures[index]
                    if claims.covers(signature.group, offset):
                        continue
                    key = (offset, signature.probe_bytes)
                    probe = probes.get(key)
                    if probe is None:
                        local = offset - start
                        if local + signature.probe_bytes <= len(buffer):
                            probe = buffer[local : local + signature.probe_bytes]
                        else:
                            view.seek(offset)
                            probe = view.read(signature.probe_bytes)
                        probes = {key: probe}
                    entry = _build_candidate_entry(
                        view,
                        path=image_path,
                        file_size=run_hi,
                        offset=offset,
                        signature=signature,
                        output_dir=Path(output_dir),
                        extract=extract,
                        max_carve_bytes=max_carve_bytes,
                        probe=probe,
                    )
                    if entry is None:
                        continue
                    claims.claim(signature, entry)
                    entry["cluster"] = (offset - partition_offset) // cluster_size
                    counted += 1
                    entries.append(entry)
    except OSError as exc:
        return entries, f"read-error:{exc}"
    return entries, None


def _carve_workers(workers: int | None) -> int:
    if workers is not None and workers > 0:
        return workers
    raw = os.environ.get(CARVE_PROCS_ENV, "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return max(2, (os.cpu_count() or 2) // 2)


def _discard_result(result: tuple[list[dict[str, object]], str | None]) -> None:
    for entry in result[0]:
        extracted = entry.get("extracted_path")
        if extracted:
            Path(str(extracted)).unlink(missing_ok=True)


def _run_batches(
    batches: Sequence[Sequence[tuple[int, int, int, int]]],
    workers: int,
    common: tuple,
    check_cancel: Callable[[], None] | None,
    consume: Callable[[tuple[list[dict[str, object]], str | None]], bool],
) -> None:
    """Feed batch results to ``consume`` in batch order until it returns True (the run cap).

    Process pool (spawn); threads only when the pool cannot be built or breaks. Worker exceptions
    propagate. A cancel (``check_cancel`` raising) or an early stop drops the queued batches."""
    if workers <= 1 or len(batches) <= 1:
        for batch in batches:
            if check_cancel is not None:
                check_cancel()
            if consume(_scan_unallocated_batch(common[0], common[1], batch, *common[2:])):
                return
        return
    done = 0  # batches already consumed; a pool fallback continues after them
    for pool_factory in (
        lambda: futures.ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("spawn")),
        lambda: futures.ThreadPoolExecutor(max_workers=workers),
    ):
        try:
            pool = pool_factory()
        except (OSError, PermissionError, ImportError, NotImplementedError):
            continue
        pending: list[futures.Future] = []
        taken = 0
        graceful = False
        try:
            try:
                pending = [
                    pool.submit(_scan_unallocated_batch, common[0], common[1], batch, *common[2:])
                    for batch in batches[done:]
                ]
                for item in pending:
                    if check_cancel is not None:
                        check_cancel()
                    result = item.result()
                    taken += 1
                    done += 1
                    if consume(result):
                        graceful = True
                        return
                graceful = True
                return
            except BrokenProcessPool:
                continue
        finally:
            pool.shutdown(wait=graceful, cancel_futures=True)
            for item in pending[taken:]:
                if item.done() and not item.cancelled() and item.exception() is None:
                    _discard_result(item.result())
    raise CarvingError("carving worker pool could not run")


def run_unallocated_carving(
    image: Path,
    output_dir: Path,
    *,
    recovery: bool = False,
    partition_start_sector: int | None = None,
    extract: bool = False,
    max_scan_bytes: int | None = None,
    max_carve_bytes: int = DEFAULT_MAX_CARVE_BYTES,
    max_candidates: int | None = None,
    kinds: Sequence[str] | None = None,
    workers: int | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Carve only the unallocated clusters (``$Bitmap``) of the NTFS volume in ``image``.

    Unallocated runs are split into ``SCAN_CHUNK_BYTES`` chunks (``SCAN_OVERLAP_BYTES`` overlap)
    scanned in parallel (spawn process pool, threads as fallback). ``recovery=True`` scans all
    unallocated clusters and raises the candidate cap to ``RECOVERY_MAX_CANDIDATES``; otherwise the
    default caps apply. Explicit ``max_scan_bytes`` / ``max_candidates`` win. Every cap that
    stops the scan is reported through ``core.coverage.record_coverage``. Entry ``offset`` is the
    absolute image byte offset."""
    from .ntfs_unalloc import NtfsUnallocError, open_unallocated_image

    if max_scan_bytes is None and not recovery:
        max_scan_bytes = DEFAULT_MAX_SCAN_BYTES
    if max_candidates is None:
        max_candidates = RECOVERY_MAX_CANDIDATES if recovery else DEFAULT_MAX_CANDIDATES
    if (max_scan_bytes is not None and max_scan_bytes < 1) or max_carve_bytes < 1 or max_candidates < 1:
        raise CarvingError("carving caps must be positive integers")
    image = Path(image)
    if not image.is_file():
        raise CarvingError(f"carving image does not exist: {image}")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    carved_dir = output_dir / "carved"
    if extract:
        carved_dir.mkdir(parents=True, exist_ok=True)
    kind_tuple = tuple(kinds) if kinds else None
    _select_signatures(kind_tuple)  # unknown kinds fail here, not in a worker

    try:
        with open_unallocated_image(
            image,
            partition_start_sector=partition_start_sector,
            work_dir=output_dir / "unalloc",
            check_cancel=check_cancel,
        ) as source:
            runs = list(source.runs.runs)
            partition_offset = source.partition_offset
            cluster_size = source.cluster_size
            info = {
                "image_media_kind": source.media_kind,
                "bitmap_method": source.bitmap_method,
                "partition_start_sector": source.partition.get("start_sector"),
                "cluster_size": cluster_size,
                "total_clusters": source.total_clusters,
                "unallocated_bytes": source.unallocated_bytes,
                "run_count": len(runs),
                "runs_truncated": source.runs.truncated,
            }
    except NtfsUnallocError as exc:
        raise CarvingError(str(exc)) from exc

    unallocated_bytes = int(info["unallocated_bytes"])  # type: ignore[call-overload]
    if info["runs_truncated"]:
        from .ntfs_unalloc import MAX_RUNS

        record_coverage(COVERAGE_AREA, "unallocated_run_cap", MAX_RUNS, None, "runs")
    tasks, scan_truncated = plan_unallocated_tasks(
        runs, partition_offset=partition_offset, cluster_size=cluster_size, scan_limit=max_scan_bytes,
        chunk_bytes=SCAN_CHUNK_BYTES,
    )
    if scan_truncated:
        record_coverage(COVERAGE_AREA, "scan_bytes_cap", max_scan_bytes, unallocated_bytes, "bytes")
    scanned_bytes = sum(emit_end - start for _lo, _hi, start, emit_end in tasks)

    worker_count = _carve_workers(workers)
    per_batch = max(1, -(-len(tasks) // (worker_count * 2))) if tasks else 1
    batches = [tasks[index : index + per_batch] for index in range(0, len(tasks), per_batch)]
    common = (
        str(image), kind_tuple, str(carved_dir), extract, max_carve_bytes, max_candidates, partition_offset, cluster_size
    )

    # Merge in offset order and apply range claims across chunk boundaries (a docx spanning chunks
    # claims its member entries, the same rule a single-pass scan applies). Merging stops at the
    # run-wide candidate cap and the remaining batches are cancelled.
    by_kind = {signature.kind: signature for signature in reversed(SIGNATURES)}
    claims = _Claims()
    entries: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    found = 0
    batch_capped = False

    def consume(result: tuple[list[dict[str, object]], str | None]) -> bool:
        nonlocal found, batch_capped
        batch_entries, error = result
        if error:
            skipped.append({"path": str(image), "reason": error})
        if len(batch_entries) >= max_candidates:
            batch_capped = True
        for entry in batch_entries:
            signature = by_kind[str(entry["kind"])]
            extracted = entry.get("extracted_path")
            if found >= max_candidates:
                if extracted:
                    Path(str(extracted)).unlink(missing_ok=True)
                continue
            offset = int(entry["offset"])  # type: ignore[arg-type]
            claims.prune(offset)  # offsets ascend: ranges ending before it can no longer cover
            if claims.covers(signature.group, offset):
                if extracted:
                    Path(str(extracted)).unlink(missing_ok=True)
                continue
            claims.claim(signature, entry)
            entry.pop(_CLAIM_END, None)
            found += 1
            entries.append(entry)
        return found >= max_candidates

    if batches:
        _run_batches(batches, worker_count, common, check_cancel, consume)
    candidate_capped = found >= max_candidates or batch_capped
    if candidate_capped:
        record_coverage(COVERAGE_AREA, "candidate_cap", max_candidates, found, "candidates")

    payload: dict[str, object] = {
        "command": "carve",
        "mode": "unallocated",
        "root": str(image),
        "input_kind": "image",
        "generated_at": dt.datetime.now().isoformat(),
        "output_dir": str(output_dir),
        "safety": {
            "extract": extract,
            "recovery": recovery,
            "max_scan_bytes": max_scan_bytes,
            "max_carve_bytes": max_carve_bytes,
            "max_candidates": max_candidates,
            "signature_kinds": [signature.kind for signature in _select_signatures(kind_tuple)],
            "scan_chunk_bytes": SCAN_CHUNK_BYTES,
            "scan_overlap_bytes": SCAN_OVERLAP_BYTES,
            "workers": worker_count,
        },
        "unallocated": {**info, "scanned_bytes": scanned_bytes, "scan_truncated": scan_truncated, "chunk_count": len(tasks)},
        "summary": {
            "scanned_file_count": 1,
            "scanned_byte_count": scanned_bytes,
            "candidate_count": len(entries),
            "candidate_cap_reached": candidate_capped,
            "candidate_kind_counts": count_candidate_kinds(entries),
            "extracted_count": sum(1 for entry in entries if entry.get("extracted_path")),
            "rejected_count": sum(1 for entry in entries if entry.get("status") == STATUS_REJECTED),
            "skipped_count": len(skipped),
            "kind_counts": count_kinds(entries),
            "status_counts": count_statuses(entries),
        },
        "entries": entries,
        "skipped": skipped,
    }
    write_result(payload, output_dir / "rapidtriage-carve.json")
    return payload


def _buffer_matches(buffer: bytes, base: int, signatures: Sequence[CarvingSignature]) -> list[tuple[int, int, int]]:
    """Every header match in ``buffer`` as ``(file offset, tie order, signature index)``, sorted.

    Candidates are processed in offset order (not signature by signature) so a
    range claimed by an accepted container suppresses the matches inside it;
    at one offset specific signatures go before ``fallback`` ones.
    """
    matches: list[tuple[int, int, int]] = []
    for index, signature in enumerate(signatures):
        start_at = 0
        while True:
            pos = buffer.find(signature.start, start_at)
            if pos < 0:
                break
            start_at = pos + 1
            offset = base + pos - signature.anchor
            if offset >= 0:
                matches.append((offset, 1 if signature.fallback else 0, index))
    matches.sort()
    return matches


class _Claims:
    """Accepted ``[start, end)`` ranges per signature group (pruned as the scan moves on)."""

    def __init__(self) -> None:
        self.ranges: dict[str, list[tuple[int, int]]] = {}

    def covers(self, group: str | None, offset: int) -> bool:
        return group is not None and any(start <= offset < end for start, end in self.ranges.get(group, ()))

    def claim(self, signature: CarvingSignature, entry: Mapping[str, object]) -> None:
        """Claim the candidate's verified range: a rejected unterminated header block claims what it
        parsed; a truncated/footerless candidate claims only up to its last verified structure."""
        if signature.group is None or not signature.claims_range:
            return
        explicit = entry.get(_CLAIM_END)
        if entry.get("status") == STATUS_REJECTED and explicit is None:
            return
        start = int(entry["offset"])  # type: ignore[arg-type]
        end = int(explicit) if explicit is not None else int(entry.get("end_offset") or 0)  # type: ignore[arg-type]
        if end > start:
            self.ranges.setdefault(signature.group, []).append((start, end))

    def prune(self, below: int) -> None:
        for group, ranges in self.ranges.items():
            self.ranges[group] = [item for item in ranges if item[1] > below]


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
    check_cancel: Callable[[], None] | None = None,
    on_entry: Callable[[dict[str, object]], None] | None = None,
    count_rejected: bool = True,
    stats: dict[str, object] | None = None,
) -> tuple[list[dict[str, object]], int]:
    """Scan one source in overlapping chunks; returns (entries, bytes_scanned).

    Header matches in the final ``SCAN_OVERLAP_BYTES`` of a window are
    deferred to the next window so headers straddling chunk boundaries
    are not missed. Carving itself seeks to the candidate offset and
    reads a bounded window, so footers may live beyond the scan chunk.
    Matches are handled in offset order; a match inside a range an accepted
    candidate of the same ``group`` claimed is skipped, and a rejection
    whose reason is "not this format at all" (``carving_formats.SILENT_PREFIXES``)
    is dropped without an entry.

    Optional hooks (defaults keep the CLI behaviour): ``check_cancel`` is
    called before every chunk read and every candidate (it raises to stop);
    ``on_entry`` receives each entry as soon as it is built instead of the
    returned list collecting it (so a cancelled scan keeps what it emitted);
    ``count_rejected=False`` stops ``false-positive-rejected`` entries from
    counting toward ``remaining``; a signature kind with more than
    :data:`MAX_UNCOUNTED_REJECTIONS_PER_KIND` rejections in the source is then
    no longer evaluated there (``stats["rejection_capped_kinds"]``).
    """
    entries: list[dict[str, object]] = []
    rejections: dict[str, int] = {}
    capped_kinds: set[str] = set()
    counted = 0
    scanned = 0
    tail = b""
    base = 0  # file offset of buffer[0]
    claims = _Claims()
    with path.open("rb") as handle:
        while True:
            if check_cancel is not None:
                check_cancel()
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
            probes: dict[tuple[int, int], bytes] = {}
            for offset, _tie, index in _buffer_matches(buffer, base, signatures):
                signature = signatures[index]
                # An anchored pattern (``ftyp`` at +4) whose file start lies before
                # this window was handled by the previous one.
                if offset >= emit_limit or offset < base:
                    continue
                if counted >= remaining:
                    break
                if claims.covers(signature.group, offset) or signature.kind in capped_kinds:
                    continue
                if check_cancel is not None:
                    check_cancel()
                # The probe comes from the buffer when it fits (no extra read);
                # matches at one offset share the same probe object.
                key = (offset, signature.probe_bytes)
                probe = probes.get(key)
                if probe is None:
                    local = offset - base
                    if local >= 0 and local + signature.probe_bytes <= len(buffer):
                        probe = buffer[local : local + signature.probe_bytes]
                    else:
                        handle_position = handle.tell()
                        try:
                            handle.seek(offset)
                            probe = handle.read(min(signature.probe_bytes, max(0, read_limit - offset)))
                        finally:
                            handle.seek(handle_position)
                    probes = {key: probe}
                # Building a candidate seeks to its offset and reads its window;
                # the scan resumes from the chunk position afterwards (without
                # this, the next chunk read continued after the carve window).
                position = handle.tell()
                try:
                    entry = _build_candidate_entry(
                        handle,
                        path=path,
                        file_size=read_limit,
                        offset=offset,
                        signature=signature,
                        output_dir=output_dir,
                        extract=extract,
                        max_carve_bytes=max_carve_bytes,
                        probe=probe,
                    )
                finally:
                    handle.seek(position)
                if entry is None:
                    continue  # silently not this format
                claims.claim(signature, entry)
                entry.pop(_CLAIM_END, None)
                if count_rejected or entry.get("status") != STATUS_REJECTED:
                    counted += 1
                else:
                    rejections[signature.kind] = rejections.get(signature.kind, 0) + 1
                    if rejections[signature.kind] >= MAX_UNCOUNTED_REJECTIONS_PER_KIND:
                        capped_kinds.add(signature.kind)
                if on_entry is not None:
                    on_entry(entry)
                else:
                    entries.append(entry)
            tail = buffer[-SCAN_OVERLAP_BYTES:]
            base = base + len(buffer) - len(tail)
            claims.prune(base - SCAN_OVERLAP_BYTES)
            if eof:
                break
    if stats is not None and capped_kinds:
        stats.setdefault("rejection_capped_kinds", {})
        capped = stats["rejection_capped_kinds"]
        if isinstance(capped, dict):
            for kind in sorted(capped_kinds):
                capped[kind] = int(capped.get(kind, 0)) + 1
    return entries, scanned


def _rejected_entry(
    path: Path, offset: int, signature: CarvingSignature, rejection: str
) -> dict[str, object]:
    return {
        "source_path": str(path),
        "kind": signature.kind,
        "extension": signature.extension,
        "offset": offset,
        "extracted_path": None,
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


def carved_family(kind: str) -> dict[str, object]:
    """``recovery_method`` + the evidence-tree family of a carved candidate (row fields)."""
    family = CARVED_FAMILIES.get(kind)
    fields: dict[str, object] = {"recovery_method": "carved"}
    if family is not None:
        fields.update({"family_kind": family[0], "family_artifact_type": family[1], "family_label": family[2]})
    return fields


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
    probe: bytes | None = None,
) -> dict[str, object] | None:
    """One candidate entry, or ``None`` when the validator says "not this format" (silent)."""
    limit = max_carve_bytes if signature.max_bytes is None else min(max_carve_bytes, signature.max_bytes)
    window_size = min(limit, file_size - offset)
    # Validate on the header probe first: a rejected candidate never reads its
    # (up to max_carve_bytes) carve window.
    if probe is None:
        handle.seek(offset)
        probe = handle.read(min(signature.probe_bytes, file_size - offset))
    probe = probe[: max(0, min(len(probe), file_size - offset))]
    rejection = _safe_call(signature.validator, probe) if signature.validator else None
    if rejection is not None:
        if rejection.startswith("truncated-") and offset + len(probe) >= file_size:
            return None  # a header cut by the end of the file is not a false positive (silent)
        entry = None if formats.is_silent(rejection) else _rejected_entry(path, offset, signature, rejection)
        if entry is not None and rejection in RANGE_CLAIMING_REJECTIONS:
            entry[_CLAIM_END] = offset + len(probe)
        return entry
    if signature.walker is not None and window_size > PREWALK_BYTES:
        # Pre-walk a small prefix: an MP3 frame sync or a corrupt container is rejected
        # without reading its whole (up to max_carve_bytes) window.
        handle.seek(offset)
        early = _safe_call(signature.walker, handle.read(PREWALK_BYTES))
        if isinstance(early, str) and not formats.prefix_dependent(early):
            return None if formats.is_silent(early) else _rejected_entry(path, offset, signature, early)
    handle.seek(offset)
    window = handle.read(window_size)
    boundary = _safe_call(signature.walker, window) if signature.walker is not None else None
    if isinstance(boundary, str):
        return None if formats.is_silent(boundary) else _rejected_entry(path, offset, signature, boundary)
    claim_end: int | None = None
    if boundary is not None:
        length, status, boundary_method = boundary[:3]
        carved, end_offset = window[: max(0, length)], max(0, length)
        if len(boundary) > 3:
            claim_end = offset + int(boundary[3])  # type: ignore[misc]
        elif status == STATUS_LENGTH_FIELD_TRUNCATED and length >= len(window):
            claim_end = offset  # a declared length past the window verifies nothing: claim nothing
    else:
        carved, end_offset, status, boundary_method = carve_candidate(
            window, 0, signature, max_carve_bytes=window_size
        )
    digest = hashlib.sha256(carved).hexdigest()
    entry: dict[str, object] = {
        "source_path": str(path),
        "kind": signature.kind,
        "extension": signature.extension,
        "offset": offset,
        "extracted_path": None,
        "end_offset": offset + end_offset,
        "size": len(carved),
        "sha256": digest,
        "status": status,
        "confidence": _status_confidence(status),
        "boundary_method": boundary_method,
        "recovery": carved_recovery_record(
            status,
            signature=signature,
            source_path=path,
            offset=offset,
            boundary_method=boundary_method,
        ),
    }
    if claim_end is not None:
        entry[_CLAIM_END] = claim_end
    if extract:
        output_path = output_dir / f"{path.stem}-{offset:012x}-{digest[:12]}{signature.extension}"
        output_path.write_bytes(carved)
        entry["extracted_path"] = str(output_path)
    return entry


def _safe_call(function: Callable[[bytes], object], data: bytes):
    """A validator/walker result; running out of memory on a hostile structure is a rejection."""
    try:
        return function(data)
    except MemoryError:
        return f"{getattr(function, '__name__', 'walker')}-memory-exhausted"


def _status_confidence(status: str) -> str:
    if status in (STATUS_FOOTER_VALIDATED, STATUS_LENGTH_FIELD):
        return CONFIDENCE_HIGH
    if status in (STATUS_LENGTH_FIELD_TRUNCATED, STATUS_TEXT_BOUNDARY):
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
    handled by overlapping windows instead of whole-file reads. Same
    validators, walkers, range claims and silent drops as ``_scan_source``.
    """
    selected = list(signatures or SIGNATURES)
    entries: list[dict[str, object]] = []
    claims = _Claims()
    handle = io.BytesIO(data)
    # Same rules as ``_scan_source`` (range claims only; no per-signature resume point), so
    # the in-memory and the chunked file scan report the same candidates.
    for offset, _tie, index in _buffer_matches(data, 0, selected):
        if remaining <= 0:
            break
        signature = selected[index]
        if claims.covers(signature.group, offset):
            continue
        entry = _build_candidate_entry(
            handle,
            path=source_path,
            file_size=len(data),
            offset=offset,
            signature=signature,
            output_dir=output_dir,
            extract=extract,
            max_carve_bytes=max_carve_bytes,
        )
        if entry is None:
            continue
        claims.claim(signature, entry)
        entry.pop(_CLAIM_END, None)
        entries.append(entry)
        remaining -= 1
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
    if status == STATUS_TEXT_BOUNDARY:
        return build_recovery_record(
            CANDIDATE_KIND_CARVED,
            confidence=CONFIDENCE_MEDIUM,
            validation_status=VALIDATION_PARTIAL,
            deletion_state="unallocated-candidate",
            source_path=str(source_path),
            source_offset=offset,
            boundary_method=boundary_method or "text-boundary",
            signature_type=signature.kind,
            limitation=(
                "Header block validated; the end is the first NUL byte or the next "
                "message separator, so the body may be cut short or include trailing text."
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
