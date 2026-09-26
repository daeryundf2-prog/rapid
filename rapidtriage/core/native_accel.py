"""Native acceleration bridge for RapidTriage (R4-1).

Resolution order for :func:`scan_evtx`:

1. ``rapidcore_native`` — the PyO3 extension built from
   ``engines/rust/crates/rapidcore`` (fastest, in-process).
2. ``rapid-worker`` — the workspace Rust binary invoked with
   ``evtx-scan`` (bounded subprocess).
3. Pure-Python scanner — always available, ~20-40x slower than PyO3 but
   still streaming/bounded.

The scan output is a structural index only: chunk offsets, record offsets,
record ids, FILETIME timestamps, and allocation status. It does not decode
BinXML payloads — full record decoding stays in the existing Python provider
(or rapid-worker's richer mode).
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

EVTX_FILE_SIGNATURE = b"ElfFile\x00"
EVTX_CHUNK_SIGNATURE = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"**\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
RECORD_HEADER_SIZE = 24
MAX_RECORD_SIZE = 16 * 1024 * 1024

_NATIVE_DIR = Path(__file__).resolve().parent.parent / "native"
_WORKSPACE_WORKER = (
    Path(__file__).resolve().parents[2] / "engines" / "rust" / "target" / "release" / "rapid-worker"
)


def _load_extension():
    if str(_NATIVE_DIR) not in sys.path:
        sys.path.insert(0, str(_NATIVE_DIR))
    try:
        import rapidcore_native  # type: ignore

        return rapidcore_native
    except ImportError:
        return None


_EXTENSION = _load_extension()


def engine() -> str:
    """Return the active acceleration engine name."""
    if _EXTENSION is not None:
        return "pyo3-rapidcore"
    if _worker_binary() is not None:
        return "rapid-worker-subprocess"
    return "python-fallback"


def available() -> bool:
    return engine() != "python-fallback"


def _worker_binary() -> Path | None:
    for suffix in ("", ".exe"):
        candidate = _WORKSPACE_WORKER.with_suffix(suffix) if suffix else _WORKSPACE_WORKER
        if candidate.exists():
            return candidate
    found = shutil.which("rapid-worker")
    return Path(found) if found else None


def _read_u32(blob: bytes, offset: int) -> int:
    if offset + 4 > len(blob):
        return 0
    return struct.unpack_from("<I", blob, offset)[0]


def _read_u64(blob: bytes, offset: int) -> int:
    if offset + 8 > len(blob):
        return 0
    return struct.unpack_from("<Q", blob, offset)[0]


def _scan_evtx_python(path: Path, max_records: int) -> dict[str, Any]:
    """Streaming pure-Python scanner mirroring rapidcore::evtx::scan_evtx."""
    with open(path, "rb") as handle:
        header = handle.read(FILE_HEADER_SIZE)
        file_header = {
            "signature_valid": header[0:8] == EVTX_FILE_SIGNATURE,
            "major_version": struct.unpack_from("<H", header, 40)[0] if len(header) > 41 else 0,
            "minor_version": struct.unpack_from("<H", header, 38)[0] if len(header) > 39 else 0,
            "next_record_identifier": _read_u64(header, 24),
        }
        result: dict[str, Any] = {
            "file_header": file_header,
            "chunks": [],
            "records": [],
            "truncated": False,
        }
        chunk_index = 0
        absolute_offset = FILE_HEADER_SIZE
        while True:
            blob = handle.read(CHUNK_SIZE)
            if not blob:
                break
            if blob[0:8] == EVTX_CHUNK_SIGNATURE:
                chunk = {
                    "offset": absolute_offset,
                    "index": chunk_index,
                    "first_record_number": _read_u64(blob, 8),
                    "last_record_number": _read_u64(blob, 16),
                    "first_record_id": _read_u64(blob, 24),
                    "last_record_id": _read_u64(blob, 32),
                    "last_record_offset": _read_u32(blob, 40),
                    "free_space_offset": _read_u32(blob, 44),
                }
                result["chunks"].append(chunk)
                for record in _scan_records_in_chunk(blob, chunk, max_records - len(result["records"])):
                    result["records"].append(record)
                if len(result["records"]) >= max_records:
                    result["truncated"] = True
                    break
            if len(blob) < CHUNK_SIZE:
                break
            chunk_index += 1
            absolute_offset += CHUNK_SIZE
        return result


def _scan_records_in_chunk(blob: bytes, chunk: dict[str, Any], budget: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    offset = 0
    while offset + RECORD_HEADER_SIZE <= len(blob) and len(records) < budget:
        if blob[offset : offset + 4] == EVTX_RECORD_MAGIC:
            declared_size = _read_u32(blob, offset + 4)
            if RECORD_HEADER_SIZE <= declared_size <= MAX_RECORD_SIZE:
                end = offset + declared_size
                trailing_size = _read_u32(blob, end - 4) if end <= len(blob) else 0
                free_space = chunk["free_space_offset"]
                records.append(
                    {
                        "offset": chunk["offset"] + offset,
                        "chunk_offset": chunk["offset"],
                        "chunk_index": chunk["index"],
                        "declared_size": declared_size,
                        "trailing_size": trailing_size,
                        "trailing_size_valid": trailing_size == declared_size,
                        "record_id": _read_u64(blob, offset + 8),
                        "timestamp_filetime": _read_u64(blob, offset + 16),
                        "allocation_status": "allocated" if not free_space or offset < free_space else "slack",
                    }
                )
                offset = end if end <= len(blob) else offset + 4
                continue
            offset += 4
            continue
        offset += 1
    return records


def scan_evtx(path: str | Path, max_records: int = 100_000) -> dict[str, Any]:
    """Scan an EVTX file for chunk/record structure.

    Returns a dict with ``file_header``, ``chunks``, ``records``, and
    ``truncated`` keys. Records include ``offset``, ``record_id``,
    ``timestamp_filetime``, ``trailing_size_valid``, and
    ``allocation_status`` (``allocated`` vs ``slack`` for carve candidates).
    """
    path = Path(path)
    if _EXTENSION is not None:
        return json.loads(_EXTENSION.scan_evtx(str(path), max_records))
    worker = _worker_binary()
    if worker is not None:
        completed = subprocess.run(
            [str(worker), "evtx-scan", str(path), "--max-records", str(max_records)],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        return json.loads(completed.stdout)
    return _scan_evtx_python(path, max_records)


def engine_info() -> dict[str, Any]:
    """Describe the active acceleration path for capability reporting."""
    info: dict[str, Any] = {"engine": engine(), "available": available()}
    if _EXTENSION is not None:
        info["version"] = _EXTENSION.engine_version()
        info["path"] = str(_NATIVE_DIR / "rapidcore_native.pyd")
    else:
        worker = _worker_binary()
        if worker is not None:
            info["path"] = str(worker)
    return info
