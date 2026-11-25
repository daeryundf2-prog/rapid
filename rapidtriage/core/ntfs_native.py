"""Opt-in Rust engine for the native $MFT / $UsnJrnl:$J parsers.

``RAPIDTRIAGE_NTFS_ENGINE=rust`` routes :func:`parse_mft_record_headers` and
:func:`parse_usn_record_scan` to ``rapid_ntfs_native`` (the PyO3 build of
``engines/rust/crates/rapid-ntfs``, staged by ``scripts/build-rapid-ntfs.py``).
Anything else, an unset variable, a missing extension or a Rust-side error
keeps the Python parsers in ``rapidtriage.artifacts.windows.filesystem``.

The Rust records carry the fields the NTFS-meta analysis reads; the fields it
leaves out (hashes, ``path_candidates``, attribute-list resolution, the USN
cursor-window profile) are listed in ``docs/architecture/rapid-ntfs.md``.
"""

from __future__ import annotations

import logging
import os
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

ENGINE_ENV = "RAPIDTRIAGE_NTFS_ENGINE"
RUST_ENGINE = "rust"
PYTHON_ENGINE = "python"

_NATIVE_DIR = Path(__file__).resolve().parent.parent / "native"
_LOG = logging.getLogger(__name__)


@cache
def load_extension() -> ModuleType | None:
    if str(_NATIVE_DIR) not in sys.path:
        sys.path.insert(0, str(_NATIVE_DIR))
    try:
        import rapid_ntfs_native  # type: ignore[import-not-found]
    except ImportError:
        return None
    return rapid_ntfs_native


def requested_engine() -> str:
    return (os.environ.get(ENGINE_ENV) or PYTHON_ENGINE).strip().lower()


def active_engine() -> str:
    if requested_engine() != RUST_ENGINE:
        return PYTHON_ENGINE
    if load_extension() is None:
        _warn_once("rapid_ntfs_native is not built; using the Python NTFS parser")
        return PYTHON_ENGINE
    return RUST_ENGINE


@cache
def _warn_once(message: str) -> None:
    _LOG.warning(message)


def parse_mft_record_headers(blob: bytes) -> list[dict[str, Any]]:
    from ..artifacts.windows.filesystem import parse_mft_record_headers as python_parser

    if active_engine() == RUST_ENGINE:
        try:
            return load_extension().parse_mft_record_headers(blob)  # type: ignore[union-attr]
        except Exception as exc:
            _warn_once(f"Rust $MFT parser failed ({exc!r}); using the Python NTFS parser")
    return python_parser(blob)


def parse_usn_record_scan(
    blob: bytes,
    *,
    record_limit: int | None = None,
    start_offset: int = 0,
    max_scan_bytes: int | None = None,
) -> dict[str, Any]:
    from ..artifacts.windows.filesystem import USN_RECORD_SCAN_LIMIT
    from ..artifacts.windows.filesystem import parse_usn_record_scan as python_parser

    limit = USN_RECORD_SCAN_LIMIT if record_limit is None else record_limit
    if active_engine() == RUST_ENGINE:
        try:
            return load_extension().parse_usn_record_scan(  # type: ignore[union-attr]
                blob, record_limit=limit, start_offset=start_offset, max_scan_bytes=max_scan_bytes
            )
        except Exception as exc:
            _warn_once(f"Rust $UsnJrnl parser failed ({exc!r}); using the Python NTFS parser")
    return python_parser(blob, record_limit=limit, start_offset=start_offset, max_scan_bytes=max_scan_bytes)
