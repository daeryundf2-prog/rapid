"""Opt-in Rust engine for the native $MFT / $UsnJrnl:$J parsers (rapid-ntfs).

The Python parsers in :mod:`rapidtriage.artifacts.windows.filesystem` stay the
default and the reference. ``RAPIDTRIAGE_NTFS_ENGINE=rust`` swaps in
``rapid_ntfs_native`` (the PyO3 build of ``engines/rust/crates/rapid-ntfs``,
staged by ``scripts/build-rapid-ntfs.py``). Its records carry every field of
the Python records, with the same values and types, except the Python-only
fields named in :data:`PYTHON_ONLY_FIELDS` (docs/architecture/rapid-ntfs.md).

A consumer resolves the engine once per input with :func:`resolve_ntfs_engine`
and names the Python-only fields it reads. An unknown engine value, a consumer
that reads a Python-only field, a missing or stale build and a Rust-side error
all get the Python parser, and :meth:`NtfsEngine.provenance` records which
engine ran and why in the run metadata (nothing for the default engine).
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

ENGINE_ENV = "RAPIDTRIAGE_NTFS_ENGINE"
PYTHON_ENGINE = "python"
RUST_ENGINE = "rust"
ENGINES = (PYTHON_ENGINE, RUST_ENGINE)

# engines/rust/crates/rapid-ntfs version the Python reference is diffed against
# (tests/test_rapid_ntfs_parity.py). A build reporting another version is stale
# and is not used; bump both together whenever either parser changes.
RAPID_NTFS_VERSION = "0.1.0"

# Field groups of the Python records that the Rust records leave out.
PYTHON_ONLY_FIELDS = {
    "hashes": "usa_fixup_application.record_sha256_*, $DATA sha256 / resident_data_hashes, runlist_decode.preview_sha256",
    "attribute_list_resolution": "attribute_list_resolution, validation_checks.attribute_list_*",
    "cursor_window_profile": "USN scan cursor_window_profile",
}

_NATIVE_DIR = Path(__file__).resolve().parent.parent / "native"
_LOG = logging.getLogger(__name__)


@cache
def load_native_ntfs_parser() -> tuple[Any, str]:
    """``(rapid_ntfs_native module, "")`` or ``(None, reason)``."""
    if str(_NATIVE_DIR) not in sys.path:
        sys.path.insert(0, str(_NATIVE_DIR))
    try:
        import rapid_ntfs_native  # type: ignore[import-not-found]
    except ImportError as exc:
        return None, f"rapid_ntfs_native 확장 모듈이 빌드되지 않았습니다(scripts/build-rapid-ntfs.py): {exc}"
    version = str(rapid_ntfs_native.engine_version())
    if version != RAPID_NTFS_VERSION:
        return None, (
            f"rapid_ntfs_native 버전({version})이 Python 파서 기준 버전({RAPID_NTFS_VERSION})과 다릅니다"
            "(scripts/build-rapid-ntfs.py로 다시 빌드 필요)"
        )
    return rapid_ntfs_native, ""


@cache
def _warn_once(message: str) -> None:
    _LOG.warning(message)


@dataclass
class NtfsEngine:
    """The parser engine of one input; see :func:`resolve_ntfs_engine`."""

    requested: str
    active: str
    native_module: Any = None
    notice_ko: str = ""
    native_failed: bool = False
    python_fallback_count: int = 0

    def parse_mft_record_headers(self, blob: bytes) -> list[dict[str, Any]]:
        if self.native_module is not None:
            try:
                return self.native_module.parse_mft_record_headers(blob)
            except Exception as exc:
                self._native_failed("$MFT", exc)
        if self.native_failed:
            self.python_fallback_count += 1
        from ..artifacts.windows.filesystem import parse_mft_record_headers

        return parse_mft_record_headers(blob)

    def parse_usn_record_scan(
        self,
        blob: bytes,
        *,
        record_limit: int,
        start_offset: int = 0,
        max_scan_bytes: int | None = None,
    ) -> dict[str, Any]:
        if self.native_module is not None:
            try:
                return self.native_module.parse_usn_record_scan(
                    blob, record_limit=record_limit, start_offset=start_offset, max_scan_bytes=max_scan_bytes
                )
            except Exception as exc:
                self._native_failed("$UsnJrnl", exc)
        if self.native_failed:
            self.python_fallback_count += 1
        from ..artifacts.windows.filesystem import parse_usn_record_scan

        return parse_usn_record_scan(
            blob, record_limit=record_limit, start_offset=start_offset, max_scan_bytes=max_scan_bytes
        )

    def _native_failed(self, artifact: str, exc: Exception) -> None:
        # A native error ends Rust use for the rest of this input: every later
        # call (counted in python_fallback_count with the failed one) is Python.
        self.native_failed = True
        self.native_module = None
        self.active = PYTHON_ENGINE
        self.notice_ko = f"Rust {artifact} 파서 오류로 이 호출부터 Python 파서로 처리했습니다: {exc!r}"
        _warn_once(f"Rust {artifact} parser failed ({exc!r}); using the Python NTFS parser")

    def provenance(self, artifact: str) -> dict[str, object]:
        """``native_<artifact>_engine*`` run-metadata fields; empty for the default engine."""
        if self.requested == PYTHON_ENGINE and not self.notice_ko:
            return {}
        prefix = f"native_{artifact}_engine"
        fields: dict[str, object] = {prefix: self.active, f"{prefix}_requested": self.requested}
        if self.active == RUST_ENGINE or self.native_failed:
            fields[f"{prefix}_version"] = RAPID_NTFS_VERSION
            fields[f"{prefix}_python_fallback_count"] = self.python_fallback_count
        if self.notice_ko:
            fields[f"{prefix}_notice_ko"] = self.notice_ko
        return fields


def resolve_ntfs_engine(*, reads_python_only: Iterable[str] = ()) -> NtfsEngine:
    """Engine for one input from ``RAPIDTRIAGE_NTFS_ENGINE`` (default ``python``).

    ``reads_python_only`` names the :data:`PYTHON_ONLY_FIELDS` groups the
    consumer reads; any of them keeps the Python parser (Rust records would
    silently lack them).
    """
    needed = sorted(set(reads_python_only))
    unknown = [name for name in needed if name not in PYTHON_ONLY_FIELDS]
    if unknown:
        raise ValueError(f"unknown Python-only NTFS field groups: {unknown}")
    requested = (os.environ.get(ENGINE_ENV) or PYTHON_ENGINE).strip().lower()
    if requested not in ENGINES:
        return NtfsEngine(
            requested,
            PYTHON_ENGINE,
            notice_ko=f"알 수 없는 NTFS 엔진 값({requested})이라 Python 파서로 처리했습니다(python|rust).",
        )
    if requested == PYTHON_ENGINE:
        return NtfsEngine(requested, PYTHON_ENGINE)
    if needed:
        return NtfsEngine(
            requested,
            PYTHON_ENGINE,
            notice_ko=f"Rust 파서 레코드에 없는 필드({', '.join(needed)})를 읽는 처리라 Python 파서로 처리했습니다.",
        )
    module, reason = load_native_ntfs_parser()
    if module is None:
        _warn_once(reason)
        return NtfsEngine(
            requested, PYTHON_ENGINE, notice_ko=f"Rust NTFS 파서를 쓸 수 없어 Python 파서로 처리했습니다: {reason}."
        )
    return NtfsEngine(requested, RUST_ENGINE, native_module=module)
