"""Opt-in native (Rust) EVTX chunk decoder.

The Python ``EvtxChunkDecoder`` in :mod:`eventlog` stays the default and the
reference. ``rust`` swaps in ``rapidcore_native.EvtxChunkDecoder`` (built from
``engines/rust/crates/rapidcore``, ``src/evtx_binxml.rs``), a port that
returns the same ``decoded`` dicts, error types and messages, so the rows built
from it are identical (``tests/test_evtx_engine_diff.py``).

Selection: the eventlog collector option ``evtx_engine`` (CLI
``--eventlog-evtx-engine``) or, when unset, the ``RAPIDTRIAGE_EVTX_ENGINE``
environment variable; ``python`` when neither is set. A requested ``rust``
engine that cannot load (module not built, stale build) falls back to Python
and the eventlog-file row records why (``native_evtx_engine_notice_ko``).
"""

from __future__ import annotations

import os
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

EVTX_ENGINE_ENV = "RAPIDTRIAGE_EVTX_ENGINE"
EVTX_ENGINE_PYTHON = "python"
EVTX_ENGINE_RUST = "rust"
EVTX_ENGINES = (EVTX_ENGINE_PYTHON, EVTX_ENGINE_RUST)

# Status codes of ``rapidcore_native.EvtxChunkDecoder.decode_record``.
_NATIVE_DECODED = 0
_NATIVE_DECODE_ERROR = 1
_NATIVE_INDEX_ERROR = 2

# Row kernels the Rust engine also runs; a build missing any of them is stale.
NATIVE_ENGINE_FUNCTIONS = (
    "redact_recovery_passwords_in",
    "profile_observe_details",
    "profile_common",
    "profile_strip_level",
    "profile_merge",
    "dump_json_row",
    "EventlogTriageProjector",
)


def validate_evtx_engine(value: str) -> str:
    engine = str(value).strip().lower()
    if engine not in EVTX_ENGINES:
        raise ValueError(f"unsupported evtx_engine: {value} (supported: {', '.join(EVTX_ENGINES)})")
    return engine


def requested_evtx_engine(option: str | None) -> str:
    """Collector option, else ``RAPIDTRIAGE_EVTX_ENGINE``, else ``python`` (raw, lower-cased)."""
    return str(option or os.environ.get(EVTX_ENGINE_ENV) or EVTX_ENGINE_PYTHON).strip().lower()


def load_native_evtx_decoder() -> tuple[Any, str]:
    """``(rapidcore_native module, "")`` or ``(None, reason)``."""
    from rapidtriage.core import native_accel

    from .eventlog import EVTX_NATIVE_DECODER_VERSION

    module = native_accel.extension()
    if module is None:
        return None, "rapidcore_native 확장 모듈이 빌드되지 않았습니다(scripts/build-native-accel.py)"
    required = ("EvtxChunkDecoder", "evtx_decoder_version", *NATIVE_ENGINE_FUNCTIONS)
    if not all(hasattr(module, name) for name in required):
        return None, "rapidcore_native 확장 모듈에 EVTX 엔진 함수가 없습니다(이전 빌드)"
    native_version = str(module.evtx_decoder_version())
    if native_version != EVTX_NATIVE_DECODER_VERSION:
        return None, (
            f"rapidcore_native 디코더 버전({native_version})이 Python 디코더 버전"
            f"({EVTX_NATIVE_DECODER_VERSION})과 다릅니다(다시 빌드 필요)"
        )
    return module, ""


@dataclass(frozen=True)
class EvtxEngineSelection:
    requested: str
    active: str
    native_module: Any = None
    notice_ko: str = ""

    def file_row_fields(self, native_stats: Mapping[str, int]) -> dict[str, object]:
        """eventlog-file provenance; empty for the default Python engine (rows unchanged)."""
        if self.requested == EVTX_ENGINE_PYTHON and not self.notice_ko:
            return {}
        fields: dict[str, object] = {
            "native_evtx_engine": self.active,
            "native_evtx_engine_requested": self.requested,
        }
        if self.native_module is not None:
            fields["native_evtx_engine_python_fallback_chunk_count"] = int(
                native_stats.get("native_decoder_python_fallback_chunk_count", 0)
            )
        if self.notice_ko:
            fields["native_evtx_engine_notice_ko"] = self.notice_ko
        return fields


def resolve_evtx_engine(option: str | None) -> EvtxEngineSelection:
    requested = requested_evtx_engine(option)
    if requested not in EVTX_ENGINES:
        return EvtxEngineSelection(
            requested,
            EVTX_ENGINE_PYTHON,
            notice_ko=f"알 수 없는 EVTX 엔진 값({requested})이라 Python 디코더로 처리했습니다(python|rust).",
        )
    if requested == EVTX_ENGINE_PYTHON:
        return EvtxEngineSelection(requested, EVTX_ENGINE_PYTHON)
    module, reason = load_native_evtx_decoder()
    if module is None:
        return EvtxEngineSelection(
            requested,
            EVTX_ENGINE_PYTHON,
            notice_ko=f"Rust EVTX 디코더를 쓸 수 없어 Python 디코더로 처리했습니다: {reason}.",
        )
    return EvtxEngineSelection(requested, EVTX_ENGINE_RUST, native_module=module)


def native_row_kernels(option: str | None) -> Any:
    """``rapidcore_native`` when the Rust engine is active for ``option``, else ``None``.

    Row writers outside the provider (compaction, JSON rows, profile expansion)
    use it to pick the same engine the eventlog collector resolves.
    """
    return resolve_evtx_engine(option).native_module


class NativeEvtxChunkDecoder:
    """``EvtxChunkDecoder`` interface over ``rapidcore_native.EvtxChunkDecoder``.

    Records the native decoder cannot reproduce exactly (it reports them as
    unsupported: lone-surrogate character references, non-ASCII ANSI strings,
    pathologically deep element trees) switch the rest of the chunk to the
    Python decoder. The records already decoded in this chunk are replayed
    first so its name/template caches, token budget and template-parse count
    are exactly what a Python-only walk would have had.
    """

    __slots__ = ("_chunk", "_decoded", "_native", "_python")

    def __init__(self, module: Any, chunk: bytes, *, render_xml: bool) -> None:
        self._chunk = chunk
        self._native = module.EvtxChunkDecoder(chunk, render_xml)
        self._python: Any = None
        self._decoded: list[tuple[int, int]] = []

    @property
    def template_parse_count(self) -> int:
        return int((self._python or self._native).template_parse_count)

    @property
    def used_python(self) -> bool:
        return self._python is not None

    def decode_record(self, record_offset: int, record_size: int) -> dict[str, object]:
        if self._python is None:
            status, payload = self._native.decode_record(record_offset, record_size)
            if status == _NATIVE_DECODED:
                self._decoded.append((record_offset, record_size))
                return payload
            if status in (_NATIVE_DECODE_ERROR, _NATIVE_INDEX_ERROR):
                self._decoded.append((record_offset, record_size))
                if status == _NATIVE_INDEX_ERROR:
                    raise IndexError(payload)
                from .eventlog import EvtxDecodeError

                raise EvtxDecodeError(payload)
            self._switch_to_python()
        return self._python.decode_record(record_offset, record_size)

    def _switch_to_python(self) -> None:
        from .eventlog import EvtxChunkDecoder, EvtxDecodeError

        python = EvtxChunkDecoder(self._chunk)
        for offset, size in self._decoded:
            try:
                python.decode_record(offset, size)
            except (EvtxDecodeError, IndexError, struct.error, ValueError, RecursionError, UnicodeError):
                continue
        self._python = python
