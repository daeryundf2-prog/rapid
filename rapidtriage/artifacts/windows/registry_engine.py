"""Registry hive reader engine selection.

The hive-reading layer (``NativeRegistryHive``) has two interchangeable engines:

- ``python`` (default): the pure-Python reader in ``registry.py``;
- ``rust`` (opt-in): the ``rapid_registry_native`` PyO3 extension built from
  ``engines/rust/crates/rapid-registry`` (``python scripts/build-native-accel.py --crate rapid-registry``).

Select with ``RAPIDTRIAGE_REGISTRY_ENGINE=rust`` or the CLI's ``--registry-engine rust``. Both
engines produce identical rows (``tests/test_registry_rust_differential.py``). When ``rust`` is
requested but the extension is missing or built for another contract, or the value is unknown,
the Python engine is used and a Korean notice is recorded on each ``registry-hive`` row
(``native_registry_engine*`` fields, present only when a non-default engine was requested).
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from pathlib import Path
from types import ModuleType

REGISTRY_ENGINE_ENV = "RAPIDTRIAGE_REGISTRY_ENGINE"
REGISTRY_ENGINES = ("python", "rust")
REGISTRY_NATIVE_MODULE = "rapid_registry_native"
# Must equal ABI_VERSION in engines/rust/crates/rapid-registry/src/lib.rs.
REGISTRY_NATIVE_ABI_VERSION = 1
REGISTRY_NATIVE_BUILD_HINT = "python scripts/build-native-accel.py --crate rapid-registry"
NATIVE_DIR = Path(__file__).resolve().parents[2] / "native"
LOGGER = logging.getLogger(__name__)

_extension: tuple[ModuleType | None, str] | None = None
_logged_notices: set[str] = set()


def load_registry_extension() -> tuple[ModuleType | None, str]:
    """(module, problem): the staged extension when importable and contract-compatible."""
    global _extension
    if _extension is None:
        if str(NATIVE_DIR) not in sys.path:
            sys.path.insert(0, str(NATIVE_DIR))
        try:
            module: ModuleType | None = importlib.import_module(REGISTRY_NATIVE_MODULE)
            problem = ""
        except ImportError as exc:
            module, problem = None, f"import-failed: {exc}"
        if module is not None and getattr(module, "ABI_VERSION", None) != REGISTRY_NATIVE_ABI_VERSION:
            problem = f"abi-mismatch: built {getattr(module, 'ABI_VERSION', None)}, expected {REGISTRY_NATIVE_ABI_VERSION}"
            module = None
        _extension = (module, problem)
    return _extension


def registry_engine_status() -> dict[str, str]:
    """``requested`` / ``active`` engine and the Korean fallback notice (empty when none)."""
    requested = (os.environ.get(REGISTRY_ENGINE_ENV) or "").strip().lower() or "python"
    if requested == "python":
        return {"requested": "python", "active": "python", "notice_ko": ""}
    if requested != "rust":
        notice = (
            f"알 수 없는 레지스트리 엔진 값({REGISTRY_ENGINE_ENV}={requested!r})이어서 Python 엔진으로 처리했습니다"
            f"(사용 가능: {', '.join(REGISTRY_ENGINES)})."
        )
        return _fallback(requested, notice)
    module, problem = load_registry_extension()
    if module is None:
        notice = (
            f"Rust 레지스트리 엔진({REGISTRY_NATIVE_MODULE})을 사용할 수 없어 Python 엔진으로 처리했습니다"
            f"({problem}). `{REGISTRY_NATIVE_BUILD_HINT}`로 빌드하십시오."
        )
        return _fallback(requested, notice)
    return {"requested": "rust", "active": "rust", "notice_ko": ""}


def registry_engine_row_fields(status: dict[str, str]) -> dict[str, str]:
    """Provenance fields for a ``registry-hive`` row; empty for the default Python engine."""
    if status.get("requested", "python") == "python":
        return {}
    return {
        "native_registry_engine": status.get("active", "python"),
        "native_registry_engine_requested": status.get("requested", ""),
        "native_registry_engine_notice_ko": status.get("notice_ko", ""),
    }


def _fallback(requested: str, notice: str) -> dict[str, str]:
    if notice not in _logged_notices:
        _logged_notices.add(notice)
        LOGGER.warning(notice)
    return {"requested": requested, "active": "python", "notice_ko": notice}
