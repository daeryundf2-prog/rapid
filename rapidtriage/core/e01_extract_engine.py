"""Engine selection for the native E01 -> NTFS file extraction walk.

``extract_e01_native`` recovers files with one of two engines that produce the same tree and
the same stats:

- ``python`` (default): ``_recover_priority_paths`` / ``_walk_ntfs_dir`` /
  ``_sweep_deleted_mft_records`` over dissect.ntfs;
- ``rust`` (opt-in): the ``rapid_extract_native`` PyO3 extension built from
  ``engines/rust/crates/rapid-extract`` (``python scripts/build-e01-extract-native.py``). Python
  still opens the image (pyewf or a raw file) and selects the partition; the extension reads the
  media itself (its own EWF v1 reader with parallel chunk decoding, or the raw file), walks NTFS,
  and copies the files on worker threads, in one call. Reads it cannot serve go through the pyewf
  handle, and any copy that fails makes it redo the whole walk sequentially.

Select with ``RAPIDTRIAGE_E01_EXTRACT_ENGINE=rust``; ``RAPIDTRIAGE_E01_EXTRACT_THREADS`` sets the
copy/decode threads (default: CPU count, at most 8; ``1`` copies during the walk) and
``RAPIDTRIAGE_E01_EXTRACT_READER=python`` keeps every media read on pyewf. Both engines produce identical output
(``tests/test_e01_extract_rust_parity.py``). When ``rust`` is requested but the extension is
missing, built for another contract, or fails on the image, the Python engine runs instead and
the fallback is recorded (``extract_engine`` in the result, a Korean notice in the warnings).
The Rust engine never skips files for the output drive's free-space reserve
(``RAPIDTRIAGE_NATIVE_MIN_FREE_GB``): when the reserve would be reached it stops, and the Python
engine, whose ``ExtractSpaceGuard`` decides what is written, redoes the image.
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import shutil
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any

E01_EXTRACT_ENGINE_ENV = "RAPIDTRIAGE_E01_EXTRACT_ENGINE"
E01_EXTRACT_THREADS_ENV = "RAPIDTRIAGE_E01_EXTRACT_THREADS"
E01_EXTRACT_READER_ENV = "RAPIDTRIAGE_E01_EXTRACT_READER"
E01_EXTRACT_ENGINES = ("python", "rust")
E01_EXTRACT_NATIVE_MODULE = "rapid_extract_native"
# Must equal ABI_VERSION in engines/rust/crates/rapid-extract/src/lib.rs.
E01_EXTRACT_NATIVE_ABI_VERSION = 3
# engines/rust/crates/rapid-extract version this package was checked against
# (tests/test_e01_extract_rust_parity.py). A build reporting another version is stale and refused:
# bump the crate version and this constant together.
E01_EXTRACT_NATIVE_VERSION = "0.1.0"
# Run-metadata field prefix (cf. native_mft_engine* of the rapid-ntfs bridge).
E01_EXTRACT_METADATA_PREFIX = "native_e01_extract_engine"
E01_EXTRACT_BUILD_HINT = "python scripts/build-e01-extract-native.py"
# Error prefix of the extension when the free-space reserve would be reached (extract.rs).
E01_EXTRACT_SPACE_RESERVE_ERROR = "free-space-reserve"
NATIVE_DIR = Path(__file__).resolve().parents[1] / "native"
LOGGER = logging.getLogger(__name__)

_extension: tuple[ModuleType | None, str] | None = None


def load_extract_extension() -> tuple[ModuleType | None, str]:
    """(module, problem): the staged extension when importable and contract-compatible."""
    global _extension
    if _extension is None:
        if str(NATIVE_DIR) not in sys.path:
            sys.path.insert(0, str(NATIVE_DIR))
        try:
            module: ModuleType | None = importlib.import_module(E01_EXTRACT_NATIVE_MODULE)
            problem = ""
        except ImportError as exc:
            module, problem = None, f"import-failed: {exc}"
        if module is not None and getattr(module, "ABI_VERSION", None) != E01_EXTRACT_NATIVE_ABI_VERSION:
            problem = f"abi-mismatch: built {getattr(module, 'ABI_VERSION', None)}, expected {E01_EXTRACT_NATIVE_ABI_VERSION}"
            module = None
        if module is not None:
            version = _engine_version(module)
            if version != E01_EXTRACT_NATIVE_VERSION:
                problem = f"stale-build: built {version}, expected {E01_EXTRACT_NATIVE_VERSION}"
                module = None
        _extension = (module, problem)
    return _extension


def _engine_version(module: ModuleType) -> str | None:
    try:
        return str(module.engine_version())
    except Exception:  # an extension without engine_version() predates the version gate
        return None


def _is_engine_failure(exc: BaseException) -> bool:
    """An error of the extension. pyo3 raises a Rust panic as ``pyo3_runtime.PanicException``, a
    ``BaseException`` that ``except Exception`` lets through (extract.rs also catches panics)."""
    return isinstance(exc, Exception) or type(exc).__name__ == "PanicException"


def extract_engine_metadata(status: Mapping[str, Any]) -> dict[str, Any]:
    """``native_e01_extract_engine*`` run-metadata fields for an ``extract_engine`` status (empty for
    the default Python engine, whose output stays unchanged)."""
    if not status:
        return {}
    prefix = E01_EXTRACT_METADATA_PREFIX
    active = str(status.get("active") or "python")
    return {
        prefix: active,
        f"{prefix}_requested": str(status.get("requested") or "python"),
        f"{prefix}_version": E01_EXTRACT_NATIVE_VERSION if active == "rust" else None,
        f"{prefix}_fallback_reason": str(status.get("fallback_reason") or ""),
        f"{prefix}_notice_ko": str(status.get("notice_ko") or ""),
    }


def e01_extract_engine_status() -> dict[str, str]:
    """``requested`` / ``active`` engine and the Korean fallback notice (empty when none)."""
    requested = (os.environ.get(E01_EXTRACT_ENGINE_ENV) or "").strip().lower() or "python"
    if requested == "python":
        return {"requested": "python", "active": "python", "notice_ko": ""}
    if requested != "rust":
        return _fallback(
            requested,
            f"알 수 없는 E01 추출 엔진 값({E01_EXTRACT_ENGINE_ENV}={requested!r})이어서 Python 엔진으로 처리했습니다"
            f"(사용 가능: {', '.join(E01_EXTRACT_ENGINES)}).",
            f"unknown-engine: {requested}",
        )
    module, problem = load_extract_extension()
    if module is None:
        return _fallback(
            requested,
            f"Rust E01 추출 엔진({E01_EXTRACT_NATIVE_MODULE})을 사용할 수 없어 Python 엔진으로 처리했습니다"
            f"({problem}). `{E01_EXTRACT_BUILD_HINT}`로 빌드하십시오.",
            f"extension-unavailable: {problem}",
        )
    return {"requested": "rust", "active": "rust", "notice_ko": ""}


def e01_extract_threads() -> int:
    raw = (os.environ.get(E01_EXTRACT_THREADS_ENV) or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return max(1, min(os.cpu_count() or 1, 8))


def run_rust_extraction(
    status: dict[str, Any],
    *,
    handle: Any,
    segments: list[Path],
    byte_offset: int,
    size: int,
    extract_dir: Path,
    stats: dict[str, int],
    include_deleted: bool,
    priority_paths: tuple[str, ...],
    on_progress: Callable[[Mapping[str, int]], None] | None,
    free_at_start: int = -1,
    min_free_bytes: int = 0,
    free_space_probe: Callable[[], int] | None = None,
) -> bool:
    """Run the Rust walk into ``stats``; False (``status`` switched to the Python fallback, any
    files it wrote removed, ``stats`` untouched) when the extension fails on this image."""
    module, _problem = load_extract_extension()
    if module is None:
        return False
    before = set(extract_dir.iterdir()) if extract_dir.is_dir() else None

    def notify(view: Mapping[str, int]) -> None:
        # As ``_notify_progress``: progress is advisory, so an observer that raises must not
        # abort the run (here: make the Rust engine fail over to Python).
        if on_progress is not None:
            with contextlib.suppress(Exception):
                on_progress(MappingProxyType(dict(view)))

    def progress(snapshot: Mapping[str, int]) -> None:
        notify({**stats, **snapshot})

    try:
        result = module.extract_tree(
            handle,
            byte_offset,
            size,
            str(extract_dir),
            int(stats["file_limit"]),
            include_deleted,
            list(priority_paths),
            progress,
            segments=[str(path) for path in segments],
            media_size=int(handle.get_media_size()),
            threads=e01_extract_threads(),
            reader="python" if (os.environ.get(E01_EXTRACT_READER_ENV) or "").strip().lower() == "python" else "auto",
            free_at_start=int(free_at_start),
            min_free_bytes=int(min_free_bytes),
            free_space=free_space_probe,
        )
    except BaseException as exc:  # the Rust engine reports every failure as one exception
        if not _is_engine_failure(exc):
            raise  # KeyboardInterrupt / SystemExit are not engine failures
        _discard_new_entries(extract_dir, before)
        if str(exc).startswith(E01_EXTRACT_SPACE_RESERVE_ERROR):
            reason = str(exc)
            notice = (
                "출력 드라이브 여유 공간이 예약치에 가까워 Rust E01 추출 엔진 대신 Python 엔진으로 처리했습니다"
                f"(여유 공간 보호는 Python 엔진이 맡습니다: {exc})."
            )
        else:
            panicked = not isinstance(exc, Exception) or "panicked" in str(exc)
            reason = f"{'panic' if panicked else 'engine-error'}: {type(exc).__name__}: {exc}"
            notice = f"Rust E01 추출 엔진이 이 이미지에서 실패해 Python 엔진으로 다시 처리했습니다({exc})."
        status.update(_fallback("rust", notice, reason))
        return False
    stats.update({key: int(value) for key, value in dict(result["stats"]).items()})
    status["media_reader"] = str(result["media_reader"])
    status["python_reads"] = int(result["python_reads"])
    status["rerun_reason"] = result["rerun_reason"]
    status["walk_seconds"] = round(float(result["walk_seconds"]), 3)
    status["copy_seconds"] = round(float(result["copy_seconds"]), 3)
    notify(stats)
    return True


def _discard_new_entries(extract_dir: Path, before: set[Path] | None) -> None:
    if not extract_dir.exists():
        return
    if before is None:
        shutil.rmtree(extract_dir, ignore_errors=True)
        return
    for entry in set(extract_dir.iterdir()) - before:
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            entry.unlink(missing_ok=True)


def _fallback(requested: str, notice: str, reason: str) -> dict[str, str]:
    LOGGER.warning(notice)
    return {"requested": requested, "active": "python", "notice_ko": notice, "fallback_reason": reason}
