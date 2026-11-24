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
"""

from __future__ import annotations

import importlib
import logging
import os
import shutil
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

E01_EXTRACT_ENGINE_ENV = "RAPIDTRIAGE_E01_EXTRACT_ENGINE"
E01_EXTRACT_THREADS_ENV = "RAPIDTRIAGE_E01_EXTRACT_THREADS"
E01_EXTRACT_READER_ENV = "RAPIDTRIAGE_E01_EXTRACT_READER"
E01_EXTRACT_ENGINES = ("python", "rust")
E01_EXTRACT_NATIVE_MODULE = "rapid_extract_native"
# Must equal ABI_VERSION in engines/rust/crates/rapid-extract/src/lib.rs.
E01_EXTRACT_NATIVE_ABI_VERSION = 2
E01_EXTRACT_BUILD_HINT = "python scripts/build-e01-extract-native.py"
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
        _extension = (module, problem)
    return _extension


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
        )
    module, problem = load_extract_extension()
    if module is None:
        return _fallback(
            requested,
            f"Rust E01 추출 엔진({E01_EXTRACT_NATIVE_MODULE})을 사용할 수 없어 Python 엔진으로 처리했습니다"
            f"({problem}). `{E01_EXTRACT_BUILD_HINT}`로 빌드하십시오.",
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
) -> bool:
    """Run the Rust walk into ``stats``; False (``status`` switched to the Python fallback, any
    files it wrote removed, ``stats`` untouched) when the extension fails on this image."""
    module, _problem = load_extract_extension()
    if module is None:
        return False
    before = set(extract_dir.iterdir()) if extract_dir.is_dir() else None

    def progress(snapshot: Mapping[str, int]) -> None:
        if on_progress is not None:
            on_progress({**stats, **snapshot})

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
        )
    except Exception as exc:  # the Rust engine reports every failure as one exception
        _discard_new_entries(extract_dir, before)
        status.update(
            _fallback(
                "rust",
                f"Rust E01 추출 엔진이 이 이미지에서 실패해 Python 엔진으로 다시 처리했습니다({exc}).",
            )
        )
        return False
    stats.update({key: int(value) for key, value in dict(result["stats"]).items()})
    status["media_reader"] = str(result["media_reader"])
    status["python_reads"] = int(result["python_reads"])
    status["rerun_reason"] = result["rerun_reason"]
    status["walk_seconds"] = round(float(result["walk_seconds"]), 3)
    status["copy_seconds"] = round(float(result["copy_seconds"]), 3)
    if on_progress is not None:
        on_progress(stats)
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


def _fallback(requested: str, notice: str) -> dict[str, str]:
    LOGGER.warning(notice)
    return {"requested": requested, "active": "python", "notice_ko": notice}
