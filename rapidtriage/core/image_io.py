"""Unicode-safe OpenCV image reads.

``cv2.imread`` takes a narrow (ANSI) path on Windows and silently returns
``None`` for paths outside the active code page (e.g. Korean file names), so
those images were skipped. Non-ASCII paths are read as bytes and decoded with
``cv2.imdecode``; ASCII paths keep using ``cv2.imread`` unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def imread_unicode_safe(cv2_module: Any, path: str | Path, flags: int | None = None) -> Any:
    """``cv2.imread(path, flags)`` that also works for non-ASCII paths."""
    text = str(path)
    args = () if flags is None else (flags,)
    if text.isascii() or not hasattr(cv2_module, "imdecode"):
        return cv2_module.imread(text, *args)
    try:
        import numpy as np

        buffer = np.fromfile(text, dtype=np.uint8)
    except (ImportError, OSError, ValueError):
        return None
    if buffer.size == 0:
        return None
    decode_flags = flags if flags is not None else getattr(cv2_module, "IMREAD_COLOR", 1)
    try:
        return cv2_module.imdecode(buffer, decode_flags)
    except Exception:
        return None
