from __future__ import annotations

from typing import Any

__all__ = ["build_manifest", "run_docs_search", "run_extract"]


def build_manifest(*args: Any, **kwargs: Any) -> Any:
    from .docs import build_manifest as impl

    return impl(*args, **kwargs)


def run_docs_search(*args: Any, **kwargs: Any) -> Any:
    from .docs import run_docs_search as impl

    return impl(*args, **kwargs)


def run_extract(*args: Any, **kwargs: Any) -> Any:
    from .extract import run_extract as impl

    return impl(*args, **kwargs)
