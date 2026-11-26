"""Phase messages from inside a provider's ``collect`` (run progress).

A provider's progress is otherwise only its row count, which stands still
while the provider walks a large tree without yielding (``windows-filesystem``
reads the header of every file and buffers its few mismatch rows until the
scan totals are known: close to an hour without a new row on a full volume).
``stream_artifact_collection`` installs a sink for the thread that runs
``collect``; providers call :func:`report_provider_progress` with a short
Korean phase message. Without a sink (CLI, tests) the call does nothing.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterator

ProviderMessageSink = Callable[[str], None]

# Files between two scan messages of a provider's tree walk.
PROVIDER_SCAN_REPORT_EVERY = 2_000

_state = threading.local()


@contextlib.contextmanager
def provider_progress_sink(sink: ProviderMessageSink | None) -> Iterator[None]:
    """Route :func:`report_provider_progress` calls of this thread to ``sink``."""
    previous = getattr(_state, "sink", None)
    _state.sink = sink
    try:
        yield
    finally:
        _state.sink = previous


def report_provider_progress(message: str) -> None:
    sink = getattr(_state, "sink", None)
    if sink is not None:
        sink(message)
