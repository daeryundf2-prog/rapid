"""Keep the system awake while a run is processing (R8 T-353).

On Windows a run calls ``SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)`` when it
starts, so the machine does not go to sleep in the middle of a long image, and
``SetThreadExecutionState(ES_CONTINUOUS)`` when it ends — completed, failed or cancelled, also
when the run raises. The display may still turn off (no ``ES_DISPLAY_REQUIRED``). The request is
per thread, so it is cleared on the thread that set it. Elsewhere this is a no-op.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Iterator
from contextlib import contextmanager

__all__ = [
    "ES_CONTINUOUS",
    "ES_SYSTEM_REQUIRED",
    "prevent_system_sleep",
]

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


def _set_thread_execution_state(flags: int) -> bool:
    """Call ``SetThreadExecutionState``; False off Windows or when the call is unavailable/fails."""
    if sys.platform != "win32":
        return False
    try:
        function = ctypes.windll.kernel32.SetThreadExecutionState  # type: ignore[attr-defined]
        function.argtypes = [ctypes.c_uint32]
        function.restype = ctypes.c_uint32
        return bool(function(flags))
    except (AttributeError, OSError):
        return False


@contextmanager
def prevent_system_sleep() -> Iterator[bool]:
    """Hold a system-required power request for the ``with`` body; yields whether it was taken."""
    acquired = _set_thread_execution_state(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    try:
        yield acquired
    finally:
        if acquired:
            _set_thread_execution_state(ES_CONTINUOUS)
