"""Local-only product telemetry (P0): whitelisted events, salted ids, metrics from the local log."""

from __future__ import annotations

from .recorder import (
    SESSION_ID,
    activate_for_process,
    disabled_reason,
    is_recording,
    iter_events,
    link_run_case,
    record,
    telemetry_dir,
    write_settings,
)
from .schema import count_bucket, size_bucket

__all__ = [
    "SESSION_ID",
    "activate_for_process",
    "count_bucket",
    "disabled_reason",
    "is_recording",
    "iter_events",
    "link_run_case",
    "record",
    "size_bucket",
    "telemetry_dir",
    "write_settings",
]
