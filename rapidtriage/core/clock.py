"""Wall-clock helpers for output and audit timestamps (R8 T-132).

Every timestamp RapidTriage writes into an output file carries its UTC offset, so a report made
on a UTC server and one made in New York name the same instant. The local time and its offset come
from the same rule as the export audit record (``core.audit.audit_timestamps``, T-029).
Readers keep accepting older outputs whose timestamps have no offset.
"""

from __future__ import annotations

import datetime as dt


def now_local() -> dt.datetime:
    """Now as an aware local datetime (system time zone, with its UTC offset)."""
    return dt.datetime.now(dt.timezone.utc).astimezone()


def now_local_iso() -> str:
    """Now as ISO 8601 local time with its UTC offset, e.g. ``2026-11-12T21:40:00.123456+09:00``."""
    from .audit import audit_timestamps

    return audit_timestamps(dt.datetime.now(dt.timezone.utc))["generated_at"]
