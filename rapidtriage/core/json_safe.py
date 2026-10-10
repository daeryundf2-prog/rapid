"""JSON fallback encoder shared by every RapidTriage output writer.

Provider outputs occasionally carry raw parser values (ESE ``bytes`` columns,
``datetime`` objects, ``Path`` instances, ``set`` collections). Writing them
with ``json.dump`` and no ``default=`` handler raises ``TypeError`` at the very
end of a stage and loses the whole stage result. ``json_default`` converts the
known lossless cases and still raises ``TypeError`` for anything else so
genuinely unexpected objects are not silently hidden.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from pathlib import PurePath


def json_default(value: object) -> object:
    """``json.dump(default=...)`` hook for forensic outputs.

    ``bytes``/``bytearray``/``memoryview`` are recorded losslessly as
    ``{"__type__": "bytes", "hex": ..., "length": ...}`` so the original
    value can be reconstructed from the JSON output.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"__type__": "bytes", "hex": raw.hex(), "length": len(raw)}
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, Decimal):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
