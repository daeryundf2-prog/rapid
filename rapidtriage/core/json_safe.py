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
import re
from decimal import Decimal
from pathlib import PurePath

_SURROGATE = re.compile("[\ud800-\udfff]")


def escape_lone_surrogates(value: object) -> tuple[object, int]:
    """``(value, count)`` with every surrogate code point written as its ``\\udXXX`` text.

    Surrogates (e.g. from a ``"\\ud800"`` JSON escape) are not characters and
    UTF-8 output cannot hold them. ``str.encode("utf-8", "backslashreplace")``
    writes each one as the escape that produced it; nothing is dropped.
    Strings, dict keys and values, list and tuple items are visited; ``count``
    is the number of code points escaped, and ``value`` itself is returned
    when there were none.
    """
    if isinstance(value, str):
        if value.isascii():
            return value, 0
        count = len(_SURROGATE.findall(value))
        return (value.encode("utf-8", "backslashreplace").decode("utf-8"), count) if count else (value, 0)
    if isinstance(value, dict):
        total = 0
        items = []
        for key, item in value.items():
            new_key, key_count = escape_lone_surrogates(key)
            new_item, item_count = escape_lone_surrogates(item)
            total += key_count + item_count
            items.append((new_key, new_item))
        return (dict(items), total) if total else (value, 0)
    if isinstance(value, (list, tuple)):
        total = 0
        out = []
        for item in value:
            new_item, item_count = escape_lone_surrogates(item)
            total += item_count
            out.append(new_item)
        return (tuple(out) if isinstance(value, tuple) else out, total) if total else (value, 0)
    return value, 0


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
