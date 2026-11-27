"""Turn raw values at an event's trigger into the coarse, whitelisted props it records.

The raw value (a search string, an evidence path) is read here and only its
shape leaves: term count, length bucket, script, category, input kind.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .schema import count_bucket

if TYPE_CHECKING:
    from ..search_index.query import ParsedQuery

HASH_FIELDS = frozenset({"md5", "sha1", "sha256", "hash"})
_HEX_HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PHONE = re.compile(r"\+?\d[\d\-\s]{6,}\d")
_SUFFIX_KINDS = {".vhd": "vhd", ".vhdx": "vhd", ".iso": "iso", ".zip": "zip", ".egg": "egg"}


def text_script(texts: Iterable[str]) -> str:
    """``hangul`` | ``latin`` | ``digit`` | ``mixed`` of the letters/digits in ``texts``."""
    seen: set[str] = set()
    for text in texts:
        for char in text:
            if "\uac00" <= char <= "\ud7a3" or "\u3131" <= char <= "\u318e":
                seen.add("hangul")
            elif char.isdigit():
                seen.add("digit")
            elif char.isalpha():
                seen.add("latin")
    if len(seen) == 1:
        return seen.pop()
    if seen == {"latin", "digit"}:
        return "latin"
    return "mixed" if seen else "latin"


def query_shape(parsed: ParsedQuery) -> dict[str, object]:
    """``search_submitted`` props of a parsed search-index query (the query text is not kept)."""
    terms = [term for term, _negated in parsed.terms]
    texts = [term.value.text for term in terms]
    longest = max((len(text) for text in texts), default=0)
    if any(term.value.kind == "regex" for term in terms):
        category = "regex"
    elif any(term.field in HASH_FIELDS or _HEX_HASH.fullmatch(text) for term, text in zip(terms, texts)):
        category = "hash"
    elif any(_EMAIL.fullmatch(text) for text in texts):
        category = "email"
    elif any(_PHONE.fullmatch(text) for text in texts):
        category = "phone"
    else:
        category = "keyword"
    return {
        "term_count": len(terms),
        "term_len_bucket": count_bucket(longest),
        "script": text_script(texts),
        "category": category,
        "scope": "field" if any(term.field != "kw" for term in terms) else "all",
        "from_keyword_pack": False,
    }


def evidence_input_kind(source_type: str, path: Path) -> str:
    """Input kind enum of a registered evidence item (the path is read for its suffix only)."""
    if source_type in {"folder", "e01", "raw"}:
        return source_type
    return _SUFFIX_KINDS.get(path.suffix.lower(), "export")


def crash_component(component: object) -> str:
    """``api`` | ``run`` | ``worker`` of a crash context ``component`` (``other`` otherwise)."""
    text = str(component or "")
    if text.startswith(("web", "api")):
        return "api"
    if text.startswith("run"):
        return "run"
    return "worker" if text.startswith("worker") else "other"
