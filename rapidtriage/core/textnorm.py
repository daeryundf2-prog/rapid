"""Unicode normalization for search matching and indexing.

Evidence text arrives in mixed normalization forms: macOS (HFS+/APFS) file
names and many Mac-authored documents carry NFD text, so Korean syllables are
stored as decomposed Hangul jamo ("진정서" becomes 9 jamo code points) and an
NFC keyword typed on Windows never matches with plain ``str.lower()``.
``str.lower()`` also misses full case folding (``ß``/``ss``, ``İ``).

Only matching and indexing normalize. Provider output values stay as parsed.

* :func:`normalize_search_text` - NFC then full casefold. Apply it to BOTH the
  haystack and the needle of substring / token matching. For ASCII input it is
  identical to ``str.lower()``.
* :func:`normalize_nfc` - NFC only. Used where something else already folds
  case (SQLite FTS5 ``unicode61`` tokenizer, ``re.IGNORECASE``) and where
  casefolding would change meaning (regex patterns: ``\\D`` must not become
  ``\\d``). ``unicode61`` folds case and strips diacritics but does not compose
  Hangul jamo, so NFC on both the inserted text and the MATCH query is what
  makes NFD Korean searchable.
* :func:`locate_normalized` - find a normalized needle in original text and
  return the matching span on the NFC form of that text, for previews.
  Normalization changes string length (NFD -> NFC shrinks, ``ß`` -> ``ss``
  grows), so offsets found in normalized text must not slice the original.
"""

from __future__ import annotations

import functools
import unicodedata

__all__ = [
    "locate_normalized",
    "normalize_nfc",
    "normalize_search_term",
    "normalize_search_text",
]


def normalize_nfc(value: str) -> str:
    """Return ``value`` in NFC (canonical composition); ASCII is returned as-is."""
    if value.isascii():
        return value
    return unicodedata.normalize("NFC", value)


def normalize_search_text(value: str) -> str:
    """Return the canonical caseless form used for search matching.

    ``unicodedata.normalize("NFC", value).casefold()``; equals ``value.lower()``
    for ASCII input.
    """
    if value.isascii():
        return value.lower()
    return unicodedata.normalize("NFC", value).casefold()


@functools.lru_cache(maxsize=8192)
def normalize_search_term(value: str) -> str:
    """Cached :func:`normalize_search_text` for short, repeated needles (rule terms, keywords)."""
    return normalize_search_text(value)


def locate_normalized(text: str, needle: str) -> tuple[str, int, int] | None:
    """Find ``needle`` (any form) in ``text`` under :func:`normalize_search_text`.

    Returns ``(display_text, start, end)`` where ``display_text`` is the NFC
    form of ``text`` (identical to ``text`` when it is already NFC) and
    ``display_text[start:end]`` covers the match, or ``None`` when absent.
    The span is mapped back from casefolded offsets character by character,
    so length-changing folds (``ß`` -> ``ss``) never shift the preview window.
    """
    folded_needle = normalize_search_text(needle)
    if not folded_needle:
        return None
    display = normalize_nfc(text)
    folded = display.lower() if display.isascii() else display.casefold()
    index = folded.find(folded_needle)
    if index < 0:
        return None
    end_folded = index + len(folded_needle)
    if len(folded) == len(display):
        # casefold maps each code point to >= 1 code points, so equal total
        # length means every code point folded to exactly one: offsets agree.
        return display, index, end_folded
    start = -1
    end = len(display)
    consumed = 0
    for position, char in enumerate(display):
        width = len(char.casefold())
        if start < 0 and consumed + width > index:
            start = position
        consumed += width
        if consumed >= end_folded:
            end = position + 1
            break
    return display, max(start, 0), end
