"""``viewer_hint`` of ``GET /source-preview`` (r7 L4, console review C-W1).

The console picks its viewer tab from this hint instead of the MIME type: Chromium ``History``,
``Cookies``, ``Login Data`` and ``Web Data`` have no extension, so ``mimetypes`` calls them
``application/octet-stream`` although their first 16 bytes are the SQLite header. The hint says
how the mode was detected (``magic-bytes`` · ``extension``) and, for browser-profile databases, which
table holds the rows of each parsed artifact type (parser hint) so the viewer can open the
``urls`` table at the row's ``source_row_id`` (= rowid; ``urls.id`` / ``visits.id`` are
``INTEGER PRIMARY KEY``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

# Parsed browser artifact type -> candidate source tables (Chromium first, then Firefox names).
BROWSER_ROW_TABLES: Mapping[str, tuple[str, ...]] = {
    "browser-history": ("urls", "moz_places"),
    "browser-visit": ("visits", "moz_historyvisits"),
    "browser-download": ("downloads", "moz_annos"),
    "browser-history-downloads": ("downloads",),
    "browser-search": ("keyword_search_terms",),
    "browser-cookie": ("cookies", "moz_cookies"),
    "browser-autofill": ("autofill", "moz_formhistory"),
    "browser-autofill-address": ("autofill_profiles", "addresses"),
    "browser-credit-card": ("credit_cards",),
    "browser-login": ("logins",),
    "browser-omnibox-shortcut": ("omni_box_shortcuts",),
    "browser-top-site": ("top_sites",),
    "browser-bookmark": ("moz_bookmarks",),
}

# Table names listed in the hint (the preview itself previews at most SQLITE_PREVIEW_TABLE_LIMIT).
SQLITE_HINT_TABLE_LIMIT = 256


def sqlite_viewer_hint(detected_by: str, table_names: Iterable[str]) -> dict[str, object]:
    """``{mode: "sqlite", detected_by, sqlite_tables, row_tables}`` for one SQLite source file."""
    names = [str(name) for name in table_names][:SQLITE_HINT_TABLE_LIMIT]
    present = set(names)
    row_tables: dict[str, str] = {}
    for artifact_type, candidates in BROWSER_ROW_TABLES.items():
        table = next((name for name in candidates if name in present), None)
        if table:
            row_tables[artifact_type] = table
    return {
        "mode": "sqlite",
        "detected_by": detected_by,
        "sqlite_tables": names,
        "row_tables": row_tables,
    }

