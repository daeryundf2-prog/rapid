"""Per-run search index ``rapidtriage-search.db`` (plan search-2026-10-13 §3.0).

* :mod:`.schema` -- tables, tokenizer detection, connections;
* :mod:`.build` -- flatten every run output into ``search_doc`` rows (full and
  incremental builds, staleness);
* :mod:`.query` -- the §3.1 query grammar (the server is its only interpreter);
* :mod:`.engine` -- query execution (keyset pages, facets, histogram, budget);
* :mod:`.hashsets` -- hash-set store (``<data dir>/hash-sets/<id>.sqlite``).

The index lives next to the run outputs, is separate from the case DB and can
be deleted and rebuilt at any time.
"""

from __future__ import annotations

from .schema import INDEX_FILE_NAME, INDEX_VERSION, index_path_for

__all__ = ["INDEX_FILE_NAME", "INDEX_VERSION", "index_path_for"]
