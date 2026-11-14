"""Run pipeline ``persist`` step: build the run-local case DB search index.

The persist step imports the run's outputs into ``<output_dir>/rapidtriage-case.db``
(SQLite FTS5) with ``CaseDatabase.import_run_output`` so unified search can use
the index instead of rescanning every output (see core/search_fts.py). Inputs
are streamed (artifact JSONL rows, timeline events, candidate arrays) and the
documents' text comes from the docs stage's spool, so the step neither holds
outputs in memory nor extracts documents a second time.
"""

from __future__ import annotations

import datetime as dt
import gc
import json
import re
import time
from collections.abc import Iterator, Mapping
from pathlib import Path

from ..case_db import CaseDatabase

CASE_DB_FILE_NAME = "rapidtriage-case.db"
DOCS_TEXT_SPOOL_NAME = "rapidtriage-docs-text.tmp.jsonl"
SEARCH_BACKEND_FTS = "fts"
SEARCH_BACKEND_SCAN = "scan"
_SQLITE_SIDECAR_SUFFIXES = ("", "-wal", "-shm", "-journal")


class DocumentTextSpool:
    """Append-only JSONL spool of ``(path, text, extraction_error)`` rows.

    The docs stage writes one line per candidate (via ``run_docs_search``'s
    ``text_sink``); the persist step streams it back in the same order.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None
        self.count = 0

    def __enter__(self) -> DocumentTextSpool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8", newline="\n")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def write(self, path: str, text: str, extraction_error: str) -> None:
        if self._handle is None:
            return
        self._handle.write(json.dumps([path, text, extraction_error], ensure_ascii=False))
        self._handle.write("\n")
        self.count += 1


def iter_document_text_spool(path: Path) -> Iterator[tuple[str, str, str | None]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            doc_path, text, error = json.loads(line)
            yield str(doc_path), str(text), (str(error) if error else None)


def remove_case_db_files(db_path: Path) -> None:
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        candidate = db_path.with_name(db_path.name + suffix)
        try:
            candidate.unlink()
        except FileNotFoundError:
            continue


def run_case_id(output_dir: Path) -> str:
    """Deterministic case id for a run-local case DB (from the output dir name).

    One ``run-`` prefix only: ``run-subset7`` stays ``run-subset7`` (it was
    ``run-run-subset7``). :func:`legacy_run_case_ids` lists the older form so
    readers can still find a DB built before the change.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", output_dir.name.lower()).strip("-")
    if not slug or slug == "run":
        return "run"
    return slug if slug.startswith("run-") else f"run-{slug}"


def legacy_run_case_ids(output_dir: Path) -> list[str]:
    slug = re.sub(r"[^a-z0-9]+", "-", output_dir.name.lower()).strip("-")
    legacy = f"run-{slug}" if slug else "run"
    return [legacy] if legacy != run_case_id(output_dir) else []


def build_run_case_db(
    output_dir: Path,
    outputs: Mapping[str, object],
    *,
    root: str,
    source: Mapping[str, object] | None = None,
    docs_text_spool: Path | None = None,
) -> dict[str, object]:
    """(Re)build ``<output_dir>/rapidtriage-case.db`` from the run outputs.

    Returns a persist record: ``status`` (``completed``/``failed``), timing,
    row counts and, on failure, the error text. Never raises for import
    errors: a failed index leaves the run usable with the scan backend.
    """
    db_path = output_dir / CASE_DB_FILE_NAME
    started_at = time.time()
    record: dict[str, object] = {
        "path": str(db_path),
        "started_at": _iso(started_at),
        "case_id": run_case_id(output_dir),
        "document_text_source": "docs-stage-spool" if docs_text_spool and docs_text_spool.is_file() else "re-extract",
    }
    summary = {
        "root": root,
        "source": dict(source or {}),
        "outputs": {key: str(value) for key, value in outputs.items()},
    }
    document_texts = (
        iter_document_text_spool(docs_text_spool)
        if docs_text_spool is not None and docs_text_spool.is_file()
        else None
    )
    # The import allocates millions of short-lived rows; in a run process
    # holding large live object graphs every cyclic-GC pass walks all of them
    # (refcounting still frees the rows), so the collector is paused for the
    # import and restored afterwards.
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        remove_case_db_files(db_path)
        database = CaseDatabase(db_path, bulk_load=True)
        database.initialize()
        result = database.import_run_output(
            summary,
            case_id=str(record["case_id"]),
            case_name=f"RapidTriage run {output_dir.name}",
            document_texts=document_texts,
            hash_files=False,
        )
    except Exception as exc:  # persist failure must not fail the run
        try:
            remove_case_db_files(db_path)
        except OSError:
            pass
        record.update(
            {
                "status": "failed",
                "search_backend": SEARCH_BACKEND_SCAN,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    else:
        counts = result.get("summary") if isinstance(result.get("summary"), Mapping) else {}
        record.update(
            {
                "status": "completed",
                "search_backend": SEARCH_BACKEND_FTS,
                "counts": dict(counts),
                "size_bytes": db_path.stat().st_size if db_path.is_file() else 0,
            }
        )
    finally:
        if gc_was_enabled:
            gc.enable()
        if document_texts is not None:
            document_texts.close()  # releases the spool handle (Windows unlink)
        if docs_text_spool is not None:
            try:
                docs_text_spool.unlink(missing_ok=True)
            except OSError:
                pass
    completed_at = time.time()
    record["completed_at"] = _iso(completed_at)
    record["elapsed_seconds"] = round(completed_at - started_at, 3)
    return record


def build_run_geo_index(
    output_dir: Path,
    artifact_outputs: Mapping[str, Path],
    artifact_payloads: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """위치 행 색인 (plan r6 §3.3 갈래 C): ``<output_dir>/rapidtriage-geo-index.json`` from one
    pass over every kind's rows, so the console's map view never scans the run. Never raises: a
    failed index leaves the run usable (the API builds it on the first map request)."""
    try:
        from ...api.app.geo_index import write_run_geo_index
    except Exception as exc:  # pragma: no cover - the API package is part of the install
        return {"status": "skipped", "reason": f"{type(exc).__name__}: {exc}"}
    sources = [
        (kind, artifact_payloads[kind], Path(path))
        for kind, path in sorted(artifact_outputs.items())
        if kind in artifact_payloads
    ]
    return write_run_geo_index(output_dir, sources)


def build_run_families(output_dir: Path, outputs: Mapping[str, object]) -> dict[str, object]:
    """계열·중복·예외 항목 (R7 갈래 A): ``rapidtriage-families.jsonl``, ``rapidtriage-dedup.json`` and
    ``rapidtriage-irregular.json`` next to the outputs, derived from them in one pass. Never raises:
    a failed derivation leaves the run usable (the API derives on the first request)."""
    try:
        from ...api.app.families import write_run_families
    except Exception as exc:  # pragma: no cover - the API package is part of the install
        return {"status": "skipped", "reason": f"{type(exc).__name__}: {exc}"}
    return write_run_families(output_dir, outputs)


def skipped_case_db_record(reason: str) -> dict[str, object]:
    return {"status": "skipped", "search_backend": SEARCH_BACKEND_SCAN, "reason": reason}


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()
