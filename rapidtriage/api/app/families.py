"""계열·중복·예외 항목 of a run (R7 갈래 A): one derivation over the run outputs, its files and the
row sets the listing conditions ``family=`` / ``dup=`` / ``irregular=`` use.

Sources (:func:`collect_sources`): every ``artifacts_<kind>`` output, the files output (candidates
and inventory), the docs output (documents joined to their files row by path) and the rows of the
completed ``carve`` analyses. Artifact JSONL streams are read in blocks: only lines holding one of
the probes (:data:`ARTIFACT_PROBES`: the row types the relations, items and irregular categories
read) are parsed -- a kind whose shared profiles hold a probe parses every line.

Files next to the run outputs (written by the run's ``persist`` step, :func:`write_run_families`,
or on the first request when missing or stale): ``rapidtriage-families.jsonl`` (a header line with
the source stamp, then one parent → child edge per line), ``rapidtriage-dedup.json`` and
``rapidtriage-irregular.json``. A stamp mismatch, a file that does not validate, or a source that
changed during the build rebuilds; ``RAPIDTRIAGE_INDEX_PERSIST=0`` or a read-only folder keeps the
result in memory only (``source: memory``) -- never an error. Stdlib only.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ...core.artifact_profiles import PROFILE_REF_KEY
from ...core.dedup import (
    DEDUP_FILE_NAME,
    DEDUP_FORMAT,
    DedupIndex,
    compute_dedup,
    container_key,
    dedup_document,
    dedup_index_from_document,
    item_keys,
)
from ...core.families import (
    FAMILIES_FILE_NAME,
    FAMILIES_FORMAT,
    FamilyBuilder,
    FamilyIndex,
    SourceRow,
    base_ref,
    family_index_from_records,
    iter_family_records,
    norm_path,
    parse_ref,
)
from ...core.irregular import (
    ARTIFACT_PROBES as IRREGULAR_PROBES,
)
from ...core.irregular import (
    IRREGULAR_FILE_NAME,
    IRREGULAR_FORMAT,
    IrregularIndex,
    bucket_of,
    irregular_document,
    irregular_index_from_document,
    row_categories,
)
from ...core.jobs import read_output_json
from ...core.json_stream import JsonStreamError, iter_array_items
from .index_cache import SingleFlightIndexCache, head_tail_digest, index_persist_enabled
from .jsonl_records import (
    expand_row,
    iter_artifact_records,
    iter_jsonl_records,
    iter_records_at,
    jsonl_records_path,
    parse_record_line,
    payload_profiles,
)
from .row_conditions import ResolvedRowSets, RowSetQuery, row_is_partial

LOGGER = logging.getLogger(__name__)

FAMILY_PROBES: tuple[bytes, ...] = (
    b'"email-',
    b'"archive-file-inventory"',
    b'"android-backup',
    b'"chat-message"',
    b'"chat-attachment"',
    b'"container_member"',
)
ARTIFACT_PROBES: tuple[bytes, ...] = tuple(dict.fromkeys(FAMILY_PROBES + IRREGULAR_PROBES))
# Exact probes for the (small) shared profiles of a kind.
_PROBE = re.compile(b"|".join(re.escape(probe) for probe in ARTIFACT_PROBES))
# Line probes for the JSONL scan: fewer, broader substrings of the same set, searched with
# ``bytes.find`` (a 35-way regex alternation over 1 GB of JSONL took ~40 s; these ~4 s / 500 MB).
# Every exact probe contains one of them, so no matching line is missed.
LINE_PROBES: tuple[bytes, ...] = (
    b'"email-',
    b'"archive-',
    b'"android-backup',
    b'"chat-',
    b'"container_member"',
    b'"file-signature-mismatch"',
    b'"parser_error"',
    b'"parse_status"',
    b'"decrypt_status"',
    b'"coverage"',
    b'truncated"',
    b"invalid",
    b"unreadable",
    b"-error",
    b'"is_deleted"',
    b'"deleted',
    b"ncrypt",
    b'"supported":false',
    b'"supported": false',
)
SCAN_BLOCK_BYTES = 8 << 20
DERIVED_CACHE_RUNS = 4
FILES_LANES = ("candidates", "inventory")
CARVE_KIND = "carve"
ANALYSES_DIR = "analyses"

# (kind, payload, payload path) of one artifacts output.
Source = tuple[str, Mapping[str, object], Path]


@dataclass
class DerivedSources:
    kinds: list[Source]
    files_path: Path | None = None
    docs_path: Path | None = None
    # (analysis id, rows.jsonl, analysis.json) of completed carve analyses.
    carves: list[tuple[str, Path, Path]] = field(default_factory=list)


@dataclass
class RunDerived:
    stamp: tuple[object, ...]
    families: FamilyIndex
    dedup: DedupIndex
    irregular: IrregularIndex
    source: str = "built"  # file | built | memory
    elapsed_seconds: float = 0.0
    scanned_rows: int = 0
    parsed_rows: int = 0
    _row_sets: dict[tuple[object, ...], dict[tuple[str, str], frozenset[int]]] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- row sets (conditions) ------------------------------------------------------------

    def rows_of(self, refs: Iterable[str]) -> dict[tuple[str, str], frozenset[int]]:
        """``{(collection, kind or files lane): record indices}`` of the row refs among ``refs``
        (virtual entries / attachments and other collections are dropped)."""
        out: dict[tuple[str, str], set[int]] = {}
        for ref in refs:
            if base_ref(ref) != ref:
                continue
            parsed = parse_ref(ref)
            if parsed is None:
                continue
            collection, kind, locator = parsed
            if collection == "artifacts":
                out.setdefault(("artifacts", kind), set()).add(int(locator.rsplit("/", 1)[1]))
            elif collection == "files":
                _empty, lane, number = locator.split("/")
                out.setdefault(("files", lane), set()).add(int(number))
        return {key: frozenset(values) for key, values in out.items()}

    def _cached(self, key: tuple[object, ...], compute: Callable[[], Iterable[str]]) -> dict[tuple[str, str], frozenset[int]]:
        with self._lock:
            found = self._row_sets.get(key)
        if found is not None:
            return found
        value = self.rows_of(compute())
        with self._lock:
            if len(self._row_sets) > 64:
                self._row_sets.clear()
            self._row_sets[key] = value
        return value

    def family_rows(self, ref: str) -> dict[tuple[str, str], frozenset[int]]:
        return self._cached(("family", ref), lambda: self.families.family(base_ref(ref) if parse_ref(ref) else ref))

    def dup_rows(self, mode: str, status: str) -> dict[tuple[str, str], frozenset[int]]:
        def compute() -> list[str]:
            index = self.dedup.mode(mode)
            return [ref for ref in index.status if index.matches(ref, status)]

        return self._cached(("dup", mode, status), compute)

    def irregular_rows(self, categories: Iterable[str]) -> dict[tuple[str, str], frozenset[int]]:
        wanted = tuple(sorted(set(categories)))
        return self._cached(("irregular", wanted), lambda: [ref for name in wanted for ref in self.irregular.refs(name)])


# --- sources ---------------------------------------------------------------------------------------


def _path_or_none(value: object) -> Path | None:
    if not value:
        return None
    path = Path(str(value))
    return path if path.is_file() else None


def carve_analyses(output_dir: Path | None) -> list[tuple[str, Path, Path]]:
    """Completed (or cancelled / failed with rows) ``carve`` analyses of a run, id order."""
    if output_dir is None:
        return []
    root = Path(output_dir) / ANALYSES_DIR
    found: list[tuple[str, Path, Path]] = []
    try:
        directories = sorted(item for item in root.iterdir() if item.is_dir())
    except OSError:
        return []
    for directory in directories:
        state_path = directory / "analysis.json"
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(state, dict) or state.get("kind") != CARVE_KIND:
            continue
        if state.get("status") not in ("completed", "cancelled", "failed"):
            continue
        rows = directory / "rows.jsonl"
        if rows.is_file():
            found.append((directory.name, rows, state_path))
    return found


def collect_sources(outputs: Mapping[str, object], output_dir: Path | None) -> DerivedSources:
    """The run outputs the derivation reads (unreadable artifact payloads are skipped)."""
    kinds: list[Source] = []
    for name in sorted(outputs):
        if not str(name).startswith("artifacts_"):
            continue
        path = _path_or_none(outputs[name])
        if path is None:
            continue
        try:
            payload = read_output_json(path)
        except (OSError, ValueError) as exc:
            LOGGER.info("families: artifact output %s skipped: %s", path, exc)
            continue
        kinds.append((str(name).removeprefix("artifacts_"), payload, path))
    return DerivedSources(
        kinds=kinds,
        files_path=_path_or_none(outputs.get("files")),
        docs_path=_path_or_none(outputs.get("docs")),
        carves=carve_analyses(output_dir),
    )


def _file_stamp(path: Path | None) -> tuple[object, ...]:
    if path is None:
        return ("", -1, -1)
    try:
        stat = path.stat()
    except OSError:
        return (path.name, -1, -1)
    return (path.name, stat.st_size, stat.st_mtime_ns)


def sources_stamp(sources: DerivedSources) -> tuple[object, ...]:
    """Revision of every file the derivation reads (name, size, mtime_ns)."""
    kinds = tuple(
        (kind, *_file_stamp(Path(path)), *_file_stamp(jsonl_records_path(payload, path)))
        for kind, payload, path in sorted(sources.kinds, key=lambda item: item[0])
    )
    carves = tuple((analysis_id, *_file_stamp(rows), *_file_stamp(state)) for analysis_id, rows, state in sources.carves)
    return (("files", *_file_stamp(sources.files_path)), ("docs", *_file_stamp(sources.docs_path)), kinds, carves)


def _stamp_paths(sources: DerivedSources) -> list[Path]:
    paths: list[Path] = [path for path in (sources.files_path, sources.docs_path) if path is not None]
    for _kind, payload, path in sorted(sources.kinds, key=lambda item: item[0]):
        paths.append(Path(path))
        records = jsonl_records_path(payload, path)
        if records is not None:
            paths.append(records)
    for _analysis_id, rows, _state in sources.carves:
        paths.append(rows)
    return paths


def stamp_digests(sources: DerivedSources) -> list[str | None]:
    return [head_tail_digest(path) for path in _stamp_paths(sources)]


def _jsonable(value: object) -> object:
    return json.loads(json.dumps(value))


# --- row stream --------------------------------------------------------------------------------------


def _blocks(handle) -> Iterator[bytes]:
    tail = b""
    while True:
        block = handle.read(SCAN_BLOCK_BYTES)
        if not block:
            if tail:
                yield tail
            return
        data = tail + block if tail else block
        cut = data.rfind(b"\n") + 1
        if cut == 0:
            tail = data
            continue
        tail = data[cut:]
        yield data[:cut] if tail else data


def kind_line_probes(profiles: Mapping[str, object] | None) -> tuple[bytes, ...]:
    """:data:`LINE_PROBES` plus ``"profile_ref":"<id>"`` of every shared profile (type template,
    codes or a per-file context) holding an exact probe: such a row matches although its own line
    does not."""
    extra: list[bytes] = []
    key = json.dumps(PROFILE_REF_KEY).encode("ascii")
    for profile_id, profile in (profiles or {}).items():
        try:
            blob = json.dumps(profile, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        except (TypeError, ValueError):
            blob = b'"email-'
        if _PROBE.search(blob) is not None:
            value = json.dumps(str(profile_id), ensure_ascii=False).encode("utf-8")
            extra.extend((key + b":" + value, key + b": " + value))
    return LINE_PROBES + tuple(extra)


def _matching_line_starts(block: bytes, probes: Sequence[bytes]) -> list[int]:
    """Sorted start offsets of the lines of ``block`` holding any probe."""
    starts: set[int] = set()
    for probe in probes:
        at = block.find(probe)
        while at >= 0:
            start = block.rfind(b"\n", 0, at) + 1
            starts.add(start)
            end = block.find(b"\n", at)
            if end < 0:
                break
            at = block.find(probe, end)
    return sorted(starts)


@dataclass
class _Counter:
    scanned: int = 0
    parsed: int = 0


def iter_kind_rows(kind: str, payload: Mapping[str, object], payload_path: Path, counter: _Counter) -> Iterator[SourceRow]:
    """Probe-matching rows of one kind in record order (:func:`_hot_profile_pattern`)."""
    records_path = jsonl_records_path(payload, payload_path)
    profiles = payload_profiles(payload)
    if records_path is None:
        for record_index, row in iter_artifact_records(payload, payload_path=payload_path):
            counter.scanned += 1
            counter.parsed += 1
            yield SourceRow("artifacts", kind, f"/artifacts/{record_index}", row)
        return
    probes = kind_line_probes(profiles)
    index = 0
    lines_before = 0
    with open(records_path, "rb") as handle:
        for block in _blocks(handle):
            lines = block.count(b"\n") + (0 if block.endswith(b"\n") else 1)
            uniform = block.count(b"\n{") + (1 if block.startswith(b"{") else 0) == lines
            if uniform:
                counter.scanned += lines
                counted, counted_at = 0, 0
                for start in _matching_line_starts(block, probes):
                    counted += block.count(b"\n", counted_at, start)
                    counted_at = start
                    end = block.find(b"\n", start)
                    line = block[start : len(block) if end < 0 else end].strip()
                    row = parse_record_line(line, path=records_path, line_number=lines_before + counted + 1)
                    counter.parsed += 1
                    if row is not None:
                        yield SourceRow("artifacts", kind, f"/artifacts/{index + counted}", expand_row(row, profiles))
                index += lines
            else:
                for number, line in enumerate(block.split(b"\n")[:lines], start=lines_before + 1):
                    stripped = line.strip()
                    if not stripped.startswith(b"{"):
                        continue
                    record_index = index
                    index += 1
                    counter.scanned += 1
                    if not any(probe in stripped for probe in probes):
                        continue
                    counter.parsed += 1
                    row = parse_record_line(stripped, path=records_path, line_number=number)
                    if row is not None:
                        yield SourceRow("artifacts", kind, f"/artifacts/{record_index}", expand_row(row, profiles))
            lines_before += lines


def _files_rows(files_path: Path | None, counter: _Counter) -> Iterator[SourceRow]:
    """Files rows, streamed one lane at a time (the 30+ MB files output is never held whole)."""
    if files_path is None:
        return
    for lane in FILES_LANES:
        try:
            items = iter_array_items(files_path, lane)
            for position, row in enumerate(items):
                counter.scanned += 1
                if isinstance(row, Mapping):
                    yield SourceRow("files", "", f"/{lane}/{position}", row)
        except JsonStreamError:
            continue  # the lane is missing (older outputs) or not an array


def _carve_rows(carves: Sequence[tuple[str, Path, Path]], counter: _Counter) -> Iterator[SourceRow]:
    for analysis_id, rows_path, _state in carves:
        for record_index, _offset, row, _line in iter_jsonl_records(rows_path):
            counter.scanned += 1
            if row is not None:
                yield SourceRow("analysis", analysis_id, f"/rows/{record_index}", row)


def documents_by_path(docs_path: Path | None) -> dict[str, Mapping[str, object]]:
    if docs_path is None:
        return {}
    try:
        payload = read_output_json(docs_path)
    except (OSError, ValueError):
        return {}
    candidates = payload.get("candidates")
    out: dict[str, Mapping[str, object]] = {}
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, Mapping):
                key = norm_path(item.get("path"))
                if key:
                    out.setdefault(key, item)
    return out


def derive(sources: DerivedSources, *, stamp: tuple[object, ...] | None = None) -> RunDerived:
    """One pass over the sources: families, dedup (three modes) and irregular items."""
    stamp = sources_stamp(sources) if stamp is None else stamp
    started = time.perf_counter()
    counter = _Counter()
    documents = documents_by_path(sources.docs_path)
    builder = FamilyBuilder()
    keys: dict[str, str] = {}
    containers: dict[str, str] = {}
    irregular = IrregularIndex()

    def rows() -> Iterator[SourceRow]:
        yield from _files_rows(sources.files_path, counter)
        for kind, payload, path in sorted(sources.kinds, key=lambda item: item[0]):
            yield from iter_kind_rows(kind, payload, Path(path), counter)
        yield from _carve_rows(sources.carves, counter)

    for source in rows():
        builder.add(source)
        for ref, key in item_keys(source):
            keys.setdefault(ref, key)
        own = container_key(source)
        if own:
            containers[source.ref] = own
        irregular.add(source.ref, bucket_of(source), row_categories(source, documents, row_is_partial))
    families = builder.finish()
    dedup = compute_dedup(keys, families, container_keys=containers)
    return RunDerived(
        stamp=stamp,
        families=families,
        dedup=dedup,
        irregular=irregular,
        elapsed_seconds=round(time.perf_counter() - started, 3),
        scanned_rows=counter.scanned,
        parsed_rows=counter.parsed,
    )


# --- files -------------------------------------------------------------------------------------------


def _atomic_write(target: Path, write: Callable[[object], None]) -> None:
    temp = target.with_name(f"{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            write(handle)
        os.replace(temp, target)
    except BaseException:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def write_derived_files(derived: RunDerived, output_dir: Path, sources: DerivedSources) -> list[Path]:
    """Write the three files (``OSError`` when the folder is read-only)."""
    header = {
        "format": FAMILIES_FORMAT,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "stamp": _jsonable(derived.stamp),
        "digests": stamp_digests(sources),
        "edge_count": derived.families.edge_count,
        "scanned_rows": derived.scanned_rows,
        "parsed_rows": derived.parsed_rows,
    }
    output_dir = Path(output_dir)
    families_path = output_dir / FAMILIES_FILE_NAME
    dedup_path = output_dir / DEDUP_FILE_NAME
    irregular_path = output_dir / IRREGULAR_FILE_NAME

    def write_families(handle) -> None:
        handle.write(json.dumps(header, ensure_ascii=False, separators=(",", ":")) + "\n")
        for record in iter_family_records(derived.families):
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    stamp_block = {"stamp": header["stamp"], "digests": header["digests"], "generated_at": header["generated_at"]}
    _atomic_write(dedup_path, lambda handle: json.dump({**dedup_document(derived.dedup), **stamp_block}, handle, ensure_ascii=False, separators=(",", ":")))
    _atomic_write(irregular_path, lambda handle: json.dump({**irregular_document(derived.irregular), **stamp_block}, handle, ensure_ascii=False, separators=(",", ":")))
    # The families file last: its header is what a reader checks first.
    _atomic_write(families_path, write_families)
    return [families_path, dedup_path, irregular_path]


def read_derived_files(output_dir: Path, stamp: tuple[object, ...], sources: DerivedSources) -> RunDerived | None:
    """The stored derivation when all three files carry the current stamp and digests and validate."""
    output_dir = Path(output_dir)
    wanted_stamp = _jsonable(stamp)
    digests: list[str | None] | None = None
    try:
        with open(output_dir / FAMILIES_FILE_NAME, encoding="utf-8") as handle:
            header = json.loads(handle.readline() or "null")
            if not isinstance(header, dict) or header.get("format") != FAMILIES_FORMAT or header.get("stamp") != wanted_stamp:
                return None
            digests = stamp_digests(sources)
            if header.get("digests") != digests:
                return None
            families = family_index_from_records(json.loads(line) for line in handle if line.strip())
        documents = []
        for name, form in ((DEDUP_FILE_NAME, DEDUP_FORMAT), (IRREGULAR_FILE_NAME, IRREGULAR_FORMAT)):
            with open(output_dir / name, encoding="utf-8") as handle:
                document = json.load(handle)
            if not isinstance(document, dict) or document.get("format") != form:
                return None
            if document.get("stamp") != wanted_stamp or document.get("digests") != digests:
                return None
            documents.append(document)
        dedup = dedup_index_from_document(documents[0])
        irregular = irregular_index_from_document(documents[1])
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError) as exc:
        LOGGER.info("families files in %s ignored (%s); rebuilding", output_dir, type(exc).__name__)
        return None
    return RunDerived(
        stamp=stamp,
        families=families,
        dedup=dedup,
        irregular=irregular,
        source="file",
        scanned_rows=int(header.get("scanned_rows") or 0),
        parsed_rows=int(header.get("parsed_rows") or 0),
    )


def load_or_build(sources: DerivedSources, output_dir: Path | None) -> RunDerived:
    stamp = sources_stamp(sources)
    if output_dir is not None:
        stored = read_derived_files(output_dir, stamp, sources)
        if stored is not None:
            return stored
    derived = derive(sources, stamp=stamp)
    if output_dir is None or not index_persist_enabled() or sources_stamp(sources) != stamp:
        derived.source = "memory"
        return derived
    try:
        write_derived_files(derived, output_dir, sources)
    except OSError as exc:
        LOGGER.info("families kept in memory (output folder not writable): %s", exc)
        derived.source = "memory"
    return derived


def write_run_families(output_dir: Path, outputs: Mapping[str, object]) -> dict[str, object]:
    """Run-completion step (``persist``): derive and store. Never raises."""
    started = time.perf_counter()
    try:
        sources = collect_sources(outputs, output_dir)
        derived = derive(sources)
        paths = write_derived_files(derived, output_dir, sources)
    except Exception as exc:  # the run stays usable: the API derives on demand
        return {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    return {
        "status": "completed",
        "paths": [str(path) for path in paths],
        "edges": derived.families.edge_count,
        "dedup_items": len(derived.dedup.keys),
        "irregular": derived.irregular.summary()["total"],
        "scanned_rows": derived.scanned_rows,
        "parsed_rows": derived.parsed_rows,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


# --- per-run service -----------------------------------------------------------------------------------


class _DerivedCache(SingleFlightIndexCache[RunDerived]):
    def peek(self, key: tuple[object, ...]) -> RunDerived | None:
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
            return found


class FamiliesService:
    """Per-run derivations (LRU of :data:`DERIVED_CACHE_RUNS`), built single-flight per stamp."""

    def __init__(self, max_runs: int = DERIVED_CACHE_RUNS) -> None:
        self.cache = _DerivedCache(max_runs)

    def clear(self) -> None:
        self.cache.clear()

    def get(self, run_id: str, outputs: Mapping[str, object], output_dir: Path | None) -> RunDerived:
        sources = collect_sources(outputs, output_dir)
        key = (run_id, sources_stamp(sources))
        return self.cache.get_or_build(key, lambda: load_or_build(sources, output_dir))

    def peek(self, run_id: str, outputs: Mapping[str, object], output_dir: Path | None) -> RunDerived | None:
        """The cached derivation when ready (never builds)."""
        sources = collect_sources(outputs, output_dir)
        return self.cache.peek((run_id, sources_stamp(sources)))

    def ready_or_stored(self, run_id: str, outputs: Mapping[str, object], output_dir: Path | None) -> RunDerived | None:
        """The cached derivation, else the current stored files (read, never written), else
        ``None``: listings annotate rows only from what exists -- they never start a build (the
        families / dedup / irregular routes and the row-set conditions do)."""
        sources = collect_sources(outputs, output_dir)
        key = (run_id, sources_stamp(sources))
        found = self.cache.peek(key)
        if found is not None or output_dir is None:
            return found
        stored = read_derived_files(output_dir, key[1], sources)
        if stored is None:
            return None
        return self.cache.get_or_build(key, lambda: stored)


FAMILIES_SERVICE = FamiliesService()


# --- row-set conditions ----------------------------------------------------------------------------------

@dataclass
class RowSets:
    """Resolved row sets: the record indices of each collection that pass every given condition."""

    query: RowSetQuery
    allowed: dict[tuple[str, str], frozenset[int]]
    stamp: tuple[object, ...]

    def artifacts(self, kind: str) -> frozenset[int]:
        return self.allowed.get(("artifacts", kind), frozenset())

    def files(self, lane: str) -> frozenset[int]:
        return self.allowed.get(("files", lane), frozenset())

    def timeline_event(self, event: Mapping[str, object]) -> bool:
        """An event passes when its source artifact row does (``details.source_record``); events
        without one (files / documents events) never pass a row-set condition."""
        details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
        record = details.get("source_record") if isinstance(details, Mapping) else None
        if isinstance(record, Mapping):
            output = str(record.get("output") or "")
            row_index = record.get("row_index")
            if output.startswith("artifacts_") and isinstance(row_index, int) and not isinstance(row_index, bool):
                return row_index in self.artifacts(output.removeprefix("artifacts_"))
        return False

    def cache_key(self) -> tuple[object, ...]:
        return (self.query.cache_key(), self.stamp)


def restrict_rows(
    rows: Iterable[tuple[int, dict[str, object]]], allowed: frozenset[int] | None
) -> Iterator[tuple[int, dict[str, object]]]:
    """``rows`` whose record index is in ``allowed`` (``None``: all of them)."""
    for record_index, row in rows:
        if allowed is None or record_index in allowed:
            yield record_index, row


def restrict_indices(indices: Sequence[int], allowed: frozenset[int] | None) -> Sequence[int]:
    """Ascending ``indices`` kept in ``allowed`` (``None``: unchanged)."""
    if allowed is None:
        return indices
    return [index for index in indices if index in allowed]


def restrict_rows_for(rows_for, row_sets: RowSets | ResolvedRowSets | None):
    """``filter_across_kinds`` ``rows_for`` narrowed to the row sets: a kind yields only its rows in
    them (read by record index when there is no other source); ``rows_for`` unchanged without
    row sets."""
    if row_sets is None:
        return rows_for

    def narrowed(kind: str, payload: dict[str, object], payload_path: Path, start: int):
        allowed = row_sets.artifacts(kind)
        if rows_for is None:
            return iter_records_at(payload, payload_path, sorted(index for index in allowed if index >= start))
        return restrict_rows(rows_for(kind, payload, payload_path, start), allowed)

    return narrowed


def resolve_row_sets(query: RowSetQuery, derived: RunDerived) -> RowSets:
    parts: list[dict[tuple[str, str], frozenset[int]]] = []
    if query.family is not None:
        parts.append(derived.family_rows(query.family))
    if query.dup is not None:
        parts.append(derived.dup_rows(query.dup_mode, query.dup))
    if query.irregular is not None:
        parts.append(derived.irregular_rows(query.irregular))
    allowed = dict(parts[0]) if parts else {}
    for other in parts[1:]:
        allowed = {key: values & other[key] for key, values in allowed.items() if key in other}
    return RowSets(query=query, allowed=allowed, stamp=derived.stamp)


# --- row annotations -----------------------------------------------------------------------------------------


def row_annotations(derived: RunDerived, ref: str) -> dict[str, object]:
    """``family`` / ``dedup`` fields of one listed row (empty when the row has neither)."""
    out: dict[str, object] = {}
    families = derived.families
    link = families.parent.get(ref)
    children = families.children.get(ref) or []
    if link is not None or children:
        parent_info = families.info(link[0]) if link else None
        out["family"] = {
            "parent": link[0] if link else None,
            "parent_title": parent_info.title if parent_info else None,
            "relation": link[1] if link else None,
            "children": len(children),
            "top": families.top(ref),
        }
    found = derived.dedup.mode("item").lookup(ref)
    if found is not None:
        out["dedup"] = {"status": found[0], "count": found[1]}
    return out


def annotate_artifact_rows(derived: RunDerived, kind: str, rows: Iterable[object]) -> None:
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("record_index"), int):
            extra = row_annotations(derived, f"artifacts:{kind}:/artifacts/{row['record_index']}")
            if extra:
                row.update(extra)


def annotate_files_rows(derived: RunDerived, lane: str, rows: Iterable[object]) -> None:
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("record_index"), int):
            extra = row_annotations(derived, f"files::/{lane}/{row['record_index']}")
            if extra:
                row.update(extra)
