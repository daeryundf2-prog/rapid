"""One triage-flag pass over a run output (plan viewer-families §3.1 "실행 지점").

``run_triage_flags`` reads every row source of a run once -- per-kind
artifacts, the files output (``candidates`` / ``inventory``) and completed
analyses whose kind some rule reads -- applies the catalogue rules, lets the
cross-row rules emit their flags, and writes two files into ``out_dir``
(inside the run output directory; nothing is written anywhere else):

* ``flags.jsonl`` -- one line per flagged row ``{kind, record_index, flags:
  [{id, grade, label, evidence, note?}]}`` in source order, flags sorted A>B>C;
  ``kind`` = artifact kind, ``files:candidates``/``files:inventory`` or
  ``analysis:<analysis_id>``;
* ``summary.json`` -- counts by rule / grade / kind (``rows_by_best_grade``
  per kind feeds the tree), the catalogue version and rule versions, rows
  scanned per source, rule errors and truncation notes.

Both are written to a temp name and ``os.replace``-d, ``summary.json`` last.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..json_safe import json_default
from ..json_stream import iter_array_items
from . import RULE_CLASSES
from .base import (
    GRADE_RANK,
    GRADES,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    as_list,
    parse_time,
    split_windows_path,
)
from .catalog import Catalog, load_catalog
from .records import iter_artifact_rows, iter_jsonl_rows
from .usb import vbr_serial

FLAGS_FILE_NAME = "flags.jsonl"
SUMMARY_FILE_NAME = "summary.json"
SUMMARY_VERSION = "triage-flags-summary-v1"
MAX_FLAGS_PER_RULE = 200_000
MAX_FLAGGED_ROWS = 2_000_000
CANCEL_CHECK_EVERY = 2_000
# Files rows folded into the shared file-listing context (paths/folders/names). Beyond it the
# listing is treated as unknown (``file_missing`` -> None) instead of growing without bound.
FILES_CONTEXT_MAX_ROWS = 1_000_000
# File-system mtimes kept for documents.modified_vs_fs (the document parser has no fs time):
# only document-like files, inside the same row cap.
DOCUMENT_MTIME_EXTENSIONS = frozenset(
    {"doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "hwp", "hwpx", "pdf", "odt", "ods", "odp", "rtf"}
)
VOLUME_SENTINELS = frozenset({"windows", "users", "program files", "program files (x86)", "programdata", "$recycle.bin", "documents and settings"})
# Policy-dependent event sources (U-F4 "부재 ≠ 미발생"): id -> (Korean label, note when no record).
POLICY_SOURCES: dict[str, tuple[str, str]] = {
    "process_creation_4688": (
        "프로세스 생성 감사(Security 4688)",
        "프로세스 생성 감사는 기본값이 꺼져 있습니다. 4688이 없다고 해서 프로그램이 실행되지 않았다는 뜻이 아닙니다.",
    ),
    "powershell_scriptblock_4104": (
        "PowerShell 스크립트 블록 로깅(4104)",
        "스크립트 블록 로깅은 정책으로 켜야 기록됩니다(일부 의심 블록은 기본 기록). 부재 ≠ 미실행.",
    ),
    "usb_device_logs": (
        "USB 장치 로그(DriverFrameworks 2003/2100 · Partition 1006)",
        "DriverFrameworks-UserMode 로그는 기본 비활성이고 Partition/Diagnostic은 Windows 10 1607 이후에만 있습니다. 부재 ≠ 미연결.",
    ),
    "sysmon": (
        "Sysmon",
        "Sysmon은 별도 설치가 필요합니다. 없으면 프로세스·네트워크 세부 기록이 없습니다.",
    ),
}
_POWERSHELL_OPERATIONAL = "microsoft-windows-powershell/operational"
_DRIVER_FRAMEWORKS = "microsoft-windows-driverframeworks-usermode/operational"
_PARTITION_DIAGNOSTIC = "microsoft-windows-partition/diagnostic"
_SYSMON = "microsoft-windows-sysmon/operational"
# Kinds whose rows feed shared context (removable letters, host names, USB serials) read first.
SOURCE_PRIORITY = ("windows-registry", "windows-os-account", "eventlog", "windows-system")


@dataclass
class RowSource:
    kind: str
    collection: str
    source_kind: str
    rows: Callable[[], Iterable[tuple[int, Mapping[str, object]]]]
    total: int | None = None
    types: frozenset[str] | None = None


@dataclass
class TriageInputs:
    output_dir: Path
    artifact_payloads: Mapping[str, Path] = field(default_factory=dict)
    files_path: Path | None = None
    # (analysis_id, analysis kind, rows.jsonl path, flushed row_count)
    analyses: Sequence[tuple[str, str, Path, int]] = ()
    # Already-loaded payloads (the run stage has them in memory): kind -> artifacts payload, files payload.
    # Without ``files_payload`` the files output is streamed member by member (never loaded whole).
    artifact_payload_objects: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    files_payload: Mapping[str, object] | None = None


@dataclass
class Progress:
    """Callbacks of a pass: ``begin(kind, index, count)``, ``rows(kind, done)``, ``check_cancel()``."""

    begin: Callable[[str, int, int], None] = lambda *_args: None
    rows: Callable[[str, int], None] = lambda *_args: None
    check_cancel: Callable[[], None] = lambda: None


def _load_json(path: Path) -> dict[str, object]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def volume_relative(raw: object) -> str:
    """Casefolded ``\\``-joined path from the first volume sentinel (``Windows``, ``Users`` …) of an evidence path."""
    _drive, rest = split_windows_path(raw)
    parts = rest.split("\\")
    for index, part in enumerate(parts):
        if part in VOLUME_SENTINELS:
            return "\\".join(parts[index:])
    return ""


def build_rules(catalog: Catalog, overrides: Mapping[str, Mapping[str, Any]] | None = None) -> list[Rule]:
    rules: list[Rule] = []
    for spec in catalog.specs.values():
        cls = RULE_CLASSES.get(spec.id)
        if cls is None:
            raise ValueError(f"카탈로그 규칙 {spec.id}의 구현이 없습니다")
        params = {**dict(spec.params), **dict((overrides or {}).get(spec.id) or {})}
        rules.append(cls(params))
    return rules


FILES_COLLECTIONS = ("candidates", "inventory")


# A files output up to this size is parsed once (fast); a larger one is streamed member by member
# (bounded memory, slower: the pure-Python stream reader runs at a few MB/s).
FILES_LOAD_MAX_BYTES = 256 * 1024 * 1024


class FilesOutput:
    """The run's files output: an in-memory payload, or a path loaded once when small and streamed when large."""

    def __init__(self, payload: Mapping[str, object] | None, path: Path | None) -> None:
        self.payload = payload
        self.path: Path | None = None
        self.streamed = False
        self.load_error: str | None = None
        if payload is not None or path is None or not Path(path).is_file():
            return
        try:
            small = Path(path).stat().st_size <= FILES_LOAD_MAX_BYTES
        except OSError:
            small = False
        if small:
            try:
                self.payload = _load_json(Path(path))
                return
            except (OSError, ValueError) as exc:
                self.load_error = f"{type(exc).__name__}: {exc}"[:300]
                return
        self.path = Path(path)
        self.streamed = True

    @property
    def available(self) -> bool:
        return self.payload is not None or self.path is not None

    def total(self, collection: str) -> int | None:
        rows = self.payload.get(collection) if self.payload is not None else None
        return len(rows) if isinstance(rows, list) else None

    def rows(self, collection: str):
        """``(index, row)`` of one collection (``JsonStreamError``/``OSError`` propagate to the caller)."""
        if self.payload is not None:
            rows = self.payload.get(collection)
            yield from enumerate(rows if isinstance(rows, list) else [])
            return
        if self.path is None:
            return
        yield from enumerate(iter_array_items(self.path, collection))

    def has_rows(self, collection: str) -> bool:
        if self.payload is not None:
            rows = self.payload.get(collection)
            return isinstance(rows, list) and bool(rows)
        return self.path is not None


def _files_context(ctx: FlagContext, files: FilesOutput, *, max_rows: int | None = None) -> dict[str, object]:
    """Fold the file listing into ``ctx`` (at most ``max_rows`` rows); returns the ``files_context`` summary block."""
    cap = FILES_CONTEXT_MAX_ROWS if max_rows is None else max_rows
    mtimes: dict[str, object] = {}
    folded = 0
    capped = False
    error: str | None = None
    try:
        for collection in FILES_COLLECTIONS:
            for _index, row in files.rows(collection):
                if not isinstance(row, Mapping):
                    continue
                if folded >= cap:
                    capped = True
                    break
                folded += 1
                path = str(row.get("path") or "")
                relative = volume_relative(path)
                if relative:
                    ctx.file_paths.add(relative)
                    if "\\" in relative:
                        ctx.file_dirs.add(relative.rsplit("\\", 1)[0])
                name = str(row.get("name") or "").casefold() or path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
                if name:
                    ctx.file_names.add(name)
                modified = row.get("fs_modified_at") or row.get("modified_at")
                if path and modified and name.rsplit(".", 1)[-1] in DOCUMENT_MTIME_EXTENSIONS:
                    mtimes[path.casefold()] = modified
            if capped:
                break
    except (OSError, ValueError) as exc:  # JsonStreamError is a ValueError
        error = f"{type(exc).__name__}: {exc}"[:300]
    if capped or error:
        # A partial listing would make "target missing" rules claim absence: treat it as unknown.
        ctx.file_paths.clear()
        ctx.file_dirs.clear()
        ctx.file_names.clear()
        ctx.file_paths_known = False
    else:
        ctx.file_paths_known = bool(ctx.file_paths)
    ctx.shared["file_mtimes"] = mtimes
    block: dict[str, object] = {
        "rows_folded": folded,
        "max_rows": cap,
        "capped": capped,
        "listing_known": ctx.file_paths_known,
        "streamed": files.streamed,
    }
    if error:
        block["error"] = error
    return block


def _collect_context(view: RowView, ctx: FlagContext) -> None:
    """Shared facts other rules read: removable drive letters, host names, USB volume serials/arrivals, active days."""
    kind, row_type = view.source_kind, view.type
    if row_type == "windows-mounted-device":
        letter = view.text("drive_letter").rstrip(":\\").lower()
        if letter and view.flag("removable_usb") is True:
            ctx.shared.setdefault("removable_letters", set()).add(letter[-1])
    elif row_type == "windows-computer-name":
        name = view.text("computer_name")
        if name:
            ctx.hostnames.add(name)
    elif row_type in {"windows-usb-device", "registry-usb"}:
        arrival = parse_time(view.get("last_arrival_at"))
        if arrival is not None:
            ctx.shared.setdefault("usb_arrivals", []).append(arrival)
    elif kind == "eventlog":
        computer = view.text("computer")
        if computer and len(ctx.hostnames) < 64:
            ctx.hostnames.add(computer.split(".")[0])
        moment = parse_time(view.get("timestamp"))
        if moment is not None:
            ctx.shared.setdefault("activity_days", Counter())[moment.date().isoformat()] += 1
        _count_policy(view, ctx)
        if view.event_id() == "1006" and view.channel() == _PARTITION_DIAGNOSTIC:
            for name in ("Vbr0", "Vbr1", "Vbr2", "Vbr3"):
                vsn = vbr_serial(view.ev_text(name))
                if vsn:
                    ctx.shared.setdefault("usb_vsns", {})[vsn] = view.ev_text("SerialNumber")
    elif row_type == "prefetch-file":
        days = ctx.shared.setdefault("activity_days", Counter())
        for value in as_list(view.get("last_run_times")):
            moment = parse_time(value)
            if moment is not None:
                days[moment.date().isoformat()] += 1


def _count_policy(view: RowView, ctx: FlagContext) -> None:
    """Records of the policy-dependent sources (``POLICY_SOURCES``); duplicates of live records count once."""
    if view.is_duplicate():
        return
    channel, event_id = view.channel(), view.event_id()
    counts: Counter[str] = ctx.shared.setdefault("policy", Counter())
    if event_id == "4688" and (channel == "security" or "security-auditing" in view.provider()):
        counts["process_creation_4688"] += 1
    elif event_id == "4104" and channel == _POWERSHELL_OPERATIONAL:
        counts["powershell_scriptblock_4104"] += 1
    elif channel == _DRIVER_FRAMEWORKS or (channel == _PARTITION_DIAGNOSTIC and event_id == "1006"):
        counts["usb_device_logs"] += 1
    elif channel == _SYSMON:
        counts["sysmon"] += 1


def policy_sources(ctx: FlagContext, *, eventlog_scanned: bool) -> list[dict[str, object]]:
    """``[{id, label, count, note}]`` of the policy-dependent sources (empty when no event log was read)."""
    if not eventlog_scanned:
        return []
    counts: Counter[str] = ctx.shared.get("policy") or Counter()
    return [
        {"id": source_id, "label": label, "count": int(counts.get(source_id, 0)), "note": note}
        for source_id, (label, note) in POLICY_SOURCES.items()
    ]


def _row_sources(inputs: TriageInputs, files: FilesOutput, load_errors: dict[str, str]) -> list[RowSource]:
    sources: list[RowSource] = []
    order = {kind: position for position, kind in enumerate(SOURCE_PRIORITY)}
    for kind in sorted(inputs.artifact_payloads, key=lambda name: (order.get(name, len(order)), name)):
        path = Path(inputs.artifact_payloads[kind])
        preloaded = inputs.artifact_payload_objects.get(kind)
        if preloaded is not None:
            payload = preloaded
        else:
            try:
                payload = _load_json(path)
            except (OSError, ValueError) as exc:
                load_errors[kind] = f"{type(exc).__name__}: {exc}"[:300]
                continue
        summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
        counts = summary.get("artifact_type_counts") if isinstance(summary, Mapping) else None
        types = frozenset(str(name) for name in counts) if isinstance(counts, Mapping) and counts else None
        total = payload.get("record_count") if isinstance(payload.get("record_count"), int) else None

        def rows(payload: Mapping[str, object] = payload, path: Path = path):
            return iter_artifact_rows(payload, path)

        sources.append(RowSource(kind, "artifacts", kind, rows, total, types))
    for collection in FILES_COLLECTIONS:
        if files.has_rows(collection):
            sources.append(
                RowSource(
                    f"files:{collection}",
                    "files",
                    "files",
                    lambda collection=collection: files.rows(collection),
                    files.total(collection),
                    frozenset({"file"}),
                )
            )
    for analysis_id, analysis_kind, rows_path, row_count in inputs.analyses:
        def analysis_rows(rows_path: Path = rows_path, row_count: int = row_count):
            return ((index, row) for index, row in iter_jsonl_rows(rows_path, limit=row_count) if row is not None)

        sources.append(RowSource(f"analysis:{analysis_id}", "analysis", analysis_kind, analysis_rows, row_count))
    return sources


CONTEXT_TYPES = frozenset({"prefetch-file", "windows-mounted-device", "windows-computer-name", "windows-usb-device", "registry-usb"})


def _source_wanted(source: RowSource, rules: Sequence[Rule]) -> bool:
    """False when no rule (and no context collector) reads any row type of the source (from its type counts)."""
    if source.collection != "artifacts" or source.types is None:
        return source.kind == "eventlog" or any(source.collection in rule.selector.collections for rule in rules)
    if source.kind == "eventlog" or source.types & CONTEXT_TYPES:
        return True
    return any(rule.accepts(source.collection, source.source_kind, row_type) for rule in rules for row_type in source.types)


class _Collector:
    """Flags per row with the per-rule / total caps."""

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self.flags: dict[RowRef, dict[str, dict[str, object]]] = defaultdict(dict)
        self.per_rule: Counter[str] = Counter()
        self.suppressed: Counter[str] = Counter()
        # artifact_type of flagged rows (known for ``apply`` flags; cross-row flags may lack it).
        self.types: dict[RowRef, str] = {}

    def add(
        self,
        ref: RowRef,
        rule_id: str,
        evidence: Mapping[str, object],
        note: str | None,
        row_type: str | None = None,
        grade_cap: str | None = None,
    ) -> None:
        row_flags = self.flags.get(ref)
        if row_flags is not None and rule_id in row_flags:
            return
        if self.per_rule[rule_id] >= MAX_FLAGS_PER_RULE or (row_flags is None and len(self.flags) >= MAX_FLAGGED_ROWS):
            self.suppressed[rule_id] += 1
            return
        spec = self.catalog.specs[rule_id]
        grade = spec.grade
        if grade_cap in GRADE_RANK and GRADE_RANK[grade_cap] > GRADE_RANK.get(grade, 0):
            grade = grade_cap  # downgrade only; a cap never raises the catalogue grade
        flag: dict[str, object] = {"id": rule_id, "grade": grade, "label": spec.label_ko, "evidence": dict(evidence)}
        if note:
            flag["note"] = note
        self.flags[ref][rule_id] = flag
        self.per_rule[rule_id] += 1
        if row_type and ref not in self.types:
            self.types[ref] = row_type


def _write_atomic(path: Path, write: Callable[[Any], None]) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            write(handle)
        replace_with_retry(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


REPLACE_ATTEMPTS = 20


def replace_with_retry(source: Path, target: Path, *, attempts: int = REPLACE_ATTEMPTS) -> None:
    """``os.replace`` retried briefly: Windows refuses while a reader holds ``target`` open."""
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)


def run_triage_flags(
    inputs: TriageInputs,
    out_dir: Path,
    *,
    source_label: str,
    params: Mapping[str, Mapping[str, Any]] | None = None,
    incident_start: str | None = None,
    incident_end: str | None = None,
    progress: Progress | None = None,
    catalog: Catalog | None = None,
) -> dict[str, object]:
    """Run every catalogue rule over ``inputs`` and write ``flags.jsonl`` + ``summary.json`` into ``out_dir``."""
    started = time.monotonic()
    progress = progress or Progress()
    catalog = catalog or load_catalog()
    rules = build_rules(catalog, params)
    ctx = FlagContext(incident_start=parse_time(incident_start), incident_end=parse_time(incident_end))
    files = FilesOutput(inputs.files_payload, inputs.files_path)
    files_block = _files_context(ctx, files) if files.available else None
    if files.load_error is not None:
        files_block = {"rows_folded": 0, "listing_known": False, "error": files.load_error}
    for rule in rules:
        rule.prepare(ctx)
    collector = _Collector(catalog)
    errors: dict[str, dict[str, object]] = {}

    def record_error(rule_id: str, exc: Exception) -> None:
        entry = errors.setdefault(rule_id, {"count": 0, "message": f"{type(exc).__name__}: {exc}"[:300]})
        entry["count"] = int(entry["count"]) + 1

    load_errors: dict[str, str] = {}
    sources = _row_sources(inputs, files, load_errors)
    if files.load_error is not None:
        load_errors["files"] = files.load_error
    for kind, message in load_errors.items():
        errors[f"source:{kind}"] = {"count": 1, "message": f"읽기 실패: {message}"[:300]}
    coverage: dict[str, dict[str, object]] = {kind: {"expected": None, "reached": 0, "error": True} for kind in load_errors}
    scanned: dict[str, int] = {}
    skipped: list[str] = []
    order: dict[str, int] = {}
    for position, source in enumerate(sources):
        order[source.kind] = position
        progress.check_cancel()
        if not _source_wanted(source, rules):
            skipped.append(source.kind)
            progress.begin(source.kind, position, len(sources))
            continue
        progress.begin(source.kind, position, len(sources))
        cache: dict[tuple[str, str], list[Rule]] = {}
        count = 0
        reached = 0
        failed = False
        try:
            for index, row in source.rows():
                count += 1
                reached = max(reached, index + 1)
                if count % CANCEL_CHECK_EVERY == 0:
                    progress.check_cancel()
                    progress.rows(source.kind, count)
                view = RowView(
                    kind=source.kind,
                    collection=source.collection,
                    source_kind=source.source_kind,
                    index=index,
                    row=row,
                    artifact_type="file" if source.collection == "files" else None,
                )
                try:
                    _collect_context(view, ctx)
                except Exception as exc:  # a malformed row never stops the pass
                    record_error("context", exc)
                key = (source.collection, view.type)
                applicable = cache.get(key)
                if applicable is None:
                    applicable = [rule for rule in rules if rule.accepts(source.collection, source.source_kind, view.type)]
                    cache[key] = applicable
                for rule in applicable:
                    try:
                        result = rule.apply(view, ctx)
                    except Exception as exc:  # one rule's bug never stops the pass
                        record_error(rule.rule_id, exc)
                        continue
                    if result is not None:
                        collector.add(view.ref, rule.rule_id, result.evidence, result.note, view.type, result.grade)
        except (OSError, ValueError) as exc:  # unreadable / truncated stream: the tail of this source is unread
            failed = True
            errors.setdefault(f"source:{source.kind}", {"count": 1, "message": f"읽기 실패: {exc}"[:300]})
        scanned[source.kind] = count
        coverage[source.kind] = {"expected": source.total, "reached": reached, "error": failed}
        progress.rows(source.kind, count)
    progress.check_cancel()
    for rule in rules:
        try:
            for ref, result in rule.finalize(ctx):
                collector.add(ref, rule.rule_id, result.evidence, result.note, grade_cap=result.grade)
        except Exception as exc:
            record_error(rule.rule_id, exc)
    progress.check_cancel()
    return _write_outputs(
        out_dir,
        catalog=catalog,
        collector=collector,
        order=order,
        scanned=scanned,
        skipped=skipped,
        errors=errors,
        source_label=source_label,
        ctx=ctx,
        params=params,
        elapsed=time.monotonic() - started,
        coverage=coverage,
        files_block=files_block,
    )


def coverage_block(coverage: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    """``{complete, incomplete: [kind], sources: {kind: {expected, reached, error}}}``: a source is incomplete
    when it failed to load or read, or fewer records were reached than its ``record_count``."""
    incomplete = sorted(
        kind
        for kind, entry in coverage.items()
        if entry.get("error")
        or (isinstance(entry.get("expected"), int) and int(entry.get("reached") or 0) < int(entry["expected"]))
    )
    return {"complete": not incomplete, "incomplete": incomplete, "sources": {kind: dict(entry) for kind, entry in sorted(coverage.items())}}


def _write_outputs(
    out_dir: Path,
    *,
    catalog: Catalog,
    collector: _Collector,
    order: Mapping[str, int],
    scanned: Mapping[str, int],
    skipped: list[str],
    errors: Mapping[str, object],
    source_label: str,
    ctx: FlagContext,
    params: Mapping[str, object] | None,
    elapsed: float,
    coverage: Mapping[str, Mapping[str, object]] | None = None,
    files_block: Mapping[str, object] | None = None,
) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_rule: Counter[str] = Counter()
    by_grade: Counter[str] = Counter()
    rows_by_best: Counter[str] = Counter()
    by_kind: dict[str, dict[str, int]] = {}
    by_kind_type: dict[str, dict[str, dict[str, int]]] = {}
    ordered = sorted(collector.flags.items(), key=lambda item: (order.get(item[0][0], len(order)), item[0][0], item[0][1]))

    def write_flags(handle) -> None:
        for (kind, index), flags in ordered:
            items = sorted(flags.values(), key=lambda flag: (GRADE_RANK[str(flag["grade"])], str(flag["id"])))
            best = str(items[0]["grade"])
            kind_counts = by_kind.setdefault(kind, {"rows": 0, "flags": 0, **{grade: 0 for grade in GRADES}})
            kind_counts["rows"] += 1
            kind_counts[best] += 1
            kind_counts["flags"] += len(items)
            rows_by_best[best] += 1
            type_counts = by_kind_type.setdefault(kind, {}).setdefault(
                collector.types.get((kind, index), ""), {grade: 0 for grade in GRADES}
            )
            type_counts[best] += 1
            for flag in items:
                by_rule[str(flag["id"])] += 1
                by_grade[str(flag["grade"])] += 1
            line = {"kind": kind, "record_index": index, "flags": items}
            handle.write(json.dumps(line, ensure_ascii=False, default=json_default) + "\n")

    _write_atomic(out_dir / FLAGS_FILE_NAME, write_flags)
    coverage_summary = coverage_block(coverage or {})
    summary: dict[str, object] = {
        "version": SUMMARY_VERSION,
        # "partial": some source could not be read to its end -- its unread tail carries no flags.
        "status": "completed" if coverage_summary["complete"] else "partial",
        "coverage": coverage_summary,
        "source": source_label,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "catalog_version": catalog.version,
        "rule_versions": {spec.id: spec.version for spec in catalog.specs.values()},
        # What exactly produced these flags: catalogue version, SHA-256 per YAML file, rule versions.
        "rule_set": {
            "catalog_version": catalog.version,
            "files": dict(sorted(catalog.file_hashes.items())),
            "rule_versions": {spec.id: spec.version for spec in catalog.specs.values()},
        },
        "flagged_rows": len(ordered),
        "flag_count": sum(by_rule.values()),
        # Rows by their strongest flag (the grid's ``flag_grade`` filter counts these cumulatively).
        "rows_by_best_grade": {grade: rows_by_best.get(grade, 0) for grade in GRADES},
        "flags_by_grade": {grade: by_grade.get(grade, 0) for grade in GRADES},
        "by_rule": {rule_id: by_rule[rule_id] for rule_id in sorted(by_rule)},
        "by_kind": by_kind,
        # kind -> artifact_type ("" = unknown: a cross-row flag) -> rows by strongest grade (tree domain badges).
        "by_kind_type": by_kind_type,
        "policy_sources": policy_sources(ctx, eventlog_scanned=bool(scanned.get("eventlog"))),
        "rows_scanned": dict(scanned),
        "skipped_sources": skipped,
        "suppressed": dict(collector.suppressed),
        "rule_errors": dict(errors),
        "incident_window": {"start": ctx.incident_start.isoformat() if ctx.incident_start else None, "end": ctx.incident_end.isoformat() if ctx.incident_end else None},
        "params_override": dict(params or {}),
        "file_listing_known": ctx.file_paths_known,
        "files_context": dict(files_block) if files_block is not None else None,
        "host_names": sorted(ctx.hostnames)[:20],
        "elapsed_s": round(elapsed, 3),
        "limitation": (
            "특이사항은 조사 우선순위를 돕는 단서이며 판단이 아닙니다. 각 지표의 오탐 주의와 근거 필드를 확인하세요. "
            "provisional 지표는 실데이터 검증 전입니다."
        ),
    }

    def write_summary(handle) -> None:
        handle.write(json.dumps(summary, ensure_ascii=False, indent=2, default=json_default) + "\n")

    _write_atomic(out_dir / SUMMARY_FILE_NAME, write_summary)
    return summary
