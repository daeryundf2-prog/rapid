"""Run identity times for the console (R7 L1: C-G2 · C-G3 · C-D5 · P6).

One representative start / end per run, so 랜딩 · 처리 · 접수 · 케이스 선택기 print the same
instant: the run's own progress file (``rapidtriage-run-progress.json`` ``started_at`` /
``completed_at``, written by the process that produced the folder) when it belongs to the job,
else the job record -- except an imported run, whose job times are the import time (they say
when the folder was added, not when it was processed): without a progress file it has no
processing times at all and the console prints "—" for its duration.

Also the evidence clock the console needs without reading the outputs: the evidence system's
time zone (``summary.disclosures.timezone.evidence_timezone``) and the newest evidence time
(``timeline_max_ts``) that anchors the relative date presets ("증거 기준 최근 7일") -- read from the
saved timeline index (``rapidtriage-timeline-index.bin``, its time column only) when it matches the
timeline, else the newest file time of the input fingerprint. Everything here only reads.
"""

from __future__ import annotations

import datetime as dt
import json
import struct
import threading
from array import array
from collections.abc import Mapping
from pathlib import Path

from ...core.jobs import RunJob, progress_belongs_to_job
from ...core.run.progress import RUN_PROGRESS_FILE_NAME
from .index_cache import head_tail_digest
from .timeline_index import _HEADER_LEN, INDEX_MAGIC, MISSING, _header, index_path_for

#: Newest evidence time accepted: later values (clock junk, the year 2100 sentinels) are ignored.
FUTURE_SLACK = dt.timedelta(days=1)
LATEST_ACCEPTED = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)

_LOCK = threading.Lock()
_PROGRESS_CACHE: dict[str, tuple[tuple[int, int], dict[str, object]]] = {}
_TIMELINE_MAX_CACHE: dict[str, tuple[tuple[int, int, int, int], str | None]] = {}
_CACHE_MAX = 256


def _stat_key(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def _remember(cache: dict, key: str, value: object) -> None:
    with _LOCK:
        if len(cache) >= _CACHE_MAX:
            cache.pop(next(iter(cache)))
        cache[key] = value


def progress_times(output_dir: Path | None) -> dict[str, object] | None:
    """``status`` / ``started_at`` / ``completed_at`` of the folder's progress file (cached by size + mtime)."""
    if output_dir is None:
        return None
    path = Path(output_dir) / RUN_PROGRESS_FILE_NAME
    stamp = _stat_key(path)
    if stamp is None:
        return None
    key = str(path)
    with _LOCK:
        cached = _PROGRESS_CACHE.get(key)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, Mapping):
        return None
    times = {name: payload.get(name) for name in ("status", "started_at", "completed_at")}
    _remember(_PROGRESS_CACHE, key, (stamp, times))
    return times


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def run_times(job: RunJob) -> dict[str, object]:
    """``{started_at, completed_at, source, imported_at}`` -- the run's representative times.

    ``source``: ``run-progress`` (the folder's progress file), ``job`` (the job record of a run
    started here) or ``none`` (an imported run without a progress file: no processing times).
    ``imported_at`` is the import time of an imported run (``null`` otherwise).
    """
    imported = job.origin == "imported"
    output_dir = None
    if not job.superseded_by:
        try:
            output_dir = job.output_dir()
        except (OSError, RuntimeError, ValueError):
            output_dir = None
    progress = progress_times(output_dir)
    # An imported folder's progress file is older than the import by definition; a run started
    # here must have written it itself (a retry into the same folder rewrites it).
    usable = progress is not None and (imported or progress_belongs_to_job(progress, job))
    started = _text(progress.get("started_at")) if usable and progress else None
    completed = _text(progress.get("completed_at")) if usable and progress else None
    if started:
        source = "run-progress"
        if not completed and not imported and job.status not in {"queued", "running"}:
            completed = job.completed_at
    elif imported:
        source = "none"
        completed = None
    else:
        source = "job"
        started = job.started_at or job.created_at
        completed = job.completed_at
    return {
        "started_at": started,
        "completed_at": completed,
        "source": source,
        "imported_at": job.created_at if imported else None,
    }


def evidence_timezone(summary: Mapping[str, object] | None) -> dict[str, object] | None:
    """The evidence system's time zone the run read (registry), ``None`` when not recorded."""
    if not isinstance(summary, Mapping):
        return None
    disclosures = summary.get("disclosures")
    timezone = disclosures.get("timezone") if isinstance(disclosures, Mapping) else None
    found = timezone.get("evidence_timezone") if isinstance(timezone, Mapping) else None
    if not isinstance(found, Mapping):
        return None
    name = _text(found.get("name"))
    bias = found.get("bias_minutes")
    if name is None and not isinstance(bias, int):
        return None
    return {
        "name": name,
        "bias_minutes": bias if isinstance(bias, int) and not isinstance(bias, bool) else None,
        "status": _text(timezone.get("evidence_timezone_status")) if isinstance(timezone, Mapping) else None,
    }


def _latest_accepted(now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    limit = min(now + FUTURE_SLACK, LATEST_ACCEPTED)
    return int(limit.timestamp() * 1_000_000)


def _iso_from_us(value: int) -> str:
    return (dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=value)).isoformat()


def timeline_index_max(timeline_path: Path, *, now: dt.datetime | None = None) -> str | None:
    """Newest accepted row time of a saved timeline index that matches ``timeline_path`` (time column only)."""
    stamp = _stat_key(timeline_path)
    index_path = index_path_for(timeline_path)
    index_stamp = _stat_key(index_path)
    if stamp is None or index_stamp is None:
        return None
    key = str(index_path)
    signature = (*stamp, *index_stamp)
    with _LOCK:
        cached = _TIMELINE_MAX_CACHE.get(key)
    if cached is not None and cached[0] == signature:
        return cached[1]
    digest = head_tail_digest(timeline_path)
    found: str | None = None
    try:
        with index_path.open("rb") as handle:
            if handle.read(len(INDEX_MAGIC)) == INDEX_MAGIC:
                (length,) = _HEADER_LEN.unpack(handle.read(_HEADER_LEN.size))
                header = json.loads(handle.read(length).decode("utf-8")) if length <= 65536 else None
                total = header.get("count") if isinstance(header, dict) else None
                if isinstance(total, int) and total > 0 and header == _header(total, stamp, digest):
                    epoch = array("q")
                    epoch.fromfile(handle, total)
                    limit = _latest_accepted(now)
                    best = max((value for value in epoch if value != MISSING and value < limit), default=None)
                    found = _iso_from_us(best) if best is not None else None
    except (OSError, ValueError, EOFError, struct.error, UnicodeDecodeError, OverflowError):
        found = None
    _remember(_TIMELINE_MAX_CACHE, key, (signature, found))
    return found


def fingerprint_latest(summary: Mapping[str, object] | None, *, now: dt.datetime | None = None) -> str | None:
    """Newest file time of the input fingerprint (``safety.input_fingerprint.summary.latest_mtime_epoch``)."""
    if not isinstance(summary, Mapping):
        return None
    node: object = summary
    for name in ("safety", "input_fingerprint", "summary", "latest_mtime_epoch"):
        node = node.get(name) if isinstance(node, Mapping) else None
    if not isinstance(node, (int, float)) or isinstance(node, bool) or node <= 0:
        return None
    try:
        value = int(node * 1_000_000)
    except (OverflowError, ValueError):
        return None
    return _iso_from_us(value) if value < _latest_accepted(now) else None


def timeline_max(job: RunJob, *, now: dt.datetime | None = None) -> tuple[str | None, str | None]:
    """``(timeline_max_ts, source)``: ``timeline-index`` / ``evidence-mtime`` / ``(None, None)``."""
    summary = job.summary if isinstance(job.summary, Mapping) else None
    outputs = summary.get("outputs") if summary else None
    timeline = outputs.get("timeline") if isinstance(outputs, Mapping) else None
    if isinstance(timeline, str) and timeline:
        found = timeline_index_max(Path(timeline), now=now)
        if found:
            return found, "timeline-index"
    found = fingerprint_latest(summary, now=now)
    return (found, "evidence-mtime") if found else (None, None)


def run_identity_fields(job: RunJob, *, include_timeline_max: bool = False) -> dict[str, object]:
    """Fields the run list / run detail add for the console (cheap: no output is parsed)."""
    fields: dict[str, object] = {
        "run_times": run_times(job),
        "evidence_timezone": evidence_timezone(job.summary),
    }
    if include_timeline_max:
        value, source = timeline_max(job)
        fields["timeline_max_ts"] = value
        fields["timeline_max_source"] = source
    return fields
