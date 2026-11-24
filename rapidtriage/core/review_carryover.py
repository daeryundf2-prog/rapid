"""Carry an earlier run's review decisions into its replay (``run --replay-audit``).

A colleague replays a run from its audit on another machine or another copy
of the selection; the analysis repeats, but the examiner's review decisions
(case-JSON bookmarks and case-DB review marks: status, tags, note, report
flag) live beside the original output. :func:`carry_review_decisions` takes
each decision's cited output row from the original run, finds the same row in
the replay -- equal content once the original input root and output folder
are read as the replay's -- and records the decision there: a mark in the
replay's case DB, a bookmark in its case JSON. A row that changed, vanished or
cannot be told apart is not carried and is listed with the reason in
``rapidtriage-review-carryover.json``.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from collections.abc import Iterator, Mapping
from pathlib import Path

from .artifact_profiles import iter_payload_records
from .case import (
    CASE_SOURCE_EXTRA_ROWS,
    CASE_SOURCE_ROWS,
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    load_source_payload,
    resolve_case_source_row,
    save_case_payload,
)
from .case_db import CaseDatabase, CaseDatabaseError
from .case_db.run_locator import ACTIVE_MARK_SQL, RunLocatorIndex, location_source
from .run.persist import CASE_DB_FILE_NAME, run_case_id

CARRYOVER_FILE_NAME = "rapidtriage-review-carryover.json"
CASE_JSON_FILE_NAME = "rapidtriage-case.json"
RUN_SUMMARY_FILE_NAME = "rapidtriage-run-summary.json"


class _Rows:
    """Source payloads of one run, read once, with paths normalized for comparison."""

    def __init__(self, output_dir: Path, recorded_output_dir: str, root: str) -> None:
        self.output_dir = output_dir
        self.recorded_output_dir = recorded_output_dir
        # Output folder first: it may sit inside the input root.
        prefixes = ((recorded_output_dir, "<OUTPUT>"), (str(output_dir), "<OUTPUT>"), (root, "<ROOT>"))
        self.replacements = [(prefix, token) for prefix, token in prefixes if prefix]
        self.payloads: dict[Path, dict[str, object]] = {}

    def local(self, raw: str) -> Path:
        """A path the run recorded, read under where its output folder is now."""
        path = Path(raw)
        if self.recorded_output_dir:
            try:
                return self.output_dir / path.relative_to(self.recorded_output_dir)
            except ValueError:
                pass
        return path

    def payload(self, path: Path) -> dict[str, object]:
        if path not in self.payloads:
            payload = load_source_payload(path)
            if payload.get("records_file"):
                payload["records_path"] = str(path.parent / str(payload["records_file"]))
            self.payloads[path] = payload
        return self.payloads[path]

    def row(self, path: Path, pointer: str) -> dict[str, object]:
        payload = self.payload(path)
        return resolve_case_source_row(payload, source_command=str(payload.get("command") or ""), source_pointer=pointer)

    def iter_rows(self, path: Path, collection: str) -> Iterator[tuple[int, object]]:
        payload = self.payload(path)
        if payload.get("command") == "artifacts" and payload.get("records_path"):
            yield from enumerate(iter_payload_records(payload))
            return
        rows = payload.get(collection)
        yield from enumerate(rows if isinstance(rows, list) else [])

    def identity(self, row: object) -> str:
        return json.dumps(self._normalize(row), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)

    def _normalize(self, value: object) -> object:
        if isinstance(value, str):
            for prefix, token in self.replacements:
                value = value.replace(prefix, token)
            return value
        if isinstance(value, Mapping):
            copy_times = value.get("time_origin") == "acquisition-copy"
            return {
                self._normalize(key): self._normalize(item)
                for key, item in value.items()
                if not _location_bound(str(key), copy_times)
            }
        if isinstance(value, list):
            return [self._normalize(item) for item in value]
        return value


# Row fields that differ between two copies of the same selection: digests the
# parsers derive over row text that includes absolute paths, and the host
# file times of the acquisition copy (icat/copy writes new ones).
DERIVED_DIGEST_KEY_RE = re.compile(r"^(artifact_id|source_row_hashes|source_rows_head_hash)$|manifest_(hash|sha256)$")
COPY_TIME_KEYS = frozenset({"source_file_atime", "source_file_ctime", "source_file_mtime"})


def _location_bound(key: str, copy_times: bool) -> bool:
    if DERIVED_DIGEST_KEY_RE.search(key) or key in COPY_TIME_KEYS:
        return True
    return copy_times and key in ("modified_at", "modified_epoch")


def carry_review_decisions(
    *,
    original_output: Path,
    recorded_output_dir: str,
    recorded_root: str,
    replay_output: Path,
    replay_summary: Mapping[str, object],
) -> dict[str, object]:
    """Carry the original run's review decisions into the replay and write the record.

    ``original_output`` is where the audited run's folder is now (the audit's
    folder); ``recorded_output_dir``/``recorded_root`` are the output folder and
    scan root the audit recorded."""
    original = _Rows(original_output, recorded_output_dir, recorded_root)
    replay = _Rows(replay_output, str(replay_output), str(replay_summary.get("scan_scope_root") or replay_summary.get("root") or ""))
    replay_outputs = replay_summary.get("outputs") if isinstance(replay_summary.get("outputs"), Mapping) else {}
    original_outputs = _original_outputs(original_output)
    marks = _carry_case_db_marks(original, replay, original_outputs, replay_outputs, replay_output)
    bookmarks = _carry_case_bookmarks(original, replay, original_output, replay_output)
    record = {
        "command": "review-carryover",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "original_output_dir": str(original_output),
        "recorded_output_dir": recorded_output_dir,
        "replay_output_dir": str(replay_output),
        "summary": {"case_db_marks": _counts(marks), "case_bookmarks": _counts(bookmarks)},
        "case_db_marks": marks,
        "case_bookmarks": bookmarks,
    }
    (replay_output / CARRYOVER_FILE_NAME).write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return record


def _counts(entries: list[dict[str, object]]) -> dict[str, int]:
    carried = sum(1 for entry in entries if entry.get("carried"))
    return {"found": len(entries), "carried": carried, "not_carried": len(entries) - carried}


def _original_outputs(original_output: Path) -> Mapping[str, object]:
    try:
        summary = json.loads((original_output / RUN_SUMMARY_FILE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    outputs = summary.get("outputs") if isinstance(summary, Mapping) else None
    return outputs if isinstance(outputs, Mapping) else {}


def _find_row(
    original: _Rows, replay: _Rows, original_path: Path, replay_path: Path, pointer: str
) -> tuple[str | None, str]:
    """The replay pointer of the original row (same pointer first), or ``None`` and the reason."""
    try:
        wanted = original.identity(original.row(original_path, pointer))
    except (OSError, CaseBookmarkError) as exc:
        return None, f"original-row-unreadable: {exc}"
    try:
        if replay.identity(replay.row(replay_path, pointer)) == wanted:
            return pointer, "same-pointer"
    except (OSError, CaseBookmarkError):
        pass
    parts = pointer.split("/")
    try:
        payload = replay.payload(replay_path)
    except (OSError, CaseBookmarkError) as exc:
        return None, f"replay-output-unreadable: {exc}"
    command = str(payload.get("command") or "")
    if len(parts) != 3 or parts[1] not in (CASE_SOURCE_ROWS.get(command), *CASE_SOURCE_EXTRA_ROWS.get(command, ())):
        return None, "row-changed"
    matches = [index for index, row in replay.iter_rows(replay_path, parts[1]) if replay.identity(row) == wanted]
    if len(matches) == 1:
        return f"/{parts[1]}/{matches[0]}", "pointer-corrected"
    return None, "row-ambiguous" if matches else "row-changed"


def _carry_case_db_marks(
    original: _Rows,
    replay: _Rows,
    original_outputs: Mapping[str, object],
    replay_outputs: Mapping[str, object],
    replay_output: Path,
) -> list[dict[str, object]]:
    database_path = original.output_dir / CASE_DB_FILE_NAME
    if not database_path.is_file():
        return []
    try:
        source = sqlite3.connect(f"{database_path.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    translated = {name: str(original.local(str(raw))) for name, raw in original_outputs.items() if raw}
    entries: list[dict[str, object]] = []
    try:
        try:
            rows = source.execute(
                "SELECT case_id, citation_id, target_type, target_id, status, verification_status, tags_json, note, "
                "include_in_report, reviewer, assignee, priority, due_at "
                f"FROM review_mark WHERE {ACTIVE_MARK_SQL} ORDER BY id"
            ).fetchall()
        except sqlite3.Error:
            return []
        if not rows:
            return []
        replay_db = replay_output / CASE_DB_FILE_NAME
        replay_case = run_case_id(replay_output)
        target_db = CaseDatabase(replay_db) if replay_db.is_file() else None
        replay_connection = sqlite3.connect(f"{replay_db.resolve().as_uri()}?mode=ro", uri=True) if target_db else None
        indexes: dict[str, RunLocatorIndex] = {}
        try:
            replay_index = (
                RunLocatorIndex(replay_connection, replay_case, replay_outputs, output_dir=replay_output)
                if replay_connection is not None
                else None
            )
            for row in rows:
                case_id, citation_id, target_type, target_id = (str(value) for value in row[:4])
                entry: dict[str, object] = {
                    "case_id": case_id,
                    "citation_id": citation_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "note": str(row[7] or ""),
                    "include_in_report": bool(row[8]),
                    "carried": False,
                }
                entries.append(entry)
                if case_id not in indexes:
                    indexes[case_id] = RunLocatorIndex(source, case_id, translated, output_dir=original.output_dir)
                location = indexes[case_id].locate(target_type, target_id)
                cited = location_source(location) if location is not None else None
                if cited is None:
                    entry["reason"] = "original-row-not-citable"
                    continue
                output_name, pointer = cited
                entry["locator"] = dict(location or {})
                if replay_index is None or target_db is None:
                    entry["reason"] = "replay-case-db-missing"
                    continue
                if output_name not in translated or output_name not in replay_outputs:
                    entry["reason"] = f"output-missing: {output_name}"
                    continue
                new_pointer, how = _find_row(
                    original, replay, Path(translated[output_name]), Path(str(replay_outputs[output_name])), pointer
                )
                if new_pointer is None:
                    entry["reason"] = how
                    continue
                resolved = replay_index.resolve(str(location["collection"]), new_pointer, str(location.get("kind") or ""))
                if resolved is None:
                    entry["reason"] = "replay-row-not-in-case-db"
                    continue
                try:
                    tags = json.loads(str(row[6] or "[]"))
                except json.JSONDecodeError:
                    tags = []
                try:
                    target_db.mark_review(
                        case_id=replay_case,
                        target_type=resolved[0],
                        target_id=resolved[1],
                        status=str(row[4] or "unreviewed"),
                        verification_status=str(row[5] or "unverified"),
                        tags=[str(tag) for tag in tags] if isinstance(tags, list) else [],
                        note=str(row[7] or ""),
                        include_in_report=bool(row[8]),
                        reviewer=str(row[9] or ""),
                        assignee=str(row[10] or ""),
                        priority=str(row[11] or "normal"),
                        due_at=str(row[12] or ""),
                    )
                except CaseDatabaseError as exc:
                    entry["reason"] = f"replay-mark-failed: {exc}"
                    continue
                entry.update(carried=True, match=how, replay_locator=new_pointer, replay_case_id=replay_case)
        finally:
            if replay_connection is not None:
                replay_connection.close()
    finally:
        source.close()
    return entries


def _carry_case_bookmarks(original: _Rows, replay: _Rows, original_output: Path, replay_output: Path) -> list[dict[str, object]]:
    case_path = original_output / CASE_JSON_FILE_NAME
    if not case_path.is_file():
        return []
    try:
        case_payload = load_case_payload(case_path)
    except (OSError, CaseBookmarkError):
        return []
    replay_case_path = replay_output / CASE_JSON_FILE_NAME
    entries: list[dict[str, object]] = []
    for bookmark in case_payload.get("bookmarks") or []:
        if not isinstance(bookmark, Mapping):
            continue
        reference = bookmark.get("reference") if isinstance(bookmark.get("reference"), Mapping) else {}
        review = bookmark.get("review") if isinstance(bookmark.get("review"), Mapping) else {}
        entry: dict[str, object] = {
            "bookmark_id": str(bookmark.get("bookmark_id") or ""),
            "note": str(bookmark.get("note") or ""),
            "include_in_report": bool(review.get("include_in_report")),
            "carried": False,
        }
        entries.append(entry)
        raw_file, pointer = str(reference.get("file") or ""), str(reference.get("pointer") or "")
        if not raw_file or not pointer:
            entry["reason"] = "original-reference-missing"
            continue
        original_path = original.local(raw_file)
        try:
            relative = original_path.relative_to(original_output)
        except ValueError:
            entry["reason"] = "original-source-outside-output"
            continue
        replay_path = replay_output / relative
        new_pointer, how = _find_row(original, replay, original_path, replay_path, pointer)
        if new_pointer is None:
            entry["reason"] = how
            continue
        try:
            payload = create_or_update_case_payload(
                replay_case_path,
                case_id=str(case_payload.get("case_id") or "") or None,
                title=str(case_payload.get("title") or "") or None,
                source_path=replay_path,
                source_pointer=new_pointer,
                bookmark_id=str(bookmark.get("bookmark_id") or "") or None,
                tags=[str(tag) for tag in bookmark.get("tags") or []],
                note=str(bookmark.get("note") or ""),
                review_status=str(review.get("status") or "unreviewed"),
                include_in_report=bool(review.get("include_in_report")),
            )
        except (OSError, CaseBookmarkError) as exc:
            entry["reason"] = f"replay-bookmark-failed: {exc}"
            continue
        save_case_payload(replay_case_path, payload)
        entry.update(carried=True, match=how, replay_pointer=new_pointer)
    return entries
