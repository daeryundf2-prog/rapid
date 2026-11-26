"""Collect structured Unified Log events from offline evidence directories."""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Callable, Iterator
from itertools import islice
from pathlib import Path

from ..core.models import ArtifactRecord
from .unified_sidecars import SidecarError, Sidecars
from .unified_trace import parse_trace

FORMAT_REFERENCE = "https://github.com/mandiant/macos-UnifiedLogs/blob/main/ARCHITECTURE.md"
MAX_FILES = 1024
MAX_FILE_BYTES = 64 << 20
MAX_BYTES = 128 << 20
MAX_ROWS = 5000
MAX_DIRECTORY_ENTRIES = 65536
RAW_TREE = ("private", "var", "db", "diagnostics")
HEX_UUID = re.compile(r"[0-9a-fA-F]{32}")


class _Issue(ValueError):
    def __init__(self, reason: str, path: Path):
        super().__init__(reason)
        self.path = path


class _Budget:
    def __init__(self):
        self.visits = MAX_DIRECTORY_ENTRIES
        self.files = MAX_FILES
        self.bytes = MAX_BYTES

    def walk(self, root: Path, descend: Callable[[Path], bool]) -> Iterator[tuple[Path, bool]]:
        """Sort bounded directory batches and never follow evidence symlinks."""
        pending = [root]
        while pending:
            directory = pending.pop()
            children = []
            with os.scandir(directory) as entries:
                batch = list(islice(entries, self.visits + 1))
            if len(batch) > self.visits:
                raise _Issue("directory-entry-limit", directory)
            self.visits -= len(batch)
            for entry in sorted(batch, key=lambda item: item.name):
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    yield path, True
                    if descend(path):
                        children.append(path)
                elif entry.is_file(follow_symlinks=False):
                    yield path, False
            pending.extend(reversed(children))

    def read(self, path: Path) -> bytes:
        if self.files == 0:
            raise _Issue("file-count-limit", path)
        self.files -= 1
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags | getattr(os, "O_BINARY", 0)), "rb") as handle:
            member = os.fstat(handle.fileno())
            if not stat.S_ISREG(member.st_mode):
                raise _Issue("non-regular-file", path)
            if member.st_size > MAX_FILE_BYTES:
                raise _Issue("file-size-limit", path)
            if member.st_size > self.bytes:
                raise _Issue("byte-limit", path)
            self.bytes -= member.st_size
            data = handle.read(member.st_size)
            if len(data) != member.st_size:
                raise _Issue("short-read", path)
            return data


def _is_store(path: Path) -> bool:
    return path.suffix.lower() == ".logarchive" or path.parts[-4:] == RAW_TREE


def _stores(root: Path, budget: _Budget) -> Iterator[Path]:
    if _is_store(root):
        yield root
        return
    member = root
    for part in RAW_TREE:
        member = member / part
        if member.is_symlink() or not member.is_dir():
            break
    else:
        yield member
    for path, directory in budget.walk(root, lambda p: not _is_store(p) and p.name != "uuidtext"):
        if directory and _is_store(path) and path != root.joinpath(*RAW_TREE):
            yield path


def _record(path: Path, fields: dict) -> ArtifactRecord:
    details = fields.copy()
    diagnostic = details.pop("diagnostic", "")
    if diagnostic:
        details["reason"] = diagnostic
        details["format_reference"] = FORMAT_REFERENCE
    details.update(parser="macos-unified-log", parser_version="unified-log-v1",
                   coverage_status="partial", reportability="triage", source_path=str(path),
                   source_offset=details.pop("offset", 0), source_offset_unit="byte")
    kind = "diagnostic" if diagnostic else "event"
    return ArtifactRecord("macos-unified-log", "macos-unified-log-" + kind, str(path),
                          not diagnostic, details)


def _read_error(path: Path, exc: Exception) -> ArtifactRecord:
    if isinstance(exc, OSError) and exc.filename:
        path = Path(exc.filename)
    elif isinstance(exc, _Issue):
        path = exc.path
    reason = "read-error" if isinstance(exc, OSError) else str(exc)
    return _record(path, {"diagnostic": reason, "offset": getattr(exc, "offset", 0)})


class _Archive:
    def __init__(self, store: Path, evidence: Path, budget: _Budget):
        self.store = store
        self.budget = budget
        self.sidecars = Sidecars()
        self.attempted: set[tuple[str, str]] = set()
        self.issues: list[ArtifactRecord] = []
        self.string_paths: dict[tuple[str, str], str] = {}
        if store.parts[-4:] == RAW_TREE:
            sibling = store.with_name("uuidtext")
            self.string_roots = [sibling] if sibling.is_relative_to(evidence) else []
        else:
            self.string_roots = [store, store / "uuidtext"]

    def resolve(self, kind: str, uuid: str, address: int) -> tuple[str, str]:
        key = (kind, uuid.lower())
        if key not in self.attempted and HEX_UUID.fullmatch(uuid):
            self.attempted.add(key)
            self._load_strings(*key)
        return self.sidecars.resolve(kind, uuid, address)

    def _load_strings(self, kind: str, uuid: str) -> None:
        for root in self.string_roots:
            if root.is_symlink():
                continue
            prefixes = ["dsc"] if kind == "dsc" else [uuid[:2].upper(), uuid[:2]]
            name = uuid if kind == "dsc" else uuid[2:]
            for prefix in dict.fromkeys(prefixes):
                parent = root / prefix
                if parent.is_symlink():
                    continue
                for filename in dict.fromkeys((name.upper(), name)):
                    path = parent / filename
                    if path.is_symlink() or not path.is_file():
                        continue
                    try:
                        self.sidecars.add_strings(kind, uuid, self.budget.read(path))
                        self.string_paths[kind, uuid] = str(path)
                    except (OSError, _Issue, SidecarError) as exc:
                        self.issues.append(_read_error(path, exc))
                    return

    def records(self) -> Iterator[ArtifactRecord]:
        traces = []
        truncated = False

        # UUID dictionaries may contain thousands of files. Read only referenced UUIDs.
        def descend(path: Path) -> bool:
            return (not _is_store(path) and path.name not in {"dsc", "uuidtext"} and
                    not (path.parent == self.store and re.fullmatch(r"[0-9a-fA-F]{2}", path.name)))

        try:
            for path, directory in self.budget.walk(self.store, descend):
                if directory:
                    continue
                if path.suffix.lower() == ".tracev3":
                    if len(traces) == MAX_FILES:
                        if not truncated:
                            yield _record(path, {"diagnostic": "trace-file-limit"})
                            truncated = True
                    else:
                        traces.append(path)
                elif path.suffix.lower() == ".timesync":
                    try:
                        self.sidecars.add_timesync(self.budget.read(path), str(path))
                    except (OSError, _Issue, SidecarError) as exc:
                        yield _read_error(path, exc)
        except (OSError, _Issue) as exc:
            yield _read_error(self.store, exc)

        for path in traces:
            try:
                data = self.budget.read(path)
            except (OSError, _Issue) as exc:
                yield _read_error(path, exc)
                if self.budget.files == 0:
                    break
                continue
            for fields in parse_trace(data, self.resolve, self.sidecars.wall_time):
                yield from self.issues
                self.issues.clear()
                string_path = self.string_paths.get((fields.get("format_source"), fields.get("format_uuid")))
                if string_path:
                    fields["format_source_path"] = string_path
                if "continuous_time" in fields:
                    fields["continuous_time_raw"] = str(fields["continuous_time"])
                if "timestamp" in fields:
                    source, offset = self.sidecars.clock_source(fields["boot_uuid"], fields["continuous_time"])
                    fields.update(timesync_source_path=source, timesync_source_offset=offset)
                yield _record(path, fields)
            # An empty Firehose can reference a damaged process dictionary
            # without producing an event on which to flush its diagnostic.
            yield from self.issues
            self.issues.clear()


class UnifiedLogProvider:
    name = "macos-unified-log"
    collector_kind = "macos-unified-log"
    description = "Structured events from offline macOS Unified Log archives"
    target_platform = "macos"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterator[ArtifactRecord]:
        if root.is_symlink() or not root.is_dir():
            return
        root = root.resolve()
        # Never let offline discovery descend into the running Mac's log stores.
        if sys.platform == "darwin":
            for live in (Path("/private/var/db"), Path("/System/Volumes/Data/private/var/db")):
                if (root in live.parents or root == live or root.is_relative_to(live / "diagnostics")
                        or root.is_relative_to(live / "uuidtext")):
                    return
        budget = _Budget()
        count = 0
        try:
            for store in _stores(root, budget):
                for row in _Archive(store, root, budget).records():
                    if count == MAX_ROWS:
                        yield _record(Path(row.path), {"diagnostic": "row-limit",
                                                      "offset": row.details["source_offset"]})
                        return
                    yield row
                    count += 1
        except (OSError, _Issue) as exc:
            yield _read_error(root, exc)
