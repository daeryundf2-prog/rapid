"""Extraction coverage-gap recovery for Sleuth Kit ``tsk_recover`` runs.

``tsk_recover`` (Sleuth Kit 4.15 win32) leaves three classes of allocated
NTFS content out of its output tree:

* files whose extraction path reaches Windows ``MAX_PATH`` (the win32 build
  calls ``CreateFileW`` without the ``\\\\?\\`` prefix, logs
  ``Error Creating File (...)`` and moves on) - real content loss;
* zero-byte ``$DATA`` files - no content, but existence and timestamps are
  evidence;
* alternate data streams (``name:stream``) such as ``Zone.Identifier``.

This module parses the full ``tsk_recover`` stderr log, produces one
``fls -rpl`` listing right after recovery and uses it - trusting inode, attribute
id and ``$DATA`` size, never the printed name - to recover long-path files and
ADS streams with ``icat`` and to list zero-byte files. Results are sidecar files
next to the extraction root so the files index and artifact providers can merge
them without re-walking the image.

Name reliability: TSK win32 prints names in the ANSI code page (cp949 on Korean
Windows). Names are persisted as UTF-8 with ``surrogateescape`` (lossless round
trip of the raw bytes) and a best-effort ``name_hint`` decoded via UTF-8 then the
legacy code page. Characters not representable in that code page are printed by
TSK as ``?`` (an invalid NTFS name character), so a ``?`` in a hint marks a lossy
name.
"""

from __future__ import annotations

import bisect
import datetime as dt
import fnmatch
import hashlib
import json
import locale
import os
import re
import subprocess
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

E01_EXTRACT_DIR_NAME = "fs"
E01_LEGACY_EXTRACT_DIR_NAMES = ("filesystem",)
E01_STAGE_STATUS_NAME = "rapidtriage-e01-stage-status.json"

TSK_RECOVER_STDERR_LOG_NAME = "tsk_recover-stderr.log"
EXTRACTION_FAILURES_NAME = "extraction-failures.json"
FLS_LISTING_NAME = "fls-rpl.txt"
EXTRACTION_INODE_MAP_NAME = "extraction-inode-map.jsonl"
LONG_PATH_DIR_NAME = "long"
LONG_PATH_MAP_NAME = "long-path-map.json"
ZERO_BYTE_LISTING_NAME = "zero-byte-listing.json"
ADS_DIR_NAME = "ads"
ADS_MAP_NAME = "ads-map.json"
GAP_RECOVERY_SUMMARY_NAME = "extraction-gap-recovery.json"

GAP_RECOVERY_PROFILE_VERSION = "e01-extraction-gap-recovery-v1"
WINDOWS_MAX_PATH = 260
WINDOWS_MAX_DIR_PATH = 248
LONG_PATH_FALLBACK_MAX_FILES = 50_000
LONG_PATH_FALLBACK_MAX_BYTES = 20 * 1024 * 1024 * 1024
ADS_STREAM_MAX_BYTES = 1024 * 1024
ADS_MAX_STREAMS = 50_000
ICAT_TIMEOUT_SECONDS = 600
FLS_TIMEOUT_SECONDS = 4 * 3600

LONG_PATH_SOURCE_ID = "icat-long-path-fallback"
ZERO_BYTE_SOURCE_ID = "fls-listing-zero-byte"
ADS_SOURCE_ID = "icat-ads-stream"

GAP_RECOVERY_DISABLE_ENV = "RAPIDTRIAGE_E01_GAP_RECOVERY"
GAP_RECOVERY_WORKERS_ENV = "RAPIDTRIAGE_E01_GAP_WORKERS"
FLS_LEGACY_ENCODING_ENV = "RAPIDTRIAGE_FLS_LEGACY_ENCODING"

NTFS_METAFILE_NAMES = frozenset(
    {
        "$MFT",
        "$MFTMirr",
        "$LogFile",
        "$Volume",
        "$AttrDef",
        "$Bitmap",
        "$Boot",
        "$BadClus",
        "$Secure",
        "$UpCase",
        "$Extend",
        "$OrphanFiles",
    }
)

StreamRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess]

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def extended_length_path(path: Path | str) -> str:
    """Return a ``\\\\?\\`` extended-length form of an absolute Windows path.

    On non-Windows hosts the path is returned unchanged. Extended paths bypass
    ``MAX_PATH`` so recovering a long-path file cannot itself hit the limit.
    """
    text = str(path)
    if os.name != "nt":
        return text
    if text.startswith("\\\\?\\"):
        return text
    absolute = os.path.abspath(text)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def windows_path_length(text: str) -> int:
    """UTF-16 code-unit length, which is what ``MAX_PATH`` counts."""
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2


def normalize_relative_key(path: str) -> str:
    """Comparison key for relative paths: '/' separators, NFC, casefolded."""
    cleaned = path.replace("\\", "/").strip("/")
    return unicodedata.normalize("NFC", cleaned).casefold()


def legacy_listing_encoding() -> str:
    override = os.environ.get(FLS_LEGACY_ENCODING_ENV, "").strip()
    if override:
        return override
    getencoding = getattr(locale, "getencoding", None)
    encoding = getencoding() if callable(getencoding) else locale.getpreferredencoding(False)
    if not encoding or encoding.lower().replace("-", "") in {"utf8", "ascii", "ansi_x3.41968"}:
        return "cp1252"
    return encoding


# --------------------------------------------------------------------------
# fls -rpl listing
# --------------------------------------------------------------------------

_FLS_META_RE = re.compile(
    rb"^(?P<name_type>\S)/(?P<meta_type>\S+)\s+(?P<deleted>\*\s+)?"
    rb"(?P<inode>\d+)(?:-(?P<attr_type>\d+)-(?P<attr_id>\d+))?\s*(?P<realloc>\(realloc\))?\s*$"
)
_FLS_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?\s*(?:\((?P<tz>[^)]*)\)?)?"
)


@dataclass(frozen=True, slots=True)
class FlsEntry:
    name_type: str
    meta_type: str
    deleted: bool
    realloc: bool
    inode: int
    attr_type: int | None
    attr_id: int | None
    path: str
    name_hint: str
    name_lossy: bool
    size: int | None
    mtime: str | None
    atime: str | None
    ctime: str | None
    crtime: str | None

    @property
    def address(self) -> str:
        if self.attr_type is None or self.attr_id is None:
            return str(self.inode)
        return f"{self.inode}-{self.attr_type}-{self.attr_id}"

    @property
    def is_ads(self) -> bool:
        # NTFS forbids ':' in file names, so a colon in the leaf is a stream.
        return ":" in self.name_hint.rsplit("/", 1)[-1]

    @property
    def is_regular(self) -> bool:
        return self.name_type == "r" or (self.name_type == "-" and self.meta_type == "r")

    @property
    def is_directory(self) -> bool:
        return self.name_type == "d"

    @property
    def is_system_metafile(self) -> bool:
        head = self.name_hint.split("/", 1)[0].split(":", 1)[0]
        return head in NTFS_METAFILE_NAMES

    @property
    def is_orphan(self) -> bool:
        return self.name_hint.startswith("$OrphanFiles/") or self.name_hint == "$OrphanFiles"

    @property
    def is_allocated_file(self) -> bool:
        return self.is_regular and not self.deleted and not self.is_orphan

    @property
    def host_hint(self) -> str:
        if not self.is_ads:
            return self.name_hint
        parent, _, leaf = self.name_hint.rpartition("/")
        host_leaf = leaf.split(":", 1)[0]
        return f"{parent}/{host_leaf}" if parent else host_leaf

    @property
    def stream_name(self) -> str:
        if not self.is_ads:
            return ""
        return self.name_hint.rsplit("/", 1)[-1].split(":", 1)[1]

    def timestamps(self) -> dict[str, str | None]:
        return {"mtime": self.mtime, "atime": self.atime, "ctime": self.ctime, "crtime": self.crtime}


def decode_listing_name(raw: bytes, legacy_encoding: str | None = None) -> tuple[str, str, bool]:
    """Return (surrogateescape path, best-effort name hint, lossy flag)."""
    path = raw.decode("utf-8", errors="surrogateescape")
    try:
        hint = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            hint = raw.decode(legacy_encoding or legacy_listing_encoding())
        except (UnicodeDecodeError, LookupError):
            hint = raw.decode("utf-8", errors="replace")
    hint = unicodedata.normalize("NFC", hint)
    return path, hint, "?" in hint or "�" in hint


def parse_fls_timestamp(value: str) -> str | None:
    text = value.strip()
    if not text or text.startswith("0000-00-00"):
        return None
    match = _FLS_TIME_RE.match(text)
    if not match:
        return None
    date, time = match.group("date"), match.group("time")
    try:
        # Validate without strptime (hot path: four columns x ~10^6 rows).
        dt.datetime(int(date[0:4]), int(date[5:7]), int(date[8:10]), int(time[0:2]), int(time[3:5]), int(time[6:8]))
    except ValueError:
        return None
    tz = (match.group("tz") or "").strip().upper()
    suffix = "+00:00" if tz in {"UTC", "GMT", "UTC+0", "GMT+0"} else ""
    return f"{date}T{time}{suffix}"


def parse_fls_line(line: bytes, legacy_encoding: str | None = None) -> FlsEntry | None:
    line = line.rstrip(b"\r\n")
    meta, sep, rest = line.partition(b":\t")
    if not sep:
        return None
    match = _FLS_META_RE.match(meta)
    if not match:
        return None
    fields = rest.split(b"\t")
    if len(fields) >= 8:
        raw_name = b"\t".join(fields[:-7])
        tail = [field.decode("ascii", errors="replace") for field in fields[-7:]]
    else:
        raw_name = rest
        tail = []
    if not raw_name:
        return None
    path, hint, lossy = decode_listing_name(raw_name, legacy_encoding)
    size: int | None = None
    times: list[str | None] = [None, None, None, None]
    if tail:
        times = [parse_fls_timestamp(value) for value in tail[:4]]
        try:
            size = int(tail[4])
        except ValueError:
            size = None
    attr_type = match.group("attr_type")
    attr_id = match.group("attr_id")
    return FlsEntry(
        name_type=match.group("name_type").decode("ascii", errors="replace"),
        meta_type=match.group("meta_type").decode("ascii", errors="replace"),
        deleted=bool(match.group("deleted")),
        realloc=bool(match.group("realloc")),
        inode=int(match.group("inode")),
        attr_type=int(attr_type) if attr_type else None,
        attr_id=int(attr_id) if attr_id else None,
        path=path,
        name_hint=hint,
        name_lossy=lossy,
        size=size,
        mtime=times[0],
        atime=times[1],
        ctime=times[2],
        crtime=times[3],
    )


def iter_fls_listing(path: Path, legacy_encoding: str | None = None) -> Iterator[FlsEntry]:
    encoding = legacy_encoding or legacy_listing_encoding()
    with open(extended_length_path(path), "rb") as handle:
        for line in handle:
            entry = parse_fls_line(line, encoding)
            if entry is not None:
                yield entry


def parse_fls_listing_bytes(data: bytes, legacy_encoding: str | None = None) -> list[FlsEntry]:
    encoding = legacy_encoding or legacy_listing_encoding()
    entries = []
    for line in data.splitlines():
        entry = parse_fls_line(line, encoding)
        if entry is not None:
            entries.append(entry)
    return entries


def classify_listing_entry(entry: FlsEntry) -> str:
    """Coverage class of an fls row: ads, zero-byte, content, metafile, other."""
    if entry.is_directory:
        return "directory"
    if not entry.is_regular:
        return "other"
    if entry.deleted or entry.is_orphan:
        return "deleted"
    if entry.is_system_metafile:
        return "metafile"
    if entry.is_ads:
        return "ads"
    if entry.size is None:
        return "size-unknown"
    if entry.size == 0:
        return "zero-byte"
    return "content"


# --------------------------------------------------------------------------
# tsk_recover stderr
# --------------------------------------------------------------------------

_STDERR_TOKEN_RE = re.compile(
    r"Error Creating File \((?P<create>.*?)\)(?=Error |\r?\n|$)"
    r"|Error writing file (?P<write>[^\r\n]*?)(?=Error Creating File \(|\r?\n|$)"
    r"|Error extracting file from image \((?P<extract>[^\r\n]*)\)"
)
_STDERR_META_RE = re.compile(r"Meta:\s*(\d+)")
_STDERR_ADDR_RE = re.compile(r"\((\d+)\s*-\s*type:\s*(\d+)\s+id:\s*(\d+)")


def _relative_to_root(logged: str, extract_root: Path | str | None) -> str | None:
    if not extract_root:
        return None
    root = str(extract_root).replace("/", "\\").rstrip("\\")
    candidate = logged.replace("/", "\\")
    if candidate.lower().startswith(root.lower() + "\\"):
        return candidate[len(root) + 1 :].replace("\\", "/")
    return None


def parse_tsk_recover_stderr(text: str, *, extract_root: Path | str | None = None) -> list[dict[str, object]]:
    """Parse ``tsk_recover`` stderr into ``{path, reason, inode?}`` rows.

    The win32 build prints ``Error Creating File (...)`` without a newline and
    truncates the path at its ``MAX_PATH`` buffer, so logged paths are
    prefixes; ``Error extracting file from image`` lines carry the inode and
    follow the ``Error writing file`` line they explain.
    """
    rows: list[dict[str, object]] = []
    for match in _STDERR_TOKEN_RE.finditer(text):
        if match.group("create") is not None:
            logged = match.group("create")
            rows.append(_failure_row(logged, "create-failed", extract_root))
        elif match.group("write") is not None:
            logged = match.group("write").strip()
            rows.append(_failure_row(logged, "write-failed", extract_root))
        else:
            detail = match.group("extract") or ""
            inode, attr_type, attr_id = _stderr_inode(detail)
            previous = rows[-1] if rows else None
            if previous is not None and previous["reason"] == "write-failed" and previous.get("inode") is None:
                previous["inode"] = inode
                previous["attr_type"] = attr_type
                previous["attr_id"] = attr_id
                previous["detail"] = detail
                previous["deleted"] = "Status: Deleted" in detail
                continue
            rows.append(
                {
                    "path": None,
                    "relative_path": None,
                    "reason": "extract-failed",
                    "inode": inode,
                    "attr_type": attr_type,
                    "attr_id": attr_id,
                    "detail": detail,
                    "deleted": "Status: Deleted" in detail,
                }
            )
    return rows


def _failure_row(logged: str, reason: str, extract_root: Path | str | None) -> dict[str, object]:
    length = windows_path_length(logged)
    return {
        "path": logged,
        "relative_path": _relative_to_root(logged, extract_root),
        "reason": reason,
        "inode": None,
        "path_length": length,
        "path_truncated_at_max_path": length >= WINDOWS_MAX_PATH - 2,
    }


def _stderr_inode(detail: str) -> tuple[int | None, int | None, int | None]:
    address = _STDERR_ADDR_RE.search(detail)
    if address:
        return int(address.group(1)), int(address.group(2)), int(address.group(3))
    meta = _STDERR_META_RE.search(detail)
    if meta:
        return int(meta.group(1)), None, None
    return None, None, None


# --------------------------------------------------------------------------
# Extracted path <-> inode matching
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExtractedFile:
    relative_path: str
    size: int | None = None


def iter_extracted_files(root: Path) -> Iterator[ExtractedFile]:
    """Walk an extraction root with ``os.scandir`` (sizes come free on Windows)."""
    root_text = extended_length_path(root)
    pending: list[tuple[str, str]] = [(root_text, "")]
    while pending:
        current, prefix = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    relative = f"{prefix}/{entry.name}" if prefix else entry.name
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append((entry.path, relative))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        size = entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        size = None
                    yield ExtractedFile(relative, size)
        except OSError:
            continue


def _wildcard_regex(key: str) -> re.Pattern[str]:
    # TSK replaces each unrepresentable UTF-16 unit with '?'; a surrogate pair
    # may become one or two '?'.
    parts = [re.escape(part) for part in key.split("?")]
    return re.compile("^" + ".{1,2}".join(parts) + "$", re.DOTALL)


def match_extracted_to_listing(
    extracted: Iterable[ExtractedFile],
    entries: Sequence[FlsEntry],
) -> tuple[dict[str, tuple[FlsEntry, str]], list[ExtractedFile]]:
    """Map extracted relative paths to fls rows.

    Tiers, in order of precision:

    1. ``path-exact`` - NFC+casefold relative path equals the decoded fls name.
    2. ``path-wildcard`` - the fls name is lossy (``?`` from the ANSI code
       page) and is the unique regex match among unmatched rows with the same
       component count.
    3. ``parent-size`` - the extracted file's parent directory maps (via the
       directory correspondence learned from tiers 1-2) to an fls directory in
       which exactly one unmatched row has the same ``$DATA`` size.

    Only non-deleted, non-ADS regular rows are candidates (``tsk_recover -e``
    writes deleted files into the same tree; a deleted file whose path equals an
    allocated one is attributed to the allocated row - a known limitation).
    """
    candidates = [entry for entry in entries if entry.is_allocated_file and not entry.is_ads]
    by_key: dict[str, list[FlsEntry]] = {}
    for entry in candidates:
        by_key.setdefault(normalize_relative_key(entry.name_hint), []).append(entry)

    matches: dict[str, tuple[FlsEntry, str]] = {}
    used: set[int] = set()
    unmatched: list[ExtractedFile] = []
    for item in extracted:
        rows = by_key.get(normalize_relative_key(item.relative_path))
        if rows:
            choice = next((row for row in rows if id(row) not in used), rows[0])
            used.add(id(choice))
            matches[item.relative_path] = (choice, "path-exact")
        else:
            unmatched.append(item)

    lossy_rows = [entry for entry in candidates if entry.name_lossy and id(entry) not in used]
    if unmatched and lossy_rows:
        buckets: dict[int, list[tuple[re.Pattern[str], FlsEntry]]] = {}
        for entry in lossy_rows:
            key = normalize_relative_key(entry.name_hint)
            buckets.setdefault(key.count("/"), []).append((_wildcard_regex(key), entry))
        still: list[ExtractedFile] = []
        for item in unmatched:
            key = normalize_relative_key(item.relative_path)
            hits = [entry for pattern, entry in buckets.get(key.count("/"), ()) if id(entry) not in used and pattern.match(key)]
            if len(hits) == 1:
                used.add(id(hits[0]))
                matches[item.relative_path] = (hits[0], "path-wildcard")
            else:
                still.append(item)
        unmatched = still

    if unmatched:
        dir_map: dict[str, str] = {}
        for rel, (entry, _method) in matches.items():
            ext_parent = normalize_relative_key(rel).rpartition("/")[0]
            fls_parent = normalize_relative_key(entry.name_hint).rpartition("/")[0]
            dir_map.setdefault(ext_parent, fls_parent)
        leftovers: dict[tuple[str, int | None], list[FlsEntry]] = {}
        for entry in candidates:
            if id(entry) in used:
                continue
            parent = normalize_relative_key(entry.name_hint).rpartition("/")[0]
            leftovers.setdefault((parent, entry.size), []).append(entry)
        still = []
        for item in unmatched:
            ext_parent = normalize_relative_key(item.relative_path).rpartition("/")[0]
            fls_parent = dir_map.get(ext_parent)
            if fls_parent is None or item.size is None:
                still.append(item)
                continue
            pool = [entry for entry in leftovers.get((fls_parent, item.size), ()) if id(entry) not in used]
            if len(pool) == 1:
                used.add(id(pool[0]))
                matches[item.relative_path] = (pool[0], "parent-size")
            else:
                still.append(item)
        unmatched = still
    return matches, unmatched


# --------------------------------------------------------------------------
# Runners
# --------------------------------------------------------------------------


def default_stream_runner(command: Sequence[str], dest: Path, *, timeout_seconds: int | None = None) -> subprocess.CompletedProcess:
    """Run ``command`` streaming stdout straight into ``dest`` (no buffering in memory)."""
    if timeout_seconds is None:
        tool = Path(str(command[0])).stem.lower() if command else ""
        timeout_seconds = FLS_TIMEOUT_SECONDS if tool == "fls" else ICAT_TIMEOUT_SECONDS
    dest_text = extended_length_path(dest)
    os.makedirs(os.path.dirname(dest_text), exist_ok=True)
    with open(dest_text, "wb") as handle:
        try:
            completed = subprocess.run(
                list(command),
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds if timeout_seconds > 0 else None,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(list(command), 124, b"", f"timed out after {timeout_seconds}s")
        except OSError as exc:
            return subprocess.CompletedProcess(list(command), 127, b"", str(exc))
    stderr = completed.stderr.decode("utf-8", errors="replace") if isinstance(completed.stderr, bytes) else str(completed.stderr or "")
    return subprocess.CompletedProcess(list(command), completed.returncode, b"", stderr)


def text_runner_stream_adapter(runner: Callable[[Sequence[str]], subprocess.CompletedProcess]) -> StreamRunner:
    """Adapt an injectable text ``runner`` (tests) to the stream-runner contract."""

    def stream(command: Sequence[str], dest: Path) -> subprocess.CompletedProcess:
        result = runner(command)
        payload = result.stdout or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="surrogateescape")
        dest_text = extended_length_path(dest)
        os.makedirs(os.path.dirname(dest_text), exist_ok=True)
        with open(dest_text, "wb") as handle:
            handle.write(payload)
        return subprocess.CompletedProcess(list(command), result.returncode, b"", result.stderr or "")

    return stream


def gap_recovery_enabled() -> bool:
    return os.environ.get(GAP_RECOVERY_DISABLE_ENV, "1").strip().lower() not in {"0", "false", "no", "off"}


def gap_recovery_workers() -> int:
    try:
        return max(1, int(os.environ.get(GAP_RECOVERY_WORKERS_ENV, "4")))
    except ValueError:
        return 4


# --------------------------------------------------------------------------
# On-disk checks and hashing
# --------------------------------------------------------------------------


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(extended_length_path(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def exists_in_extraction(extract_dir: Path, relative_hint: str) -> bool:
    """Whether ``relative_hint`` exists under the extraction root.

    Lossy ``?`` components are matched as single-character wildcards against the
    parent directory listing; extended-length paths avoid ``MAX_PATH``.
    """
    parts = [part for part in relative_hint.split("/") if part]
    if not parts:
        return False
    if "?" not in relative_hint:
        return os.path.lexists(extended_length_path(extract_dir.joinpath(*parts)))
    current = extended_length_path(extract_dir)
    for index, part in enumerate(parts):
        if "?" not in part:
            nxt = os.path.join(current, part)
            if not os.path.lexists(nxt):
                return False
            current = nxt
            continue
        pattern = fnmatch.translate(part.replace("[", "[[]").casefold())
        regex = re.compile(pattern)
        try:
            names = os.listdir(current)
        except OSError:
            return False
        found = next((name for name in names if regex.match(unicodedata.normalize("NFC", name).casefold())), None)
        if found is None:
            return False
        current = os.path.join(current, found)
        if index == len(parts) - 1:
            return True
    return True


def extraction_path_too_long(extract_dir: Path, relative_hint: str) -> bool:
    full = str(extract_dir).rstrip("\\/") + "\\" + relative_hint.replace("/", "\\")
    if windows_path_length(full) >= WINDOWS_MAX_PATH:
        return True
    parent = full.rpartition("\\")[0]
    return windows_path_length(parent) >= WINDOWS_MAX_DIR_PATH


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(extended_length_path(tmp), "w", encoding="utf-8", errors="surrogateescape") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=1)
    os.replace(extended_length_path(tmp), extended_length_path(path))


def _json_text(value: str) -> str:
    """Make a surrogateescape string JSON/UTF-8 safe (lone surrogates -> U+FFFD)."""
    return value.encode("utf-8", errors="replace").decode("utf-8")


# --------------------------------------------------------------------------
# Long-path fallback (P14) / zero-byte listing (P15) / ADS (P17)
# --------------------------------------------------------------------------


def _needs_disk_check(check_disk: bool, extracted_inodes: set[int] | None, entry: FlsEntry) -> bool:
    """Disk probes cost ~60 ms each on deep trees; skip them when the inode map
    (built from a full walk of the extraction root) already answers, except for
    lossy names that could not be path-matched."""
    if not check_disk:
        return False
    return extracted_inodes is None or entry.name_lossy


def select_long_path_targets(
    entries: Sequence[FlsEntry],
    *,
    extract_dir: Path,
    failures: Sequence[Mapping[str, object]] = (),
    extracted_inodes: set[int] | None = None,
    check_disk: bool = True,
) -> list[FlsEntry]:
    """Content-bearing allocated rows that ``tsk_recover`` could not write.

    A row qualifies when its extraction path reaches ``MAX_PATH`` (or its parent
    reaches the 248-char directory limit) or its path starts with a logged
    ``Error Creating File`` prefix. Rows already present on disk (by inode map
    or extended-path existence check) are dropped.
    """
    prefixes = PrefixSet(
        normalize_relative_key(str(row.get("relative_path")))
        for row in failures
        if row.get("reason") == "create-failed" and row.get("relative_path")
    )
    targets: list[FlsEntry] = []
    seen: set[int] = set()
    for entry in entries:
        if classify_listing_entry(entry) != "content" or entry.inode in seen:
            continue
        if extracted_inodes is not None and entry.inode in extracted_inodes:
            continue
        qualifies = extraction_path_too_long(extract_dir, entry.name_hint)
        if not qualifies and prefixes:
            key = normalize_relative_key(entry.name_hint)
            qualifies = prefixes.match(key) is not None
        if not qualifies:
            continue
        if _needs_disk_check(check_disk, extracted_inodes, entry) and exists_in_extraction(extract_dir, entry.name_hint):
            continue
        seen.add(entry.inode)
        targets.append(entry)
    return targets


class PrefixSet:
    """Prefix membership in O(log n): the set is reduced to prefix-free form."""

    def __init__(self, prefixes: Iterable[str]) -> None:
        kept: list[str] = []
        for prefix in sorted(set(prefix for prefix in prefixes if prefix)):
            if kept and prefix.startswith(kept[-1]):
                continue
            kept.append(prefix)
        self._prefixes = kept

    def __bool__(self) -> bool:
        return bool(self._prefixes)

    def match(self, key: str) -> str | None:
        index = bisect.bisect_right(self._prefixes, key) - 1
        if index >= 0 and key.startswith(self._prefixes[index]):
            return self._prefixes[index]
        return None


def _icat_command(image: Path | str, offset_sector: int, address: str) -> list[str]:
    return ["icat", "-o", str(offset_sector), str(image), address]


def recover_long_path_files(
    targets: Sequence[FlsEntry],
    *,
    stage: Path,
    image: Path | str,
    offset_sector: int,
    stream_runner: StreamRunner,
    max_files: int = LONG_PATH_FALLBACK_MAX_FILES,
    max_bytes: int = LONG_PATH_FALLBACK_MAX_BYTES,
    workers: int = 1,
) -> dict[str, object]:
    long_dir = stage / LONG_PATH_DIR_NAME
    warnings: list[str] = []
    selected: list[FlsEntry] = []
    planned_bytes = 0
    for entry in targets:
        if len(selected) >= max_files:
            warnings.append(f"long-path fallback capped at {max_files} files; {len(targets) - len(selected)} not recovered")
            break
        if planned_bytes + int(entry.size or 0) > max_bytes:
            warnings.append(
                f"long-path fallback capped at {max_bytes} bytes; {len(targets) - len(selected)} files not recovered"
            )
            break
        planned_bytes += int(entry.size or 0)
        selected.append(entry)

    def recover(entry: FlsEntry) -> dict[str, object]:
        dest = long_dir / f"{entry.inode}.bin"
        result = stream_runner(_icat_command(image, offset_sector, str(entry.inode)), dest)
        row: dict[str, object] = {
            "inode": entry.inode,
            "address": entry.address,
            "original_relative_path": _json_text(entry.name_hint),
            "name_lossy": entry.name_lossy,
            "recovered_path": str(dest),
            "listing_size": entry.size,
            "timestamps": entry.timestamps(),
            "returncode": result.returncode,
        }
        try:
            size, sha256 = _hash_file(dest)
            row["size"] = size
            row["sha256"] = sha256
        except OSError as exc:
            row["size"] = None
            row["sha256"] = None
            row["error"] = str(exc)
        if result.returncode != 0:
            row["status"] = "icat-failed"
            row["error"] = str(result.stderr or "")[:500]
        elif row.get("size") != entry.size:
            row["status"] = "size-mismatch"
        else:
            row["status"] = "recovered"
        return row

    if workers > 1 and len(selected) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(recover, selected))
    else:
        rows = [recover(entry) for entry in selected]
    recovered = [row for row in rows if row["status"] in {"recovered", "size-mismatch"}]
    payload = {
        "profile_version": GAP_RECOVERY_PROFILE_VERSION,
        "source_id": LONG_PATH_SOURCE_ID,
        "target_count": len(targets),
        "attempted_count": len(rows),
        "recovered_count": len(recovered),
        "recovered_bytes": sum(int(row.get("size") or 0) for row in recovered),
        "failed_count": len(rows) - len(recovered),
        "caps": {"max_files": max_files, "max_bytes": max_bytes},
        "warnings": warnings,
        "files": rows,
    }
    _write_json(stage / LONG_PATH_MAP_NAME, payload)
    return payload


def build_zero_byte_listing(
    entries: Sequence[FlsEntry],
    *,
    stage: Path,
    extract_dir: Path,
    extracted_inodes: set[int] | None = None,
    check_disk: bool = True,
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    skipped_on_disk = 0
    for entry in entries:
        if classify_listing_entry(entry) != "zero-byte":
            continue
        if extracted_inodes is not None and entry.inode in extracted_inodes:
            skipped_on_disk += 1
            continue
        if _needs_disk_check(check_disk, extracted_inodes, entry) and exists_in_extraction(extract_dir, entry.name_hint):
            skipped_on_disk += 1
            continue
        rows.append(
            {
                "inode": entry.inode,
                "address": entry.address,
                "relative_path": _json_text(entry.name_hint),
                "name_lossy": entry.name_lossy,
                "size": 0,
                "timestamps": entry.timestamps(),
            }
        )
    payload = {
        "profile_version": GAP_RECOVERY_PROFILE_VERSION,
        "source_id": ZERO_BYTE_SOURCE_ID,
        "count": len(rows),
        "skipped_present_on_disk": skipped_on_disk,
        "limitation": (
            "Rows come from the fls -rpl listing ($DATA size column == 0). Names are decoded from the "
            "ANSI code page TSK win32 prints; '?' marks characters lost in that conversion. Inode is authoritative."
        ),
        "files": rows,
    }
    _write_json(stage / ZERO_BYTE_LISTING_NAME, payload)
    return payload


def recover_ads_streams(
    entries: Sequence[FlsEntry],
    *,
    stage: Path,
    image: Path | str,
    offset_sector: int,
    stream_runner: StreamRunner,
    max_stream_bytes: int = ADS_STREAM_MAX_BYTES,
    max_streams: int = ADS_MAX_STREAMS,
    workers: int = 1,
) -> dict[str, object]:
    ads_dir = stage / ADS_DIR_NAME
    streams = [entry for entry in entries if classify_listing_entry(entry) == "ads"]
    streams.sort(key=lambda entry: (entry.stream_name.casefold() != "zone.identifier", entry.inode, entry.attr_id or 0))
    warnings: list[str] = []
    if len(streams) > max_streams:
        warnings.append(f"ADS recovery capped at {max_streams} streams; {len(streams) - max_streams} not recovered")
    selected = streams[:max_streams]

    def recover(entry: FlsEntry) -> dict[str, object]:
        row: dict[str, object] = {
            "inode": entry.inode,
            "attr_type": entry.attr_type,
            "attr_id": entry.attr_id,
            "address": entry.address,
            "host_relative_path": _json_text(entry.host_hint),
            "stream_name": _json_text(entry.stream_name),
            "name_lossy": entry.name_lossy,
            "listing_size": entry.size,
            "timestamps": entry.timestamps(),
            "recovered_path": None,
        }
        if entry.size is not None and entry.size > max_stream_bytes:
            row["status"] = "skipped-size-cap"
            return row
        if entry.attr_type is None or entry.attr_id is None:
            row["status"] = "skipped-no-attribute-id"
            return row
        dest = ads_dir / f"{entry.inode}-{entry.attr_type}-{entry.attr_id}.bin"
        result = stream_runner(_icat_command(image, offset_sector, entry.address), dest)
        row["recovered_path"] = str(dest)
        try:
            size, sha256 = _hash_file(dest)
            row["size"] = size
            row["sha256"] = sha256
        except OSError as exc:
            row["error"] = str(exc)
        row["status"] = "recovered" if result.returncode == 0 and "sha256" in row else "icat-failed"
        if result.returncode != 0:
            row["error"] = str(result.stderr or "")[:500]
        return row

    if workers > 1 and len(selected) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(recover, selected))
    else:
        rows = [recover(entry) for entry in selected]
    payload = {
        "profile_version": GAP_RECOVERY_PROFILE_VERSION,
        "source_id": ADS_SOURCE_ID,
        "stream_count": len(streams),
        "recovered_count": sum(1 for row in rows if row["status"] == "recovered"),
        "zone_identifier_count": sum(1 for entry in streams if entry.stream_name.casefold() == "zone.identifier"),
        "skipped_size_cap_count": sum(1 for row in rows if row["status"] == "skipped-size-cap"),
        "caps": {"max_stream_bytes": max_stream_bytes, "max_streams": max_streams},
        "warnings": warnings,
        "streams": rows,
    }
    _write_json(stage / ADS_MAP_NAME, payload)
    return payload


def write_extraction_inode_map(
    stage: Path,
    matches: Mapping[str, tuple[FlsEntry, str]],
    unmatched: Sequence[ExtractedFile],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    path = stage / EXTRACTION_INODE_MAP_NAME
    with open(extended_length_path(path), "w", encoding="utf-8") as handle:
        for rel, (entry, method) in matches.items():
            counts[method] = counts.get(method, 0) + 1
            handle.write(
                json.dumps(
                    {"relative_path": _json_text(rel), "inode": entry.inode, "size": entry.size, "match": method},
                    ensure_ascii=False,
                )
                + "\n"
            )
        for item in unmatched:
            counts["unmatched"] = counts.get("unmatched", 0) + 1
            handle.write(
                json.dumps(
                    {"relative_path": _json_text(item.relative_path), "inode": None, "size": item.size, "match": "unmatched"},
                    ensure_ascii=False,
                )
                + "\n"
            )
    return counts


def record_tsk_recover_stderr(stage: Path, extract_dir: Path, stderr: str) -> list[dict[str, object]]:
    """Persist the full ``tsk_recover`` stderr and its parsed failure rows."""
    stage.mkdir(parents=True, exist_ok=True)
    with open(extended_length_path(stage / TSK_RECOVER_STDERR_LOG_NAME), "w", encoding="utf-8", errors="surrogateescape") as handle:
        handle.write(stderr)
    failures = parse_tsk_recover_stderr(stderr, extract_root=extract_dir)
    _write_json(
        stage / EXTRACTION_FAILURES_NAME,
        {
            "profile_version": GAP_RECOVERY_PROFILE_VERSION,
            "failure_count": len(failures),
            "reason_counts": _count_by(failures, "reason"),
            "failures": failures,
        },
    )
    return failures


def run_extraction_gap_recovery(
    *,
    stage: Path,
    extract_dir: Path,
    image: Path | str,
    offset_sector: int,
    stream_runner: StreamRunner,
    tsk_stderr: str | None = None,
    reuse_listing: bool = False,
    workers: int = 1,
    long_path_max_files: int = LONG_PATH_FALLBACK_MAX_FILES,
    long_path_max_bytes: int = LONG_PATH_FALLBACK_MAX_BYTES,
    ads_max_stream_bytes: int = ADS_STREAM_MAX_BYTES,
) -> dict[str, object]:
    """Run P14/P15/P17 after ``tsk_recover`` and return a compact summary."""
    warnings: list[str] = []
    commands: list[dict[str, object]] = []
    summary: dict[str, object] = {"profile_version": GAP_RECOVERY_PROFILE_VERSION, "stage_dir": str(stage)}

    failures: list[dict[str, object]] = []
    if tsk_stderr is not None:
        failures = record_tsk_recover_stderr(stage, extract_dir, tsk_stderr)
        summary["stderr_log"] = str(stage / TSK_RECOVER_STDERR_LOG_NAME)

    listing_path = stage / FLS_LISTING_NAME
    if not (reuse_listing and listing_path.is_file()):
        fls_command = ["fls", "-r", "-p", "-l", "-z", "UTC", "-o", str(offset_sector), str(image)]
        fls_result = stream_runner(fls_command, listing_path)
        commands.append({"purpose": "fls-coverage-listing", "command": fls_command, "returncode": fls_result.returncode,
                         "stderr_preview": str(fls_result.stderr or "")[:2000]})
        if fls_result.returncode != 0:
            warnings.append(f"fls -rpl failed (rc={fls_result.returncode}); coverage-gap recovery skipped")
            _write_json(stage / EXTRACTION_FAILURES_NAME, {"profile_version": GAP_RECOVERY_PROFILE_VERSION, "failures": failures})
            summary.update({"status": "failed", "failure_count": len(failures), "warnings": warnings, "commands": commands})
            _write_json(stage / GAP_RECOVERY_SUMMARY_NAME, summary)
            return summary
    summary["fls_listing"] = str(listing_path)

    entries = list(iter_fls_listing(listing_path))
    class_counts: dict[str, int] = {}
    for entry in entries:
        cls = classify_listing_entry(entry)
        class_counts[cls] = class_counts.get(cls, 0) + 1

    matches, unmatched = match_extracted_to_listing(iter_extracted_files(extract_dir), entries)
    match_counts = write_extraction_inode_map(stage, matches, unmatched)
    extracted_inodes = {entry.inode for entry, _method in matches.values()}

    # Resolve inodes for creation failures by logged-prefix match against the listing.
    content_rows = sorted(
        ((normalize_relative_key(entry.name_hint), entry) for entry in entries if classify_listing_entry(entry) == "content"),
        key=lambda item: item[0],
    )
    content_keys = [key for key, _entry in content_rows]
    for row in failures:
        if row.get("reason") != "create-failed" or not row.get("relative_path") or row.get("inode") is not None:
            continue
        prefix = normalize_relative_key(str(row["relative_path"]))
        hits = []
        index = bisect.bisect_left(content_keys, prefix)
        while index < len(content_rows) and content_keys[index].startswith(prefix):
            hits.append(content_rows[index][1])
            index += 1
        if len(hits) == 1:
            row["inode"] = hits[0].inode
            row["listing_size"] = hits[0].size
        elif hits:
            row["candidate_inodes"] = [entry.inode for entry in hits[:16]]
    _write_json(
        stage / EXTRACTION_FAILURES_NAME,
        {
            "profile_version": GAP_RECOVERY_PROFILE_VERSION,
            "failure_count": len(failures),
            "reason_counts": _count_by(failures, "reason"),
            "failures": failures,
        },
    )

    targets = select_long_path_targets(entries, extract_dir=extract_dir, failures=failures, extracted_inodes=extracted_inodes)
    long_payload = recover_long_path_files(
        targets,
        stage=stage,
        image=image,
        offset_sector=offset_sector,
        stream_runner=stream_runner,
        max_files=long_path_max_files,
        max_bytes=long_path_max_bytes,
        workers=workers,
    )
    warnings.extend(str(item) for item in long_payload["warnings"])
    zero_payload = build_zero_byte_listing(entries, stage=stage, extract_dir=extract_dir, extracted_inodes=extracted_inodes)
    ads_payload = recover_ads_streams(
        entries,
        stage=stage,
        image=image,
        offset_sector=offset_sector,
        stream_runner=stream_runner,
        max_stream_bytes=ads_max_stream_bytes,
        workers=workers,
    )
    warnings.extend(str(item) for item in ads_payload["warnings"])
    icat_failures = int(long_payload["failed_count"]) + sum(1 for row in ads_payload["streams"] if row.get("status") == "icat-failed")
    commands.append(
        {
            "purpose": "icat-gap-recovery",
            "command": ["icat", "-o", str(offset_sector), str(image), "<inode|inode-type-id>"],
            "returncode": 0 if icat_failures == 0 else 1,
            "invocation_count": int(long_payload["attempted_count"]) + sum(
                1 for row in ads_payload["streams"] if row.get("recovered_path")
            ),
            "failure_count": icat_failures,
        }
    )
    summary.update(
        {
            "status": "completed",
            "listing_class_counts": class_counts,
            "inode_map_match_counts": match_counts,
            "failure_count": len(failures),
            "failure_reason_counts": _count_by(failures, "reason"),
            "long_path": {key: long_payload[key] for key in ("target_count", "attempted_count", "recovered_count", "recovered_bytes", "failed_count")},
            "zero_byte": {"count": zero_payload["count"], "skipped_present_on_disk": zero_payload["skipped_present_on_disk"]},
            "ads": {key: ads_payload[key] for key in ("stream_count", "recovered_count", "zone_identifier_count", "skipped_size_cap_count")},
            "outputs": {
                "extraction_failures": str(stage / EXTRACTION_FAILURES_NAME),
                "inode_map": str(stage / EXTRACTION_INODE_MAP_NAME),
                "long_path_map": str(stage / LONG_PATH_MAP_NAME),
                "zero_byte_listing": str(stage / ZERO_BYTE_LISTING_NAME),
                "ads_map": str(stage / ADS_MAP_NAME),
            },
            "warnings": warnings,
            "commands": commands,
        }
    )
    _write_json(stage / GAP_RECOVERY_SUMMARY_NAME, summary)
    return summary


def _count_by(rows: Iterable[Mapping[str, object]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key))
        counts[value] = counts.get(value, 0) + 1
    return counts


# --------------------------------------------------------------------------
# Sidecar readers (files index / artifact providers)
# --------------------------------------------------------------------------


def extraction_stage_for_root(root: Path) -> Path | None:
    """Return the E01 stage dir when ``root`` is its extraction root."""
    parent = root.parent
    if root.name not in (E01_EXTRACT_DIR_NAME, *E01_LEGACY_EXTRACT_DIR_NAMES):
        return None
    if not (parent / E01_STAGE_STATUS_NAME).is_file() and not (parent / GAP_RECOVERY_SUMMARY_NAME).is_file():
        return None
    return parent


def _load_json(path: Path) -> Mapping[str, object] | None:
    try:
        with open(extended_length_path(path), encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, Mapping) else None


def iso_to_epoch(value: object) -> float:
    if not value:
        return 0.0
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    try:
        return parsed.timestamp()
    except (OverflowError, OSError, ValueError):
        return 0.0


@dataclass(frozen=True, slots=True)
class SidecarFile:
    relative_path: str
    size: int
    modified_at: str | None
    source_id: str
    inode: int | None
    content_path: str | None
    sha256: str | None
    timestamps: Mapping[str, object]
    name_lossy: bool
    stream_name: str | None = None


def iter_extraction_sidecar_files(root: Path) -> Iterator[SidecarFile]:
    """Yield long-path, zero-byte, and ADS rows recorded next to ``root``."""
    stage = extraction_stage_for_root(root)
    if stage is None:
        return
    long_map = _load_json(stage / LONG_PATH_MAP_NAME)
    if long_map:
        for row in long_map.get("files") or ():
            if not isinstance(row, Mapping) or row.get("status") not in {"recovered", "size-mismatch"}:
                continue
            times = row.get("timestamps") if isinstance(row.get("timestamps"), Mapping) else {}
            yield SidecarFile(
                relative_path=str(row.get("original_relative_path") or ""),
                size=int(row.get("size") or 0),
                modified_at=times.get("mtime") if isinstance(times.get("mtime"), str) else None,
                source_id=LONG_PATH_SOURCE_ID,
                inode=_optional_int(row.get("inode")),
                content_path=str(row.get("recovered_path") or "") or None,
                sha256=str(row.get("sha256") or "") or None,
                timestamps=dict(times),
                name_lossy=bool(row.get("name_lossy")),
            )
    zero = _load_json(stage / ZERO_BYTE_LISTING_NAME)
    if zero:
        for row in zero.get("files") or ():
            if not isinstance(row, Mapping):
                continue
            times = row.get("timestamps") if isinstance(row.get("timestamps"), Mapping) else {}
            yield SidecarFile(
                relative_path=str(row.get("relative_path") or ""),
                size=0,
                modified_at=times.get("mtime") if isinstance(times.get("mtime"), str) else None,
                source_id=ZERO_BYTE_SOURCE_ID,
                inode=_optional_int(row.get("inode")),
                content_path=None,
                sha256=None,
                timestamps=dict(times),
                name_lossy=bool(row.get("name_lossy")),
            )
    ads = _load_json(stage / ADS_MAP_NAME)
    if ads:
        for row in ads.get("streams") or ():
            if not isinstance(row, Mapping) or row.get("status") != "recovered":
                continue
            times = row.get("timestamps") if isinstance(row.get("timestamps"), Mapping) else {}
            stream = str(row.get("stream_name") or "")
            yield SidecarFile(
                relative_path=f"{row.get('host_relative_path') or ''}:{stream}",
                size=int(row.get("size") or 0),
                modified_at=times.get("mtime") if isinstance(times.get("mtime"), str) else None,
                source_id=ADS_SOURCE_ID,
                inode=_optional_int(row.get("inode")),
                content_path=str(row.get("recovered_path") or "") or None,
                sha256=str(row.get("sha256") or "") or None,
                timestamps=dict(times),
                name_lossy=bool(row.get("name_lossy")),
                stream_name=stream,
            )


def load_extraction_inode_index(root: Path) -> dict[str, int]:
    """Map casefolded relative path -> inode from the run's inode map, if any."""
    stage = extraction_stage_for_root(root)
    if stage is None:
        return {}
    path = stage / EXTRACTION_INODE_MAP_NAME
    index: dict[str, int] = {}
    try:
        with open(extended_length_path(path), encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                inode = row.get("inode")
                if isinstance(inode, int):
                    index[normalize_relative_key(str(row.get("relative_path") or ""))] = inode
    except OSError:
        return {}
    return index


def iter_recovered_ads_rows(root: Path) -> Iterator[Mapping[str, object]]:
    stage = extraction_stage_for_root(root)
    if stage is None:
        return
    ads = _load_json(stage / ADS_MAP_NAME)
    if not ads:
        return
    for row in ads.get("streams") or ():
        if isinstance(row, Mapping) and row.get("status") == "recovered" and row.get("recovered_path"):
            yield row


def _optional_int(value: object) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None
