"""R6 S2 lane A: AhnLab V3 traces, inventory first (plan r6-followups-2026-10-19 §2.3 갈래 A).

Public material does not document where or in which format V3 keeps its detection history
(a plain text file, a SQLite/ESE database or an encrypted store), so this module works in two
layers and marks every row ``verification: unconfirmed``:

1. ``av-product-presence`` (kind ``windows-system``) -- the AhnLab folders under
   ``Program Files``/``Program Files (x86)``/``ProgramData`` and a user's ``AppData\\Local``/
   ``AppData\\Roaming``: one ``product-folder`` row per product folder (folder name, the
   ``version*.ini`` value, file count/size), one ``log-candidate`` row per file whose suffix is
   ``.log``/``.txt``/``.db``/``.dat`` and whose name holds ``log``/``history``/``detect``/
   ``quarantine``/``event`` (size, mtime, sniffed format: text/SQLite/ESE/unknown), and one
   ``quarantine-folder`` row per folder whose name contains ``quarantine``/``vault``/``격리``
   (case-insensitive) with **counts and sizes only**: quarantine contents are never opened,
   hashed, sniffed or copied (it is malware); the count stops at ``MAX_QUARANTINE_FILES`` files,
   ``MAX_QUARANTINE_DIRS`` folders or ``MAX_WALK_DEPTH`` levels and never follows links/junctions.
2. ``av-detection-log`` rows with ``av_product=ahnlab-v3`` (the McAfee row shape): a text
   candidate yields lines with a leading timestamp and a detection word
   (``field_extraction=heuristic-lines``); a SQLite candidate yields rows of tables whose name or
   columns say detect/threat/malware/virus/infect/quarantine and which also have a path or a
   date column (``field_extraction=heuristic-sqlite``, ``schema_confidence=heuristic-sqlite``);
   a column whose name looks secret (password/token/key/secret...) is masked in ``message``.
   Anything else stays in the inventory layer.

Bounds reuse ``system_extras``: logs 64 MiB / 500,000 lines, rows per type 20,000 (also
enforced by ``collect_system_extras``). Rows are streamed: the remaining per-type budget is
passed into the text / SQLite row builders, a file is not parsed once the detection budget is
spent and the walk stops when both budgets are spent; a walk stops at ``MAX_WALK_ENTRIES`` entries per AhnLab
folder and a quarantine count at 5,000 files. One corrupt file yields an error row and the walk
continues. Standard library only.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from ...core.link_safe_walk import entry_is_directory_link
from ...core.models import ArtifactRecord
from ...core.sqlite_snapshot import open_sqlite_snapshot
from .._walk import iter_evidence_paths
from .system_extras import (
    AV_NEGATIVE,
    AV_THREAT_PATTERNS,
    AV_USER,
    MAX_LOG_BYTES,
    MAX_LOG_LINES,
    MAX_ROWS_PER_TYPE,
    TEXT_PATH,
    WINDOWS_PATH,
    base_details,
    decode_text,
    file_mtime,
    iter_lines,
    make_record,
    read_prefix,
    sha256_of,
)

PRESENCE_TYPE = "av-product-presence"
DETECTION_TYPE = "av-detection-log"
AHNLAB_PARSER_VERSION = "av-ahnlab-v1"

MAX_WALK_ENTRIES = 20_000
MAX_WALK_DEPTH = 8
MAX_QUARANTINE_FILES = 5_000
MAX_QUARANTINE_DIRS = 5_000
MAX_VERSION_INI_BYTES = 64 * 1024
MAX_SQLITE_BYTES = 64 * 1024 * 1024
MAX_SQLITE_TABLES = 200
SNIFF_BYTES = 4096

# Parent folder of an ``AhnLab`` folder -> install scope (other parents are not product folders).
AHNLAB_PARENTS = {
    "program files": ("program-files", "Program Files"),
    "program files (x86)": ("program-files-x86", "Program Files (x86)"),
    "programdata": ("programdata", "ProgramData"),
    "local": ("user-local-appdata", "사용자 AppData\\Local"),
    "roaming": ("user-roaming-appdata", "사용자 AppData\\Roaming"),
}
# A folder whose name contains one of these (case-insensitive) is a quarantine folder.
QUARANTINE_NAME_WORDS = ("quarantine", "vault", "격리")
# SQLite columns whose values are masked in ``message`` (credential-looking names).
SECRET_COLUMN_WORDS = ("password", "passwd", "pwd", "token", "secret", "key", "credential", "cookie", "session")
SECRET_MASK = "(숨김: 비밀 값으로 보이는 열)"
LOG_SUFFIXES = frozenset({".log", ".txt", ".db", ".dat"})
LOG_NAME_WORDS = ("log", "history", "detect", "quarantine", "event")
SQLITE_MAGIC = b"SQLite format 3\x00"
ESE_SIGNATURE = b"\xef\xcd\xab\x89"
FORMAT_LABELS = {"text": "텍스트", "sqlite": "SQLite", "ese": "ESE(JET)", "unknown": "알 수 없음(이진)"}

# (folder-name prefix after lower-casing and removing spaces) -> (product code, label).
PRODUCTS = (
    ("v3lite", "ahnlab-v3", "AhnLab V3 Lite"),
    ("v3is", "ahnlab-v3", "AhnLab V3 Internet Security"),
    ("v3internetsecurity", "ahnlab-v3", "AhnLab V3 Internet Security"),
    ("v3es", "ahnlab-v3", "AhnLab V3 Endpoint Security"),
    ("v3endpoint", "ahnlab-v3", "AhnLab V3 Endpoint Security"),
    ("v3net", "ahnlab-v3", "AhnLab V3 Net"),
    ("v3", "ahnlab-v3", "AhnLab V3"),
    ("astx", "ahnlab-safe-transaction", "AhnLab Safe Transaction"),
    ("safetransaction", "ahnlab-safe-transaction", "AhnLab Safe Transaction"),
)
OTHER_PRODUCT = ("ahnlab-other", "AhnLab 기타 제품(폴더 이름 기준)")

VERIFICATION = {
    "verification": "unconfirmed",
    "verification_note": "AhnLab 로그 위치·형식은 공개 자료로 확인하지 못했습니다(실표본 검증 전). 원문과 함께 확인하십시오.",
}

# AhnLab-flavoured detection words on top of the McAfee list (치료 = repaired/cleaned).
DETECTION_TERMS = (
    "detected",
    "repaired",
    "quarantin",
    "deleted",
    "cleaned",
    "blocked",
    "infected",
    "탐지",
    "치료",
    "격리",
    "차단",
    "삭제",
)
ACTIONS = (
    ("quarantin", "quarantined", "격리"),
    ("repaired", "cleaned", "치료"),
    ("cleaned", "cleaned", "치료"),
    ("deleted", "deleted", "삭제"),
    ("blocked", "blocked", "차단"),
    ("격리", "quarantined", "격리"),
    ("치료", "cleaned", "치료"),
    ("삭제", "deleted", "삭제"),
    ("차단", "blocked", "차단"),
    ("detected", "detected", "탐지"),
    ("탐지", "detected", "탐지"),
)
# ``2026-10-18 09:15:01``, ``2026.10.18 오후 3:05:11``, ``[2026/10/18 15:05:11.250]``.
LINE_TIME = re.compile(
    r"^\s*\[?(?P<date>\d{4}[-./]\d{1,2}[-./]\d{1,2})\.?[ \tT]+(?:(?P<pre>오전|오후|AM|PM|am|pm)\s*)?"
    r"(?P<time>\d{1,2}:\d{2}:\d{2})(?:[.,](?P<fraction>\d{1,6}))?(?:[ \t]*(?P<post>오전|오후|AM|PM|am|pm))?\]?"
)
SQL_DETECT_WORDS = ("detect", "threat", "malware", "virus", "infect", "quarantin")
SQL_PATH_WORDS = ("path", "file")
SQL_TIME_WORDS = ("date", "time")
SQL_ACTION_WORDS = ("action", "result", "treat", "status")


# ---------------------------------------------------------------------------
# Entry point (registered in system_extras.collect_system_extras)
# ---------------------------------------------------------------------------


class RowBudget:
    """Remaining rows per artifact type, shared by every builder of one collection."""

    def __init__(self, limit: int | None = None) -> None:
        limit = MAX_ROWS_PER_TYPE if limit is None else limit
        self.remaining = {PRESENCE_TYPE: limit, DETECTION_TYPE: limit}

    def left(self, artifact_type: str) -> int:
        return max(self.remaining.get(artifact_type, 0), 0)

    def take(self, artifact_type: str) -> bool:
        if self.remaining.get(artifact_type, 0) <= 0:
            return False
        self.remaining[artifact_type] -= 1
        return True

    @property
    def exhausted(self) -> bool:
        return all(value <= 0 for value in self.remaining.values())


def is_quarantine_name(name: str) -> bool:
    lowered = name.casefold()
    return any(word in lowered for word in QUARANTINE_NAME_WORDS)


def collect_ahnlab_v3(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    """``av-product-presence`` and AhnLab ``av-detection-log`` rows of an evidence root (streamed)."""
    budget = RowBudget()
    seen: set[str] = set()
    for folder in ahnlab_roots(root):
        if budget.exhausted:
            return
        key = str(folder).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            yield from _ahnlab_root_records(folder, root, provider, budget)
        except Exception as exc:  # pragma: no cover - a whole folder failing never stops the run
            if budget.take(DETECTION_TYPE):
                yield _error_record(provider, folder, exc, product=OTHER_PRODUCT)


def ahnlab_roots(root: Path) -> Iterator[Path]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        parent = path.parent.name.lower()
        if path.name.lower() != "ahnlab" or parent not in AHNLAB_PARENTS:
            continue
        if parent in {"local", "roaming"} and path.parent.parent.name.lower() != "appdata":
            continue
        if path.is_dir() and not path.is_symlink():
            yield path


def product_of(folder_name: str) -> tuple[str, str]:
    compact = re.sub(r"[\s_.-]+", "", folder_name.lower())
    for prefix, code, label in PRODUCTS:
        if compact.startswith(prefix):
            return code, label
    return OTHER_PRODUCT


def _user_of(folder: Path) -> str:
    """User folder name of a per-user ``AppData`` AhnLab folder (machine folders have none)."""
    appdata = folder.parent.parent
    if folder.parent.name.lower() in {"local", "roaming"} and appdata.name.lower() == "appdata":
        return appdata.parent.name
    return ""


# ---------------------------------------------------------------------------
# Inventory layer
# ---------------------------------------------------------------------------


class _Walk:
    """A bounded, non-following walk of one product folder (quarantine folders are not entered)."""

    def __init__(self) -> None:
        self.entries = 0
        self.truncated = False
        self.files: list[Path] = []
        self.quarantines: list[Path] = []
        self.skipped_links = 0

    def run(self, top: Path, depth: int = 0) -> None:
        if depth > MAX_WALK_DEPTH:
            self.truncated = True
            return
        try:
            entries = sorted(os.scandir(top), key=lambda entry: entry.name.lower())
        except OSError:
            return
        for entry in entries:
            if self.entries >= MAX_WALK_ENTRIES:
                self.truncated = True
                return
            self.entries += 1
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry_is_directory_link(entry):  # junction / reparse point: never followed
                        self.skipped_links += 1
                        continue
                    if is_quarantine_name(entry.name):
                        self.quarantines.append(Path(entry.path))
                    else:
                        self.run(Path(entry.path), depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    self.files.append(Path(entry.path))
            except OSError:
                continue


def _stat_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _ahnlab_root_records(
    folder: Path, root: Path, provider: str, budget: RowBudget | None = None
) -> Iterator[ArtifactRecord]:
    """Rows of one ``AhnLab`` folder; every row is taken from ``budget`` before it is yielded."""
    budget = budget if budget is not None else RowBudget()
    for record in _ahnlab_folder_rows(folder, provider, budget):
        if budget.take(record.artifact_type):
            yield record
        if budget.exhausted:
            return


def _ahnlab_folder_rows(folder: Path, provider: str, budget: RowBudget) -> Iterator[ArtifactRecord]:
    scope, scope_label = AHNLAB_PARENTS[folder.parent.name.lower()]
    user = _user_of(folder)
    try:
        children = sorted(folder.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        children = []
    loose = _Walk()
    for child in children:
        if budget.exhausted:
            return
        if child.is_symlink() or _is_dir_link(child):
            continue
        if child.is_dir():
            if is_quarantine_name(child.name):
                loose.quarantines.append(child)
                continue
            yield from _product_records(
                child, folder, provider, scope=scope, scope_label=scope_label, user=user, product=product_of(child.name), budget=budget
            )
        elif child.is_file():
            loose.files.append(child)
    # Files and quarantine folders directly under ``AhnLab`` belong to no product folder.
    context = {"scope": scope, "scope_label": scope_label, "user": user, "product": OTHER_PRODUCT, "product_folder": folder}
    for path in loose.files:
        if budget.exhausted:
            return
        if is_log_candidate(path):
            yield from _candidate_records(path, provider, context, budget)
    for quarantine in loose.quarantines:
        if budget.left(PRESENCE_TYPE) <= 0:
            return
        yield _quarantine_record(quarantine, provider, context)


def _is_dir_link(path: Path) -> bool:
    """A junction / reparse-point directory (``Path.is_symlink`` misses junctions before 3.12)."""
    is_junction = getattr(path, "is_junction", None)
    try:
        if is_junction is not None and is_junction():
            return True
        if os.name == "nt":
            attributes = int(getattr(path.lstat(), "st_file_attributes", 0) or 0)
            return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except OSError:
        return True
    return False


def _product_records(
    product_folder: Path,
    ahnlab_folder: Path,
    provider: str,
    *,
    scope: str,
    scope_label: str,
    user: str,
    product: tuple[str, str],
    budget: RowBudget,
) -> Iterator[ArtifactRecord]:
    walk = _Walk()
    walk.run(product_folder)
    context = {"scope": scope, "scope_label": scope_label, "user": user, "product": product, "product_folder": product_folder}
    version, version_source = read_version(walk.files, product_folder)
    candidates = [path for path in walk.files if is_log_candidate(path)]
    quarantine_rows = [_quarantine_record(path, provider, context) for path in walk.quarantines]
    quarantine_files = sum(int(row.details.get("file_count") or 0) for row in quarantine_rows)
    details = _presence_details(product_folder, context, presence_kind="product-folder", label="백신 제품 폴더(AhnLab)")
    details.update(
        {
            "ahnlab_folder": str(ahnlab_folder),
            "product_version": version,
            "product_version_source": version_source,
            "file_count": len(walk.files),
            "total_size": sum(_stat_size(path) for path in walk.files),
            "log_candidate_count": len(candidates),
            "quarantine_folder_count": len(walk.quarantines),
            "quarantine_file_count": quarantine_files,
            "walk_truncated": walk.truncated,
            "evidence_note": "제품 폴더가 있다는 것은 설치(또는 설치 흔적)를 뜻합니다. 버전은 폴더 안 version*.ini 값이며 실행 파일 버전 리소스는 읽지 않습니다.",
        }
    )
    yield make_record(provider, PRESENCE_TYPE, product_folder, details)
    for path in candidates:
        if budget.exhausted:
            return
        yield from _candidate_records(path, provider, context, budget)
    yield from quarantine_rows


def _presence_details(path: Path, context: dict[str, object], *, presence_kind: str, label: str) -> dict[str, object]:
    product = context["product"]
    assert isinstance(product, tuple)
    details = base_details(path, source_format="ahnlab-folder", recovery_method="inventory", hashes=False)
    details.update(
        {
            "parser_version": AHNLAB_PARSER_VERSION,
            "presence_kind": presence_kind,
            "presence_kind_label": {"product-folder": "제품 폴더", "log-candidate": "로그 후보 파일", "quarantine-folder": "격리 폴더"}[presence_kind],
            "av_vendor": "ahnlab",
            "av_product": product[0],
            "av_product_label": product[1],
            "product_folder": str(context["product_folder"]),
            "product_folder_name": Path(str(context["product_folder"])).name,
            "install_scope": context["scope"],
            "install_scope_label": context["scope_label"],
            "user": context["user"],
            "label": label,
            **VERIFICATION,
        }
    )
    return details


def read_version(files: list[Path], product_folder: Path) -> tuple[str, str]:
    """``version`` value of the shallowest ``version*.ini`` (``key=value`` lines only)."""
    inis = sorted(
        (path for path in files if path.name.lower().startswith("version") and path.suffix.lower() == ".ini"),
        key=lambda item: (len(item.parts), str(item).lower()),
    )
    for path in inis:
        text_value = decode_text(read_prefix(path, MAX_VERSION_INI_BYTES))
        for _number, raw in iter_lines(text_value, 2_000):
            key, sep, value = raw.partition("=")
            if sep and key.strip().lower() in {"version", "ver", "productversion", "product_version", "engineversion"} and value.strip():
                try:
                    relative = str(path.relative_to(product_folder))
                except ValueError:
                    relative = path.name
                return value.strip()[:64], relative
    return "", ""


def is_log_candidate(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in LOG_SUFFIXES and any(word in name for word in LOG_NAME_WORDS)


def sniff_format(head: bytes) -> str:
    if head.startswith(SQLITE_MAGIC):
        return "sqlite"
    if len(head) >= 8 and head[4:8] == ESE_SIGNATURE:
        return "ese"
    if not head:
        return "text"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:3] == b"\xef\xbb\xbf":
        return "text"
    if b"\x00" in head:
        # UTF-16LE without a BOM: every other byte is NUL and the rest is printable.
        odd = head[1::2]
        if odd and odd.count(0) >= len(odd) * 0.9:
            return "text"
        return "unknown"
    controls = sum(1 for byte in head if byte < 0x20 and byte not in (9, 10, 13))
    return "text" if controls <= len(head) * 0.02 else "unknown"


def _candidate_records(
    path: Path, provider: str, context: dict[str, object], budget: RowBudget | None = None
) -> Iterator[ArtifactRecord]:
    size = _stat_size(path)
    head = read_prefix(path, SNIFF_BYTES)
    sniffed = sniff_format(head)
    detection: list[ArtifactRecord] = []
    outcome = "inventory-only"
    error = ""
    # Never build more detection rows than the collection may still emit.
    limit = budget.left(DETECTION_TYPE) if budget is not None else RowBudget().left(DETECTION_TYPE)
    try:
        if sniffed in {"text", "sqlite"} and limit <= 0:
            outcome = "skipped-row-cap"
        elif sniffed == "text":
            detection = list(text_detection_records(path, provider, context, limit=limit))
            outcome = "detection-rows" if detection else "no-detection-lines"
        elif sniffed == "sqlite":
            if size > MAX_SQLITE_BYTES:
                outcome = "skipped-size-cap"
            else:
                detection, matched_tables = sqlite_detection_records(path, provider, context, limit=limit)
                outcome = "detection-rows" if detection else ("no-detection-rows" if matched_tables else "no-detection-table")
    except Exception as exc:  # corrupt input: an error row, the walk continues
        outcome = "error"
        error = f"{type(exc).__name__}: {exc}"[:200]
        detection = [_error_record(provider, path, exc, product=context["product"])]  # type: ignore[arg-type]
    details = _presence_details(path, context, presence_kind="log-candidate", label="백신 로그 후보 파일(AhnLab)")
    details.update(
        {
            "source_format": "ahnlab-log-candidate",
            "file_name": path.name,
            "relative_path": _relative(path, Path(str(context["product_folder"]))),
            "file_size": size,
            "source_file_mtime": file_mtime(path),
            "sniffed_format": sniffed,
            "sniffed_format_label": FORMAT_LABELS[sniffed],
            "parse_outcome": outcome,
            "detection_row_count": sum(1 for record in detection if record.details.get("parse_status") != "error"),
            "evidence_note": "이름·확장자로 고른 로그 후보입니다. 텍스트·SQLite만 탐지 행을 찾고, ESE·이진은 목록에만 둡니다.",
        }
    )
    if error:
        details["parse_error"] = error
    yield from detection
    yield make_record(provider, PRESENCE_TYPE, path, details)


def _relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _quarantine_record(folder: Path, provider: str, context: dict[str, object]) -> ArtifactRecord:
    """Counts and sizes only: a quarantine file is never opened (``os.scandir`` + ``stat``).

    Bounded by ``MAX_QUARANTINE_FILES`` files, ``MAX_QUARANTINE_DIRS`` folders and
    ``MAX_WALK_DEPTH`` levels; symlinks and junctions are never followed (no cycles)."""
    count = 0
    total = 0
    truncated = False
    directories = 0
    stack: list[tuple[Path, int]] = [(folder, 0)]
    while stack and not truncated:
        current, depth = stack.pop()
        directories += 1
        if directories > MAX_QUARANTINE_DIRS:
            truncated = True
            break
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry_is_directory_link(entry):
                        continue
                    if depth + 1 > MAX_WALK_DEPTH:
                        truncated = True
                        continue
                    stack.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    if count >= MAX_QUARANTINE_FILES:
                        truncated = True
                        break
                    count += 1
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    details = _presence_details(folder, context, presence_kind="quarantine-folder", label="백신 격리 폴더(AhnLab)")
    details.update(
        {
            "source_format": "ahnlab-quarantine-folder",
            "relative_path": _relative(folder, Path(str(context["product_folder"]))),
            "file_count": count,
            "total_size": total,
            "count_truncated": truncated,
            "contents_opened": False,
            "evidence_note": "격리 폴더는 파일 수·크기만 셉니다. 정책상 내용은 열거나 복사하지 않습니다(악성 코드).",
        }
    )
    return make_record(provider, PRESENCE_TYPE, folder, details)


# ---------------------------------------------------------------------------
# Detection layer
# ---------------------------------------------------------------------------


def line_time_text(match: re.Match[str]) -> str:
    year, month, day = (int(part) for part in re.split(r"[-./]", match.group("date")))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    ampm = (match.group("pre") or match.group("post") or "").lower()
    if ampm in {"pm", "오후"} and hour < 12:
        hour += 12
    elif ampm in {"am", "오전"} and hour == 12:
        hour = 0
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 61):
        return ""
    stamp = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"
    fraction = match.group("fraction")
    return f"{stamp}.{fraction[:6]}" if fraction else stamp


def _action(lowered: str) -> tuple[str, str]:
    return next(((code, label) for term, code, label in ACTIONS if term in lowered), ("", ""))


def _detection_details(path: Path, context: dict[str, object], *, source_format: str, extraction: str) -> dict[str, object]:
    product = context["product"]
    assert isinstance(product, tuple)
    details = base_details(path, source_format=source_format, hashes=False)
    details.update(
        {
            "parser_version": AHNLAB_PARSER_VERSION,
            "av_vendor": "ahnlab",
            "av_product": product[0],
            "av_product_label": product[1],
            "log_name": path.name,
            "field_extraction": extraction,
            "label": f"백신 탐지 로그({product[1]})",
            "risk_flags": ["av-detection"],
            **VERIFICATION,
        }
    )
    return details


def _row(provider: str, resolved: str, details: dict[str, object]) -> ArtifactRecord:
    """``av-detection-log`` record from a per-file template copy (no per-row ``resolve``)."""
    details.setdefault("timestamp", "")
    return ArtifactRecord(provider=provider, artifact_type=DETECTION_TYPE, path=resolved, supported=True, details=details)


def text_detection_records(
    path: Path, provider: str, context: dict[str, object], *, limit: int | None = None
) -> Iterator[ArtifactRecord]:
    """Detection lines of a text log; at most ``limit`` rows (the file is not read when ``limit`` <= 0)."""
    limit = MAX_ROWS_PER_TYPE if limit is None else limit
    if limit <= 0:
        return
    hashes = sha256_of(path)
    text_value = decode_text(read_prefix(path, MAX_LOG_BYTES))
    # base_details (resolve + stat) once per file, copied per row.
    template = _detection_details(path, context, source_format="ahnlab-text-log", extraction="heuristic-lines")
    resolved = str(path.resolve())
    produced = 0
    for number, raw in iter_lines(text_value, MAX_LOG_LINES):
        if produced >= limit:
            break
        line = raw.strip()
        lowered = line.lower()
        if not line or not any(term in lowered for term in DETECTION_TERMS) or AV_NEGATIVE.search(line):
            continue
        match = LINE_TIME.match(line)
        if not match:
            continue
        stamp = line_time_text(match)
        rest = line[match.end() :].strip()
        fields = [field.strip() for field in rest.split("\t")] if "\t" in rest else []
        paths = [field for field in fields if WINDOWS_PATH.match(field)] if fields else TEXT_PATH.findall(rest)
        threat = ""
        for pattern in AV_THREAT_PATTERNS:
            found = pattern.search(rest)
            if found:
                threat = found.group("threat").strip()
                break
        if not threat:
            found = re.search(r"(?:악성\s*코드|위협|진단명|바이러스)\s*(?:이름|명)?\s*[:=]\s*(?P<threat>[^\t,;]+)", rest)
            threat = found.group("threat").strip() if found else ""
        user_match = AV_USER.search(rest)
        user = (user_match.group("angle") or user_match.group("domain") or "") if user_match else ""
        action, action_label = _action(lowered)
        details = dict(template)
        details["risk_flags"] = list(template["risk_flags"])  # type: ignore[call-overload]
        details.update(
            {
                "source_hashes": hashes,
                "source_offset": number,
                "source_offset_unit": "line",
                "detected_at": stamp,
                "action": action,
                "action_label": action_label,
                "threat_name": threat[:200],
                "object_path": paths[-1] if paths else "",
                "process_path": paths[0] if len(paths) > 1 else "",
                "account": user[:130],
                "message": line[:1000],
                "timestamp": stamp,
                "timestamp_kind": "event" if stamp else "",
                "timestamp_timezone": "local-unknown" if stamp else "",
                "evidence_note": "AhnLab 로그 형식을 확인하지 못해 줄 첫머리 시각과 탐지 단어로 고른 행입니다. 위협명·경로는 원문(message)과 함께 확인하십시오.",
                "raw_preview": line[:500],
            }
        )
        produced += 1
        yield _row(provider, resolved, details)


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _pick(columns: list[str], words: tuple[str, ...], prefer: str = "") -> str:
    lowered = [(column, column.lower()) for column in columns]
    if prefer:
        for column, low in lowered:
            if prefer in low and any(word in low for word in words):
                return column
    return next((column for column, low in lowered if any(word in low for word in words)), "")


def sql_time_value(value: object) -> tuple[str, str]:
    """(ISO time, timezone) of a SQLite cell: Unix seconds/milliseconds or a date string."""
    if isinstance(value, bool):
        return "", ""
    if isinstance(value, (int, float)):
        seconds = float(value)
        if 1e12 <= seconds < 4.2e12:
            seconds /= 1000.0
        if 946_684_800 <= seconds < 4_102_444_800:
            stamp = dt.datetime.fromtimestamp(seconds, dt.timezone.utc).replace(tzinfo=None).isoformat()
            return stamp, "UTC"
        return "", ""
    if isinstance(value, str):
        match = LINE_TIME.match(value)
        if match:
            return line_time_text(match), "local-unknown"
    return "", ""


def _cell_text(value: object) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"(이진 {len(bytes(value))}바이트)"
    return "" if value is None else str(value)


def is_secret_column(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in SECRET_COLUMN_WORDS)


def sqlite_detection_records(
    path: Path, provider: str, context: dict[str, object], *, limit: int | None = None
) -> tuple[list[ArtifactRecord], int]:
    """Rows of tables that look like detection history (at most ``limit``); raises on a corrupt database."""
    records: list[ArtifactRecord] = []
    matched = 0
    limit = MAX_ROWS_PER_TYPE if limit is None else limit
    if limit <= 0:
        return records, matched
    hashes = sha256_of(path)
    template = _detection_details(path, context, source_format="ahnlab-sqlite-log", extraction="heuristic-sqlite")
    resolved = str(path.resolve())
    with open_sqlite_snapshot(path) as connection:
        tables = [
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT ?", (MAX_SQLITE_TABLES,))
        ]
        for table in tables:
            if table.lower().startswith("sqlite_"):
                continue
            columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({_quote(table)})")]
            names = [table.lower(), *(column.lower() for column in columns)]
            if not any(word in name for name in names for word in SQL_DETECT_WORDS):
                continue
            time_column = _pick(columns, SQL_TIME_WORDS)
            path_column = _pick(columns, SQL_PATH_WORDS, prefer="path")
            if not (time_column or path_column):
                continue
            matched += 1
            threat_column = _pick(columns, ("threat", "malware", "virus", "detect"), prefer="name")
            action_column = _pick(columns, SQL_ACTION_WORDS)
            secret_columns = {column for column in columns if is_secret_column(column)}
            cursor = connection.execute(f"SELECT rowid, * FROM {_quote(table)} LIMIT ?", (limit - len(records),))
            for row in cursor:
                cells = dict(zip(columns, row[1:]))
                stamp, timezone = sql_time_value(cells.get(time_column)) if time_column else ("", "")
                action_raw = _cell_text(cells.get(action_column)) if action_column else ""
                action, action_label = _action(action_raw.lower())
                details = dict(template)
                details["risk_flags"] = list(template["risk_flags"])  # type: ignore[call-overload]
                details.update(
                    {
                        "source_hashes": hashes,
                        "source_table": table,
                        "source_rowid": row[0],
                        "source_offset": row[0],
                        "source_offset_unit": "rowid",
                        "schema_confidence": "heuristic-sqlite",
                        "detected_at": stamp,
                        "detected_at_raw": _cell_text(cells.get(time_column))[:64] if time_column else "",
                        "action": action,
                        "action_label": action_label or action_raw[:64],
                        "threat_name": _cell_text(cells.get(threat_column))[:200] if threat_column else "",
                        "object_path": _cell_text(cells.get(path_column))[:1000] if path_column else "",
                        "process_path": "",
                        "account": "",
                        "message": json.dumps(
                            {
                                key: SECRET_MASK if key in secret_columns else _cell_text(value)[:200]
                                for key, value in list(cells.items())[:40]
                            },
                            ensure_ascii=False,
                        )[:1000],
                        "timestamp": stamp,
                        "timestamp_kind": "event" if stamp else "",
                        "timestamp_timezone": timezone if stamp else "",
                        "evidence_note": "AhnLab DB 스키마를 확인하지 못해 표·열 이름(탐지·위협·경로·시각)으로 고른 행입니다. 열 해석은 원문(message)과 함께 확인하십시오.",
                    }
                )
                records.append(_row(provider, resolved, details))
            if len(records) >= limit:
                break
    return records, matched


def _error_record(provider: str, path: Path, exc: BaseException, *, product: tuple[str, str]) -> ArtifactRecord:
    details = base_details(path, source_format="ahnlab-log", hashes=False)
    details.update(
        {
            "parser_version": AHNLAB_PARSER_VERSION,
            "av_vendor": "ahnlab",
            "av_product": product[0],
            "av_product_label": product[1],
            "log_name": path.name,
            "parse_status": "error",
            "parse_error": f"{type(exc).__name__}: {exc}"[:200],
            "label": "해석 오류",
            **VERIFICATION,
        }
    )
    return make_record(provider, DETECTION_TYPE, path, details)

