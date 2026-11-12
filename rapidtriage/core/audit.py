from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import json
import os
import socket
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from .. import __version__
from .input_root import InputRoot, resolve_input_root
from .json_safe import json_default

DEFAULT_AUDIT_ROOT_FILE_LIMIT = 5_000
DEFAULT_AUDIT_ROOT_DIR_LIMIT = 2_000

TOOL_NAME = "rapidtriage"
# Export audit history: one JSON record per line, appended next to the sidecar, never rewritten.
# The sidecar (``audit_path_for``) keeps its name and holds the latest record only.
EXPORT_AUDIT_LOG_NAME = "rapidtriage-export-audit.jsonl"
# Chain rule (same as scripts/r8-upgrade-check.py): each line carries the SHA-256 of the previous
# line's UTF-8 text (without its line ending); the first line carries "".
CHAIN_FIELD = "previous_record_sha256"
# SHA-256 of the line's own canonical JSON without this field, so an edited line names itself.
RECORD_HASH_FIELD = "record_sha256"
# T-359: how to verify, carried at the head of every export record (at most 5 lines).
VERIFICATION_METHOD_FIELD = "verification_method"
VERIFICATION_METHOD_LINES: tuple[str, ...] = (
    f"대상: 같은 폴더의 {EXPORT_AUDIT_LOG_NAME} (한 줄 = 내보내기 1건, 덧붙이기만 함)",
    f"줄 해시: {RECORD_HASH_FIELD} = 이 필드를 뺀 줄을 키 정렬·공백 없는 UTF-8 JSON으로 만든 SHA-256",
    f"사슬: {CHAIN_FIELD} = 직전 줄 원문(UTF-8, 줄바꿈 제외)의 SHA-256, 첫 줄은 빈 값",
    "순서: 첫 줄부터 차례로 확인, 사슬 필드가 없는 옛 줄은 '사슬 이전'으로 셈(깨짐 아님)",
    f"명령: rapidtriage audit-verify {EXPORT_AUDIT_LOG_NAME} --json (온전 종료 0 · 깨짐 종료 3)",
)


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_path_for(output_path: Path) -> Path:
    if output_path.suffix:
        return output_path.with_name(f"{output_path.stem}.audit{output_path.suffix}")
    return output_path.with_name(f"{output_path.name}.audit.json")


def build_input_root_record(
    root: InputRoot | Path,
    *,
    max_files: int | None = DEFAULT_AUDIT_ROOT_FILE_LIMIT,
    max_dirs: int | None = DEFAULT_AUDIT_ROOT_DIR_LIMIT,
) -> dict[str, object]:
    input_root = resolve_input_root(root)
    digest = hashlib.sha256()
    file_count = 0
    total_size = 0
    truncated = False

    for path in iter_regular_files(input_root.root_path, max_dirs=max_dirs):
        if max_files is not None and file_count >= max_files:
            truncated = True
            break
        try:
            stat_result = path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        relative = path.relative_to(input_root.root_path).as_posix()
        digest.update(relative.encode("utf-8", errors="ignore"))
        digest.update(b"\0")
        digest.update(str(stat_result.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(stat_result.st_mtime_ns).encode("ascii"))
        digest.update(b"\n")
        file_count += 1
        total_size += stat_result.st_size

    return {
        "source_path": input_root.source_path,
        "root_path": str(input_root.root_path),
        "kind": input_root.kind,
        "inventory_sha256": digest.hexdigest(),
        "file_count": file_count,
        "total_size": total_size,
        "inventory_scope": "bounded" if truncated or max_files is not None or max_dirs is not None else "complete",
        "inventory_truncated": truncated,
        "inventory_limits": {
            "max_files": max_files,
            "max_dirs": max_dirs,
        },
    }


def iter_regular_files(root: Path, *, max_dirs: int | None = None) -> Iterable[Path]:
    pending = [root]
    visited_dirs = 0
    while pending:
        current = pending.pop()
        visited_dirs += 1
        if max_dirs is not None and visited_dirs > max_dirs:
            return
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    pending.append(entry)
                    continue
                if entry.is_file():
                    yield entry
            except (FileNotFoundError, PermissionError, OSError):
                continue


def describe_file(path: Path, *, label: str | None = None) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    stat_result = resolved.stat()
    return {
        "label": label or resolved.name,
        "path": str(resolved),
        "sha256": compute_sha256(resolved),
        "size": stat_result.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat(),
    }


def write_audit_record(
    audit_path: Path,
    *,
    command: str,
    options: Mapping[str, object] | None = None,
    input_root: InputRoot | Path | None = None,
    input_files: Sequence[tuple[str, Path]] | None = None,
    output_files: Sequence[tuple[str, Path]] | None = None,
    notes: Sequence[str] | None = None,
    input_root_inventory_max_files: int | None = DEFAULT_AUDIT_ROOT_FILE_LIMIT,
    input_root_inventory_max_dirs: int | None = DEFAULT_AUDIT_ROOT_DIR_LIMIT,
) -> dict[str, object]:
    """Append the export record to the folder's history, then refresh the sidecar with it.

    History: ``rapidtriage-export-audit.jsonl`` next to the sidecar, one chained JSON line per
    export, only ever appended. Sidecar: ``audit_path`` (name unchanged) holds the latest record.
    """
    payload: dict[str, object] = {
        VERIFICATION_METHOD_FIELD: list(VERIFICATION_METHOD_LINES),
        "command": command,
        **audit_timestamps(),
        **audit_environment(),
        "audit_sidecar": audit_path.name,
        "provenance": {
            "options": dict(options or {}),
            "input_root": (
                build_input_root_record(
                    input_root,
                    max_files=input_root_inventory_max_files,
                    max_dirs=input_root_inventory_max_dirs,
                )
                if input_root is not None
                else None
            ),
            "input_files": [
                describe_file(path, label=label)
                for label, path in dedupe_records(input_files or [])
                if path.exists() and path.is_file()
            ],
            "notes": list(notes or []),
        },
        "integrity": {
            "generated_outputs": [
                describe_file(path, label=label)
                for label, path in dedupe_records(output_files or [])
                if path.exists() and path.is_file()
            ]
        },
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    record = append_audit_line(export_audit_log_path(audit_path), payload)
    with audit_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    return record


def export_audit_log_path(audit_path: Path) -> Path:
    """The append-only export audit history next to a sidecar (same folder)."""
    return audit_path.with_name(EXPORT_AUDIT_LOG_NAME)


def audit_timestamps(now: dt.datetime | None = None) -> dict[str, str]:
    """One instant as local time with its UTC offset, as UTC, and the offset itself."""
    instant = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    local = instant.astimezone()
    offset = local.strftime("%z") or "+0000"
    return {
        "generated_at": local.isoformat(),
        "generated_at_utc": instant.isoformat(),
        "utc_offset": f"{offset[:3]}:{offset[3:5]}",
    }


def audit_environment() -> dict[str, object]:
    """Tool name and version, and where the record was written (host, OS user, process id)."""
    try:
        os_user = getpass.getuser()
    except (ImportError, KeyError, OSError):  # no user name in the environment or password database
        os_user = ""
    return {
        "tool_name": TOOL_NAME,
        "tool_version": __version__,
        "host": socket.gethostname(),
        "os_user": os_user,
        "pid": os.getpid(),
    }


def _canonical_line(record: Mapping[str, object]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=json_default)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _record_self_hash(record: Mapping[str, object]) -> str:
    return _sha256_text(_canonical_line({key: value for key, value in record.items() if key != RECORD_HASH_FIELD}))


def append_audit_line(log_path: Path, record: Mapping[str, object]) -> dict[str, object]:
    """Append ``record`` as one chained JSON line (LF, flushed, fsynced). Earlier lines are never rewritten."""
    try:
        existing = log_path.read_bytes()
    except FileNotFoundError:
        existing = b""
    previous = next(
        (line for line in reversed(existing.decode("utf-8", errors="replace").splitlines()) if line.strip()),
        None,
    )
    # Round-trip through JSON so the stored values are JSON-native and a re-read hashes the same.
    normalized: dict[str, object] = json.loads(_canonical_line(record))
    normalized.pop(RECORD_HASH_FIELD, None)
    normalized[CHAIN_FIELD] = _sha256_text(previous) if previous is not None else ""
    normalized[RECORD_HASH_FIELD] = _record_self_hash(normalized)
    data = _canonical_line(normalized).encode("utf-8") + b"\n"
    if existing and not existing.endswith((b"\n", b"\r")):
        data = b"\n" + data
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return normalized


def verify_audit_chain(path: Path) -> dict[str, object]:
    """Check an export audit file and name broken lines by 1-based number.

    A line without ``previous_record_sha256`` before any chained line is "사슬 이전" (pre-chain:
    counted, not broken); an R7 sidecar (one indented JSON object) is one pre-chain record. A
    chained line must carry the SHA-256 of the previous line. A line that cannot be read, or
    whose content no longer matches its own ``record_sha256``, is named itself; when only the
    link to the next line breaks, the previous line is named (it changed, or a line after it
    was removed).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    totals = {"records": 0, "pre_chain": 0, "chained": 0, "unreadable": 0}
    broken: dict[int, str] = {}
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None
    if isinstance(whole, dict):
        totals["records"] = 1
        totals["chained" if CHAIN_FIELD in whole else "pre_chain"] = 1
        return _chain_report(path, "sidecar", totals, broken)

    previous: tuple[int, str] | None = None
    chain_started = False
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            record = None
        if not isinstance(record, dict):
            totals["unreadable"] += 1
            broken.setdefault(number, "JSON 한 줄로 읽을 수 없음")
        elif CHAIN_FIELD not in record:
            totals["records"] += 1
            if chain_started:
                broken.setdefault(number, "사슬이 시작된 뒤에 사슬 필드가 없는 줄")
            else:
                totals["pre_chain"] += 1
        else:
            totals["records"] += 1
            totals["chained"] += 1
            chain_started = True
            own = record.get(RECORD_HASH_FIELD)
            if own is not None and str(own) != _record_self_hash(record):
                broken.setdefault(number, "줄 내용이 이 줄의 해시와 다름(이 줄이 바뀜)")
            wanted = _sha256_text(previous[1]) if previous is not None else ""
            if str(record.get(CHAIN_FIELD) or "") != wanted:
                if previous is not None and number not in broken:
                    broken.setdefault(
                        previous[0], f"{number}번째 줄이 기록한 직전 줄 해시와 다름(이 줄이 바뀌었거나 뒤 줄이 빠짐)"
                    )
                else:
                    broken.setdefault(number, "직전 줄 해시 불일치")
        previous = (number, line)
    return _chain_report(path, "lines", totals, broken)


def _chain_report(path: Path, layout: str, totals: Mapping[str, int], broken: Mapping[int, str]) -> dict[str, object]:
    broken_lines = [{"line": number, "reason": broken[number]} for number in sorted(broken)]
    return {
        "path": str(path),
        "layout": layout,
        **totals,
        "pre_chain_lines": totals["pre_chain"],
        "pre_chain_label": f"사슬 이전 {totals['pre_chain']}줄",
        "ok": not broken_lines,
        "first_broken_line": broken_lines[0]["line"] if broken_lines else None,
        "broken_lines": broken_lines,
    }


def dedupe_records(records: Sequence[tuple[str, Path]]) -> list[tuple[str, Path]]:
    seen: set[tuple[str, str]] = set()
    normalized: list[tuple[str, Path]] = []
    for label, path in records:
        resolved = path.expanduser().resolve()
        key = (label, str(resolved))
        if key in seen:
            continue
        seen.add(key)
        normalized.append((label, resolved))
    return normalized
