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
    f"대상: 같은 폴더의 {EXPORT_AUDIT_LOG_NAME} (한 줄 = 내보내기 1건, 덧붙이기만 함; .audit 파일은 마지막 1건 사본)",
    f"줄 해시: {RECORD_HASH_FIELD} = 이 필드를 뺀 기록의 SHA-256, 인코딩은 UTF-8 · 키 사전순 정렬 · 구분자 ',' ':' (공백 없음)"
    " · 비ASCII 문자 이스케이프 안 함 = Python json.dumps(ensure_ascii=False, sort_keys=True, separators=(',', ':'))",
    f"사슬: {CHAIN_FIELD} = 직전 줄 원문(UTF-8, 줄바꿈 제외)의 SHA-256, 첫 줄은 빈 값; 사슬 줄에 {RECORD_HASH_FIELD}가 없으면 깨짐",
    "순서: 첫 줄부터 차례로(줄 구분은 LF만), 옛 형식 줄은 '사슬 이전'(검사하지 않은 줄), 첫 사슬 줄의 직전 해시가 비어 있지 않으면 앞부분 잘림; 끝 줄 삭제는 마지막 줄 해시를 따로 보관해야 알 수 있음",
    f"명령: rapidtriage audit-verify {EXPORT_AUDIT_LOG_NAME} --json [--expect-last <마지막 {RECORD_HASH_FIELD}>] (온전 종료 0 · 깨짐·기록 0줄 종료 3)",
)
# What an unanchored chain check cannot show (printed by audit-verify unless --expect-last matched).
UNANCHORED_LIMITS: tuple[str, ...] = (
    "끝 줄 삭제·파일 전체 재작성은 이 검사로 알 수 없음 — 마지막 줄 record_sha256을 따로 보관해 --expect-last로 비교",
)
SIDECAR_LIMIT = f".audit 파일은 마지막 1건 사본 — 이력 전체는 같은 폴더의 {EXPORT_AUDIT_LOG_NAME}를 검사해야 함"
# The keys of a record written before the chain format (R7 sidecar). Any other key is chain-era.
LEGACY_RECORD_KEYS = frozenset({"command", "generated_at", "provenance", "integrity"})
UNVERIFIABLE_NO_CHAIN = "확인 불가 — 사슬 기록 0줄: 해시로 검사할 수 있는 줄이 하나도 없어 내용을 검사하지 않았음"


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
        (line for line in reversed(_audit_lines(existing.decode("utf-8", errors="replace"))) if line.strip()),
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


def _audit_lines(text: str) -> list[str]:
    """Split on LF only (a trailing CR is dropped): ``str.splitlines`` also splits on U+2028 /
    U+0085, which ``json.dumps(ensure_ascii=False)`` writes raw inside a record (review P2-1)."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def _is_legacy_record(record: Mapping[str, object]) -> bool:
    """A record written before the chain format: only the R7 keys, a ``generated_at`` without zone."""
    if "command" not in record or not set(record) <= LEGACY_RECORD_KEYS:
        return False
    stamp = record.get("generated_at")
    if not isinstance(stamp, str):
        return stamp is None
    try:
        return dt.datetime.fromisoformat(stamp).tzinfo is None
    except ValueError:
        return False


def verify_audit_chain(path: Path, *, expected_last_sha256: str | None = None) -> dict[str, object]:
    """Check an export audit file and name broken lines by 1-based number.

    Layout (R8 WB-12 review P0-1): the history ``rapidtriage-export-audit.jsonl`` is always read
    as one record per line, whatever its formatting (an indented JSON object in it is broken); any
    other file that is one indented JSON object is an ``.audit`` sidecar. Rules:

    * "사슬 이전" (pre-chain: counted, contents not checked) only for an R7-format record (keys
      ``command`` / ``generated_at`` without zone / ``provenance`` / ``integrity`` only) before the
      first chained line; a record with any chain-era field (``verification_method``,
      ``tool_version``, ``record_sha256`` ...) but no chain field is broken (hash keys removed);
    * a chained record must carry ``record_sha256`` equal to the recomputed hash;
    * a chained line must carry the SHA-256 of the previous line; the first chained line of a
      file must carry "" (or the hash of the pre-chain line before it), else "앞부분 잘림 가능";
    * a chain-era sidecar must equal one record of an intact history next to it; without that
      history it is "확인 불가" (not intact);
    * an R7-shaped sidecar next to a history that has chained records is broken unless that exact
      record is a pre-chain line of the history (R8 WB-13 review P1-1: the R7 shape is easy to type);
    * zero records, or zero chained records (an all-R7 file, a lone ``{"command": ...}`` line), is
      never intact: nothing was checked, so the status is "확인 불가" (exit 3).

    ``expected_last_sha256`` (the last ``record_sha256`` kept elsewhere) closes tail deletion and
    whole rewrites of the history; on a sidecar it proves that one record only.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    totals = {"records": 0, "pre_chain": 0, "chained": 0, "unreadable": 0}
    broken: dict[int, str] = {}
    unverifiable: list[str] = []
    content_lines = [(number, line) for number, line in enumerate(_audit_lines(text), start=1) if line.strip()]
    is_history = path.name.lower() == EXPORT_AUDIT_LOG_NAME
    layout = "lines"
    sidecar_record: dict[str, object] | None = None
    if len(content_lines) > 1 and _json_or_none(content_lines[0][1]) is None:
        whole = _json_or_none(text)
        if isinstance(whole, dict):
            if is_history:
                # An indented object in the history is not one record per line, whatever it holds.
                broken[content_lines[0][0]] = "한 줄 한 기록 형식이 아님(여러 줄로 나뉜 JSON)"
            else:
                layout = "sidecar"
                sidecar_record = whole
    entries: list[tuple[int, str, object]] = (
        [(1, "", sidecar_record)] if sidecar_record is not None else [(n, line, _json_or_none(line)) for n, line in content_lines]
    )

    previous: tuple[int, str] | None = None
    chain_started = False
    last_hash = ""
    for number, line, record in entries:
        if not isinstance(record, dict):
            totals["unreadable"] += 1
            broken.setdefault(number, "JSON 한 줄로 읽을 수 없음")
            previous = (number, line)
            continue
        totals["records"] += 1
        legacy = _is_legacy_record(record)
        if CHAIN_FIELD not in record:
            if chain_started:
                broken.setdefault(number, "사슬이 시작된 뒤에 사슬 필드가 없는 줄")
            elif "command" not in record:
                broken.setdefault(number, "감사 기록 형식이 아님(command 없음)")
            elif not legacy:
                broken.setdefault(number, "사슬 형식 기록인데 사슬 필드가 없음(해시 필드를 지운 줄)")
            else:
                totals["pre_chain"] += 1
            previous = (number, line)
            continue
        totals["chained"] += 1
        first_chained = not chain_started
        chain_started = True
        own = record.get(RECORD_HASH_FIELD)
        if not own:
            broken.setdefault(number, f"사슬 줄에 {RECORD_HASH_FIELD}가 없음(줄 해시를 지운 줄)")
        elif str(own) != _record_self_hash(record):
            broken.setdefault(number, "줄 내용이 이 줄의 해시와 다름(이 줄이 바뀜)")
        last_hash = str(own or "")
        if layout == "lines":
            wanted = _sha256_text(previous[1]) if previous is not None else ""
            if str(record.get(CHAIN_FIELD) or "") != wanted:
                if first_chained and previous is None:
                    broken.setdefault(number, "앞부분 잘림 가능 — 첫 기록의 직전 줄 해시가 비어 있지 않음")
                elif first_chained:
                    broken.setdefault(number, "앞부분 잘림 가능 — 첫 사슬 기록의 직전 줄 해시가 바로 앞 줄과 다름")
                elif previous is not None and number not in broken:
                    broken.setdefault(
                        previous[0], f"{number}번째 줄이 기록한 직전 줄 해시와 다름(이 줄이 바뀌었거나 뒤 줄이 빠짐)"
                    )
                else:
                    broken.setdefault(number, "직전 줄 해시 불일치")
        previous = (number, line)

    history_checked: bool | None = None
    if layout == "sidecar" and sidecar_record is not None and not _is_legacy_record(sidecar_record) and not broken:
        # Not conditional on the sidecar keeping its chain field (review P0-1 D).
        history = path.with_name(EXPORT_AUDIT_LOG_NAME)
        if not history.is_file():
            unverifiable.append(f"확인 불가 — 같은 폴더에 {EXPORT_AUDIT_LOG_NAME}가 없어 이 기록을 대조할 수 없음")
        else:
            history_report = verify_audit_chain(history)
            history_records = [
                item
                for item in (_json_or_none(line) for line in _audit_lines(history.read_text(encoding="utf-8", errors="replace")))
                if isinstance(item, dict)
            ]
            history_checked = bool(history_report["ok"]) and sidecar_record in history_records
            if sidecar_record not in history_records:
                broken.setdefault(1, f"같은 폴더의 {EXPORT_AUDIT_LOG_NAME}에 이 기록과 같은 기록이 없음")
            elif not history_report["ok"]:
                broken.setdefault(
                    1, f"같은 폴더의 {EXPORT_AUDIT_LOG_NAME}가 온전하지 않음(첫 번째 깨진 줄 {history_report['first_broken_line']})"
                )
    if layout == "sidecar" and sidecar_record is not None and _is_legacy_record(sidecar_record) and not broken:
        # R8 WB-13 review P1-1 F: an R7-shaped copy beside a chain-era history must be one of its
        # pre-chain lines; any other R7-shaped sidecar there was typed after the chain began.
        history = path.with_name(EXPORT_AUDIT_LOG_NAME)
        if history.is_file():
            history_records = [
                item
                for item in (_json_or_none(line) for line in _audit_lines(history.read_text(encoding="utf-8", errors="replace")))
                if isinstance(item, dict)
            ]
            if any(CHAIN_FIELD in item for item in history_records):
                pre_chain_records = [item for item in history_records if CHAIN_FIELD not in item and _is_legacy_record(item)]
                history_checked = sidecar_record in pre_chain_records
                if not history_checked:
                    broken.setdefault(
                        1, f"사슬 이전 형식 사본인데 같은 폴더의 {EXPORT_AUDIT_LOG_NAME}(사슬 기록 있음)의 사슬 이전 줄에 같은 기록이 없음"
                    )
    if totals["records"] == 0 and not broken:
        broken[0] = "감사 기록이 0줄 — 확인할 기록이 없음"
    elif totals["chained"] == 0 and not broken:
        # R8 WB-13 review P1-1: an all-R7 file (or a lone {"command": ...} line) checked nothing.
        broken[0] = UNVERIFIABLE_NO_CHAIN
    anchor: dict[str, object] = {"expected_last_sha256": expected_last_sha256 or None, "matched": None}
    if expected_last_sha256:
        matched = bool(last_hash) and last_hash.lower() == expected_last_sha256.strip().lower()
        anchor["matched"] = matched
        if not matched:
            broken.setdefault(
                previous[0] if previous is not None else 0,
                "마지막 기록 해시가 따로 보관한 값과 다름(끝 줄 삭제·추가 또는 파일 전체 재작성)",
            )
    report = _chain_report(path, layout, totals, broken, unverifiable)
    report["last_record_sha256"] = last_hash or None
    report["anchor"] = anchor
    report["history_contains_sidecar"] = history_checked
    not_proven: list[str] = []
    # The anchor proves the history's tail; on a sidecar it proves that one record only (P0-1 C).
    if not (anchor["matched"] and layout == "lines"):
        not_proven.extend(UNANCHORED_LIMITS)
    if layout == "sidecar":
        not_proven.append(SIDECAR_LIMIT)
    if totals["pre_chain"]:
        not_proven.append(f"사슬 이전 {totals['pre_chain']}줄은 내용을 검사하지 않음(검사하지 않은 줄)")
    report["not_proven"] = not_proven
    return report


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate key {key!r}")  # review P2-2: readers disagree on which value wins
        record[key] = value
    return record


def _json_or_none(line: str) -> object:
    try:
        return json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except ValueError:  # JSONDecodeError is a ValueError, and so is a duplicate key
        return None


def _chain_report(
    path: Path, layout: str, totals: Mapping[str, int], broken: Mapping[int, str], unverifiable: Sequence[str] = ()
) -> dict[str, object]:
    broken_lines = [{"line": number, "reason": broken[number]} for number in sorted(broken)]
    if broken_lines:
        status = "unverifiable" if all(item["reason"].startswith("확인 불가") for item in broken_lines) else "broken"
    else:
        status = "unverifiable" if unverifiable else "intact"
    return {
        "path": str(path),
        "layout": layout,
        **totals,
        "pre_chain_lines": totals["pre_chain"],
        "pre_chain_label": f"사슬 이전 {totals['pre_chain']}줄",
        "unchecked_lines": totals["pre_chain"],
        "status": status,
        "unverifiable": list(unverifiable),
        "ok": status == "intact",
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
