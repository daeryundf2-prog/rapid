"""Read roots of an imported run (R8 T-350 / GAP-362).

``POST /api/runs/import`` pins the *write* side of a result folder (``output_dir`` is the folder
the summary was read from, ``outputs`` must stay inside it — :func:`core.jobs.validated_import_summary`).
The *read* side used to trust the summary too: ``root`` / ``scan_scope_root`` /
``source.analysis_root`` / ``source.stage_dir`` became roots the source routes (원본 보기, hex,
download, extract …) serve files from, so a forged summary could make the server read any folder.

For a run imported over the API (``summary["imported_run"] is True`` — set by
``POST /api/runs/import`` and by state restore for older imports, never taken from the file) the
read roots are:

* the result folder itself, unless it contains the server state folder or a credential store;
* the claimed evidence roots that lie inside that folder (image stage / extract folders);
* a claimed evidence root outside the folder only when the run's own input fingerprint
  (``rapidtriage-run-fingerprint.json`` inside the folder: relative path + size [+ SHA-256] of the
  scanned files) matches what is on disk under the claimed ``scan_scope_root`` — at least
  :data:`MATCH_RATIO` of up to :data:`SAMPLE_ROWS` recorded files — and the root is neither a
  filesystem root, nor contains the server state / a credential store / the home folder, nor lies
  inside a credential store. Other claimed roots are accepted only inside that verified root.

Anything else is refused with ``IMPORT_SOURCE_ROOT_UNVERIFIED`` ("원본 위치를 확인할 수 없습니다").
Runs the server executed itself keep their roots unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PurePosixPath

from .credential_stores import is_credential_store_path, known_credential_store_dirs

__all__ = [
    "IMPORTED_RUN_KEY",
    "IMPORT_ROOT_UNVERIFIED_MESSAGE",
    "IMPORT_SOURCE_ROOT_UNVERIFIED",
    "ImportRoots",
    "blocked_root_reason",
    "imported_run_roots",
    "is_imported_summary",
]

#: Summary key the import sets (and state restore re-sets for ``origin == "imported"``).
IMPORTED_RUN_KEY = "imported_run"
IMPORT_SOURCE_ROOT_UNVERIFIED = "IMPORT_SOURCE_ROOT_UNVERIFIED"
IMPORT_ROOT_UNVERIFIED_MESSAGE = "원본 위치를 확인할 수 없습니다"

FINGERPRINT_NAME = "rapidtriage-run-fingerprint.json"
FINGERPRINT_MAX_BYTES = 32 * 1024 * 1024
SAMPLE_ROWS = 64
MATCH_RATIO = 0.8
HASH_MAX_BYTES = 4 * 1024 * 1024
HASH_MAX_ROWS = 8
#: Verification results are reused for this long (seconds) per (root, fingerprint file state).
CACHE_SECONDS = 300

REASON_TEXT = {
    "missing": "경로가 없습니다",
    "filesystem-root": "드라이브·파일 시스템 최상위는 증거 루트로 받지 않습니다",
    "contains-server-state": "서버 상태 폴더를 포함합니다",
    "contains-credential-store": "자격 증명 저장소를 포함합니다",
    "contains-home": "사용자 홈 폴더를 포함합니다",
    "inside-credential-store": "자격 증명 저장소 안입니다",
    "fingerprint-missing": "결과 폴더에 입력 지문(rapidtriage-run-fingerprint.json)이 없습니다",
    "fingerprint-mismatch": "결과에 기록된 입력 파일(경로·크기·해시)과 맞지 않습니다",
    "outside-verified-root": "검증된 증거 루트 밖입니다",
}


@dataclass(frozen=True)
class ImportRoots:
    allowed: list[Path] = field(default_factory=list)
    #: ``(claimed root, reason code)`` for every claimed root that was not accepted.
    refused: list[tuple[Path, str]] = field(default_factory=list)


def is_imported_summary(summary: Mapping[str, object] | None) -> bool:
    return isinstance(summary, Mapping) and summary.get(IMPORTED_RUN_KEY) is True


def _resolve(value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return Path(value).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def server_state_dirs() -> list[Path]:
    from .jobs import default_state_path

    dirs: list[Path] = []
    for candidate in (default_state_path().parent, Path.home() / ".rapidtriage"):
        resolved = _resolve(str(candidate))
        if resolved is not None and resolved not in dirs:
            dirs.append(resolved)
    return dirs


def blocked_root_reason(path: Path) -> str | None:
    """Why ``path`` may never be a read root of an imported run (``None`` when it may).

    A root *inside* the state folder stays possible (practice samples live under
    ``~/.rapidtriage``); one that contains it does not."""
    if path.parent == path:
        return "filesystem-root"
    if is_credential_store_path(path):
        return "inside-credential-store"
    for state in server_state_dirs():
        if _is_under(state, path):
            return "contains-server-state"
    for store in known_credential_store_dirs():
        resolved = _resolve(str(store))
        if resolved is not None and _is_under(resolved, path):
            return "contains-credential-store"
    home = _resolve(str(Path.home()))
    if home is not None and _is_under(home, path):
        return "contains-home"
    return None


def _claimed_roots(summary: Mapping[str, object]) -> list[Path]:
    values: list[object] = [summary.get("scan_scope_root"), summary.get("root")]
    source = summary.get("source")
    if isinstance(source, Mapping):
        values += [source.get("analysis_root"), source.get("stage_dir")]
    roots: list[Path] = []
    for value in values:
        resolved = _resolve(value)
        if resolved is not None and resolved not in roots:
            roots.append(resolved)
    return roots


def _fingerprint_path(summary: Mapping[str, object], folder: Path) -> Path:
    outputs = summary.get("outputs")
    if isinstance(outputs, Mapping):
        candidate = _resolve(outputs.get("fingerprint"))
        if candidate is not None and _is_under(candidate, folder):
            return candidate
    return folder / FINGERPRINT_NAME


def imported_run_roots(summary: Mapping[str, object]) -> ImportRoots:
    """Read roots of an imported run (see the module docstring)."""
    allowed: list[Path] = []
    refused: list[tuple[Path, str]] = []
    folder = _resolve(summary.get("output_dir"))
    folder_reason: str | None = None
    if folder is not None:
        folder_reason = blocked_root_reason(folder)
        if folder_reason is None:
            allowed.append(folder)
        else:
            refused.append((folder, folder_reason))
    claimed = _claimed_roots(summary)
    anchor = _resolve(summary.get("scan_scope_root")) or (claimed[0] if claimed else None)
    verified: Path | None = None
    anchor_reason = ""
    if anchor is not None and not (folder is not None and _is_under(anchor, folder)):
        anchor_reason = _verify_anchor(anchor, summary, folder)
        if not anchor_reason:
            verified = anchor
    for root in claimed:
        if folder is not None and _is_under(root, folder):
            if folder_reason is None:
                continue  # served through the folder itself
            refused.append((root, folder_reason))
            continue
        if verified is not None and _is_under(root, verified):
            reason = blocked_root_reason(root)
            if reason is None:
                allowed.append(root)
            else:
                refused.append((root, reason))
            continue
        refused.append((root, anchor_reason if root == anchor and anchor_reason else "outside-verified-root"))
    deduped: list[Path] = []
    for root in allowed:
        if root not in deduped:
            deduped.append(root)
    return ImportRoots(allowed=deduped, refused=refused)


def _verify_anchor(anchor: Path, summary: Mapping[str, object], folder: Path | None) -> str:
    """``""`` when ``anchor`` is an acceptable, fingerprint-verified evidence root, else a reason code."""
    if not anchor.is_dir():
        return "missing" if not anchor.exists() else "fingerprint-mismatch"
    reason = blocked_root_reason(anchor)
    if reason is not None:
        return reason
    if folder is None:
        return "fingerprint-missing"
    fingerprint = _fingerprint_path(summary, folder)
    try:
        stat = fingerprint.stat()
    except OSError:
        return "fingerprint-missing"
    if not fingerprint.is_file() or stat.st_size > FINGERPRINT_MAX_BYTES:
        return "fingerprint-missing"
    bucket = int(time.time() // CACHE_SECONDS)
    return _cached_fingerprint_check(str(anchor), str(fingerprint), stat.st_mtime_ns, stat.st_size, bucket)


@lru_cache(maxsize=256)
def _cached_fingerprint_check(anchor: str, fingerprint: str, _mtime_ns: int, _size: int, _bucket: int) -> str:
    try:
        payload = json.loads(Path(fingerprint).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "fingerprint-missing"
    if not isinstance(payload, Mapping) or payload.get("command") != "run-fingerprint":
        return "fingerprint-missing"
    files = payload.get("files")
    rows = [
        row
        for row in (files if isinstance(files, list) else [])
        if isinstance(row, Mapping) and isinstance(row.get("relative_path"), str) and isinstance(row.get("size_bytes"), int)
    ]
    if not rows:
        return "fingerprint-missing"
    step = max(1, len(rows) // SAMPLE_ROWS)
    sample = rows[::step][:SAMPLE_ROWS]
    root = Path(anchor)
    matched = 0
    hashed = 0
    for row in sample:
        verdict, used_hash = _row_matches(root, row, hash_allowed=hashed < HASH_MAX_ROWS)
        hashed += int(used_hash)
        matched += int(verdict)
    return "" if matched >= max(1, math.ceil(MATCH_RATIO * len(sample))) else "fingerprint-mismatch"


def _row_matches(root: Path, row: Mapping[str, object], *, hash_allowed: bool) -> tuple[bool, bool]:
    relative = PurePosixPath(str(row["relative_path"]).replace("\\", "/"))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or ":" in relative.parts[0]:
        return False, False
    target = root.joinpath(*relative.parts)
    try:
        resolved = target.resolve()
        if not _is_under(resolved, root) or not resolved.is_file():
            return False, False
        size = resolved.stat().st_size
    except OSError:
        return False, False
    if size != row["size_bytes"]:
        return False, False
    expected = row.get("sha256")
    if not (isinstance(expected, str) and expected and hash_allowed and size <= HASH_MAX_BYTES):
        return True, False
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False, True
    return digest.hexdigest() == expected.lower(), True


def refusal_text(reason: str) -> str:
    return REASON_TEXT.get(reason, reason)


def clear_cache() -> None:
    """Forget cached verifications (tests; a re-import of a changed folder)."""
    _cached_fingerprint_check.cache_clear()
