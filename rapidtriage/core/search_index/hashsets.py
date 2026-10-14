"""Hash-set store (plan §3.2 ``/api/hash-sets``): ``<data dir>/hash-sets/<id>.sqlite``.

A set is a small SQLite file (``hash_entry(algorithm, value)`` + ``meta``)
that the search engine ATTACHes read-only for ``hashset:<id>`` /
``-hashset:<id>`` and ``options.hide_hashsets``. Text lists (one hash per
line, ``#`` comments) and CSV/NSRL RDS files are parsed with
``core.files.parse_known_good_hash_feed`` (the files stage's known-good parser).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections import Counter
from pathlib import Path

from ..files import HASH_TOKEN_RE, parse_known_good_hash_feed
from .textutil import normalize_hash

DATA_DIR_ENV = "RAPIDTRIAGE_DATA_DIR"
HASH_SET_DIR = "hash-sets"
HASH_SET_ID_RE = re.compile(r"^hs-[0-9a-f]{12}$")
LABELS = ("known-good", "known-bad", "custom")
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_REJECTED = 100
NAME_MAX_CHARS = 200


class HashSetError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def data_dir() -> Path:
    explicit = os.environ.get(DATA_DIR_ENV)
    if explicit and explicit.strip():
        return Path(explicit.strip()).expanduser()
    from ..jobs import default_state_path

    return default_state_path().parent


def hash_set_dir() -> Path:
    return data_dir() / HASH_SET_DIR


def hash_set_path(hash_set_id: str) -> Path | None:
    """Path of an existing set, ``None`` for an unknown or malformed id."""
    if not HASH_SET_ID_RE.fullmatch(hash_set_id or ""):
        return None
    path = hash_set_dir() / f"{hash_set_id}.sqlite"
    return path if path.is_file() else None


def _parse_text_lines(text: str) -> tuple[list[tuple[str, str]], list[dict[str, object]], int]:
    hashes: list[tuple[str, str]] = []
    rejected: list[dict[str, object]] = []
    rejected_count = 0
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = HASH_TOKEN_RE.findall(stripped)
        normalized = [item for item in (normalize_hash(token) for token in tokens) if item is not None]
        if not normalized:
            rejected_count += 1
            if len(rejected) < MAX_REJECTED:
                rejected.append({"line": number, "reason": "해시(MD5·SHA-1·SHA-256 16진수)가 없습니다", "text": stripped[:120]})
            continue
        hashes.extend(normalized)
    return hashes, rejected, rejected_count


def _parse_csv(data: bytes, filename: str) -> tuple[list[tuple[str, str]], list[dict[str, object]], int, str]:
    suffix = ".csv"
    with tempfile.TemporaryDirectory(prefix="rapidtriage-hashset-") as directory:
        path = Path(directory) / f"upload{suffix}"
        path.write_bytes(data)
        parsed = parse_known_good_hash_feed(path)
    records = parsed.get("records") if isinstance(parsed.get("records"), list) else []
    hashes: list[tuple[str, str]] = []
    rows_with_hash: set[int] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        normalized = normalize_hash(str(record.get("token") or ""))
        if normalized is None:
            continue
        hashes.append(normalized)
        source = record.get("source") if isinstance(record.get("source"), dict) else {}
        if isinstance(source.get("row_number"), int):
            rows_with_hash.add(int(source["row_number"]))
    rejected: list[dict[str, object]] = []
    rejected_count = 0
    row_count = int(parsed.get("row_count") or 0)
    if rows_with_hash:
        for number in range(2, row_count + 2):
            if number not in rows_with_hash:
                rejected_count += 1
                if len(rejected) < MAX_REJECTED:
                    rejected.append({"line": number, "reason": "해시 열에 해시가 없습니다"})
    return hashes, rejected, rejected_count, str(parsed.get("format") or "csv")


def _looks_csv(text_head: str, filename: str) -> bool:
    if filename.lower().endswith(".csv"):
        return True
    first = text_head.splitlines()[0] if text_head else ""
    return first.count(",") >= 2 and not HASH_TOKEN_RE.search(first)


def create_hash_set(*, name: str, label: str, data: bytes, filename: str = "") -> dict[str, object]:
    """Parse ``data`` (text or CSV/NSRL), store the set and return its summary."""
    clean_name = " ".join(str(name or "").split())[:NAME_MAX_CHARS]
    if not clean_name:
        raise HashSetError("해시 세트 이름이 필요합니다")
    if label not in LABELS:
        raise HashSetError(f"해시 세트 라벨은 {', '.join(LABELS)} 중 하나여야 합니다")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HashSetError("해시 세트 파일이 너무 큽니다(최대 50 MB)", status=413)
    if b"\x00" in data[:4096]:
        raise HashSetError("해시 세트 파일이 텍스트가 아닙니다")
    text_head = data[:65536].decode("utf-8-sig", errors="replace")
    if _looks_csv(text_head, filename):
        hashes, rejected, rejected_count, feed_format = _parse_csv(data, filename)
    else:
        hashes, rejected, rejected_count = _parse_text_lines(data.decode("utf-8-sig", errors="replace"))
        feed_format = "text"
    unique = sorted(set(hashes))
    if not unique:
        raise HashSetError("해시 세트에 유효한 해시가 없습니다")
    counts = Counter(algorithm for algorithm, _value in unique)
    hash_set_id = f"hs-{uuid.uuid4().hex[:12]}"
    directory = hash_set_dir()
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / f"{hash_set_id}.sqlite"
    temporary = directory / f"{hash_set_id}.sqlite.tmp"
    summary = {
        "id": hash_set_id,
        "name": clean_name,
        "label": label,
        "count": len(unique),
        "count_by_algorithm": dict(sorted(counts.items())),
        "sha256": hashlib.sha256(data).hexdigest(),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "format": feed_format,
        "filename": os.path.basename(filename)[:200] if filename else "",
        "rejected_count": rejected_count,
        "rejected_lines": rejected,
    }
    connection = sqlite3.connect(str(temporary))
    try:
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("CREATE TABLE hash_entry (algorithm TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (algorithm, value)) WITHOUT ROWID")
        connection.executemany("INSERT INTO hash_entry VALUES (?, ?)", unique)
        connection.execute("INSERT INTO meta VALUES ('summary', ?)", (json.dumps(summary, ensure_ascii=False),))
        connection.commit()
    finally:
        connection.close()
    os.replace(temporary, final)
    return summary


def read_hash_set(hash_set_id: str) -> dict[str, object]:
    path = hash_set_path(hash_set_id)
    if path is None:
        raise HashSetError("해시 세트를 찾을 수 없습니다", status=404)
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        row = connection.execute("SELECT value FROM meta WHERE key = 'summary'").fetchone()
    except sqlite3.Error as exc:
        raise HashSetError(f"해시 세트를 읽을 수 없습니다: {exc}", status=409) from exc
    finally:
        connection.close()
    try:
        summary = json.loads(row[0]) if row else {}
    except ValueError:
        summary = {}
    return summary if isinstance(summary, dict) else {}


def list_hash_sets() -> list[dict[str, object]]:
    directory = hash_set_dir()
    try:
        names = sorted(path.stem for path in directory.glob("hs-*.sqlite"))
    except OSError:
        return []
    sets: list[dict[str, object]] = []
    for name in names:
        try:
            summary = read_hash_set(name)
        except HashSetError:
            continue
        summary.pop("rejected_lines", None)
        sets.append(summary)
    sets.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return sets


def read_hash_values(hash_set_id: str) -> list[tuple[str, str]]:
    path = hash_set_path(hash_set_id)
    if path is None:
        raise HashSetError("해시 세트를 찾을 수 없습니다", status=404)
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return [(str(row[0]), str(row[1])) for row in connection.execute("SELECT algorithm, value FROM hash_entry")]
    finally:
        connection.close()


def delete_hash_set(hash_set_id: str) -> None:
    path = hash_set_path(hash_set_id)
    if path is None:
        raise HashSetError("해시 세트를 찾을 수 없습니다", status=404)
    path.unlink()
