"""P2P clients: BitTorrent (qBittorrent, uTorrent / BitTorrent, FrostWire, any ``.torrent``) and eMule (R5 L3).

재감사 §3 item 10. One provider, kind ``p2p``, row types:

``p2p-torrent``       a ``.torrent`` file: info-hash (v1 SHA-1 of the bencoded ``info``, v2
                      SHA-256 when ``meta version`` is 2), name, total size, file count and a
                      file-list sample, tracker hosts, creation date, ``created by``, comment
``p2p-transfer``      a client's transfer record: qBittorrent ``BT_backup\\*.fastresume``,
                      uTorrent / BitTorrent ``resume.dat`` entries, FrostWire ``*.resume``,
                      eMule ``*.part.met`` (unfinished download): added / completed time, save
                      path, uploaded / downloaded bytes, state
``p2p-shared-file``   eMule ``known.met``: shared / completed file name, size, ed2k (MD4) hash,
                      file date, last shared time, all-time uploaded / requested / accepted
``p2p-search-term``   eMule ``AC_SearchStrings.dat`` (search box history)
``p2p-client-config`` eMule ``preferences.ini``: nick, incoming / temp directory, version
``p2p-parse-error``   a source that could not be read (the run continues): a fixed ``reason`` /
                      ``reason_code`` with Korean ``reason_ko``

Bencode is decoded by a pure-Python, bounded reader (depth, item count, input size). Tracker
URLs are cut to ``scheme://host[:port]``: private-tracker URLs carry the user's passkey in the
path or query, which is never copied. Every row carries ``recovery_method``, ``parser_version``,
``source_path`` and ``client``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import struct
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from urllib.parse import urlsplit

from ..core.models import ArtifactRecord
from ._walk import iter_evidence_paths

PARSER = "p2p-artifacts"
PARSER_VERSION = "p2p-artifacts-v1"
MAX_BENCODE_BYTES = 64 * 1024 * 1024
MAX_TORRENT_BYTES = 16 * 1024 * 1024
MAX_BENCODE_DEPTH = 64
MAX_BENCODE_ITEMS = 2_000_000
MAX_TORRENT_FILES = 5_000
MAX_ROWS_PER_SOURCE = 20_000
MAX_FILE_SAMPLE = 50
MAX_TRACKERS = 20
MAX_MET_BYTES = 64 * 1024 * 1024
MAX_TEXT_CHARS = 500
MAX_SEARCH_TERMS = 5_000
MIN_UNIX = 946_684_800  # 2000-01-01
MAX_UNIX = 4_102_444_800  # 2100-01-01
CLIENT_LABELS = {
    "qbittorrent": "qBittorrent",
    "utorrent": "µTorrent",
    "bittorrent": "BitTorrent",
    "frostwire": "FrostWire",
    "emule": "eMule",
    "torrent-file": ".torrent 파일",
}
EMULE_TAG_NAMES = {
    0x01: "file_name",
    0x02: "file_size",
    0x03: "file_type",
    0x05: "last_seen_complete",
    0x08: "transferred",
    0x12: "part_file_name",
    0x14: "status",
    0x22: "flags",
    0x23: "download_active_time",
    0x34: "last_shared",
    0x3A: "file_size_hi",
    0x50: "all_time_transferred",
    0x51: "all_time_requested",
    0x52: "all_time_accepted",
    0x53: "category",
    0x54: "all_time_transferred_hi",
}
# Fixed ``p2p-parse-error`` reason codes → Korean text (R6 S2 D). The catalogue column ``reason``
# (p2p.yaml, family ``p2p-error``) carries the same value labels; a test asserts every code passed
# to ``_error`` is listed in both.
REASON_KO = {
    "torrent-unreadable": ".torrent 읽기 실패",
    "resume-unreadable": "이어받기 정보 읽기 실패",
    "resume-not-a-dictionary": "이어받기 정보 형식 아님",
    "resume-dat-unreadable": "resume.dat 읽기 실패",
    "resume-dat-not-a-dictionary": "resume.dat 형식 아님",
    "row-cap-reached": "행 상한 도달",
    "known-met-unreadable": "known.met 읽기 실패",
    "known-met-truncated": "known.met 중간에 잘림(앞 행은 유지)",
    "part-met-unreadable": ".part.met 읽기 실패",
    "search-strings-unreadable": "검색어 파일 읽기 실패",
    "preferences-unreadable": "preferences.ini 읽기 실패",
    "torrent-file-cap-reached": ".torrent 파일 수 상한 도달",
    "source-failed": "원본 처리 실패",
}
EMULE_PREFERENCE_KEYS = {"nick": "nick", "incomingdir": "incoming_dir", "tempdir": "temp_dir", "appversion": "app_version"}


class BencodeError(ValueError):
    """Malformed or over-limit bencode (Korean message)."""


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0
        self.items = 0
        self.info_span: tuple[int, int] | None = None

    def decode(self, depth: int = 0) -> object:
        if depth > MAX_BENCODE_DEPTH:
            raise BencodeError("bencode 중첩이 너무 깊습니다")
        self.items += 1
        if self.items > MAX_BENCODE_ITEMS:
            raise BencodeError("bencode 항목이 상한을 넘습니다")
        if self.position >= len(self.data):
            raise BencodeError("bencode가 중간에 끝납니다")
        lead = self.data[self.position : self.position + 1]
        if lead == b"i":
            end = self.data.find(b"e", self.position + 1, self.position + 23)
            if end < 0:
                raise BencodeError("bencode 정수가 끝나지 않습니다")
            text = self.data[self.position + 1 : end]
            if not re.fullmatch(rb"-?\d{1,20}", text):
                raise BencodeError("bencode 정수 형식이 아닙니다")
            self.position = end + 1
            return int(text)
        if lead == b"l":
            self.position += 1
            items = []
            while self._peek() != b"e":
                items.append(self.decode(depth + 1))
            self.position += 1
            return items
        if lead == b"d":
            self.position += 1
            result: dict[bytes, object] = {}
            while self._peek() != b"e":
                key = self.decode(depth + 1)
                if not isinstance(key, bytes):
                    raise BencodeError("bencode 사전 키가 문자열이 아닙니다")
                start = self.position
                value = self.decode(depth + 1)
                if key == b"info" and depth == 0 and isinstance(value, dict):
                    self.info_span = (start, self.position)
                result[key] = value
            self.position += 1
            return result
        if lead.isdigit():
            colon = self.data.find(b":", self.position, self.position + 21)
            if colon < 0:
                raise BencodeError("bencode 문자열 길이 형식이 아닙니다")
            length = int(self.data[self.position : colon])
            start = colon + 1
            if start + length > len(self.data):
                raise BencodeError("bencode 문자열이 입력 끝을 넘습니다")
            self.position = start + length
            return self.data[start : self.position]
        raise BencodeError(f"bencode 형식이 아닙니다(위치 {self.position})")

    def _peek(self) -> bytes:
        if self.position >= len(self.data):
            raise BencodeError("bencode가 중간에 끝납니다")
        return self.data[self.position : self.position + 1]


def bdecode(data: bytes) -> tuple[object, tuple[int, int] | None]:
    """``(value, (start, end) of the top-level info dict)``; raises :class:`BencodeError`."""
    if len(data) > MAX_BENCODE_BYTES:
        raise BencodeError("bencode 입력이 크기 상한을 넘습니다")
    decoder = _Decoder(data)
    value = decoder.decode()
    return value, decoder.info_span


def _text(value: object) -> str:
    if isinstance(value, bytes):
        for encoding in ("utf-8", "cp949"):
            try:
                return value.decode(encoding)[:MAX_TEXT_CHARS]
            except UnicodeDecodeError:
                continue
        return value.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS]
    if isinstance(value, str):
        return value[:MAX_TEXT_CHARS]
    return ""


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _unix(value: object) -> str | None:
    number = _int(value)
    if number is None or not MIN_UNIX <= number <= MAX_UNIX:
        return None
    return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _get(mapping: Mapping[bytes, object], *keys: bytes) -> object:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def tracker_host(url: str) -> str:
    """``scheme://host[:port]`` of a tracker URL (passkeys in path / query are dropped)."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return ""
    if not parts.scheme or not host:
        return ""
    return f"{parts.scheme.lower()}://{host}{f':{port}' if port else ''}"


def _trackers(*values: object) -> list[str]:
    hosts: list[str] = []

    def add(item: object) -> None:
        if isinstance(item, list):
            for child in item:
                add(child)
            return
        host = tracker_host(_text(item))
        if host and host not in hosts and len(hosts) < MAX_TRACKERS:
            hosts.append(host)

    for value in values:
        add(value)
    return hosts


def torrent_summary(data: bytes) -> dict[str, object]:
    """Fields of a ``.torrent`` (or any bencoded dict with an ``info`` dict); raises BencodeError."""
    value, span = bdecode(data)
    if not isinstance(value, dict):
        raise BencodeError("토렌트 최상위가 사전이 아닙니다")
    info = value.get(b"info")
    fields: dict[str, object] = {}
    if isinstance(info, dict) and span is not None:
        raw = data[span[0] : span[1]]
        v2 = _int(info.get(b"meta version")) == 2
        v1 = b"pieces" in info or not v2
        # BitTorrent v1 info-hash is SHA-1 by definition; a v2-only torrent (BEP 52, no ``pieces``) has no
        # v1 info-hash, so none is emitted rather than a SHA-1 no client would ever announce.
        fields["info_hash"] = hashlib.sha1(raw).hexdigest() if v1 else ""
        fields["torrent_version"] = "hybrid" if v1 and v2 else "v2" if v2 else "v1"
        if v2:
            fields["info_hash_v2"] = hashlib.sha256(raw).hexdigest()
        fields.update(_info_files(info))
    fields.update(
        {
            "trackers": _trackers(value.get(b"announce"), value.get(b"announce-list")),
            "created_at": _unix(value.get(b"creation date")),
            "created_by": _text(value.get(b"created by")),
            "comment": _text(_get(value, b"comment.utf-8", b"comment")),
        }
    )
    return fields


def _info_files(info: Mapping[bytes, object]) -> dict[str, object]:
    name = _text(_get(info, b"name.utf-8", b"name"))
    files: list[dict[str, object]] = []
    total = 0
    count = 0
    listed = info.get(b"files")
    if isinstance(listed, list):
        for item in listed:
            if not isinstance(item, dict):
                continue
            attr = _text(item.get(b"attr"))
            if "p" in attr:
                continue  # BEP 47 padding file
            length = _int(item.get(b"length")) or 0
            parts = _get(item, b"path.utf-8", b"path")
            path = "/".join(_text(part) for part in parts) if isinstance(parts, list) else ""
            count += 1
            total += length
            if len(files) < MAX_FILE_SAMPLE:
                files.append({"path": path[:MAX_TEXT_CHARS], "length": length})
    elif isinstance(info.get(b"file tree"), dict):
        _walk_file_tree(info[b"file tree"], [], files, totals := [0, 0])
        total, count = totals
    else:
        total = _int(info.get(b"length")) or 0
        count = 1
        files.append({"path": name, "length": total})
    return {
        "name": name,
        "total_size": total,
        "file_count": count,
        "files": files,
        "files_truncated": count > len(files),
        "piece_length": _int(info.get(b"piece length")),
        "private": _int(info.get(b"private")) == 1,
    }


def _walk_file_tree(tree: Mapping[bytes, object], prefix: list[str], files: list[dict[str, object]], totals: list[int], depth: int = 0) -> None:
    """BitTorrent v2 ``file tree`` (BEP 52): ``{name: {"": {length}}}`` nested dictionaries."""
    if depth > MAX_BENCODE_DEPTH:
        return
    for key, child in tree.items():
        if not isinstance(child, dict):
            continue
        if key == b"" and isinstance(child.get(b"length"), int):
            totals[0] += child[b"length"]
            totals[1] += 1
            if len(files) < MAX_FILE_SAMPLE:
                files.append({"path": "/".join(prefix)[:MAX_TEXT_CHARS], "length": child[b"length"]})
            continue
        _walk_file_tree(child, [*prefix, _text(key)], files, totals, depth + 1)


def user_of(path: Path, root: Path) -> str:
    """``<user>`` of ``Users\\<user>\\…`` (or ``Documents and Settings``) in the path below the walk root."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    lowered = [part.lower() for part in parts[:-1]]
    for index, part in enumerate(lowered[:-1]):
        if part in ("users", "documents and settings"):
            return parts[index + 1]
    return ""


def _record(artifact_type: str, path: Path, client: str, fields: Mapping[str, object], *, timestamp: str | None, kind: str) -> ArtifactRecord:
    details: dict[str, object] = {
        "parser": PARSER,
        "parser_version": PARSER_VERSION,
        "recovery_method": "parsed",
        "coverage_status": "parsed",
        "client": client,
        "client_label": CLIENT_LABELS.get(client, client),
        "user": "",
        "source_path": str(path),
        "timestamp": timestamp,
        "timestamp_kind": kind if timestamp else "",
        "timestamp_timezone": "UTC" if timestamp else "",
        **fields,
    }
    return ArtifactRecord(provider=P2PArtifactsProvider.name, artifact_type=artifact_type, path=str(path), supported=True, details=details)


def _error(
    path: Path, client: str, reason_code: str, exc: BaseException | None = None, *, truncated_after_rows: int | None = None
) -> ArtifactRecord:
    """``p2p-parse-error`` row: ``reason`` / ``reason_code`` are always a fixed code from :data:`REASON_KO`
    (catalogue value label). A truncated known.met used to emit ``known-met-truncated-after-N-rows``
    (pre-R6 runs keep that text); it is now ``known-met-truncated`` + ``truncated_after_rows=N``, so
    ``reason.startswith("known-met-truncated")`` still holds for older consumers."""
    extra: dict[str, object] = {} if truncated_after_rows is None else {"truncated_after_rows": truncated_after_rows}
    return _record(
        "p2p-parse-error",
        path,
        client,
        {
            "recovery_method": "not-recovered",
            "coverage_status": "parser-error",
            "parser_error": True,
            "reason": reason_code,
            "reason_code": reason_code,
            "reason_ko": REASON_KO.get(reason_code, reason_code),
            **extra,
            "error_type": type(exc).__name__ if exc is not None else "",
            "error_message": str(exc)[:300] if exc is not None else "",
        },
        timestamp=None,
        kind="",
    )


def _read(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise BencodeError(f"파일이 크기 상한({limit // (1024 * 1024)} MiB)을 넘습니다")
    return path.read_bytes()


def _client_of(path: Path) -> str:
    lowered = str(path).lower().replace("\\", "/")
    if "/qbittorrent/" in lowered:
        return "qbittorrent"
    if "frostwire" in lowered:
        return "frostwire"
    if "/utorrent/" in lowered:
        return "utorrent"
    if "/bittorrent/" in lowered:
        return "bittorrent"
    return "torrent-file"


def torrent_rows(path: Path) -> list[ArtifactRecord]:
    client = _client_of(path)
    try:
        fields = torrent_summary(_read(path, MAX_TORRENT_BYTES))
    except (BencodeError, OSError, ValueError) as exc:
        return [_error(path, client, "torrent-unreadable", exc)]
    created = fields.get("created_at")
    return [_record("p2p-torrent", path, client, fields, timestamp=created if isinstance(created, str) else None, kind="torrent-created")]


def _transfer_fields(entry: Mapping[bytes, object], client: str) -> dict[str, object]:
    info_hash = _get(entry, b"info-hash", b"info")
    info = entry.get(b"info") if isinstance(entry.get(b"info"), dict) else None
    name = _text(_get(entry, b"qBt-name", b"caption", b"name"))
    if not name and info is not None:
        name = _text(_get(info, b"name.utf-8", b"name"))
    added = _unix(_get(entry, b"added_time", b"added_on"))
    completed = _unix(_get(entry, b"completed_time", b"completed_on"))
    labels = _get(entry, b"qBt-tags", b"labels")
    return {
        "info_hash": info_hash.hex() if isinstance(info_hash, bytes) and len(info_hash) in (20, 32) else "",
        "name": name,
        "save_path": _text(_get(entry, b"qBt-savePath", b"save_path", b"path")),
        "added_at": added,
        "completed_at": completed,
        "state": "completed" if completed else "incomplete",
        "uploaded_bytes": _int(_get(entry, b"total_uploaded", b"uploaded")),
        "downloaded_bytes": _int(_get(entry, b"total_downloaded", b"downloaded")),
        "active_seconds": _int(_get(entry, b"active_time", b"runtime")),
        "seeding_seconds": _int(_get(entry, b"seeding_time", b"seedtime")),
        "category": _text(_get(entry, b"qBt-category", b"label")),
        "tags": [_text(item) for item in labels][:20] if isinstance(labels, list) else [],
        "paused": bool(_int(_get(entry, b"paused")) or 0),
        "trackers": _trackers(entry.get(b"trackers")),
        "client_entry_key": "",
    }


def _transfer_record(path: Path, client: str, fields: dict[str, object]) -> ArtifactRecord:
    completed, added = fields.get("completed_at"), fields.get("added_at")
    timestamp = completed if isinstance(completed, str) else added if isinstance(added, str) else None
    kind = "transfer-completed" if isinstance(completed, str) else "transfer-added"
    return _record("p2p-transfer", path, client, fields, timestamp=timestamp, kind=kind)


def resume_rows(path: Path) -> list[ArtifactRecord]:
    """One libtorrent resume file (qBittorrent ``.fastresume``, FrostWire ``.resume``)."""
    client = _client_of(path)
    try:
        value, _span = bdecode(_read(path, MAX_TORRENT_BYTES))
    except (BencodeError, OSError, ValueError) as exc:
        return [_error(path, client, "resume-unreadable", exc)]
    if not isinstance(value, dict):
        return [_error(path, client, "resume-not-a-dictionary")]
    return [_transfer_record(path, client, _transfer_fields(value, client))]


def resume_dat_rows(path: Path) -> list[ArtifactRecord]:
    """uTorrent / BitTorrent ``resume.dat``: one transfer per ``<name>.torrent`` key."""
    client = "bittorrent" if "/bittorrent/" in str(path).lower().replace("\\", "/") else "utorrent"
    try:
        value, _span = bdecode(_read(path, MAX_BENCODE_BYTES))
    except (BencodeError, OSError, ValueError) as exc:
        return [_error(path, client, "resume-dat-unreadable", exc)]
    if not isinstance(value, dict):
        return [_error(path, client, "resume-dat-not-a-dictionary")]
    rows: list[ArtifactRecord] = []
    for key, entry in value.items():
        if not isinstance(entry, dict) or key in (b".fileguard", b"rec"):
            continue
        if len(rows) >= MAX_ROWS_PER_SOURCE:
            rows.append(_error(path, client, "row-cap-reached"))
            break
        fields = _transfer_fields(entry, client)
        fields["client_entry_key"] = _text(key)
        rows.append(_transfer_record(path, client, fields))
    return rows


# --- eMule -------------------------------------------------------------------------------


class MetError(ValueError):
    """Malformed eMule .met file (Korean message)."""


class _Met:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.position + count > len(self.data):
            raise MetError("eMule .met 구조가 파일 끝을 넘습니다(잘림·손상)")
        chunk = self.data[self.position : self.position + count]
        self.position += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def tag(self) -> tuple[int | None, object]:
        kind = self.u8()
        if kind & 0x80:
            kind &= 0x7F
            name_id: int | None = self.u8()
        else:
            name = self.take(self.u16())
            name_id = name[0] if len(name) == 1 else None  # multi-byte names: gap tags etc.
        if kind == 0x01:
            return name_id, self.take(16)
        if kind == 0x02:
            return name_id, _met_string(self.take(self.u16()))
        if kind == 0x03:
            return name_id, self.u32()
        if kind == 0x04:
            return name_id, struct.unpack("<f", self.take(4))[0]
        if kind == 0x05:
            return name_id, self.u8()
        if kind == 0x06:
            return name_id, self.take(self.u16() // 8 + 1)  # eMule CTag skips (len / 8) + 1 bytes
        if kind == 0x07:
            return name_id, self.take(self.u32())
        if kind == 0x08:
            return name_id, self.u16()
        if kind == 0x09:
            return name_id, self.u8()
        if kind == 0x0A:
            return name_id, self.take(self.u8())
        if kind == 0x0B:
            return name_id, self.u64()
        if 0x11 <= kind <= 0x20:
            return name_id, _met_string(self.take(kind - 0x10))
        raise MetError(f"알 수 없는 eMule 태그 형식 0x{kind:02x}")

    def tags(self) -> dict[str, object]:
        count = self.u32()
        if count > 10_000:
            raise MetError("eMule 태그 수가 비정상입니다")
        out: dict[str, object] = {}
        for _ in range(count):
            name_id, value = self.tag()
            name = EMULE_TAG_NAMES.get(name_id) if name_id is not None else None
            if name and name not in out:
                out[name] = value
        return out


def _met_string(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    for encoding in ("utf-8", "cp949"):
        try:
            return raw.decode(encoding)[:MAX_TEXT_CHARS]
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")[:MAX_TEXT_CHARS]


def _ed2k_fields(file_hash: bytes, tags: Mapping[str, object]) -> dict[str, object]:
    size = tags.get("file_size") if isinstance(tags.get("file_size"), int) else None
    if size is not None and isinstance(tags.get("file_size_hi"), int):
        size += int(tags["file_size_hi"]) << 32
    name = str(tags.get("file_name") or "")
    ed2k = file_hash.hex().upper()
    return {
        "file_name": name,
        "file_size": size,
        "ed2k_hash": ed2k,
        "ed2k_link": f"ed2k://|file|{name}|{size}|{ed2k}|/" if name and size is not None else "",
        "file_type": str(tags.get("file_type") or ""),
    }


def known_met_rows(path: Path) -> list[ArtifactRecord]:
    """eMule ``known.met``: one ``p2p-shared-file`` per known (shared / completed) file."""
    try:
        reader = _Met(_read(path, MAX_MET_BYTES))
        header = reader.u8()
        if header not in (0x0E, 0x0F):
            raise MetError(f"known.met 헤더가 아닙니다(0x{header:02x})")
        count = reader.u32()
    except (MetError, BencodeError, OSError) as exc:
        return [_error(path, "emule", "known-met-unreadable", exc)]
    rows: list[ArtifactRecord] = []
    try:
        for _ in range(min(count, MAX_ROWS_PER_SOURCE)):
            date = reader.u32()
            file_hash = reader.take(16)
            parts = reader.u16()
            reader.take(16 * parts)
            tags = reader.tags()
            transferred = tags.get("all_time_transferred") if isinstance(tags.get("all_time_transferred"), int) else None
            if transferred is not None and isinstance(tags.get("all_time_transferred_hi"), int):
                transferred += int(tags["all_time_transferred_hi"]) << 32
            last_shared = _unix(tags.get("last_shared"))
            file_date = _unix(date)
            fields = {
                **_ed2k_fields(file_hash, tags),
                "file_date": file_date,
                "last_shared_at": last_shared,
                "all_time_uploaded_bytes": transferred,
                "all_time_requests": tags.get("all_time_requested") if isinstance(tags.get("all_time_requested"), int) else None,
                "all_time_accepted": tags.get("all_time_accepted") if isinstance(tags.get("all_time_accepted"), int) else None,
                "part_hash_count": parts,
            }
            timestamp = last_shared or file_date
            rows.append(_record("p2p-shared-file", path, "emule", fields, timestamp=timestamp, kind="last-shared" if last_shared else "file-date"))
        if count > MAX_ROWS_PER_SOURCE:
            rows.append(_error(path, "emule", "row-cap-reached"))
    except MetError as exc:
        rows.append(_error(path, "emule", "known-met-truncated", exc, truncated_after_rows=len(rows)))
    return rows


# eMule .part.met versions — github.com/irwir/eMule (public mirror of the eMule sources; files at the
# repository root), commit 88a8c8f2d782849642880ea616cdca60b01bd8c7 (2016-04-10):
#   opcodes.h L33-35: PARTFILE_VERSION 0xe0, PARTFILE_SPLITTEDVERSION 0xe1, PARTFILE_VERSION_LARGEFILE 0xe2
#   PartFile.cpp CPartFile::LoadPartFile L797-844 (header), L847-848 (u32 tag count + CTag list),
#   L1140-1153 (optional trailing part-hash set of the split format)
#   FileIdentifier.cpp L182-201 LoadMD4HashsetFromFile: 16-byte hash, u16 count, count x 16 bytes
#   KnownFile.cpp L892-894 LoadDateFromFile: u32
PARTFILE_VERSION = 0xE0
PARTFILE_SPLITTEDVERSION = 0xE1
PARTFILE_VERSION_LARGEFILE = 0xE2


def _part_met_header(reader: _Met, version: int) -> tuple[int | None, bytes, int, str]:
    """``(date, file hash, part-hash count, layout)`` after the version byte.

    0xE0 / 0xE2 (and the legacy 0x0E / 0x0F): date u32, then the MD4 hash set (PartFile.cpp L841-844).
    0xE1 (split format, PartFile.cpp L808 ``isnewstyle``, L826-839): the u32 at offset 1 is read first;
    when it is 0 (eMule 0.48 split files) the hash set follows at offset 5 with no date (L830-831),
    otherwise the reader seeks back to offset 2 and reads date u32 + the 16-byte file hash only
    (L834-837; the part hashes, if any, trail the tag list). The eDonkey "old part style" heuristic for
    0xE0 (L810-823, bytes 24-27 = 00 00 02 01) is not applied here.
    """
    if version != PARTFILE_SPLITTEDVERSION:
        date = reader.u32()
        file_hash = reader.take(16)
        parts = reader.u16()
        reader.take(16 * parts)
        return date, file_hash, parts, "default"
    if reader.u32() == 0:
        file_hash = reader.take(16)
        parts = reader.u16()
        reader.take(16 * parts)
        return None, file_hash, parts, "split-0.48"
    reader.position = 2
    date = reader.u32()
    return date, reader.take(16), 0, "split"


def part_met_rows(path: Path) -> list[ArtifactRecord]:
    """eMule ``<n>.part.met``: one unfinished download (``p2p-transfer``)."""
    try:
        reader = _Met(_read(path, MAX_MET_BYTES))
        version = reader.u8()
        if version not in (PARTFILE_VERSION, PARTFILE_SPLITTEDVERSION, PARTFILE_VERSION_LARGEFILE, 0x0E, 0x0F):
            raise MetError(f".part.met 버전이 아닙니다(0x{version:02x})")
        date, file_hash, parts, layout = _part_met_header(reader, version)
        tags = reader.tags()
    except (MetError, BencodeError, OSError) as exc:
        return [_error(path, "emule", "part-met-unreadable", exc)]
    if layout == "split":
        # PartFile.cpp L1141-1151: one byte, then 16-byte part hashes while ``position + 16 < length``
        # (strict, so eMule never reads a hash that ends exactly at EOF); counted the same way here.
        remaining = len(reader.data) - reader.position
        parts = max(0, (remaining - 2) // 16)
    fields = {
        **_ed2k_fields(file_hash, tags),
        "name": str(tags.get("file_name") or ""),
        "part_file_name": str(tags.get("part_file_name") or path.name.removesuffix(".met")),
        "downloaded_bytes": tags.get("transferred") if isinstance(tags.get("transferred"), int) else None,
        "state": "incomplete",
        "file_date": _unix(date),
        "last_seen_complete_at": _unix(tags.get("last_seen_complete")),
        "download_active_seconds": tags.get("download_active_time") if isinstance(tags.get("download_active_time"), int) else None,
        "info_hash": "",
        "part_met_version": f"0x{version:02x}",
        "part_met_layout": layout,
        "part_hash_count": parts,
    }
    file_date = fields["file_date"]
    return [_record("p2p-transfer", path, "emule", fields, timestamp=file_date if isinstance(file_date, str) else None, kind="part-file-date")]


def _text_file(path: Path, limit: int) -> str:
    raw = _read(path, limit)
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp949", errors="replace")


def search_string_rows(path: Path) -> list[ArtifactRecord]:
    """eMule ``AC_SearchStrings.dat``: the search box history, one term per line (newest first)."""
    try:
        text = _text_file(path, 8 * 1024 * 1024)
    except (OSError, BencodeError) as exc:
        return [_error(path, "emule", "search-strings-unreadable", exc)]
    rows = []
    for index, line in enumerate(line.strip() for line in text.splitlines()):
        if not line:
            continue
        if len(rows) >= MAX_SEARCH_TERMS:
            rows.append(_error(path, "emule", "row-cap-reached"))
            break
        rows.append(
            _record(
                "p2p-search-term",
                path,
                "emule",
                {"term": line[:MAX_TEXT_CHARS], "list_position": index, "time_note": "AC_SearchStrings.dat에는 검색 시각이 없음(목록 순서만)"},
                timestamp=None,
                kind="",
            )
        )
    return rows


def preferences_rows(path: Path) -> list[ArtifactRecord]:
    """eMule ``preferences.ini``: nick, incoming / temp directory and version (no user hash)."""
    try:
        text = _text_file(path, 2 * 1024 * 1024)
    except (OSError, BencodeError) as exc:
        return [_error(path, "emule", "preferences-unreadable", exc)]
    fields: dict[str, object] = {}
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        key, sep, value = stripped.partition("=")
        target = EMULE_PREFERENCE_KEYS.get(key.strip().lower())
        if sep and target and section == "emule" and target not in fields:
            fields[target] = value.strip()[:MAX_TEXT_CHARS]
    if not fields:
        return []
    fields["config_section"] = "eMule"
    return [_record("p2p-client-config", path, "emule", fields, timestamp=None, kind="")]


def _emule_config_dir(path: Path) -> bool:
    parent = path.parent
    if parent.name.lower() != "config":
        return False
    if "emule" in str(parent.parent).lower():
        return True
    return any((parent / name).exists() for name in ("known.met", "AC_SearchStrings.dat"))


class P2PArtifactsProvider:
    collector_kind = "p2p"
    name = "p2p-artifacts"
    description = "BitTorrent clients (qBittorrent, uTorrent, FrostWire, .torrent) and eMule transfer / share / search records"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for record in self._collect(root):
            record.details["user"] = user_of(Path(record.path), root)
            yield record

    def _collect(self, root: Path) -> Iterator[ArtifactRecord]:
        torrents = 0
        for path in self._paths(root):
            name = path.name.lower()
            try:
                if name.endswith(".torrent"):
                    torrents += 1
                    if torrents > MAX_TORRENT_FILES:
                        if torrents == MAX_TORRENT_FILES + 1:
                            yield _error(path, "torrent-file", "torrent-file-cap-reached")
                        continue
                    yield from torrent_rows(path)
                elif name.endswith(".fastresume") or (name.endswith(".resume") and _client_of(path) == "frostwire"):
                    yield from resume_rows(path)
                elif name == "resume.dat" and _client_of(path) in ("utorrent", "bittorrent"):
                    yield from resume_dat_rows(path)
                elif name == "known.met":
                    yield from known_met_rows(path)
                elif name.endswith(".part.met"):
                    yield from part_met_rows(path)
                elif name == "ac_searchstrings.dat":
                    yield from search_string_rows(path)
                elif name == "preferences.ini" and _emule_config_dir(path):
                    yield from preferences_rows(path)
            except Exception as exc:  # one source never stops the provider
                yield _error(path, _client_of(path), "source-failed", exc)

    @staticmethod
    def _paths(root: Path) -> Iterator[Path]:
        wanted_suffixes = (".torrent", ".fastresume", ".resume", ".part.met")
        wanted_names = {"resume.dat", "known.met", "ac_searchstrings.dat", "preferences.ini"}
        matches = [
            path
            for path in iter_evidence_paths(root, "*")
            if path.name.lower().endswith(wanted_suffixes) or path.name.lower() in wanted_names
        ]
        for path in sorted(matches, key=lambda item: str(item).lower()):
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue
