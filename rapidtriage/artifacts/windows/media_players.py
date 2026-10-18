"""Media player recent-play lists (plan r5-residual L1; re-audit §3 item 2): ``media-player`` provider.

Per user profile (``iter_windows_user_homes``):

* **VLC** — ``%APPDATA%\\vlc\\vlc-qt-interface.ini`` ``[RecentsMRU]`` ``list=``
  (Qt string list of ``file:///`` / stream URLs, most recent first) and
  ``times=`` (resume positions, milliseconds). ``vlcrc`` contributes the
  configured ``snapshot-path`` / ``input-record-path`` on the inventory row.
* **PotPlayer** (AXIOM 밖 국내 확장) — ``%APPDATA%\\PotPlayer*\\*.ini`` and
  ``Playlist\\*.dpl`` (``N*file*<path>`` lines), NTUSER
  ``Software\\DAUM\\PotPlayer64|PotPlayerMini64|PotPlayer|PotPlayerMini``.
* **곰플레이어** — NTUSER ``Software\\GRETECH``.
* **KMPlayer** — NTUSER ``Software\\KMPlayer`` and ``Software\\PandoraTV``.

The VLC layout is documented by the VLC sources (``RecentsMRU``). The
PotPlayer / GOM / KMPlayer value names are not vendor documented and could
not be confirmed on a sample (``verification: unconfirmed``): instead of
assuming value names, the reader takes every *path- or URL-like* string
under a key, section or value whose name says recent / remember / history /
MRU / playlist / last-play (``extraction: path-like-value-scan``). Such a
row says "this path was in the player's recent list", never when it played:
the list's own record time (ini modification time, registry key LastWrite)
is kept as ``list_last_written`` — an upper bound for the newest entry, not
a per-entry time — and the row-level ``timestamp`` stays empty.

Rows: ``media-player-recent`` (one per listed media path/URL),
``media-player-inventory`` (one per player per user: sources, counts, caps,
config paths, Korean reason when nothing was listed) and
``media-player-parse-error`` (one source that could not be read; the
collect continues).
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote, urlsplit

from ...core.models import ArtifactRecord
from .common import iter_windows_user_homes

PARSER = "media-player"
PARSER_VERSION = "media-player-v1"
MAX_INI_BYTES = 4 * 1024 * 1024
MAX_PLAYLIST_BYTES = 8 * 1024 * 1024
MAX_PLAYLIST_FILES = 200
MAX_ROWS_PER_PLAYER = 20_000
MAX_REGISTRY_KEYS_PER_ROOT = 5_000
MAX_REGISTRY_DEPTH = 4
MAX_VALUE_CHARS = 4_096

RECENT_NAME_RE = re.compile(r"remember|recent|history|mru|playlist|lastplay|last_play|lastopen|last_open|lastfile", re.IGNORECASE)
URL_RE = re.compile(r"^(?:https?|rtsp|rtsps|rtmp|rtmps|mms|mmsh|ftp|udp|rtp|file|smb|dvd|bluray|vcd)://", re.IGNORECASE)
DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
UNC_PATH_RE = re.compile(r"^\\\\[^\\/]+[\\/]")
EMBEDDED_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\[^\\/\s*?\"<>|]+\\)[^\x00-\x1f*?\"<>|]+")
QT_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{4})")
# GOM Player OPTION key (observed on a real NTUSER, R5 L1): ``_RECENTMEDIANAME###`` holds a 32-hex
# identifier of the played file (not its path) and ``_RECENTMEDIAPOS###`` the resume position.
GOM_RECENT_NAME_RE = re.compile(r"^_RECENTMEDIANAME(\d+)$", re.IGNORECASE)
HEX32_RE = re.compile(r"^[0-9A-Fa-f]{32}$")


@dataclass(frozen=True)
class PlayerSpec:
    player_id: str
    player: str
    label_ko: str
    registry_roots: tuple[str, ...] = ()
    verification: str = "unconfirmed"


PLAYERS: tuple[PlayerSpec, ...] = (
    PlayerSpec("vlc", "VLC media player", "VLC", verification="public-source-documented"),
    PlayerSpec(
        "potplayer",
        "PotPlayer",
        "팟플레이어(PotPlayer)",
        registry_roots=(
            r"Software\DAUM\PotPlayer64",
            r"Software\DAUM\PotPlayerMini64",
            r"Software\DAUM\PotPlayer",
            r"Software\DAUM\PotPlayerMini",
        ),
    ),
    PlayerSpec("gom", "GOM Player", "곰플레이어(GOM Player)", registry_roots=(r"Software\GRETECH",)),
    PlayerSpec("kmplayer", "KMPlayer", "KMPlayer", registry_roots=(r"Software\KMPlayer", r"Software\PandoraTV")),
)
VERIFICATION_NOTE_KO = {
    "public-source-documented": "VLC 소스(RecentsMRU)로 문서화된 형식",
    "unconfirmed": "공급사 문서·실제 표본으로 값 이름을 확인하지 못함 — 경로처럼 보이는 값만 모은 후보",
}


# --- value helpers ---------------------------------------------------------------------------


def decode_text(data: bytes) -> str:
    """ini/playlist bytes → text: BOM first, then UTF-8, CP949 (국내 기본), Latin-1."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if len(data) >= 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        return data.decode("utf-16-le", errors="replace")
    for encoding in ("utf-8", "cp949"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def parse_ini(text: str) -> list[tuple[str, str, str, int]]:
    """``(section, key, value, line number)`` of an ini file (duplicates kept, no interpolation)."""
    entries: list[tuple[str, str, str, int]] = []
    section = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        entries.append((section, key.strip(), value.strip(), number))
    return entries


def qt_string_list(value: str) -> list[str]:
    """Items of a Qt ``QSettings`` ini string list (``a, "b, c", d``); ``\\xNNNN`` escapes decoded."""
    items: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == '"':
            quoted = not quoted
        elif char == "\\" and quoted and index + 1 < len(value) and value[index + 1] in '"\\':
            current.append(value[index + 1])
            index += 1
        elif char == "," and not quoted:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    items.append("".join(current).strip())
    return [QT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), item) for item in items if item]


def media_location(value: str) -> dict[str, object] | None:
    """Path/URL fields of one recent entry; ``None`` when the value is not path- or URL-like."""
    text = value.strip().strip('"').strip()
    if not text or len(text) > MAX_VALUE_CHARS:
        return None
    if URL_RE.match(text):
        parts = urlsplit(text)
        if parts.scheme.lower() == "file":
            local = unquote(parts.path)
            if re.match(r"^/[A-Za-z]:/", local):
                local = local[1:]
            if parts.netloc and parts.netloc.lower() != "localhost":
                local = "\\\\" + parts.netloc + local
            local = local.replace("/", "\\")
            return _path_fields(local, url=text)
        return {
            "media_path": "",
            "media_url": text,
            "media_name": unquote(PureWindowsPath(parts.path).name) if parts.path else "",
            "media_extension": PureWindowsPath(parts.path).suffix.lower() if parts.path else "",
            "location_kind": "stream-url",
            "entry_kind": "url",
            "drive_letter": "",
            "url_scheme": parts.scheme.lower(),
            "url_host": parts.hostname or "",
        }
    if DRIVE_PATH_RE.match(text) or UNC_PATH_RE.match(text):
        return _path_fields(text.replace("/", "\\"), url="")
    match = EMBEDDED_PATH_RE.search(text)
    if match:
        fields = _path_fields(match.group(0).strip(), url="")
        fields["extracted_from_value"] = True
        return fields
    return None


def _path_fields(path: str, *, url: str) -> dict[str, object]:
    pure = PureWindowsPath(path)
    drive = pure.drive
    unc = drive.startswith("\\\\")
    return {
        "media_path": path,
        "media_url": url,
        "entry_kind": "folder" if path.endswith(("\\", "/")) else "file",
        "media_name": pure.name,
        "media_extension": pure.suffix.lower(),
        "location_kind": "unc-network" if unc else ("drive" if drive else "other"),
        "drive_letter": "" if unc else drive.rstrip(":").upper(),
        "network_host": drive.strip("\\").split("\\")[0] if unc else "",
    }


def iso_mtime(path: Path) -> str:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _mru_order(name: str) -> int | None:
    digits = re.search(r"(\d+)$", name)
    if digits is None:
        return None
    try:
        return int(digits.group(1))
    except ValueError:  # pragma: no cover - regex guarantees digits
        return None


# --- provider ---------------------------------------------------------------------------------


@dataclass
class _PlayerRun:
    spec: PlayerSpec
    user: str
    rows: list[ArtifactRecord] = field(default_factory=list)
    seen: set[tuple[str, str, str]] = field(default_factory=set)
    sources: list[dict[str, object]] = field(default_factory=list)
    errors: list[ArtifactRecord] = field(default_factory=list)
    config_paths: dict[str, str] = field(default_factory=dict)
    capped: list[str] = field(default_factory=list)
    duplicates: int = 0

    def cap(self, reason: str) -> None:
        if reason not in self.capped:
            self.capped.append(reason)


class WindowsMediaPlayersProvider:
    name = "media-player"
    collector_kind = "media-player"
    description = "Media player recent-play lists: VLC, PotPlayer, GOM Player, KMPlayer (ini, playlists, NTUSER)"
    target_platform = "windows"

    def __init__(self) -> None:
        self.collection_notes: list[str] = []

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        self.collection_notes = []
        found_any = False
        for user_home in iter_windows_user_homes(root):
            hive_source = _UserHive(user_home)
            try:
                for spec in PLAYERS:
                    run = _PlayerRun(spec=spec, user=user_home.name)
                    self._collect_player(run, user_home, hive_source)
                    if run.sources or run.rows or run.errors:
                        found_any = True
                        yield self._inventory_row(run, user_home)
                        yield from run.rows
                        yield from run.errors
                        if run.capped:
                            self.collection_notes.append(f"{spec.label_ko}({run.user}): 상한 도달 — {', '.join(run.capped)}")
            finally:
                hive_source.close()
        if not found_any:
            self.collection_notes.append(
                "미디어 플레이어(VLC·팟플레이어·곰플레이어·KMPlayer) 재생 기록 원본(ini·재생목록·NTUSER 키)이 사용자 프로필에서 발견되지 않았습니다."
            )

    # -- per player ------------------------------------------------------------------------

    def _collect_player(self, run: _PlayerRun, user_home: Path, hive: _UserHive) -> None:
        roaming = user_home / "AppData" / "Roaming"
        if run.spec.player_id == "vlc":
            vlc_dir = roaming / "vlc"
            ini = vlc_dir / "vlc-qt-interface.ini"
            if ini.is_file():
                self._guarded(run, ini, "vlc-qt-interface-ini", lambda: self._vlc_ini(run, ini))
            vlcrc = vlc_dir / "vlcrc"
            if vlcrc.is_file():
                self._guarded(run, vlcrc, "vlcrc", lambda: self._vlcrc(run, vlcrc))
        elif run.spec.player_id == "potplayer":
            for directory in _sorted_dirs(roaming, "PotPlayer*"):
                for ini in _sorted_files(directory, "*.ini", 20):
                    self._guarded(run, ini, "potplayer-ini", lambda p=ini: self._generic_ini(run, p, "potplayer-ini"))
                for playlist in _sorted_files(directory / "Playlist", "*.dpl", MAX_PLAYLIST_FILES):
                    self._guarded(run, playlist, "potplayer-dpl", lambda p=playlist: self._dpl(run, p))
        for root_key in run.spec.registry_roots:
            if hive.path is None:
                break
            self._guarded(run, hive.path, "ntuser-registry", lambda rk=root_key: self._registry_root(run, hive, rk))

    def _guarded(self, run: _PlayerRun, path: Path, source_format: str, action) -> None:
        try:
            action()
        except Exception as exc:  # one damaged source never stops the others
            run.sources.append({"path": str(path), "format": source_format, "status": "parse-error"})
            run.errors.append(
                ArtifactRecord(
                    provider=self.name,
                    artifact_type="media-player-parse-error",
                    path=str(path),
                    supported=True,
                    details={
                        **self._base(run, path, source_format, recovery_method="none"),
                        "parser_error": True,
                        "coverage_status": "parser-error",
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                        "reason_ko": f"{run.spec.label_ko} 원본을 읽지 못해 건너뜀({type(exc).__name__}); 나머지 원본은 계속 처리",
                        "timestamp": "",
                        "timestamp_source": "none-parse-error",
                    },
                )
            )

    def _base(self, run: _PlayerRun, path: Path, source_format: str, *, recovery_method: str) -> dict[str, object]:
        return {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "player": run.spec.player,
            "player_id": run.spec.player_id,
            "player_label_ko": run.spec.label_ko,
            "user": run.user,
            "recovery_method": recovery_method,
            "source_path": str(path),
            "source_format": source_format,
            "verification": run.spec.verification,
            "verification_note_ko": VERIFICATION_NOTE_KO[run.spec.verification],
            "reportability": "triage",
            "validation_required": True,
        }

    def _emit(
        self,
        run: _PlayerRun,
        path: Path,
        source_format: str,
        location: Mapping[str, object],
        *,
        recovery_method: str,
        locator: str,
        list_last_written: str,
        list_last_written_source: str,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        identity = (str(path), locator, str(location.get("media_path") or location.get("media_url") or ""))
        if identity in run.seen:
            run.duplicates += 1
            return
        if len(run.rows) >= MAX_ROWS_PER_PLAYER:
            run.cap("row-cap")
            return
        run.seen.add(identity)
        details = {
            **self._base(run, path, source_format, recovery_method=recovery_method),
            **location,
            "source_locator": locator,
            "list_last_written": list_last_written,
            "list_last_written_source": list_last_written_source,
            "timestamp": "",
            "timestamp_source": "none — list_last_written은 목록 전체의 기록 시각(최신 항목 상한)이며 항목별 재생 시각이 아님",
            "coverage_status": "mapped" if run.spec.verification != "unconfirmed" else "heuristic-candidate",
            "confidence": "medium" if run.spec.verification != "unconfirmed" else "low",
            **(dict(extra) if extra else {}),
        }
        run.rows.append(
            ArtifactRecord(provider=self.name, artifact_type="media-player-recent", path=str(path), supported=True, details=details)
        )

    # -- VLC -------------------------------------------------------------------------------

    def _vlc_ini(self, run: _PlayerRun, path: Path) -> None:
        text = _read_text(path, MAX_INI_BYTES)
        entries = parse_ini(text)
        modified = iso_mtime(path)
        recents = [entry for entry in entries if entry[0].lower() == "recentsmru"]
        items: list[str] = []
        times: list[str] = []
        line_no = 0
        for _section, key, value, number in recents:
            if key.lower() == "list":
                items = qt_string_list(value)
                line_no = number
            elif key.lower() == "times":
                times = qt_string_list(value)
        for index, item in enumerate(items):
            location = media_location(item)
            if location is None:
                continue
            position = times[index] if index < len(times) else ""
            extra: dict[str, object] = {"mru_order": index, "raw_value": item[:512]}
            if re.fullmatch(r"-?\d+", position or ""):
                extra["resume_position_ms"] = int(position)
                extra["resume_position_seconds"] = round(int(position) / 1000, 3)
            self._emit(
                run,
                path,
                "vlc-qt-interface-ini",
                location,
                recovery_method="ini-parse",
                locator=f"[RecentsMRU] list[{index}] (line {line_no})",
                list_last_written=modified,
                list_last_written_source="ini-file-mtime (acquisition copies may reset it)",
                extra=extra,
            )
        run.sources.append({"path": str(path), "format": "vlc-qt-interface-ini", "status": "read", "entries": len(items)})

    def _vlcrc(self, run: _PlayerRun, path: Path) -> None:
        text = _read_text(path, MAX_INI_BYTES)
        for _section, key, value, _number in parse_ini(text):
            if key in ("snapshot-path", "input-record-path") and value:
                run.config_paths[key] = value[:512]
        run.sources.append({"path": str(path), "format": "vlcrc", "status": "read"})

    # -- PotPlayer ini / playlists ---------------------------------------------------------

    def _generic_ini(self, run: _PlayerRun, path: Path, source_format: str) -> None:
        text = _read_text(path, MAX_INI_BYTES)
        modified = iso_mtime(path)
        taken = 0
        for section, key, value, number in parse_ini(text):
            if not (RECENT_NAME_RE.search(section) or RECENT_NAME_RE.search(key)):
                continue
            location = media_location(value)
            if location is None:
                continue
            taken += 1
            self._emit(
                run,
                path,
                source_format,
                location,
                recovery_method="ini-parse",
                locator=f"[{section}] {key} (line {number})",
                list_last_written=modified,
                list_last_written_source="ini-file-mtime (acquisition copies may reset it)",
                extra={"mru_order": _mru_order(key), "entry_name": key, "section": section, "raw_value": value[:512],
                       "extraction": "path-like-value-scan"},
            )
        run.sources.append({"path": str(path), "format": source_format, "status": "read", "entries": taken})

    def _dpl(self, run: _PlayerRun, path: Path) -> None:
        text = _read_text(path, MAX_PLAYLIST_BYTES)
        modified = iso_mtime(path)
        current = ""
        taken = 0
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if line.lower().startswith("playname="):
                current = line.split("=", 1)[1].strip()
                continue
            match = re.match(r"^(\d+)\*file\*(.+)$", line)
            if match is None:
                continue
            location = media_location(match.group(2))
            if location is None:
                continue
            taken += 1
            self._emit(
                run,
                path,
                "potplayer-dpl",
                location,
                recovery_method="playlist-parse",
                locator=f"{match.group(1)}*file* (line {number})",
                list_last_written=modified,
                list_last_written_source="playlist-file-mtime (acquisition copies may reset it)",
                extra={"mru_order": int(match.group(1)), "playlist_name": path.name, "extraction": "dpl-file-line"},
            )
        for row in run.rows:
            if row.details.get("source_path") == str(path) and current and row.details.get("media_path") == current:
                row.details["playlist_current_item"] = True
        run.sources.append({"path": str(path), "format": "potplayer-dpl", "status": "read", "entries": taken})

    # -- NTUSER ----------------------------------------------------------------------------

    def _registry_root(self, run: _PlayerRun, hive: _UserHive, root_key: str) -> None:
        source = hive.source()
        if source is None:
            return
        source.reset_budget()
        top = source.key(root_key)
        if top is None:
            return
        visited = 0
        taken = 0
        stack: list[tuple[object, int, bool]] = [(top, 0, bool(RECENT_NAME_RE.search(root_key)))]
        while stack:
            view, depth, recent_scope = stack.pop()
            visited += 1
            if visited > MAX_REGISTRY_KEYS_PER_ROOT:
                run.cap("registry-key-cap")
                break
            values = getattr(view, "values", {}) or {}
            rel = str(getattr(view, "rel", ""))
            product_key = rel[len(root_key):].strip("\\").split("\\", 1)[0] if len(rel) > len(root_key) else ""
            for name, value in sorted(values.items(), key=lambda item: str(item[0]).lower()):
                gom = GOM_RECENT_NAME_RE.match(str(name))
                if gom and isinstance(value, str) and HEX32_RE.match(value.strip()):
                    taken += 1
                    position = values.get(f"_RECENTMEDIAPOS{gom.group(1)}")
                    self._emit(
                        run,
                        hive.path or Path(""),
                        "ntuser-registry",
                        {"media_path": "", "media_url": "", "media_name": "", "media_extension": "", "entry_kind": "file-hash",
                         "location_kind": "hash-only", "drive_letter": "", "media_hash": value.strip().lower()},
                        recovery_method="registry-value",
                        locator=f"HKCU\\{rel}\\{name}",
                        list_last_written=str(getattr(view, "last_written", "") or ""),
                        list_last_written_source="registry-key-last-written",
                        extra={
                            "mru_order": int(gom.group(1)),
                            "entry_name": str(name),
                            "product_key": product_key,
                            "registry_key_path": f"HKCU\\{rel}",
                            "registry_value_name": str(name),
                            "resume_position_raw": position if isinstance(position, int) else None,
                            "extraction": "gom-recentmedia-hash",
                            "hash_note_ko": "곰플레이어는 최근 재생 파일을 경로 대신 32자리 16진 식별자로 남깁니다(해시 알고리즘·입력 미확인). "
                            "파일 경로는 알 수 없으며, 후보 파일 경로의 해시와 대조해야 합니다.",
                        },
                    )
                    continue
                if not (recent_scope or RECENT_NAME_RE.search(str(name))):
                    continue
                for text in _registry_texts(value):
                    location = media_location(text)
                    if location is None:
                        continue
                    taken += 1
                    self._emit(
                        run,
                        hive.path or Path(""),
                        "ntuser-registry",
                        location,
                        recovery_method="registry-value",
                        locator=f"HKCU\\{rel}\\{name or '(기본값)'}",
                        list_last_written=str(getattr(view, "last_written", "") or ""),
                        list_last_written_source="registry-key-last-written",
                        extra={
                            "mru_order": _mru_order(str(name)),
                            "entry_name": str(name),
                            "product_key": product_key,
                            "registry_key_path": f"HKCU\\{rel}",
                            "registry_value_name": str(name),
                            "raw_value": text[:512],
                            "extraction": "path-like-value-scan",
                        },
                    )
            if depth < MAX_REGISTRY_DEPTH:
                children = source.subkeys(view)
                for child in reversed(children):
                    stack.append((child, depth + 1, recent_scope or bool(RECENT_NAME_RE.search(str(getattr(child, "name", ""))))))
        run.sources.append({"path": f"{hive.path}::HKCU\\{root_key}", "format": "ntuser-registry", "status": "read", "entries": taken})

    # -- inventory -------------------------------------------------------------------------

    def _inventory_row(self, run: _PlayerRun, user_home: Path) -> ArtifactRecord:
        rows = len(run.rows)
        if rows:
            reason = ""
        elif run.errors and not [source for source in run.sources if source.get("status") == "read"]:
            reason = f"{run.spec.label_ko}: 원본을 읽지 못했습니다(처리 오류 행 참고)."
        else:
            reason = f"{run.spec.label_ko}: 설정·목록 원본은 있으나 최근 재생 경로로 볼 수 있는 값이 없습니다(기록 끔·목록 비움·미확인 형식)."
        details = {
            **self._base(run, user_home, "inventory", recovery_method="filesystem-inventory"),
            "source_path": str(user_home),
            "sources": run.sources[:50],
            "source_count": len(run.sources),
            "recent_rows": rows,
            "parse_error_count": len(run.errors),
            "duplicate_entries_merged": run.duplicates,
            "config_paths": dict(run.config_paths),
            "snapshot_path": run.config_paths.get("snapshot-path", ""),
            "record_path": run.config_paths.get("input-record-path", ""),
            "caps_hit": list(run.capped),
            "reason_ko": reason,
            "coverage_status": "rows-recovered" if rows else "inventory-only",
            "timestamp": "",
            "timestamp_source": "none-inventory-row",
        }
        return ArtifactRecord(provider=self.name, artifact_type="media-player-inventory", path=str(user_home), supported=True, details=details)


class _UserHive:
    """Lazily opened ``NTUSER.DAT`` of one profile (read through ``registry_depth.HiveKeySource``)."""

    def __init__(self, user_home: Path) -> None:
        self.path: Path | None = None
        for name in ("NTUSER.DAT", "ntuser.dat", "NTUSER.dat"):
            candidate = user_home / name
            try:
                if candidate.is_file():
                    self.path = candidate
                    break
            except OSError:
                continue
        self._hive: object | None = None
        self._source: object | None = None
        self._opened = False

    def source(self):
        if not self._opened:
            self._opened = True
            if self.path is not None:
                from .registry import NativeRegistryHive
                from .registry_depth import HiveKeySource

                hive = NativeRegistryHive.open(self.path)
                if hive is None:
                    raise ValueError("NTUSER.DAT is not a regf hive (signature missing or unreadable)")
                self._hive = hive
                self._source = HiveKeySource(hive, "NTUSER")
        return self._source

    def close(self) -> None:
        closer = getattr(self._hive, "close", None)
        if callable(closer):
            closer()
        self._hive = None
        self._source = None


def _registry_texts(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value[:200]:
            if isinstance(item, str):
                yield item
    elif isinstance(value, (bytes, bytearray)) and 4 <= len(value) <= MAX_VALUE_CHARS * 2:
        raw = bytes(value)
        if len(raw) % 2 == 0 and raw[1:2] == b"\x00":
            text = raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
            if text.isprintable():
                yield text


def _read_text(path: Path, limit: int) -> str:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        data = data[:limit]
    return decode_text(data)


def _sorted_dirs(root: Path, pattern: str) -> list[Path]:
    try:
        return sorted((item for item in root.glob(pattern) if item.is_dir()), key=lambda item: item.name.lower())
    except OSError:
        return []


def _sorted_files(root: Path, pattern: str, limit: int) -> list[Path]:
    try:
        if not root.is_dir():
            return []
        return sorted((item for item in root.glob(pattern) if item.is_file()), key=lambda item: item.name.lower())[:limit]
    except OSError:
        return []
