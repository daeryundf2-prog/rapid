"""Registry depth plugins (plan r3-os-depth §3.1 O1): typed rows from hives *and* ``.reg`` exports.

One set of decoders runs over a small key-source interface, so a native hive
(``NativeRegistryHive``) and a ``.reg`` export produce the same row contract:

* ``registry-network-profile`` -- ``NetworkList\\Profiles`` joined with
  ``Signatures\\{Managed,Unmanaged}`` (profile name, first/last connected
  SYSTEMTIME, gateway MAC, DNS suffix, category, connection type).
* ``registry-network-share`` -- ``MountPoints2``, ``Map Network Drive MRU`` and
  ``Network\\<drive>`` (mapped drives).
* ``registry-wlan-profile`` -- ``WlanSvc\\Interfaces\\<if>\\Profiles\\<p>`` (SSID
  from ``MetaData\\Channel Hints``) and wireless (NameType 71) NetworkList profiles.
* ``registry-office-mru`` -- Office ``File MRU`` / ``Place MRU`` (also under
  ``User MRU\\<account>``), ``[F…][T<FILETIME>][O…]*path`` items.
* ``registry-known-dll`` -- ``Session Manager\\KnownDLLs`` against a baseline.
* ``registry-default-browser`` -- ``UrlAssociations\\http(s)\\UserChoice``.
* ``execution-pca`` -- ``AppCompatFlags\\Compatibility Assistant\\Store|Persisted``
  (the ``PcaAppLaunchDic.txt``/``PcaGeneralDb*.txt`` files: :mod:`.pca`).
* ``execution-feature-usage`` -- ``Explorer\\FeatureUsage\\{AppSwitched,…}`` counts.
* ``registry-install-state`` -- ``App Paths`` and MSI ``Installer\\UserData\\<SID>\\Products``
  (``Uninstall`` stays ``windows-installed-program``: no duplicate rows).

R5 L2 (:data:`R5_DEPTH_ARTIFACT_TYPES`, plan r5-residual §3 L2):

* ``startup-item`` -- ``Explorer\\StartupApproved\\{Run,Run32,StartupFolder}`` (12-byte value:
  byte 0 ``02``/``06`` enabled, ``03``/``07`` disabled, bytes 4-12 FILETIME of the disabling),
  joined with the ``Run`` value of the same name (command).
* ``registry-logon-banner`` -- ``legalnoticecaption``/``legalnoticetext`` of ``Policies\\System``
  and ``Winlogon``.
* ``ssh-known-host`` / ``ssh-client-session`` -- PuTTY ``SshHostKeys``/``Sessions`` and WinSCP
  ``SshHostKeys``/``Sessions``. Password values (WinSCP ``Password``, PuTTY/WinSCP
  ``ProxyPassword``) are never copied: rows only say ``password_saved``.
* ``office-identity`` -- ``Office\\<ver>\\Common\\Identity\\Identities\\<id>``.
* ``desktop-wallpaper`` -- ``Control Panel\\Desktop`` ``WallPaper``/``TranscodedImageCache`` and
  ``Explorer\\Wallpapers`` ``BackgroundHistoryPath<N>``.

NetworkList dates are SYSTEMTIME in *local* wall-clock time: they are kept
without an offset (``timestamp_timezone = local-unknown``). Each decoder is
isolated (one corrupt key never stops the others) and every type is capped at
:data:`MAX_DEPTH_ROWS_PER_TYPE` rows per source.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ...core.models import ArtifactRecord

DEPTH_PARSER = "windows-registry-depth"
DEPTH_PARSER_VERSION = "registry-depth-v1"
MAX_DEPTH_ROWS_PER_TYPE = 50_000
MAX_EXPORT_BYTES = 256 * 1024 * 1024
# One ``.reg`` value (after joining ``\`` continuation lines); a larger value is dropped and disclosed.
MAX_EXPORT_VALUE_CHARS = 16 * 1024 * 1024
MAX_SUBKEYS_PER_LIST = 20_000
# Keys one decoder may expand per source: a hostile subkey list (every entry pointing at the
# same cell, or at an ancestor) cannot turn the nested Office/WLAN walks into an N**4 blow-up.
MAX_DEPTH_KEYS_PER_DECODER = 200_000
DEPTH_ARTIFACT_TYPES = (
    "registry-network-profile",
    "registry-network-share",
    "registry-wlan-profile",
    "registry-office-mru",
    "registry-known-dll",
    "registry-default-browser",
    "execution-pca",
    "execution-feature-usage",
    "registry-install-state",
)
# R5 L2 row types (kept apart from DEPTH_ARTIFACT_TYPES, the R3 contract of its tests).
R5_DEPTH_ARTIFACT_TYPES = (
    "startup-item",
    "registry-logon-banner",
    "ssh-known-host",
    "ssh-client-session",
    "office-identity",
    "desktop-wallpaper",
)

NETWORKLIST = r"Microsoft\Windows NT\CurrentVersion\NetworkList"
EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
NETWORK_CATEGORY_LABELS = {0: "공용(Public)", 1: "개인(Private)", 2: "도메인(Domain)"}
NETWORK_NAME_TYPE_LABELS = {6: "유선", 23: "VPN", 71: "무선(Wi-Fi)", 243: "모바일 광대역"}
SHARE_SOURCE_LABELS = {
    "mountpoints2": "MountPoints2(탐색기 마운트 이력)",
    "map-network-drive-mru": "네트워크 드라이브 연결 MRU",
    "network-drive": "매핑 드라이브(Network\\<드라이브>)",
}
SHARE_KIND_LABELS = {
    "network-share": "네트워크 공유",
    "volume-guid": "볼륨 GUID",
    "drive-letter": "드라이브 문자",
    "other": "기타",
}
FEATURE_USAGE_LABELS = {
    "AppSwitched": "작업 표시줄 앱 전환",
    "ShowJumpView": "점프 목록 열기",
    "AppLaunch": "작업 표시줄 고정 앱 실행",
    "AppBadgeUpdated": "앱 배지 갱신",
    "TrayButtonClicked": "트레이 단추 클릭",
}
OFFICE_MRU_KINDS = {"file mru": ("file", "최근 파일"), "place mru": ("place", "최근 폴더")}
OFFICE_ITEM = re.compile(r"^(?:\[F(?P<flags>[0-9A-Fa-f]+)\])?(?:\[T(?P<time>[0-9A-Fa-f]{1,16})\])?(?:\[O(?P<o>[0-9A-Fa-f]+)\])?\*(?P<path>.+)$")
OFFICE_VERSION = re.compile(r"^\d+\.\d+$")
BROWSER_PROG_IDS: tuple[tuple[str, str], ...] = (
    ("chromehtml", "Google Chrome"),
    ("msedgehtm", "Microsoft Edge"),
    ("msedgebhtml", "Microsoft Edge Beta"),
    ("firefoxurl", "Mozilla Firefox"),
    ("ie.http", "Internet Explorer"),
    ("whalehtml", "네이버 웨일"),
    ("bravehtml", "Brave"),
    ("operastable", "Opera"),
    ("operagxstable", "Opera GX"),
    ("vivaldihtm", "Vivaldi"),
    ("appxq0fevzme2pys62n3e0fbqa7peapykr8v", "Microsoft Edge(레거시)"),
)
# KnownDLLs of a default Windows 10/11 install (x64; ARM64 adds the xtajit/wowarmhw entries).
# A value outside this list is a review lead (third-party or tampered KnownDLLs), not a verdict.
KNOWN_DLL_BASELINE = frozenset(
    name.casefold()
    for name in (
        "_wow64cpu.dll", "_wowarmhw.dll", "_xtajit.dll", "advapi32.dll", "clbcatq.dll", "combase.dll",
        "COMDLG32.dll", "coml2.dll", "DifxApi.dll", "gdi32.dll", "gdiplus.dll", "IMAGEHLP.dll",
        "IMM32.dll", "kernel32.dll", "MSCTF.dll", "MSVCRT.dll", "NORMALIZ.dll", "NSI.dll", "ole32.dll",
        "OLEAUT32.dll", "PSAPI.DLL", "rpcrt4.dll", "sechost.dll", "Setupapi.dll", "SHCORE.dll",
        "SHELL32.dll", "SHLWAPI.dll", "user32.dll", "WLDAP32.dll", "wow64.dll", "wow64base.dll",
        "wow64con.dll", "wow64cpu.dll", "wow64win.dll", "WS2_32.dll", "xtajit.dll", "xtajit64.dll",
        "xtajit64se.dll",
        "wowarmhw.dll", "lz32.dll", "url.dll", "urlmon.dll", "wininet.dll", "wintrust.dll",
        "crypt32.dll", "gdi32full.dll", "msvcp_win.dll", "ucrtbase.dll", "kernelbase.dll",
        "ntdll.dll", "win32u.dll", "imagehlp.dll", "ws2_32.dll", "cfgmgr32.dll", "bcrypt.dll",
        "bcryptprimitives.dll", "shcore.dll", "windows.storage.dll", "profapi.dll", "powrprof.dll",
        "kernel.appcore.dll", "umpdc.dll", "msasn1.dll", "cryptbase.dll", "wldp.dll",
    )
)
KNOWN_DLL_DIRECTORY_VALUES = frozenset({"dlldirectory", "dlldirectory32", "dlldirectoryarm", "dlldirectorychpe32"})


# ---------------------------------------------------------------------------
# Key sources
# ---------------------------------------------------------------------------


@dataclass
class KeyView:
    """One key as the decoders see it: root-relative path, values, LastWrite (hive only)."""

    rel: str
    name: str
    values: dict[str, object]
    last_written: str = ""
    native: object = None
    line: int = 0
    ancestry: frozenset[int] = frozenset()


class KeySource:
    """``key(rel)`` and ``subkeys(view)`` over a hive or an export (one hive kind, one user)."""

    hive_kind = ""
    keys_visited = 0
    budget_exhausted = False

    def reset_budget(self) -> None:
        self.keys_visited = 0
        self.budget_exhausted = False

    def charge(self, count: int) -> int:
        """How many of ``count`` keys may still be expanded under :data:`MAX_DEPTH_KEYS_PER_DECODER`."""
        allowed = max(0, min(count, MAX_DEPTH_KEYS_PER_DECODER - self.keys_visited))
        self.keys_visited += allowed
        if allowed < count:
            self.budget_exhausted = True
        return allowed

    def key(self, rel: str) -> KeyView | None:  # pragma: no cover - interface
        raise NotImplementedError

    def subkeys(self, view: KeyView) -> list[KeyView]:  # pragma: no cover - interface
        raise NotImplementedError

    def control_set(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class HiveKeySource(KeySource):
    def __init__(self, hive: object, hive_kind: str) -> None:
        self.hive = hive
        self.hive_kind = hive_kind
        self._ccs: str | None = None

    def _view(self, rel: str, key: object) -> KeyView:
        hive = self.hive
        return KeyView(
            rel=rel,
            name=str(key.name),  # type: ignore[attr-defined]
            values=hive.values_dict(key),  # type: ignore[attr-defined]
            last_written=key.last_written_at,  # type: ignore[attr-defined]
            native=key,
        )

    def key(self, rel: str) -> KeyView | None:
        key = self.hive.open_key(rel)  # type: ignore[attr-defined]
        return self._view(rel, key) if key is not None else None

    def subkeys(self, view: KeyView) -> list[KeyView]:
        """Children of ``view``: each cell once, never the key itself or one of its ancestors."""
        if view.native is None or self.budget_exhausted:
            return []
        own = int(getattr(view.native, "offset", 0) or 0)
        ancestry = view.ancestry | {own}
        seen: set[int] = set()
        unique = []
        for child in self.hive.subkeys(view.native)[:MAX_SUBKEYS_PER_LIST]:  # type: ignore[attr-defined]
            offset = int(getattr(child, "offset", 0) or 0)
            if offset in seen or offset in ancestry:
                continue  # duplicate or cyclic subkey-list entry
            seen.add(offset)
            unique.append(child)
        views = []
        for child in unique[: self.charge(len(unique))]:
            child_view = self._view(f"{view.rel}\\{child.name}", child)
            child_view.ancestry = ancestry
            views.append(child_view)
        return views

    def control_set(self) -> str:
        if self._ccs is None:
            from .registry import resolve_current_control_set

            self._ccs = resolve_current_control_set(self.hive)[0]  # type: ignore[arg-type]
        return self._ccs


class ExportKeySource(KeySource):
    """Keys of one hive (and one user) of a ``.reg`` export; parents are implied."""

    def __init__(self, hive_kind: str, mount: str, user_sid: str) -> None:
        self.hive_kind = hive_kind
        self.mount = mount
        self.user_sid = user_sid
        self.keys: dict[str, KeyView] = {}
        self.children: dict[str, dict[str, str]] = {}

    def add(self, rel: str, values: dict[str, object], line: int) -> None:
        parts = [part for part in rel.split("\\") if part]
        rel = "\\".join(parts)
        lowered = rel.casefold()
        existing = self.keys.get(lowered)
        if existing is not None:
            existing.values.update(values)
        else:
            self.keys[lowered] = KeyView(rel=rel, name=parts[-1] if parts else "", values=values, line=line)
        for index in range(1, len(parts) + 1):
            parent = "\\".join(parts[: index - 1]).casefold()
            child = "\\".join(parts[:index])
            self.children.setdefault(parent, {}).setdefault(child.casefold(), child)

    def key(self, rel: str) -> KeyView | None:
        lowered = "\\".join(part for part in rel.split("\\") if part).casefold()
        view = self.keys.get(lowered)
        if view is None and lowered in self.children:
            original = rel.strip("\\")
            view = KeyView(rel=original, name=original.rsplit("\\", 1)[-1], values={})
        return view

    def subkeys(self, view: KeyView) -> list[KeyView]:
        found: list[KeyView] = []
        if self.budget_exhausted:
            return found
        children = sorted(self.children.get(view.rel.casefold(), {}).items())[:MAX_SUBKEYS_PER_LIST]
        for lowered, original in children[: self.charge(len(children))]:
            child = self.keys.get(lowered) or KeyView(rel=original, name=original.rsplit("\\", 1)[-1], values={})
            found.append(child)
        return found

    def control_set(self) -> str:
        for candidate in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
            if candidate.casefold() in self.children.get("", {}):
                return candidate
        return "CurrentControlSet"


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


@dataclass
class DepthRow:
    artifact_type: str
    label: str
    view: KeyView
    fields: dict[str, object]
    timestamp: str = ""
    timestamp_label: str = ""
    timestamp_timezone: str = "UTC"
    preview: str = ""
    risk_flags: tuple[str, ...] = ()


# ``timestamp_label`` -> ``timestamp_kind`` (the console's time-semantics column). A key LastWrite
# (PCA Store/Persisted, App Paths, MountPoints2 ...) is never a per-item run or open time.
TIMESTAMP_KINDS = {
    "last_written": "last-written",
    "last_written_mru_head": "last-written",
    "last_connected": "last-connected",
    "first_connected": "first-connected",
    "last_opened": "last-opened",
    "startup_disabled": "disabled",
}


def timestamp_kind(row: DepthRow) -> str:
    return TIMESTAMP_KINDS.get(row.timestamp_label, "") if row.timestamp else ""


@dataclass
class DepthStats:
    counts: dict[str, int] = field(default_factory=dict)
    capped: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    key_budget_exhausted: list[str] = field(default_factory=list)
    oversized_values: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "parser": DEPTH_PARSER,
            "parser_version": DEPTH_PARSER_VERSION,
            "row_counts": dict(sorted(self.counts.items())),
            "capped_types": sorted(set(self.capped)),
            "row_cap_per_type": MAX_DEPTH_ROWS_PER_TYPE,
            "key_budget_exhausted_decoders": sorted(set(self.key_budget_exhausted)),
            "key_budget_per_decoder": MAX_DEPTH_KEYS_PER_DECODER,
            "oversized_export_value_count": len(self.oversized_values),
            "oversized_export_values": self.oversized_values[:20],
            "export_value_char_cap": MAX_EXPORT_VALUE_CHARS,
            "decoder_errors": self.errors[:20],
            "decoder_error_count": len(self.errors),
        }


def iter_depth_rows(source: KeySource, stats: DepthStats) -> Iterable[DepthRow]:
    """Every depth row of one source; one decoder failing is recorded and isolated."""
    decoders: Sequence[Callable[[KeySource], Iterable[DepthRow]]] = DECODERS_BY_HIVE.get(source.hive_kind, ())
    for decoder in decoders:
        source.reset_budget()
        try:
            for row in decoder(source):
                count = stats.counts.get(row.artifact_type, 0)
                if count >= MAX_DEPTH_ROWS_PER_TYPE:
                    if row.artifact_type not in stats.capped:
                        stats.capped.append(row.artifact_type)
                    break  # stop the decoder: draining a capped generator is the blow-up itself
                stats.counts[row.artifact_type] = count + 1
                yield row
        except Exception as exc:  # one corrupt key family must not stop the rest
            stats.errors.append({"decoder": decoder.__name__, "error": f"{type(exc).__name__}: {exc}"[:300]})
        if source.budget_exhausted:
            stats.key_budget_exhausted.append(f"{source.hive_kind}:{decoder.__name__}")


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


def text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        even = raw[: len(raw) - (len(raw) % 2)]
        cut = next((index for index in range(0, len(even), 2) if even[index : index + 2] == b"\x00\x00"), len(even))
        return even[:cut].decode("utf-16-le", errors="replace")
    return str(value)


def as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and 1 <= len(value) <= 8:
        return int.from_bytes(bytes(value), "little")
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def as_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return b""


def systemtime_text(raw: object) -> str:
    """16-byte SYSTEMTIME (year, month, weekday, day, h, m, s, ms) as local wall-clock ISO text (no offset)."""
    data = as_bytes(raw)
    if len(data) < 16:
        return ""
    year, month, _weekday, day, hour, minute, second, millis = (
        int.from_bytes(data[index : index + 2], "little") for index in range(0, 16, 2)
    )
    if not (1980 <= year <= 9999 and millis < 1000):
        return ""
    try:  # calendar validation (February 31st, month 13, hour 24 ...)
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        return ""
    stamp = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"
    return f"{stamp}.{millis:03d}" if millis else stamp


def mac_text(raw: object) -> str:
    data = as_bytes(raw)
    if len(data) != 6 or not any(data):
        return ""
    return ":".join(f"{byte:02x}" for byte in data)


def filetime_text(ticks: int) -> str:
    from .registry import filetime_to_iso_ticks

    return filetime_to_iso_ticks(ticks)


def mru_order(values: Mapping[str, object]) -> dict[str, int]:
    """``MRUList`` (letters) or ``MRUListEx`` (DWORD list) -> value name -> position (0 = newest)."""
    raw_ex = values.get("MRUListEx")
    if isinstance(raw_ex, (bytes, bytearray)):
        order: dict[str, int] = {}
        for index in range(0, len(raw_ex) - 3, 4):
            item = int.from_bytes(raw_ex[index : index + 4], "little")
            if item == 0xFFFFFFFF:
                break
            order[str(item)] = len(order)
        return order
    letters = text(values.get("MRUList"))
    return {char: position for position, char in enumerate(letters)}


def unc_host(path: str) -> str:
    stripped = path.replace("/", "\\")
    if not stripped.startswith("\\\\"):
        return ""
    return stripped[2:].split("\\", 1)[0]


def base_name(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]


# ---------------------------------------------------------------------------
# Decoders: SOFTWARE
# ---------------------------------------------------------------------------


def network_profile_rows(source: KeySource) -> Iterable[DepthRow]:
    signatures: dict[str, tuple[str, KeyView]] = {}
    for scope in ("Managed", "Unmanaged"):
        parent = source.key(f"{NETWORKLIST}\\Signatures\\{scope}")
        for signature in source.subkeys(parent) if parent is not None else []:
            guid = text(signature.values.get("ProfileGuid")).strip().casefold()
            if guid:
                signatures.setdefault(guid, (scope, signature))
    profiles = source.key(f"{NETWORKLIST}\\Profiles")
    seen: set[str] = set()
    for profile in source.subkeys(profiles) if profiles is not None else []:
        guid = profile.name.casefold()
        seen.add(guid)
        scope, signature = signatures.get(guid, ("", None))
        yield from _network_profile(profile, profile.name, scope, signature)
    for guid, (scope, signature) in sorted(signatures.items()):
        if guid not in seen:  # signature whose profile key is gone (deleted profile)
            yield from _network_profile(signature, text(signature.values.get("ProfileGuid")), scope, signature, orphan=True)


def _network_profile(
    view: KeyView, guid: str, scope: str, signature: KeyView | None, *, orphan: bool = False
) -> Iterable[DepthRow]:
    values = view.values if not orphan else {}
    sig = signature.values if signature is not None else {}
    category = as_int(values.get("Category"))
    name_type = as_int(values.get("NameType"))
    managed = as_int(values.get("Managed"))
    first = systemtime_text(values.get("DateCreated"))
    last = systemtime_text(values.get("DateLastConnected"))
    name = text(values.get("ProfileName")) or text(sig.get("FirstNetwork")) or text(sig.get("Description"))
    fields: dict[str, object] = {
        "profile_guid": guid,
        "profile_name": name,
        "description": text(values.get("Description")) or text(sig.get("Description")),
        "first_connected_at": first,
        "last_connected_at": last,
        "connection_time_zone": "local-unknown",
        "category": category,
        "category_label": NETWORK_CATEGORY_LABELS.get(category, "") if category is not None else "",
        "name_type": name_type,
        "name_type_label": NETWORK_NAME_TYPE_LABELS.get(name_type, "") if name_type is not None else "",
        "managed": bool(managed) if managed is not None else (scope == "Managed" if scope else None),
        "signature_scope": scope,
        "gateway_mac": mac_text(sig.get("DefaultGatewayMac")),
        "dns_suffix": text(sig.get("DnsSuffix")),
        "first_network": text(sig.get("FirstNetwork")),
        "signature_source": as_int(sig.get("Source")),
        "signature_key": signature.rel if signature is not None else "",
        "profile_key_missing": orphan,
        "timestamp_semantics": "DateCreated/DateLastConnected는 SYSTEMTIME 현지 시각입니다(시간대 표시 없음).",
    }
    yield DepthRow(
        "registry-network-profile",
        "네트워크 프로필(NetworkList)",
        view,
        fields,
        timestamp=last or first,
        timestamp_label="last_connected" if last else ("first_connected" if first else ""),
        timestamp_timezone="local-unknown",
        preview=f"{name} ({fields['name_type_label'] or '종류 미상'}) 마지막 연결 {last or '-'}",
    )
    if name_type == 71 and not orphan:
        yield DepthRow(
            "registry-wlan-profile",
            "무선 연결 이력(NetworkList)",
            view,
            {
                "ssid": name,
                "profile_guid": guid,
                "source_kind": "networklist-wireless",
                "source_kind_label": "NetworkList 무선 프로필",
                "first_connected_at": first,
                "last_connected_at": last,
                "connection_time_zone": "local-unknown",
                "gateway_mac": fields["gateway_mac"],
                "dns_suffix": fields["dns_suffix"],
                "category_label": fields["category_label"],
                "interface_guid": "",
                "profile_index": None,
            },
            timestamp=last or first,
            timestamp_label="last_connected" if last else ("first_connected" if first else ""),
            timestamp_timezone="local-unknown",
            preview=f"Wi-Fi {name} 마지막 연결 {last or '-'}",
        )


def channel_hints_ssid(raw: object) -> str:
    """SSID from ``MetaData\\Channel Hints`` (DWORD length + SSID bytes); ``""`` when not decodable."""
    data = as_bytes(raw)
    if len(data) < 5:
        return ""
    length = int.from_bytes(data[:4], "little")
    if not 0 < length <= 32 or len(data) < 4 + length:
        return ""
    ssid = data[4 : 4 + length]
    try:
        return ssid.decode("utf-8")
    except UnicodeDecodeError:
        return ssid.decode("latin-1")


def wlan_profile_rows(source: KeySource) -> Iterable[DepthRow]:
    interfaces = source.key(r"Microsoft\WlanSvc\Interfaces")
    for interface in source.subkeys(interfaces) if interfaces is not None else []:
        profiles = source.key(f"{interface.rel}\\Profiles")
        for profile in source.subkeys(profiles) if profiles is not None else []:
            metadata = source.key(f"{profile.rel}\\MetaData")
            meta = metadata.values if metadata is not None else {}
            ssid = channel_hints_ssid(meta.get("Channel Hints"))
            yield DepthRow(
                "registry-wlan-profile",
                "무선 프로필(WlanSvc)",
                profile,
                {
                    "ssid": ssid,
                    "ssid_source": "channel-hints" if ssid else "",
                    "profile_guid": profile.name,
                    "interface_guid": interface.name,
                    "profile_index": as_int(profile.values.get("ProfileIndex")),
                    "source_kind": "wlansvc-profile",
                    "source_kind_label": "WlanSvc 프로필 키",
                    "metadata_value_names": sorted(meta)[:20],
                    "first_connected_at": "",
                    "last_connected_at": "",
                },
                timestamp=profile.last_written,
                timestamp_label="last_written" if profile.last_written else "",
                preview=f"Wi-Fi {ssid or profile.name}",
            )


def install_state_rows(source: KeySource) -> Iterable[DepthRow]:
    prefix = "Software\\" if source.hive_kind == "NTUSER" else ""
    bases = [f"{prefix}Microsoft\\Windows\\CurrentVersion\\App Paths"]
    if not prefix:
        bases.append(r"Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths")
    for base in bases:
        parent = source.key(base)
        for app in source.subkeys(parent) if parent is not None else []:
            executable = text(app.values.get("")).strip().strip('"')
            yield DepthRow(
                "registry-install-state",
                "설치 상태(App Paths)",
                app,
                {
                    "state_source": "app-paths",
                    "state_source_label": "App Paths 등록",
                    "application_name": app.name,
                    "executable_path": executable,
                    "app_path_dir": text(app.values.get("Path")),
                    "display_name": app.name,
                    "wow6432": base.startswith("Wow6432Node"),
                },
                timestamp=app.last_written,
                timestamp_label="last_written" if app.last_written else "",
                preview=f"{app.name} → {executable}",
            )
    if prefix:
        return
    user_data = source.key(r"Microsoft\Windows\CurrentVersion\Installer\UserData")
    for sid_key in source.subkeys(user_data) if user_data is not None else []:
        products = source.key(f"{sid_key.rel}\\Products")
        for product in source.subkeys(products) if products is not None else []:
            properties = source.key(f"{product.rel}\\InstallProperties")
            if properties is None:
                continue
            values = properties.values
            name = text(values.get("DisplayName"))
            yield DepthRow(
                "registry-install-state",
                "설치 상태(MSI 제품)",
                properties,
                {
                    "state_source": "msi-product",
                    "state_source_label": "Windows Installer 제품",
                    "product_code": product.name,
                    "installer_sid": sid_key.name,
                    "display_name": name,
                    "application_name": name,
                    "display_version": text(values.get("DisplayVersion")),
                    "publisher": text(values.get("Publisher")),
                    "install_date": text(values.get("InstallDate")),
                    "install_location": text(values.get("InstallLocation")),
                    "install_source": text(values.get("InstallSource")),
                    "local_package": text(values.get("LocalPackage")),
                    "uninstall_string": text(values.get("UninstallString")),
                },
                timestamp=properties.last_written,
                timestamp_label="last_written" if properties.last_written else "",
                preview=f"{name or product.name} {text(values.get('DisplayVersion'))}".strip(),
            )


# ---------------------------------------------------------------------------
# Decoders: SYSTEM
# ---------------------------------------------------------------------------


def known_dll_rows(source: KeySource) -> Iterable[DepthRow]:
    ccs = source.control_set()
    key = source.key(f"{ccs}\\Control\\Session Manager\\KnownDLLs")
    if key is None:
        return
    for name, value in sorted(key.values.items(), key=lambda item: item[0].casefold()):
        dll = text(value).strip()
        directory = name.casefold() in KNOWN_DLL_DIRECTORY_VALUES
        in_baseline = directory or dll.casefold() in KNOWN_DLL_BASELINE
        flags = () if in_baseline else ("known-dll-not-in-baseline",)
        yield DepthRow(
            "registry-known-dll",
            "알려진 DLL(KnownDLLs)",
            key,
            {
                "value_name": name or "(default)",
                "dll_name": dll,
                "entry_kind": "directory" if directory else "dll",
                "in_default_baseline": in_baseline,
                "control_set": ccs,
                "baseline_note": "기본 목록에 없는 항목은 검토 단서입니다(서드파티·변조 가능성).",
            },
            timestamp=key.last_written,
            timestamp_label="last_written" if key.last_written else "",
            preview=f"{name} = {dll}",
            risk_flags=flags,
        )


# ---------------------------------------------------------------------------
# Decoders: NTUSER
# ---------------------------------------------------------------------------


def network_share_rows(source: KeySource) -> Iterable[DepthRow]:
    mount_points = source.key(f"{EXPLORER}\\MountPoints2")
    for entry in source.subkeys(mount_points) if mount_points is not None else []:
        name = entry.name
        if name.startswith("##"):
            kind, share = "network-share", "\\\\" + name[2:].replace("#", "\\")
        elif name.startswith("{"):
            kind, share = "volume-guid", name
        elif len(name) == 1 and name.isalpha():
            kind, share = "drive-letter", f"{name.upper()}:"
        else:
            kind, share = "other", name
        yield DepthRow(
            "registry-network-share",
            "네트워크 공유·마운트(MountPoints2)",
            entry,
            {
                "share_path": share,
                "share_server": unc_host(share),
                "share_kind": kind,
                "share_kind_label": SHARE_KIND_LABELS[kind],
                "is_network": kind == "network-share",
                "source_kind": "mountpoints2",
                "source_kind_label": SHARE_SOURCE_LABELS["mountpoints2"],
                "mount_label": text(entry.values.get("_LabelFromReg")) or text(entry.values.get("_LabelFromDesktopINI")),
                "drive_letter": share if kind == "drive-letter" else "",
                "mru_position": None,
            },
            timestamp=entry.last_written,
            timestamp_label="last_written" if entry.last_written else "",
            preview=share,
        )
    mru = source.key(f"{EXPLORER}\\Map Network Drive MRU")
    if mru is not None:
        order = mru_order(mru.values)
        for name, value in sorted(mru.values.items()):
            if name in {"MRUList", "MRUListEx"} or not name:
                continue
            share = text(value).strip()
            position = order.get(name)
            head = position == 0
            yield DepthRow(
                "registry-network-share",
                "네트워크 드라이브 연결 MRU",
                mru,
                {
                    "share_path": share,
                    "share_server": unc_host(share),
                    "share_kind": "network-share",
                    "share_kind_label": SHARE_KIND_LABELS["network-share"],
                    "is_network": True,
                    "source_kind": "map-network-drive-mru",
                    "source_kind_label": SHARE_SOURCE_LABELS["map-network-drive-mru"],
                    "value_name": name,
                    "mru_position": position,
                    "drive_letter": "",
                    "timestamp_semantics": "키 최종 수정 시각은 MRU 최상위(0번) 항목에만 해당합니다.",
                },
                timestamp=mru.last_written if head else "",
                timestamp_label="last_written_mru_head" if head and mru.last_written else "",
                preview=share,
            )
    network = source.key("Network")
    for drive in source.subkeys(network) if network is not None else []:
        remote = text(drive.values.get("RemotePath"))
        yield DepthRow(
            "registry-network-share",
            "매핑 드라이브(Network)",
            drive,
            {
                "share_path": remote,
                "share_server": unc_host(remote),
                "share_kind": "network-share",
                "share_kind_label": SHARE_KIND_LABELS["network-share"],
                "is_network": True,
                "source_kind": "network-drive",
                "source_kind_label": SHARE_SOURCE_LABELS["network-drive"],
                "drive_letter": f"{drive.name.upper()}:",
                "username": text(drive.values.get("UserName")),
                "provider_name": text(drive.values.get("ProviderName")),
                "connection_type": as_int(drive.values.get("ConnectionType")),
                "mru_position": None,
            },
            timestamp=drive.last_written,
            timestamp_label="last_written" if drive.last_written else "",
            preview=f"{drive.name.upper()}: → {remote}",
        )


def office_mru_rows(source: KeySource) -> Iterable[DepthRow]:
    office = source.key(r"Software\Microsoft\Office")
    for version in source.subkeys(office) if office is not None else []:
        if not OFFICE_VERSION.match(version.name):
            continue
        for application in source.subkeys(version):
            lists: list[tuple[KeyView, str]] = []
            for child in source.subkeys(application):
                lowered = child.name.casefold()
                if lowered in OFFICE_MRU_KINDS:
                    lists.append((child, ""))
                elif lowered == "user mru":
                    for account in source.subkeys(child):
                        lists.extend(
                            (grandchild, account.name)
                            for grandchild in source.subkeys(account)
                            if grandchild.name.casefold() in OFFICE_MRU_KINDS
                        )
            for mru, account in lists:
                yield from _office_items(mru, version.name, application.name, account)


def _office_items(mru: KeyView, version: str, application: str, account: str) -> Iterable[DepthRow]:
    kind, kind_label = OFFICE_MRU_KINDS[mru.name.casefold()]
    for name, value in mru.values.items():
        match = re.fullmatch(r"(?i)item (\d+)", name)
        if not match:
            continue
        raw = text(value)
        parsed = OFFICE_ITEM.match(raw)
        path = parsed.group("path") if parsed else raw
        ticks = int(parsed.group("time"), 16) if parsed and parsed.group("time") else 0
        opened = filetime_text(ticks) if ticks else ""
        number = int(match.group(1))
        yield DepthRow(
            "registry-office-mru",
            f"Office {kind_label}",
            mru,
            {
                "office_version": version,
                "application": application,
                "mru_kind": kind,
                "mru_kind_label": kind_label,
                "account_id": account,
                "item_number": number,
                "mru_position": number - 1,
                "file_path": path,
                "file_name": base_name(path) if kind == "file" else "",
                "last_opened_at": opened,
                "flags_hex": parsed.group("flags") if parsed and parsed.group("flags") else "",
                "raw_value": raw[:1000],
                "value_name": name,
            },
            timestamp=opened,
            timestamp_label="last_opened" if opened else "",
            preview=f"{application} {path}",
        )


def default_browser_rows(source: KeySource) -> Iterable[DepthRow]:
    base = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
    for protocol in ("http", "https"):
        key = source.key(f"{base}\\{protocol}\\UserChoice")
        if key is None:
            continue
        prog_id = text(key.values.get("ProgId"))
        lowered = prog_id.casefold()
        browser = next((label for prefix, label in BROWSER_PROG_IDS if lowered.startswith(prefix)), "")
        yield DepthRow(
            "registry-default-browser",
            "기본 브라우저",
            key,
            {
                "protocol": protocol,
                "prog_id": prog_id,
                "browser": browser or prog_id,
                "browser_known": bool(browser),
                "user_choice_hash": text(key.values.get("Hash")),
                "timestamp_semantics": "UserChoice 키 마지막 기록 = 기본 브라우저를 마지막으로 설정한 시각(근사).",
            },
            timestamp=key.last_written,
            timestamp_label="last_written" if key.last_written else "",
            preview=f"{protocol}: {browser or prog_id}",
        )


def pca_registry_rows(source: KeySource) -> Iterable[DepthRow]:
    base = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant"
    for leaf, kind, label in (("Store", "pca-store", "PCA Store"), ("Persisted", "pca-persisted", "PCA Persisted")):
        key = source.key(f"{base}\\{leaf}")
        if key is None:
            continue
        for name, value in sorted(key.values.items()):
            if not name:
                continue
            data = as_bytes(value)
            yield DepthRow(
                "execution-pca",
                f"프로그램 호환성 도우미({label})",
                key,
                {
                    "source_kind": kind,
                    "source_kind_label": f"레지스트리 {label}",
                    "executable_path": name,
                    "executable_name": base_name(name),
                    "value_size": len(data) if data else None,
                    "value_sha256": hashlib.sha256(data).hexdigest() if data else "",
                    "evidence_note": "PCA 레지스트리 항목은 실행 시도 흔적입니다(키 마지막 기록 시각은 키 전체에 공통).",
                },
                timestamp=key.last_written,
                timestamp_label="last_written" if key.last_written else "",
                preview=name,
            )


def feature_usage_rows(source: KeySource) -> Iterable[DepthRow]:
    base = source.key(f"{EXPLORER}\\FeatureUsage")
    for feature in source.subkeys(base) if base is not None else []:
        label = FEATURE_USAGE_LABELS.get(feature.name, feature.name)
        for name, value in sorted(feature.values.items()):
            if not name:
                continue
            count = as_int(value)
            yield DepthRow(
                "execution-feature-usage",
                f"FeatureUsage({label})",
                feature,
                {
                    "feature": feature.name,
                    "feature_label": label,
                    "application": name,
                    "executable_name": base_name(name) if "\\" in name else name,
                    "count": count,
                    "evidence_note": "횟수는 작업 표시줄 상호작용 누적 값이며 시각은 키 단위입니다.",
                },
                timestamp=feature.last_written,
                timestamp_label="last_written" if feature.last_written else "",
                preview=f"{label}: {name} ({count if count is not None else '-'}회)",
            )


# ---------------------------------------------------------------------------
# Decoders: R5 L2 (startup items, logon banner, SSH clients, Office identities, wallpaper)
# ---------------------------------------------------------------------------

STARTUP_APPROVED_SOURCES = (
    ("Run", "run", "Run(자동 실행 값)"),
    ("Run32", "run32", "Run32(32비트 자동 실행 값)"),
    ("StartupFolder", "startup-folder", "시작프로그램 폴더 항목"),
)
STARTUP_ENABLED_BYTES = frozenset({0x02, 0x06})
STARTUP_DISABLED_BYTES = frozenset({0x03, 0x07})
# Value names that hold a (DPAPI-less, reversibly obfuscated) password: never copied into a row.
SECRET_VALUE_NAMES = frozenset({"password", "proxypassword", "tunnelpassword", "passphrase", "encryptedpassword"})
WINSCP_PROTOCOLS = {0: "SCP", 1: "SFTP(SCP 대체)", 2: "SFTP", 5: "FTP", 6: "WebDAV", 7: "S3"}
PUTTY_HOST_KEY_NAME = re.compile(r"^(?P<type>[^@]+)@(?P<port>\d+):(?P<host>.+)$")
OFFICE_PROVIDER_LABELS = {
    "adal": "회사·학교 계정(Entra ID/ADAL)",
    "liveid": "개인 Microsoft 계정(MSA)",
    "orgid": "회사 계정(OrgId)",
}


SECRET_CLIENT_KEYS = (r"software\simontatham\putty", r"software\martin prikryl\winscp 2")
SECRET_PLACEHOLDER = "(비밀번호 값 — 저장하지 않음)"


def is_secret_value(key_path: str, value_name: str) -> bool:
    """A PuTTY/WinSCP password value (``Password``, ``ProxyPassword`` …): never copied into any row."""
    folded = key_path.replace("/", "\\").casefold()
    return value_name.strip('"').casefold() in SECRET_VALUE_NAMES and any(marker in folded for marker in SECRET_CLIENT_KEYS)


def hive_secret_strings(hive: object) -> set[str]:
    """Data of the PuTTY/WinSCP password values of one hive, so the hive string scan can drop them."""
    source = HiveKeySource(hive, "NTUSER")
    secrets: set[str] = set()
    for base in (r"Software\SimonTatham\PuTTY", r"Software\Martin Prikryl\WinSCP 2"):
        try:
            sessions = source.key(f"{base}\\Sessions")
            for session in source.subkeys(sessions) if sessions is not None else []:
                for name, value in session.values.items():
                    secret = text(value).strip()
                    if name.casefold() in SECRET_VALUE_NAMES and len(secret) >= 4:
                        secrets.add(secret)
        except Exception:  # pragma: no cover - a corrupt key never stops the hive walk
            continue
    return secrets


def value_ci(values: Mapping[str, object], name: str) -> object:
    """Value ``name`` of a key, case-insensitively (``legalnoticecaption`` vs ``LegalNoticeCaption``)."""
    if name in values:
        return values[name]
    folded = name.casefold()
    return next((value for key, value in values.items() if key.casefold() == folded), None)


def percent_decoded(name: str) -> str:
    """PuTTY/WinSCP session key names are %XX-encoded (``My%20Server``)."""
    from urllib.parse import unquote

    return unquote(name)


def startup_approved_state(raw: object) -> tuple[bool | None, str, str]:
    """``(enabled, state byte hex, disabled-at ISO)`` of a 12-byte StartupApproved value."""
    data = as_bytes(raw)
    if not data:
        return None, "", ""
    state = data[0]
    enabled: bool | None = True if state in STARTUP_ENABLED_BYTES else (False if state in STARTUP_DISABLED_BYTES else None)
    disabled_at = ""
    if enabled is False and len(data) >= 12:
        ticks = int.from_bytes(data[4:12], "little")
        disabled_at = filetime_text(ticks) if ticks else ""
    return enabled, f"{state:02X}", disabled_at


def _run_commands(source: KeySource, relative: str) -> dict[str, str]:
    key = source.key(relative)
    if key is None:
        return {}
    return {name.casefold(): text(value) for name, value in key.values.items() if name}


def startup_approved_rows(source: KeySource) -> Iterable[DepthRow]:
    machine = source.hive_kind == "SOFTWARE"
    prefix = "" if machine else "Software\\"
    base = f"{prefix}Microsoft\\Windows\\CurrentVersion"
    run_values = {
        "run": _run_commands(source, f"{base}\\Run"),
        "run32": _run_commands(source, "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run") if machine else _run_commands(source, f"{base}\\Run"),
    }
    for leaf, kind, kind_label in STARTUP_APPROVED_SOURCES:
        key = source.key(f"{base}\\Explorer\\StartupApproved\\{leaf}")
        if key is None:
            continue
        for name, value in sorted(key.values.items(), key=lambda item: item[0].casefold()):
            if not name:
                continue
            enabled, state_hex, disabled_at = startup_approved_state(value)
            command = run_values.get(kind, {}).get(name.casefold(), "")
            state_label = "사용" if enabled else ("사용 안 함" if enabled is False else "알 수 없음")
            timestamp = disabled_at or key.last_written
            label = "startup_disabled" if disabled_at else ("last_written" if key.last_written else "")
            yield DepthRow(
                artifact_type="startup-item",
                label=f"시작 프로그램 승인 상태({kind_label})",
                view=key,
                fields={
                    "item_name": name,
                    "startup_source": f"startup-approved-{kind}",
                    "startup_source_label": f"StartupApproved\\{leaf}",
                    "scope": "machine" if machine else "user",
                    "scope_label": "시스템(모든 사용자)" if machine else "사용자",
                    "enabled": enabled,
                    "state_label": state_label,
                    "state_byte_hex": state_hex,
                    "disabled_at": disabled_at,
                    "command": command,
                    "target_path": command,
                    "run_value_found": bool(command) if kind != "startup-folder" else None,
                    "value_name": name,
                    "evidence_note": (
                        "StartupApproved는 작업 관리자 '시작 프로그램'의 사용 여부입니다. 비활성화 시각은 값 4–12바이트 FILETIME, "
                        "사용 중인 항목의 시각은 키 단위 마지막 기록입니다."
                    ),
                },
                timestamp=timestamp,
                timestamp_label=label,
                preview=f"{name} ({state_label}) {command}".strip(),
            )


def logon_banner_rows(source: KeySource) -> Iterable[DepthRow]:
    for relative, policy_label in (
        (r"Microsoft\Windows\CurrentVersion\Policies\System", "정책(Policies\\System)"),
        (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
    ):
        key = source.key(relative)
        if key is None:
            continue
        caption = text(value_ci(key.values, "legalnoticecaption")).strip()
        body = text(value_ci(key.values, "legalnoticetext")).strip()
        if not caption and not body:
            continue
        yield DepthRow(
            artifact_type="registry-logon-banner",
            label=f"로그온 배너({policy_label})",
            view=key,
            fields={
                "banner_caption": caption,
                "banner_text": body[:4000],
                "banner_text_truncated": len(body) > 4000,
                "banner_source": "policies-system" if "Policies" in relative else "winlogon",
                "banner_source_label": policy_label,
                "evidence_note": "로그온 전 표시되는 법적 고지(보안 서약·모니터링 고지). 시각은 키 마지막 기록입니다.",
            },
            timestamp=key.last_written,
            timestamp_label="last_written" if key.last_written else "",
            preview=f"{caption} — {body[:160]}",
        )


def _session_fields(values: Mapping[str, object]) -> dict[str, object]:
    port = as_int(value_ci(values, "PortNumber"))
    saved = {name.casefold() for name, value in values.items() if name.casefold() in SECRET_VALUE_NAMES and text(value)}
    return {
        "host_name": text(value_ci(values, "HostName")).strip(),
        "user_name": text(value_ci(values, "UserName")).strip(),
        "port": port,
        "public_key_file": text(value_ci(values, "PublicKeyFile")).strip(),
        "proxy_host": text(value_ci(values, "ProxyHost")).strip(),
        "password_saved": "password" in saved or "encryptedpassword" in saved,
        "proxy_password_saved": "proxypassword" in saved,
        "secret_values_stored": False,
    }


def ssh_client_rows(source: KeySource) -> Iterable[DepthRow]:
    clients = (
        ("putty", "PuTTY", r"Software\SimonTatham\PuTTY"),
        ("winscp", "WinSCP", r"Software\Martin Prikryl\WinSCP 2"),
    )
    for client, client_label, base in clients:
        host_keys = source.key(f"{base}\\SshHostKeys")
        if host_keys is not None:
            for name, value in sorted(host_keys.values.items()):
                match = PUTTY_HOST_KEY_NAME.match(name or "")
                material = text(value)
                yield DepthRow(
                    artifact_type="ssh-known-host",
                    label=f"SSH 호스트 키({client_label})",
                    view=host_keys,
                    fields={
                        "client": client,
                        "client_label": client_label,
                        "host": match.group("host") if match else name,
                        "port": int(match.group("port")) if match else None,
                        "key_type": match.group("type") if match else "",
                        "key_sha256": hashlib.sha256(material.encode("utf-8")).hexdigest() if material else "",
                        "fingerprint_sha256": "",
                        "value_name": name,
                        "evidence_note": "SSH 서버에 처음 접속할 때 저장한 서버 공개키입니다(접속 이력). 시각은 키 단위 마지막 기록입니다.",
                    },
                    timestamp=host_keys.last_written,
                    timestamp_label="last_written" if host_keys.last_written else "",
                    preview=f"{client_label} {name}",
                )
        sessions = source.key(f"{base}\\Sessions")
        for session in source.subkeys(sessions) if sessions is not None else []:
            fields = _session_fields(session.values)
            if not fields["host_name"]:
                continue  # "Default Settings" and other templates without a host
            protocol_raw = value_ci(session.values, "Protocol") if client == "putty" else as_int(value_ci(session.values, "FSProtocol"))
            protocol = text(protocol_raw) if client == "putty" else WINSCP_PROTOCOLS.get(protocol_raw, "") if isinstance(protocol_raw, int) else ""
            yield DepthRow(
                artifact_type="ssh-client-session",
                label=f"저장된 접속 세션({client_label})",
                view=session,
                fields={
                    "client": client,
                    "client_label": client_label,
                    "session_name": percent_decoded(session.name),
                    "protocol": protocol,
                    **fields,
                    "evidence_note": "저장된 세션 설정입니다. 비밀번호 값은 복사하지 않고 저장 여부만 표시합니다.",
                },
                timestamp=session.last_written,
                timestamp_label="last_written" if session.last_written else "",
                preview=f"{client_label} {fields['user_name']}@{fields['host_name']}:{fields['port'] or ''}".rstrip(":"),
                risk_flags=("ssh-password-saved",) if fields["password_saved"] else (),
            )


def office_identity_rows(source: KeySource) -> Iterable[DepthRow]:
    office = source.key(r"Software\Microsoft\Office")
    for version in source.subkeys(office) if office is not None else []:
        if not OFFICE_VERSION.match(version.name):
            continue
        identities = source.key(f"{version.rel}\\Common\\Identity\\Identities")
        for identity in source.subkeys(identities) if identities is not None else []:
            values = identity.values
            email = text(value_ci(values, "EmailAddress")).strip()
            provider = text(value_ci(values, "ProviderId")).strip()
            sign_in = text(value_ci(values, "SignInName")).strip()
            if not (email or sign_in or provider):
                continue
            yield DepthRow(
                artifact_type="office-identity",
                label="Office 연결 계정",
                view=identity,
                fields={
                    "office_version": version.name,
                    "identity_id": identity.name,
                    "email_address": email,
                    "sign_in_name": sign_in,
                    "friendly_name": text(value_ci(values, "FriendlyName")).strip(),
                    "provider_id": provider,
                    "provider_label": OFFICE_PROVIDER_LABELS.get(provider.casefold(), provider),
                    "tenant_id": text(value_ci(values, "TenantId")).strip(),
                    "identity_provider": text(value_ci(values, "IdP")).strip(),
                    "evidence_note": "Office에 로그인한 계정(회사·개인). 시각은 계정 키 마지막 기록입니다.",
                },
                timestamp=identity.last_written,
                timestamp_label="last_written" if identity.last_written else "",
                preview=f"{email or sign_in} ({OFFICE_PROVIDER_LABELS.get(provider.casefold(), provider) or '-'})",
            )


def transcoded_image_cache_path(raw: object) -> str:
    """Original wallpaper path of ``TranscodedImageCache`` (UTF-16LE from offset 0x18)."""
    data = as_bytes(raw)
    return text(data[0x18:]).strip() if len(data) > 0x18 else ""


def wallpaper_rows(source: KeySource) -> Iterable[DepthRow]:
    desktop = source.key(r"Control Panel\Desktop")
    if desktop is not None:
        current = text(value_ci(desktop.values, "WallPaper")).strip()
        original = transcoded_image_cache_path(value_ci(desktop.values, "TranscodedImageCache"))
        if current or original:
            yield DepthRow(
                artifact_type="desktop-wallpaper",
                label="바탕 화면 배경(레지스트리)",
                view=desktop,
                fields={
                    "wallpaper_source": "control-panel-desktop",
                    "wallpaper_source_label": "Control Panel\\Desktop",
                    "wallpaper_path": current,
                    "original_path": original,
                    "history_position": None,
                    "wallpaper_style": text(value_ci(desktop.values, "WallpaperStyle")),
                    "tile_wallpaper": text(value_ci(desktop.values, "TileWallpaper")),
                    "evidence_note": "WallPaper = 현재 배경 파일(보통 TranscodedWallpaper), TranscodedImageCache = 원본 이미지 경로.",
                },
                timestamp=desktop.last_written,
                timestamp_label="last_written" if desktop.last_written else "",
                preview=original or current,
            )
    history = source.key(f"{EXPLORER}\\Wallpapers")
    if history is not None:
        for name, value in sorted(history.values.items()):
            match = re.fullmatch(r"(?i)BackgroundHistoryPath(\d+)", name or "")
            if not match or not text(value).strip():
                continue
            position = int(match.group(1))
            yield DepthRow(
                artifact_type="desktop-wallpaper",
                label="바탕 화면 배경 기록",
                view=history,
                fields={
                    "wallpaper_source": "background-history",
                    "wallpaper_source_label": "Explorer\\Wallpapers 기록",
                    "wallpaper_path": "",
                    "original_path": text(value).strip(),
                    "history_position": position,
                    "value_name": name,
                },
                timestamp=history.last_written if position == 0 else "",
                timestamp_label="last_written_mru_head" if position == 0 and history.last_written else "",
                preview=text(value).strip(),
            )


DECODERS_BY_HIVE: dict[str, tuple[Callable[[KeySource], Iterable[DepthRow]], ...]] = {
    "SOFTWARE": (network_profile_rows, wlan_profile_rows, install_state_rows, startup_approved_rows, logon_banner_rows),
    "SYSTEM": (known_dll_rows,),
    "NTUSER": (
        network_share_rows,
        office_mru_rows,
        default_browser_rows,
        pca_registry_rows,
        feature_usage_rows,
        install_state_rows,
        startup_approved_rows,
        ssh_client_rows,
        office_identity_rows,
        wallpaper_rows,
    ),
}


# ---------------------------------------------------------------------------
# Hive integration
# ---------------------------------------------------------------------------


def hive_kind_for_path(path: Path) -> str:
    upper = path.name.upper()
    if upper == "NTUSER.DAT":
        return "NTUSER"
    return upper if upper in {"SOFTWARE", "SYSTEM"} else ""


def hive_depth_records(context: object, stats: DepthStats) -> Iterable[ArtifactRecord]:
    """Depth rows of one opened hive (``NativeHiveRowContext``)."""
    kind = hive_kind_for_path(context.path)  # type: ignore[attr-defined]
    if not kind:
        return
    source = HiveKeySource(context.hive, kind)  # type: ignore[attr-defined]
    for row in iter_depth_rows(source, stats):
        record = context.row(  # type: ignore[attr-defined]
            row.artifact_type,
            label=row.label,
            relative_key=row.view.rel,
            key=row.view.native,
            fields=row.fields,
            timestamp=row.timestamp,
            timestamp_label=row.timestamp_label,
            raw_preview=row.preview,
            risk_flags=row.risk_flags,
        )
        record.details.update(
            {
                "parser": DEPTH_PARSER,
                "parser_version": DEPTH_PARSER_VERSION,
                "recovery_method": "parsed",
                "source_offset": record.details.get("key_cell_offset"),
                "timestamp_timezone": row.timestamp_timezone if row.timestamp else "",
                "timestamp_kind": timestamp_kind(row),
            }
        )
        yield record


# ---------------------------------------------------------------------------
# .reg export integration
# ---------------------------------------------------------------------------

EXPORT_ROOTS: tuple[tuple[str, str, str], ...] = (
    ("hkey_local_machine\\software\\", "SOFTWARE", "HKLM\\SOFTWARE"),
    ("hklm\\software\\", "SOFTWARE", "HKLM\\SOFTWARE"),
    ("hkey_local_machine\\system\\", "SYSTEM", "HKLM\\SYSTEM"),
    ("hklm\\system\\", "SYSTEM", "HKLM\\SYSTEM"),
    ("hkey_current_user\\", "NTUSER", "HKCU"),
    ("hkcu\\", "NTUSER", "HKCU"),
)


def split_export_key(key: str) -> tuple[str, str, str, str] | None:
    """``(hive kind, mount, user SID, root-relative path)`` of an exported key; ``None`` = not decoded here."""
    lowered = key.casefold()
    for prefix, kind, mount in EXPORT_ROOTS:
        if lowered.startswith(prefix):
            return kind, mount, "", key[len(prefix) :]
    for prefix in ("hkey_users\\", "hku\\"):
        if lowered.startswith(prefix):
            rest = key[len(prefix) :]
            sid, _, relative = rest.partition("\\")
            if not sid or sid.casefold().endswith("_classes"):
                return None
            return "NTUSER", f"HKU\\{sid}", sid if sid.upper().startswith("S-1-") else "", relative
    return None


def decode_export_value(raw: str) -> object:
    """A ``.reg`` value literal as the hive reader would decode it (str, int, list, bytes)."""
    value = raw.strip()
    if value.startswith('"'):
        body = value[1:-1] if value.endswith('"') and len(value) >= 2 else value[1:]
        return body.replace('\\"', '"').replace("\\\\", "\\")
    lowered = value.casefold()
    if lowered.startswith("dword:"):
        try:
            return int(value[6:].strip(), 16)
        except ValueError:
            return value
    if lowered.startswith("hex"):
        type_text, _, body = value.partition(":")
        cleaned = re.sub(r"[^0-9a-fA-F]", "", body)
        cleaned = cleaned[: len(cleaned) - (len(cleaned) % 2)]
        try:
            data = bytes.fromhex(cleaned)
        except ValueError:
            return b""
        value_type = type_text[4:-1] if type_text.casefold().startswith("hex(") else ""
        if value_type in {"1", "2"}:
            return text(data)
        if value_type == "7":
            even = data[: len(data) - (len(data) % 2)]
            return [item for item in even.decode("utf-16-le", errors="replace").split("\x00") if item]
        if value_type.casefold() == "b":
            return int.from_bytes(data[:8], "little")
        if value_type == "4":
            return int.from_bytes(data[:4], "little")
        return data
    return value


def iter_export_keys(
    lines: Sequence[str], stats: DepthStats | None = None
) -> Iterable[tuple[str, dict[str, object], int]]:
    """``(key, decoded values, line number)`` of a ``.reg`` text; ``\\`` continuation lines are joined.

    Continuation parts are collected in a list and joined once (no quadratic re-concatenation);
    a value whose text exceeds :data:`MAX_EXPORT_VALUE_CHARS` is dropped and disclosed in
    ``stats.oversized_values``.
    """
    current = ""
    current_line = 0
    values: dict[str, object] = {}
    parts: list[str] = []
    parts_chars = 0
    oversized = False
    for number, line in enumerate([*lines, ""], start=1):
        stripped = line.strip()
        if parts and not stripped and number <= len(lines):
            continue  # blank line inside a continued value (CR CR LF line ends)
        if parts:
            continued = stripped.endswith("\\")
            piece = stripped[:-1] if continued else stripped
            if not oversized:
                parts.append(piece)
                parts_chars += len(piece)
                oversized = parts_chars > MAX_EXPORT_VALUE_CHARS
            if continued:
                continue
            stripped = "".join(parts)
            parts, parts_chars = [], 0
            if oversized:
                oversized = False
                if stats is not None:
                    stats.oversized_values.append(f"{current}:{number}"[:300])
                continue
        elif stripped.endswith("\\") and "=" in stripped and not stripped.startswith("["):
            parts, parts_chars = [stripped[:-1]], len(stripped) - 1
            oversized = parts_chars > MAX_EXPORT_VALUE_CHARS
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            if current:
                yield current, values, current_line
            current, current_line, values = stripped[1:-1], number, {}
            if current.startswith("-"):
                current = ""  # deletion entry: no values to decode
            continue
        if not current or "=" not in stripped:
            continue
        if stripped.startswith("@="):
            name, literal = "", stripped[2:]
        elif stripped.startswith('"'):
            match = re.match(r'^"((?:[^"\\]|\\.)*)"=(.*)$', stripped)
            if not match:
                continue
            name, literal = match.group(1).replace('\\"', '"').replace("\\\\", "\\"), match.group(2)
        else:
            continue
        if literal.strip() == "-":
            continue
        values[name] = decode_export_value(literal)
    if current:
        yield current, values, current_line


def export_sources(lines: Sequence[str], stats: DepthStats | None = None) -> list[ExportKeySource]:
    sources: dict[tuple[str, str], ExportKeySource] = {}
    for key, values, line in iter_export_keys(lines, stats):
        split = split_export_key(key)
        if split is None:
            continue
        kind, mount, sid, relative = split
        source = sources.get((kind, mount))
        if source is None:
            source = sources[(kind, mount)] = ExportKeySource(kind, mount, sid)
        source.add(relative, values, line)
    return list(sources.values())


def looks_like_utf16(data: bytes) -> str:
    """``"utf-16-le"``/``"utf-16-be"`` when a BOM-less buffer has the NUL pattern of UTF-16 text
    (most odd or even bytes of the first 4 KiB are NUL), else ``""``."""
    sample = data[:4096]
    pairs = len(sample) // 2
    if pairs < 2:
        return ""
    odd_nuls = sum(1 for index in range(1, pairs * 2, 2) if sample[index] == 0)
    even_nuls = sum(1 for index in range(0, pairs * 2, 2) if sample[index] == 0)
    if odd_nuls >= pairs * 0.6 and even_nuls <= pairs * 0.1:
        return "utf-16-le"
    if even_nuls >= pairs * 0.6 and odd_nuls <= pairs * 0.1:
        return "utf-16-be"
    return ""


def decode_export_bytes(data: bytes) -> str:
    """``.reg`` text: UTF-16 only with a BOM or the UTF-16 NUL pattern, then UTF-8, then CP949
    (``REGEDIT4`` ANSI exports of Korean systems). A CP949 file of even length is never read as
    UTF-16 (any even-length buffer decodes as UTF-16 without error)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    utf16 = looks_like_utf16(data)
    if utf16:
        return data.decode(utf16, errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp949", errors="replace")


def read_export_lines(path: Path) -> list[str]:
    try:
        if path.stat().st_size > MAX_EXPORT_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    return decode_export_bytes(data).splitlines()


def export_depth_records(path: Path, source_hashes: Mapping[str, str], stats: DepthStats | None = None) -> Iterable[ArtifactRecord]:
    """Depth rows of one ``.reg`` export (keys of several hives/users are kept apart)."""
    from .registry import WindowsRegistryProvider

    stats = stats or DepthStats()
    resolved = str(path.resolve())
    for source in export_sources(read_export_lines(path), stats):
        for row in iter_depth_rows(source, stats):
            key_path = f"{source.mount}\\{row.view.rel}"
            details: dict[str, object] = {
                "parser": DEPTH_PARSER,
                "parser_version": DEPTH_PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "label": row.label,
                "source_path": resolved,
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "recovery_method": "parsed",
                "source_offset": row.view.line or None,
                "source_offset_unit": "line",
                "hive_name": source.hive_kind,
                "hive_hint": source.mount,
                "hive_mount": source.mount,
                "user_sid": source.user_sid,
                "key_path": key_path,
                "key": key_path,
                "key_last_written_at": "",
                **row.fields,
                "timestamp": row.timestamp,
                "timestamp_label": row.timestamp_label if row.timestamp else "",
                "timestamp_timezone": row.timestamp_timezone if row.timestamp else "",
                "timestamp_kind": timestamp_kind(row),
                "risk_flags": sorted(set(row.risk_flags)),
                "risk_score": min(100, 25 * len(set(row.risk_flags))),
                "raw_preview": (row.preview or key_path)[:2000],
            }
            yield ArtifactRecord(
                provider=WindowsRegistryProvider.name,
                artifact_type=row.artifact_type,
                path=resolved,
                supported=True,
                details=details,
            )
