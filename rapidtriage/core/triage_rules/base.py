"""Triage-flag rule primitives (plan viewer-families §3.1).

A rule reads one row at a time (``apply(row, ctx)``) and returns a
:class:`RuleResult` or ``None``. Cross-row rules keep small per-row facts in
their own state while ``apply`` runs and emit their flags from
``finalize(ctx)`` once every source has been read (one pass over the run);
``prepare(ctx)`` runs once before the pass (thresholds, external sets).

Rows are wrapped in :class:`RowView`: ``kind`` is the source label the flag
is stored under (artifact kind, ``files:candidates``/``files:inventory`` or
``analysis:<analysis_id>``), ``index`` the record index readers use.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

GRADES = ("A", "B", "C")
GRADE_RANK = {"A": 0, "B": 1, "C": 2}
EVIDENCE_TEXT_MAX = 300
EVENT_DATA_KEYS = ("event_data", "data", "user_data", "binxml_event_data_values_by_name", "event_data_values_by_name")

RowRef = tuple[str, int]


@dataclass(frozen=True)
class RuleResult:
    """One flag: ``evidence`` = the field values that triggered it (``{field: value}``)."""

    evidence: Mapping[str, object]
    note: str | None = None


# --- row view ------------------------------------------------------------------


class RowView:
    """One row as rules see it (artifact row, files row or analysis row)."""

    __slots__ = ("_lower_event", "collection", "details", "index", "kind", "row", "source_kind", "type")

    def __init__(
        self,
        *,
        kind: str,
        collection: str,
        source_kind: str,
        index: int,
        row: Mapping[str, object],
        artifact_type: str | None = None,
    ) -> None:
        self.kind = kind
        self.collection = collection
        self.source_kind = source_kind
        self.index = index
        self.row = row
        details = row if collection == "files" else row.get("details")
        self.details: Mapping[str, object] = details if isinstance(details, Mapping) else {}
        self.type = artifact_type if artifact_type is not None else str(row.get("artifact_type") or "")
        self._lower_event: dict[str, object] | None = None

    @property
    def ref(self) -> RowRef:
        return (self.kind, self.index)

    def get(self, *keys: str) -> object:
        """First non-empty value among ``keys`` in the record fields (``details``; a files row's own keys), then EventData."""
        for key in keys:
            value = self.details.get(key)
            if not _empty(value):
                return value
        return self.ev(*keys) if self.collection == "artifacts" else None

    def text(self, *keys: str) -> str:
        value = self.get(*keys)
        if _empty(value) or isinstance(value, (Mapping, list, tuple)):
            return ""
        return str(value).strip()

    def ev(self, *names: str) -> object:
        """First non-empty EventData/UserData value among ``names`` (case-insensitive)."""
        if self._lower_event is None:
            merged: dict[str, object] = {}
            for key in EVENT_DATA_KEYS:
                data = self.details.get(key)
                if isinstance(data, Mapping):
                    for name, value in data.items():
                        if isinstance(value, list) and len(value) == 1:
                            value = value[0]
                        merged.setdefault(str(name).lower(), value)
            self._lower_event = merged
        for name in names:
            value = self._lower_event.get(name.lower())
            if not _empty(value) and value != "-":
                return value
        return None

    def ev_text(self, *names: str) -> str:
        value = self.ev(*names)
        return "" if _empty(value) or isinstance(value, (Mapping, list)) else str(value).strip()

    def raw(self, *paths: str) -> object:
        """First non-empty value of the source row kept under ``details.raw`` (``a.b`` paths, case-insensitive)."""
        raw = self.details.get("raw")
        if not isinstance(raw, Mapping):
            return None
        for path in paths:
            value: object = raw
            for part in path.split("."):
                if not isinstance(value, Mapping):
                    value = None
                    break
                lowered = part.lower()
                value = next((item for key, item in value.items() if str(key).lower() == lowered), None)
            if not _empty(value):
                return value
        return None

    def time(self, *keys: str) -> dt.datetime | None:
        for key in keys:
            moment = parse_time(self.get(key))
            if moment is not None:
                return moment
        return None

    def number(self, *keys: str) -> float | None:
        return as_number(self.get(*keys))

    def flag(self, *keys: str) -> bool | None:
        return as_bool(self.get(*keys))

    def path(self) -> str:
        value = self.row.get("path") or self.details.get("source_path") or self.details.get("path")
        return str(value or "")

    def event_id(self) -> str:
        value = self.get("event_id", "eventId", "EventID")
        text = str(value or "").strip()
        return text.split(".")[0] if text else ""

    def channel(self) -> str:
        return self.text("channel", "Channel", "channel_family").lower()

    def provider(self) -> str:
        return self.text("provider_name", "ProviderName", "provider").lower()

    def is_duplicate(self) -> bool:
        """A recovered EVTX copy of a live record (counted once by aggregate rules)."""
        return as_bool(self.details.get("duplicate_of_live_record")) is True


def _empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


# --- selection --------------------------------------------------------------------


@dataclass(frozen=True)
class Select:
    """Which rows a rule reads: collection + (artifact/analysis) kind + artifact type."""

    collections: frozenset[str] = frozenset({"artifacts"})
    kinds: frozenset[str] | None = None
    types: frozenset[str] | None = None
    prefixes: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()

    def accepts(self, collection: str, source_kind: str, artifact_type: str) -> bool:
        if collection not in self.collections:
            return False
        if self.kinds is not None and source_kind not in self.kinds:
            return False
        if self.types is None and not self.prefixes and not self.suffixes:
            return True
        if self.types is not None and artifact_type in self.types:
            return True
        if self.prefixes and artifact_type.startswith(self.prefixes):
            return True
        return bool(self.suffixes) and artifact_type.endswith(self.suffixes)


def select(
    *,
    types: Iterable[str] | None = None,
    kinds: Iterable[str] | None = None,
    prefixes: Iterable[str] = (),
    suffixes: Iterable[str] = (),
    collections: Iterable[str] = ("artifacts",),
) -> Select:
    return Select(
        collections=frozenset(collections),
        kinds=frozenset(kinds) if kinds is not None else None,
        types=frozenset(types) if types is not None else None,
        prefixes=tuple(prefixes),
        suffixes=tuple(suffixes),
    )


EVENTLOG = select(kinds={"eventlog"}, types={"eventlog-event", "eventlog-detection"})


# --- rules ------------------------------------------------------------------------


RULE_CLASSES: dict[str, type[Rule]] = {}


def register(rule_id: str):
    """Class decorator: the implementation of catalogue rule ``rule_id``."""

    def wrap(cls: type[Rule]) -> type[Rule]:
        if rule_id in RULE_CLASSES:
            raise ValueError(f"duplicate triage rule implementation: {rule_id}")
        cls.rule_id = rule_id
        RULE_CLASSES[rule_id] = cls
        return cls

    return wrap


class Rule:
    """Base rule: ``selector`` picks rows; ``apply`` flags one row; ``finalize`` emits deferred flags."""

    rule_id: ClassVar[str] = ""
    selector: ClassVar[Select] = select()

    def __init__(self, params: Mapping[str, Any] | None = None) -> None:
        self.params: dict[str, Any] = dict(params or {})

    def param(self, name: str, default: Any = None) -> Any:
        value = self.params.get(name, default)
        return default if value is None else value

    def accepts(self, collection: str, source_kind: str, artifact_type: str) -> bool:
        return self.selector.accepts(collection, source_kind, artifact_type)

    def prepare(self, ctx: FlagContext) -> None:
        """Called once before the pass."""

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        return iter(())


@dataclass
class FlagContext:
    """Run-wide inputs shared by the rules of one pass."""

    incident_start: dt.datetime | None = None
    incident_end: dt.datetime | None = None
    # Volume-relative, casefolded paths of the run's files (files output + MFT).
    file_paths: set[str] = field(default_factory=set)
    file_dirs: set[str] = field(default_factory=set)
    file_names: set[str] = field(default_factory=set)
    file_paths_known: bool = False
    hostnames: set[str] = field(default_factory=set)
    shared: dict[str, Any] = field(default_factory=dict)

    def in_incident(self, moment: dt.datetime | None) -> bool:
        if moment is None or (self.incident_start is None and self.incident_end is None):
            return False
        if self.incident_start is not None and moment < self.incident_start:
            return False
        return not (self.incident_end is not None and moment > self.incident_end)

    @property
    def has_incident_window(self) -> bool:
        return self.incident_start is not None or self.incident_end is not None

    def file_missing(self, raw_path: str) -> bool | None:
        """``True`` when a system-volume path is absent from the run's file listing although its folder
        was listed (``False``: listed; ``None``: cannot tell -- other volume, folder never listed)."""
        if not self.file_paths_known:
            return None
        drive, rest = split_windows_path(raw_path)
        if not rest or drive not in ("", "c", "volume"):
            return None
        if rest in self.file_paths:
            return False
        parent = rest.rsplit("\\", 1)[0] if "\\" in rest else ""
        return True if parent and parent in self.file_dirs else None


# --- value helpers -------------------------------------------------------------------

_FRACTION = re.compile(r"(\.\d{6})\d+")
_EPOCH_UTC = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def parse_time(value: object) -> dt.datetime | None:
    """ISO-8601 text (``Z``, 7-digit fractions, naive = UTC) or epoch seconds -> aware UTC datetime."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number <= 0:
            return None
        if number > 1e14:  # microseconds
            number /= 1e6
        elif number > 1e11:  # milliseconds
            number /= 1e3
        try:
            return _EPOCH_UTC + dt.timedelta(seconds=number)
        except OverflowError:
            return None
    text = str(value).strip()
    if len(text) < 10 or not text[:4].isdigit():
        return None
    text = text.replace(" ", "T", 1) if len(text) > 10 and text[10] == " " else text
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(r"\1", text)
    try:
        moment = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    if moment.year < 1971:
        return None  # 1601/1970 placeholders are "no time"
    return moment.astimezone(dt.timezone.utc)


def parse_local_time(value: object) -> dt.datetime | None:
    """EXIF-style local time (``YYYY:MM:DD HH:MM:SS``, no zone) as a naive datetime."""
    if value is None:
        return None
    text = str(value).strip()
    match = re.match(r"^(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})", text)
    if not match:
        return None
    try:
        return dt.datetime(*(int(part) for part in match.groups()))
    except ValueError:
        return None


def iso(moment: dt.datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def as_number(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "y"}:
            return True
        if lowered in {"false", "no", "0", "n", ""}:
            return False
    return None


def as_list(value: object) -> list[object]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def short(value: object) -> object:
    """Evidence value: strings cut to ``EVIDENCE_TEXT_MAX`` characters, lists to 10 items."""
    if isinstance(value, str):
        return value if len(value) <= EVIDENCE_TEXT_MAX else value[:EVIDENCE_TEXT_MAX] + "…"
    if isinstance(value, (list, tuple)):
        return [short(item) for item in list(value)[:10]]
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return value


def evidence(**values: object) -> dict[str, object]:
    return {key: short(value) for key, value in values.items() if not _empty(value)}


# --- network / mail helpers --------------------------------------------------------------

_IP_PORT = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?(?::(\d+))?$")


def clean_ip(value: object) -> str:
    """An IP from ``1.2.3.4``, ``1.2.3.4:3389``, ``[::1]:3389``, ``::ffff:1.2.3.4``; ``""`` when not an IP."""
    text = str(value or "").strip()
    if not text or text == "-":
        return ""
    if text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    match = _IP_PORT.match(text)
    candidate = match.group(1) if match else text
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return ""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def is_public_ip(value: object) -> bool:
    """True for a global unicast address (not RFC1918/loopback/link-local/CGNAT/reserved/unspecified)."""
    text = clean_ip(value)
    if not text:
        return False
    address = ipaddress.ip_address(text)
    return bool(address.is_global) and not address.is_multicast


_EMAIL_ADDRESS = re.compile(r"[A-Za-z0-9._%+'\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def email_domain(value: object) -> str:
    """Domain of the (last) address in a header value; ``""`` when none."""
    text = str(value or "")
    matches = _EMAIL_ADDRESS.findall(text)
    return matches[-1].lower().rstrip(".") if matches else ""


def org_domain(domain: str) -> str:
    """Registrable-ish domain: last two labels (three for ``co.kr``-style second levels)."""
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    second = labels[-2]
    if second in {"co", "or", "ne", "go", "ac", "re", "com", "net", "org", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def url_host(value: object) -> str:
    text = str(value or "").strip().lower()
    match = re.match(r"^[a-z][a-z0-9+.\-]*://([^/?#:]+)", text)
    return match.group(1).strip(".") if match else ""


def host_matches(host: str, domains: Iterable[str]) -> str:
    """The listed domain ``host`` equals or is a subdomain of (``""`` when none)."""
    host = host.lower().strip(".")
    for domain in domains:
        domain = str(domain).lower().strip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return domain
    return ""


# --- path helpers -------------------------------------------------------------------

_VOLUME_PREFIX = re.compile(r"^.?\\?(?:\\volume\{[^}]*\}|\\device\\harddiskvolume\d+)\\", re.IGNORECASE)
_DRIVE = re.compile(r"^([a-z]):\\", re.IGNORECASE)


def split_windows_path(raw: object) -> tuple[str, str]:
    """``(drive, rest)``: drive letter (lowercase), ``"unc"``, ``"volume"`` or ``""``; ``rest`` casefolded, ``\\``-joined."""
    text = str(raw or "").strip().strip('"').replace("/", "\\")
    if not text:
        return "", ""
    lowered = text.casefold()
    for prefix in ("\\\\?\\", "\\??\\"):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix):]
            if lowered.startswith("unc\\"):
                lowered = "\\\\" + lowered[4:]
            break
    if lowered.startswith("\\\\"):
        return "unc", lowered[2:]
    volume = _VOLUME_PREFIX.match(lowered)
    if volume:
        return "volume", lowered[volume.end():]
    drive = _DRIVE.match(lowered)
    if drive:
        return drive.group(1), lowered[3:]
    for env, value in (("%systemroot%\\", "windows\\"), ("%windir%\\", "windows\\"), ("%programfiles%\\", "program files\\")):
        if lowered.startswith(env):
            return "c", value + lowered[len(env):]
    return "", lowered.lstrip("\\")


USER_WRITABLE_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\programdata\\",
    "\\perflogs\\",
    "\\windows\\temp\\",
    "\\desktop\\",
)


def user_writable_marker(raw: object, markers: Iterable[str] = USER_WRITABLE_MARKERS) -> str:
    """The user-writable path marker in ``raw`` (``""`` when none)."""
    drive, rest = split_windows_path(raw)
    if not rest:
        return ""
    probe = "\\" + rest
    for marker in markers:
        if marker in probe:
            return marker.strip("\\")
    return ""


# Persistence/service targets: ProgramData and Desktop hold legitimate service binaries too often.
PERSISTENCE_MARKERS = tuple(marker for marker in USER_WRITABLE_MARKERS if marker not in {"\\programdata\\", "\\desktop\\"})

SYSTEM_DIR_PREFIXES = ("windows\\", "program files\\", "program files (x86)\\")


def under_system_dir(raw: object) -> bool:
    _drive, rest = split_windows_path(raw)
    return rest.startswith(SYSTEM_DIR_PREFIXES)


LOLBINS = (
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "wscript",
    "cscript",
    "msiexec",
    "installutil",
    "regasm",
    "regsvcs",
    "msbuild",
    "wmic",
    "forfiles",
    "hh.exe",
    "cmstp",
)
ENCODED_POWERSHELL = re.compile(
    r"(?:^|\s)-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|\biex\b|invoke-expression|downloadstring|-encodedcommand",
    re.IGNORECASE,
)


def lolbin_in(text: str) -> str:
    lowered = text.lower()
    for name in LOLBINS:
        if re.search(rf"(?:^|[\\/\s\"']){re.escape(name)}(?:\.exe)?(?:[\s\"']|$)", lowered):
            return name
    return ""


def suspicious_command(text: str, markers: Iterable[str] = USER_WRITABLE_MARKERS) -> list[str]:
    """Reasons a command line looks like a dropper/persistence payload."""
    reasons: list[str] = []
    marker = user_writable_marker(text, markers)
    if marker:
        reasons.append(f"사용자 쓰기 경로({marker})")
    if ENCODED_POWERSHELL.search(text):
        reasons.append("인코딩/다운로드 PowerShell")
    lolbin = lolbin_in(text)
    if lolbin:
        reasons.append(f"LOLBin({lolbin})")
    lowered = text.lower()
    if "cmd" in lowered and re.search(r"cmd(?:\.exe)?\"?\s+/c", lowered):
        reasons.append("cmd /c")
    if lowered.lstrip('"').startswith("\\\\"):
        reasons.append("UNC 경로")
    return reasons


def base_name(raw: object) -> str:
    text = str(raw or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1].casefold() if text else ""


def extension(raw: object) -> str:
    name = base_name(raw)
    return name.rsplit(".", 1)[-1] if "." in name else ""


def fix_mojibake(text: str) -> str:
    """Undo a cp949/UTF-8 string that was decoded as Latin-1 (LNK NetBIOS names)."""
    if not text or all(ord(char) < 128 for char in text):
        return text
    try:
        raw = text.encode("latin-1")
    except UnicodeEncodeError:
        return text
    for codec in ("utf-8", "cp949"):
        try:
            return raw.decode(codec)
        except UnicodeDecodeError:
            continue
    return text


def hamming64(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def hex_hash(value: object) -> int | None:
    text = str(value or "").strip().lower().removeprefix("0x")
    if not text or len(text) > 32 or any(char not in "0123456789abcdef" for char in text):
        return None
    return int(text, 16)


def hour_of(moment: dt.datetime, offset_hours: float = 0.0) -> int:
    return (moment + dt.timedelta(hours=offset_hours)).hour


def window_groups(
    items: list[tuple[dt.datetime, RowRef]], window: dt.timedelta, minimum: int
) -> list[list[tuple[dt.datetime, RowRef]]]:
    """Maximal runs where at least ``minimum`` items fall within ``window`` (items sorted in place)."""
    items.sort(key=lambda item: item[0])
    flagged: set[int] = set()
    start = 0
    for end in range(len(items)):
        while items[end][0] - items[start][0] > window:
            start += 1
        if end - start + 1 >= minimum:
            flagged.update(range(start, end + 1))
    groups: list[list[tuple[dt.datetime, RowRef]]] = []
    current: list[tuple[dt.datetime, RowRef]] = []
    last = -2
    for position in sorted(flagged):
        if position != last + 1 and current:
            groups.append(current)
            current = []
        current.append(items[position])
        last = position
    if current:
        groups.append(current)
    return groups
