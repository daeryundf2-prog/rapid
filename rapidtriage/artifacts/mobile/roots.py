"""Mobile acquisition-root detection.

Rows are only classified inside a detected mobile acquisition root. A
Windows triage tree (AppData, browser extension ``_locales`` folders, Task
Manager settings, ...) carries JSON/CSV files whose generic keys look like
mobile rows; without an acquisition signature none of them is mobile data.

Signatures (structure/magic based, never absolute-path substrings):

* iOS backup: ``Manifest.db`` (SQLite magic) / ``Manifest.plist`` /
  ``Manifest.mbdb`` together with ``Info.plist`` or ``Status.plist`` in the
  same directory.
* Android data tree: path segments ``data/data/<package>`` or
  ``data/user/<n>/<package>``.
* Android adb backup: ``.ab`` file starting with ``ANDROID BACKUP`` (R5 L3: its tar members
  are unpacked in memory by ``adb_backup.collect_adb_backup``; R6 S2: with a run output, its
  SQLite members are copied to ``<output>/mobile-inner/`` and handed to the app parsers with
  :func:`adb_inner_hint` as the token-matching hint).
* Cellebrite UFED: ``.ufd`` / ``.ufdr`` / ``.ufdx`` or a report XML carrying
  the Cellebrite report namespace.
* Magnet AXIOM: ``.mfdb`` case database or ``Case Information`` file naming
  AXIOM/Magnet.
* Oxygen Forensic: ``.ofb`` / ``.ofbr`` or a report XML naming Oxygen.
* MSAB XRY: ``.xry`` / ``.xrep``.
* Vendor export metadata sidecar (``export-metadata.json`` /
  ``export_manifest.json`` / ``*.export-metadata.json``) whose tool field
  names a known mobile vendor.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

NO_MOBILE_ACQUISITION_NOTICE = "모바일 추출물 없음"

_SQLITE_MAGIC = b"SQLite format 3\x00"
_ADB_BACKUP_MAGIC = b"ANDROID BACKUP"
_IOS_MANIFEST_NAMES = {"manifest.db", "manifest.plist", "manifest.mbdb"}
_IOS_COMPANION_NAMES = {"info.plist", "status.plist"}
_VENDOR_SIDECAR_NAMES = {"export-metadata.json", "export_manifest.json", "export-manifest.json"}
_VENDOR_TOOL_KEYS = ("vendor_tool", "tool_name", "vendor", "tool", "source_tool", "acquisition_tool")
_VENDOR_TOKENS = (
    ("cellebrite", ("cellebrite", "ufed", "physical analyzer")),
    ("xry", ("xry", "msab")),
    ("graykey", ("graykey", "grayshift")),
    ("axiom", ("axiom", "magnet")),
    ("oxygen", ("oxygen",)),
)
_HEAD_BYTES = 8192
_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", re.IGNORECASE)


@dataclass(frozen=True)
class MobileAcquisitionRoot:
    path: Path
    kind: str
    source_tool: str
    signature: str
    single_file: bool = False

    def contains(self, candidate: Path) -> bool:
        if self.single_file:
            return candidate == self.path
        try:
            candidate.relative_to(self.path)
        except ValueError:
            return False
        return True

    def relative_hint(self, candidate: Path) -> Path:
        """Root-relative hint path used for token matching (never absolute)."""

        if self.single_file:
            return Path(candidate.name)
        try:
            return Path(self.path.name) / candidate.relative_to(self.path)
        except ValueError:
            return Path(candidate.name)

    def to_details(self, walk_root: Path) -> dict[str, object]:
        try:
            relative = self.path.relative_to(walk_root).as_posix() or "."
        except ValueError:
            relative = str(self.path)
        return {
            "mobile_acquisition_root": relative,
            "mobile_acquisition_root_kind": self.kind,
            "mobile_acquisition_root_signature": self.signature,
        }


def _read_head(path: Path, size: int = _HEAD_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def _vendor_from_text(text: str) -> str:
    lowered = text.lower()
    for vendor, tokens in _VENDOR_TOKENS:
        if any(token in lowered for token in tokens):
            return vendor
    return ""


def _vendor_sidecar_tool(path: Path) -> str:
    try:
        payload = json.loads(path.read_bytes().decode("utf-8", errors="replace"))
    except (OSError, ValueError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    for key in _VENDOR_TOOL_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            vendor = _vendor_from_text(value)
            if vendor:
                return vendor
    return ""


def _android_data_root(relative_parts: Sequence[str], walk_root: Path) -> Path | None:
    lowered = [part.lower() for part in relative_parts]
    for index in range(len(lowered) - 2):
        if lowered[index] != "data":
            continue
        if lowered[index + 1] == "data" and _PACKAGE_RE.match(relative_parts[index + 2]):
            return walk_root.joinpath(*relative_parts[:index]) if index else walk_root
        if (
            lowered[index + 1] == "user"
            and index + 3 < len(lowered)
            and lowered[index + 2].isdigit()
            and _PACKAGE_RE.match(relative_parts[index + 3])
        ):
            return walk_root.joinpath(*relative_parts[:index]) if index else walk_root
    return None


def _file_signature(path: Path, walk_root: Path) -> MobileAcquisitionRoot | None:
    name = path.name.lower()
    suffix = path.suffix.lower()
    parent = path.parent
    if name in _IOS_MANIFEST_NAMES:
        if name == "manifest.db" and not _read_head(path, 16).startswith(_SQLITE_MAGIC):
            return None
        siblings = {child.name.lower() for child in _safe_iterdir(parent)}
        if siblings & _IOS_COMPANION_NAMES:
            return MobileAcquisitionRoot(parent, "ios-backup", "ios-backup", path.name)
        return None
    if suffix == ".ab" and _read_head(path, len(_ADB_BACKUP_MAGIC)) == _ADB_BACKUP_MAGIC:
        return MobileAcquisitionRoot(path, "android-adb-backup", "android-adb-backup", path.name, single_file=True)
    if suffix in {".ufd", ".ufdr", ".ufdx"}:
        return MobileAcquisitionRoot(parent, "cellebrite-ufed", "cellebrite", path.name)
    if suffix == ".mfdb":
        return MobileAcquisitionRoot(parent, "magnet-axiom", "axiom", path.name)
    if suffix in {".ofb", ".ofbr"}:
        return MobileAcquisitionRoot(parent, "oxygen-forensic", "oxygen", path.name)
    if suffix in {".xry", ".xrep"}:
        return MobileAcquisitionRoot(parent, "msab-xry", "xry", path.name)
    if path.stem.lower().startswith("case information") and suffix in {".txt", ".xml"}:
        vendor = _vendor_from_text(_read_head(path).decode("utf-8", errors="replace"))
        if vendor == "axiom":
            return MobileAcquisitionRoot(parent, "magnet-axiom", "axiom", path.name)
        return None
    if suffix == ".xml" and (name == "report.xml" or _vendor_from_text(path.stem)):
        head = _read_head(path).decode("utf-8", errors="replace").lower()
        if "pa.cellebrite.com" in head or ("cellebrite" in head and "<project" in head):
            return MobileAcquisitionRoot(parent, "cellebrite-ufed-report", "cellebrite", path.name)
        if "oxygen forensic" in head:
            return MobileAcquisitionRoot(parent, "oxygen-forensic-report", "oxygen", path.name)
        return None
    if name in _VENDOR_SIDECAR_NAMES or name.endswith(".export-metadata.json"):
        vendor = _vendor_sidecar_tool(path)
        if vendor:
            return MobileAcquisitionRoot(parent, f"{vendor}-export-manifest", vendor, path.name)
    return None


def _safe_iterdir(directory: Path) -> list[Path]:
    try:
        return list(directory.iterdir())
    except OSError:
        return []


def detect_mobile_acquisition_roots(walk_root: Path, files: Iterable[Path]) -> list[MobileAcquisitionRoot]:
    roots: dict[tuple[str, str], MobileAcquisitionRoot] = {}
    for path in files:
        try:
            relative_parts = path.relative_to(walk_root).parts
        except ValueError:
            relative_parts = path.parts
        android_root = _android_data_root(relative_parts[:-1], walk_root)
        if android_root is not None:
            key = (str(android_root), "android-data-tree")
            roots.setdefault(key, MobileAcquisitionRoot(android_root, "android-data-tree", "android-data", "data/data"))
        root = _file_signature(path, walk_root)
        if root is not None:
            roots.setdefault((str(root.path), root.kind), root)
    return sorted(roots.values(), key=lambda item: (len(item.path.parts), str(item.path).lower()))


def adb_inner_hint(package: str, domain: str, member_path: str, *, safe: Callable[..., str]) -> PurePosixPath:
    """Root-relative hint ``apps/<package>/<domain>/<path>`` of an adb backup inner database (R6 S2).

    The extracted copy lives under a hashed run-output folder, so the app parsers' token matching
    (``is_chat_app_database_candidate`` / ``detect_chat_service``, data categories) uses this hint
    instead. It is never a filesystem path: every component goes through ``safe`` (the adb
    ``safe_component`` rule), so ``..``, drives and ``:`` never appear."""
    parts = [safe(part, fallback="_") for part in member_path.replace("\\", "/").split("/") if part]
    return PurePosixPath("apps", safe(package, fallback="_"), safe(domain, fallback="_"), *(parts or ["member.db"]))


def root_for_path(path: Path, roots: Sequence[MobileAcquisitionRoot]) -> MobileAcquisitionRoot | None:
    """Return the deepest acquisition root that contains ``path``."""

    best: MobileAcquisitionRoot | None = None
    for root in roots:
        if root.contains(path) and (best is None or len(root.path.parts) >= len(best.path.parts)):
            best = root
    return best
