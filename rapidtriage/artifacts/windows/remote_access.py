from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp, iter_windows_user_homes

PARSER_VERSION = "windows-remote-access-v1"
RDP_CACHE_ROOT = ("AppData", "Local", "Microsoft", "Terminal Server Client", "Cache")
RDP_DESTINATION_RE = re.compile(r"(?i)\\terminal server client\\(?:default|servers)\\(?P<destination>[^\\\]\"]+)")


class WindowsRemoteAccessProvider:
    name = "windows-remote-access"
    collector_kind = "windows-remote-access"
    description = "Windows RDP configuration, cache, and exported destination artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_rdp_config_files(root)
        yield from collect_rdp_cache_files(root)
        yield from collect_rdp_registry_exports(root)


def collect_rdp_config_files(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        documents = user_root / "Documents"
        candidates = list(documents.glob("*.rdp")) if documents.is_dir() else []
        default_rdp = user_root / "Documents" / "Default.rdp"
        if default_rdp.is_file() and default_rdp not in candidates:
            candidates.append(default_rdp)
        for path in sorted((item for item in candidates if item.is_file()), key=lambda item: item.name.lower()):
            fields = parse_rdp_file(path)
            stat_result = path.stat()
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-config",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "rdp"),
                    "user": user_root.name,
                    "destination": fields.get("full address", ""),
                    "username_hint": fields.get("username", ""),
                    "screen_mode": fields.get("screen mode id", ""),
                    "gateway_hostname": fields.get("gatewayhostname", ""),
                    "fields": fields,
                    "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp_source": "rdp_file_modified_at",
                },
            )


def collect_rdp_cache_files(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        cache_root = user_root.joinpath(*RDP_CACHE_ROOT)
        if not cache_root.is_dir():
            continue
        for path in sorted((item for item in cache_root.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
            stat_result = path.stat()
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-cache-file",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "rdp-cache"),
                    "user": user_root.name,
                    "entry_name": path.name,
                    "size": stat_result.st_size,
                    "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp_source": "rdp_cache_modified_at",
                    "note": "RDP cache file inventoried for remote-access review; thumbnail decoding is not enabled in this build.",
                },
            )


def collect_rdp_registry_exports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
        text = read_text(path)
        if "Terminal Server Client" not in text:
            continue
        destinations = sorted(set(match.group("destination") for match in RDP_DESTINATION_RE.finditer(text)))
        for destination in destinations:
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-destination",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "reg-export"),
                    "destination": destination,
                    "evidence_strength": "remote-access-destination",
                    "raw_preview": text[:1000],
                },
            )


def parse_rdp_file(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in read_text(path).splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) != 3:
            continue
        key, _value_type, value = parts
        fields[key.strip().lower()] = value.strip()
    return fields


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return data.decode(encoding, errors="replace")


def source_details(path: Path, source_format: str) -> dict[str, object]:
    return {
        "parser": "windows-remote-access",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_hashes": {"sha256": compute_sha256(path)},
    }
