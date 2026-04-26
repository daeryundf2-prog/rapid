from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord

PARSER_VERSION = "reg-export-v1"
REGISTRY_EXPORT_PATTERN = re.compile(r"^\[(?P<key>.+)]$")
REGISTRY_VALUE_PATTERN = re.compile(r'^(?P<name>@|"[^"]+")=(?P<value>.*)$')


class WindowsRegistryProvider:
    name = "windows-registry"
    description = "Windows Registry .reg export artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            yield from collect_reg_export(path)


def collect_reg_export(path: Path) -> Iterable[ArtifactRecord]:
    try:
        lines = path.read_text(encoding="utf-16").splitlines()
    except UnicodeError:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return
    except OSError:
        return

    current_key = ""
    values: dict[str, str] = {}
    for line in [*lines, ""]:
        stripped = line.strip()
        key_match = REGISTRY_EXPORT_PATTERN.match(stripped)
        if key_match:
            if current_key:
                yield build_registry_record(path, current_key, values)
            current_key = key_match.group("key")
            values = {}
            continue
        value_match = REGISTRY_VALUE_PATTERN.match(stripped)
        if current_key and value_match:
            raw_name = value_match.group("name")
            name = "(default)" if raw_name == "@" else raw_name.strip('"')
            values[name] = value_match.group("value")
    if current_key:
        yield build_registry_record(path, current_key, values)


def build_registry_record(path: Path, key: str, values: dict[str, str]) -> ArtifactRecord:
    lowered_key = key.lower()
    artifact_type = "registry-key"
    if "usb" in lowered_key or "usbstor" in lowered_key:
        artifact_type = "registry-usb"
    if "run\\" in lowered_key or lowered_key.endswith("\\run"):
        artifact_type = "registry-run-key"
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-registry-reg-export",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "key": key,
            "hive_hint": key.split("\\", 1)[0],
            "value_count": len(values),
            "values": dict(sorted(values.items())),
            "raw_preview": f"[{key}]",
        },
    )
