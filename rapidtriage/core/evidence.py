from __future__ import annotations

import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .e01 import E01_SUFFIXES, E01_REQUIRED_TOOLS, missing_e01_tools


class EvidenceAdapter(Protocol):
    name: str
    supported_suffixes: tuple[str, ...]

    def identify(self, source: Path) -> "EvidenceAdapterResult":
        ...


@dataclass(frozen=True)
class EvidenceAdapterResult:
    adapter: str
    source_path: str
    detected_format: str
    supported: bool
    can_mount: bool
    can_extract: bool
    required_tools: list[str]
    missing_tools: list[str]
    message: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class FolderAdapter:
    name = "folder"
    supported_suffixes: tuple[str, ...] = ()

    def identify(self, source: Path) -> EvidenceAdapterResult:
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="folder",
            supported=source.is_dir(),
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Directory evidence can be scanned directly." if source.is_dir() else "Source is not a directory.",
        )


class EwfAdapter:
    name = "ewf"
    supported_suffixes = E01_SUFFIXES

    def identify(self, source: Path) -> EvidenceAdapterResult:
        missing = missing_e01_tools()
        supported = source.suffix.lower() in self.supported_suffixes
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="e01" if source.suffix.lower() == ".e01" else "ex01",
            supported=supported and not missing,
            can_mount=supported and not missing,
            can_extract=supported and not missing,
            required_tools=list(E01_REQUIRED_TOOLS),
            missing_tools=missing,
            message=(
                "E01/Ex01 can be extracted with libewf and Sleuth Kit tools."
                if supported and not missing
                else "E01/Ex01 detected, but required external tools are missing. Use WSL2 or a mounted/extracted folder."
            ),
        )


class RawImageAdapter:
    name = "raw-image"
    supported_suffixes = (".dd", ".raw", ".img", ".001", ".000", ".0000", ".0001", ".00001", ".ima")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="raw",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Raw/split image detected. Mount it with OS/forensic tooling, then scan the mounted or recovered folder.",
        )


class IsoAdapter:
    name = "iso"
    supported_suffixes = (".iso", ".dmg", ".wim", ".swm")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "optical-archive-image",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message=f"{suffix.upper()} image detected. Mount/extract it first, then scan the mounted folder.",
        )


class VirtualDiskAdapter:
    name = "virtual-disk"
    supported_suffixes = (".vhd", ".vhdx", ".vmdk", ".vdi", ".xva", ".qcow", ".qcow2")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        recommended_tools = recommended_virtual_disk_tools(source.suffix.lower())
        missing = [tool for tool in recommended_tools if shutil.which(tool) is None]
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=source.suffix.lower().lstrip(".") or "virtual-disk",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=recommended_tools,
            missing_tools=missing,
            message=(
                "Virtual disk detected. Use Windows Disk Management/PowerShell, qemu-nbd, or guestmount to expose it, "
                "then scan the mounted filesystem folder."
            ),
        )


class ForensicContainerAdapter:
    name = "forensic-container"
    supported_suffixes = (".ad1", ".l01", ".lx01", ".aff", ".aff4", ".aff4-l")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "forensic-container",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message=(
                f"{suffix.upper()} forensic container detected. Direct parsing is not implemented yet; "
                "export or mount it with the acquisition vendor/tool, then scan the resulting folder."
            ),
        )


class MobilePackageAdapter:
    name = "mobile-package"
    supported_suffixes = (".ab", ".ufd", ".ufdx")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "mobile-package",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message=(
                f"{suffix.upper()} mobile extraction package detected. Import/parsing is planned; "
                "for now export files/databases from Cellebrite/XRY/GrayKey/AXIOM and scan that folder."
            ),
        )


class MemoryDumpAdapter:
    name = "memory-dump"
    supported_suffixes = (".mem", ".dmp", ".vmem", ".vmss", ".vmsn", ".hpak", ".crash")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        volatility = "vol"
        missing = [] if shutil.which(volatility) else [volatility]
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "memory-dump",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[volatility],
            missing_tools=missing,
            message=(
                "Memory dump detected. RapidTriage can inventory/hash the file; deep memory analysis should be run "
                "with Volatility/Volatility3 and imported as reports/logs."
            ),
        )


class UnsupportedAdapter:
    name = "unsupported"
    supported_suffixes: tuple[str, ...] = ()

    def identify(self, source: Path) -> EvidenceAdapterResult:
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=source.suffix.lower().lstrip(".") or "unknown",
            supported=False,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Evidence format is not supported yet. Mount or extract it first, then scan the resulting folder.",
        )


ADAPTERS: tuple[EvidenceAdapter, ...] = (
    FolderAdapter(),
    EwfAdapter(),
    ForensicContainerAdapter(),
    RawImageAdapter(),
    IsoAdapter(),
    VirtualDiskAdapter(),
    MobilePackageAdapter(),
    MemoryDumpAdapter(),
)


def identify_evidence(source: Path) -> EvidenceAdapterResult:
    resolved = source.expanduser().resolve()
    if resolved.is_dir():
        return FolderAdapter().identify(resolved)
    suffix = resolved.suffix.lower()
    for adapter in ADAPTERS:
        if suffix in adapter.supported_suffixes:
            return adapter.identify(resolved)
    return UnsupportedAdapter().identify(resolved)


def recommended_virtual_disk_tools(suffix: str) -> list[str]:
    if sys.platform.startswith("win"):
        if suffix in (".vhd", ".vhdx"):
            return ["powershell"]
        return ["qemu-img"]
    if suffix in (".vmdk", ".vdi", ".qcow", ".qcow2", ".xva"):
        return ["qemu-img"]
    return []


def supported_evidence_formats() -> list[dict[str, object]]:
    return [
        {
            "adapter": adapter.name,
            "suffixes": list(adapter.supported_suffixes),
        }
        for adapter in ADAPTERS
    ]
