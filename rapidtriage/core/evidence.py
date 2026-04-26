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
    support_level: str
    scan_strategy: str
    next_actions: list[str]
    warnings: list[str]
    external_validation_required: bool = True

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
            support_level="direct-folder" if source.is_dir() else "unsupported",
            scan_strategy="scan-folder" if source.is_dir() else "select-folder-or-supported-image",
            next_actions=[
                "Run rapidtriage run on this folder in read-only mode.",
                "Use collect-plan first for large mounted Windows/macOS evidence.",
            ]
            if source.is_dir()
            else ["Select a mounted/exported evidence folder or a recognized evidence image."],
            warnings=[] if source.is_dir() else ["Path is not a directory."],
            external_validation_required=False,
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
            support_level="direct-extract" if supported and not missing else "tooling-required",
            scan_strategy="auto-extract-then-scan" if supported and not missing else "mount-or-export-first",
            next_actions=(
                ["Run rapidtriage run IMAGE.E01 --mode hacking --output-dir OUTPUT."]
                if supported and not missing
                else [
                    "Install libewf and Sleuth Kit tools, or use WSL2 where they are available.",
                    "Alternatively mount/export the E01/Ex01 with a trusted forensic tool and scan the resulting folder.",
                ]
            ),
            warnings=[] if supported and not missing else ["Direct E01/Ex01 extraction is disabled until required tools are present."],
            external_validation_required=True,
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
            support_level="detected-only",
            scan_strategy="mount-or-recover-first",
            next_actions=[
                "Mount read-only with OS/forensic tooling or recover the filesystem with Sleuth Kit.",
                "Scan the mounted/exported folder with rapidtriage run.",
            ],
            warnings=["RapidTriage does not directly parse raw/split disk image files yet."],
            external_validation_required=True,
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
            support_level="detected-only",
            scan_strategy="mount-or-extract-first",
            next_actions=[
                f"Mount or extract the {suffix.upper()} image read-only using trusted platform tooling.",
                "Run RapidTriage against the mounted/exported folder.",
            ],
            warnings=[f"Direct {suffix.upper()} image parsing is not implemented in RapidTriage yet."],
            external_validation_required=True,
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
            support_level="detected-only",
            scan_strategy="mount-virtual-disk-first",
            next_actions=virtual_disk_next_actions(source.suffix.lower()),
            warnings=["Direct virtual disk mounting/extraction is not implemented inside RapidTriage yet."],
            external_validation_required=True,
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
            support_level="detected-only",
            scan_strategy="vendor-export-first",
            next_actions=[
                f"Open the {suffix.upper()} container in its acquisition/vendor tool.",
                "Export a filesystem folder, selected logical files, or parser CSV/JSON outputs.",
                "Run RapidTriage against the exported folder and preserve the vendor export log.",
            ],
            warnings=[f"Direct {suffix.upper()} container parsing is not implemented yet."],
            external_validation_required=True,
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
            support_level="detected-only",
            scan_strategy="vendor-export-first",
            next_actions=[
                "Export files/databases/reports from the mobile forensic tool.",
                "Scan the exported folder and ingest APKs, documents, media, and browser/app databases where present.",
            ],
            warnings=["Full mobile extraction package import is not implemented yet."],
            external_validation_required=True,
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
            support_level="import-tool-output",
            scan_strategy="run-volatility-then-import-output",
            next_actions=[
                "Run Volatility/Volatility3 against the memory image.",
                "Export process, cmdline, netscan, malfind, and related outputs as JSON/JSONL.",
                "Run rapidtriage artifacts --kind memory-volatility on the exported output folder.",
            ],
            warnings=["RapidTriage does not directly analyze raw memory dumps yet."],
            external_validation_required=True,
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
            support_level="unsupported",
            scan_strategy="manual-export-first",
            next_actions=[
                "Identify the source format with the acquisition tool or case notes.",
                "Mount/export the contents to a folder and run RapidTriage on that folder.",
            ],
            warnings=["Unknown evidence format."],
            external_validation_required=True,
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


def virtual_disk_next_actions(suffix: str) -> list[str]:
    if sys.platform.startswith("win") and suffix in (".vhd", ".vhdx"):
        return [
            "Mount the VHD/VHDX read-only with Windows Disk Management or PowerShell where policy allows.",
            "Scan the mounted drive letter or exported folder with RapidTriage.",
        ]
    if suffix in (".vmdk", ".vdi", ".qcow", ".qcow2", ".xva"):
        return [
            "Use qemu-img/qemu-nbd, guestmount, or a trusted forensic VM tool to expose the filesystem read-only.",
            "Export or mount the filesystem and scan that folder with RapidTriage.",
        ]
    return [
        "Mount the virtual disk read-only with platform or forensic tooling.",
        "Scan the mounted/exported filesystem folder with RapidTriage.",
    ]


def supported_evidence_formats() -> list[dict[str, object]]:
    return [
        {
            "adapter": adapter.name,
            "suffixes": list(adapter.supported_suffixes),
            "support_level": adapter_support_level(adapter),
        }
        for adapter in ADAPTERS
    ]


def adapter_support_level(adapter: EvidenceAdapter) -> str:
    if isinstance(adapter, EwfAdapter):
        return "direct-extract-when-tools-present"
    if isinstance(adapter, FolderAdapter):
        return "direct-folder"
    if isinstance(adapter, MemoryDumpAdapter):
        return "import-tool-output"
    return "detected-only"
