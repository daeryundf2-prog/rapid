from __future__ import annotations

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
    supported_suffixes = (".dd", ".raw", ".img")

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
            message="Raw image detected. Mount/extract support is planned; scan a mounted folder for now.",
        )


class IsoAdapter:
    name = "iso"
    supported_suffixes = (".iso",)

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="iso",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="ISO detected. Mount/extract support is planned; scan a mounted folder for now.",
        )


class VirtualDiskAdapter:
    name = "virtual-disk"
    supported_suffixes = (".vhd", ".vhdx", ".vmdk")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=source.suffix.lower().lstrip(".") or "virtual-disk",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Virtual disk detected. Mount/extract support is planned; scan a mounted folder for now.",
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
    RawImageAdapter(),
    IsoAdapter(),
    VirtualDiskAdapter(),
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
