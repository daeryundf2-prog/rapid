"""Run-mode profiles and the run-mode error type."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .constants import (
    CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
    GENERAL_FORENSIC_ARTIFACT_KINDS,
    RUN_DOC_EXTRACT_KINDS,
    WINDOWS_FORENSIC_ARTIFACT_KINDS,
)

__all__ = [
    "RUN_PROFILES",
    "RunModeError",
    "RunProfile",
    "resolve_scan_root",
]


@dataclass(frozen=True)
class RunProfile:
    mode: str
    description: str
    keywords: tuple[str, ...]
    docs_extract_kinds: tuple[str, ...]
    file_extract_categories: tuple[str, ...]
    file_scan_categories: tuple[str, ...]
    file_scan_path_contains: tuple[str, ...] = ()
    scan_root_parts: tuple[str, ...] = ()
    preferred_locations: tuple[str, ...] = ()
    artifacts_kinds: tuple[str, ...] = ()


RUN_PROFILES: dict[str, RunProfile] = {
    "seizure": RunProfile(
        mode="seizure",
        description="Seizure triage focused on user folders, recent modifications, and high-value documents, archives, and databases.",
        keywords=("seizure", "download", "desktop", "document", "archive", "database", "recent", "evidence"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "databases",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
            "images",
        ),
        scan_root_parts=("Users",),
        preferred_locations=("downloads", "desktop", "documents"),
        artifacts_kinds=(
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
        ),
    ),
    "fraud": RunProfile(
        mode="fraud",
        description="Document-forward fraud triage focused on payment, account, and invoice evidence.",
        keywords=("fraud", "invoice", "payment", "transfer", "bank", "account", "receipt", "refund"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "mobile-images"),
        file_scan_categories=("documents", "archives", "databases", "emails", "mobile-images", "images"),
        artifacts_kinds=(
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
        ),
    ),
    "hacking": RunProfile(
        mode="hacking",
        description="Intrusion triage focused on suspicious binaries, credential theft, persistence, and attacker tooling.",
        keywords=("hacking", "malware", "credential", "powershell", "persistence", "ransomware", "shell", "exfil"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps"),
        file_scan_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps", "images"),
        artifacts_kinds=(
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
        ),
    ),
    "recovery": RunProfile(
        mode="recovery",
        description="Recovery triage focused on deleted, recycled, or restorable file candidates without doing carving.",
        keywords=("recovery", "deleted", "recycle", "trash", "restore", "backup", "recent"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "images", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "images",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
        ),
        file_scan_path_contains=("recycle",),
        preferred_locations=("$recycle.bin", "recycle", "trash", "deleted"),
        artifacts_kinds=(
            "recent-files",
            "email",
            "cloud-export",
            "mobile-export",
            "kakaotalk-macos",
            "kakaotalk-windows",
            "android-apk",
            "media-image",
            "generic-documents",
            "memory-volatility",
            "synthetic-media",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-registry",
            "windows-shellbags",
            "windows-prefetch",
            "windows-filesystem",
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
        ),
    ),
}


class RunModeError(ValueError):
    """Raised when the requested run mode is invalid or unsupported."""


def resolve_scan_root(root: Path, profile: RunProfile) -> Path:
    if not profile.scan_root_parts:
        return root
    candidate = root.joinpath(*profile.scan_root_parts)
    if candidate.exists():
        return candidate
    return root
