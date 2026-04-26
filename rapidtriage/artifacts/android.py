from __future__ import annotations

import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "android-apk-v1"
ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"
DANGEROUS_PERMISSION_KEYWORDS = (
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_PHONE_STATE",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",
    "QUERY_ALL_PACKAGES",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "RECEIVE_BOOT_COMPLETED",
)


class AndroidApkProvider:
    collector_kind = "android-apk"
    name = "android-apk-artifacts"
    description = "Android APK inventory, hashes, manifest metadata, permissions, and triage risk flags"
    target_platform = "android"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*.apk"), key=lambda item: str(item).lower()):
            if path.is_file():
                yield build_apk_record(path)


def build_apk_record(path: Path) -> ArtifactRecord:
    resolved = path.resolve()
    stat_result = resolved.stat()
    details: dict[str, object] = {
        "parser": "android-apk",
        "parser_version": PARSER_VERSION,
        "source_path": str(resolved),
        "source_format": "apk",
        "source_size": stat_result.st_size,
        "entry_name": resolved.name,
        "hashes": compute_hashes(resolved),
    }
    try:
        with zipfile.ZipFile(resolved) as archive:
            details.update(parse_apk_zip(archive))
    except (OSError, zipfile.BadZipFile):
        details.update(
            {
                "valid_zip": False,
                "manifest_format": "unreadable",
                "risk_flags": ["apk-not-readable"],
                "risk_score": 25,
            }
        )
    return ArtifactRecord(
        provider=AndroidApkProvider.name,
        artifact_type="android-apk",
        path=str(resolved),
        supported=True,
        details=details,
    )


def parse_apk_zip(archive: zipfile.ZipFile) -> dict[str, object]:
    names = archive.namelist()
    dex_entries = sorted(name for name in names if name.endswith(".dex"))
    native_libraries = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
    certificate_entries = sorted(name for name in names if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")))
    manifest = parse_manifest(archive)
    permissions = sorted(manifest.get("permissions", []))
    risk_flags = build_risk_flags(
        permissions=permissions,
        dex_entries=dex_entries,
        native_libraries=native_libraries,
        certificate_entries=certificate_entries,
        manifest_format=str(manifest.get("manifest_format", "")),
    )
    return {
        "valid_zip": True,
        "zip_entry_count": len(names),
        "dex_count": len(dex_entries),
        "dex_entries": dex_entries[:25],
        "native_library_count": len(native_libraries),
        "native_libraries": native_libraries[:25],
        "certificate_entries": certificate_entries[:10],
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions(permissions),
        "risk_flags": risk_flags,
        "risk_score": score_risk(risk_flags, permissions, native_libraries, dex_entries),
        **manifest,
    }


def parse_manifest(archive: zipfile.ZipFile) -> dict[str, object]:
    try:
        raw = archive.read("AndroidManifest.xml")
    except KeyError:
        return {"manifest_format": "missing", "package": "", "permissions": []}
    text = decode_text_manifest(raw)
    if not text:
        return {
            "manifest_format": "binary-or-unsupported",
            "package": "",
            "permissions": [],
            "raw_manifest_preview": raw[:80].hex(),
        }
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {
            "manifest_format": "text-unparseable",
            "package": "",
            "permissions": [],
            "raw_manifest_preview": text[:400],
        }
    package = root.attrib.get("package", "")
    permissions = []
    for element in root.iter():
        if local_name(element.tag) != "uses-permission":
            continue
        name = element.attrib.get(f"{ANDROID_NAMESPACE}name") or element.attrib.get("name")
        if name:
            permissions.append(name)
    uses_sdk = next((element for element in root.iter() if local_name(element.tag) == "uses-sdk"), None)
    application = next((element for element in root.iter() if local_name(element.tag) == "application"), None)
    return {
        "manifest_format": "xml",
        "package": package,
        "version_name": root.attrib.get(f"{ANDROID_NAMESPACE}versionName", ""),
        "version_code": root.attrib.get(f"{ANDROID_NAMESPACE}versionCode", ""),
        "min_sdk": sdk_attr(uses_sdk, "minSdkVersion"),
        "target_sdk": sdk_attr(uses_sdk, "targetSdkVersion"),
        "application_label": sdk_attr(application, "label"),
        "permissions": permissions,
        "raw_manifest_preview": text[:400],
    }


def decode_text_manifest(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-16"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        stripped = text.lstrip("\ufeff\x00\r\n\t ")
        if stripped.startswith("<"):
            return stripped
    return ""


def sdk_attr(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    return element.attrib.get(f"{ANDROID_NAMESPACE}{name}") or element.attrib.get(name, "")


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def dangerous_permissions(permissions: list[str]) -> list[str]:
    hits = []
    for permission in permissions:
        suffix = permission.rsplit(".", 1)[-1]
        if suffix in DANGEROUS_PERMISSION_KEYWORDS:
            hits.append(permission)
    return hits


def build_risk_flags(
    *,
    permissions: list[str],
    dex_entries: list[str],
    native_libraries: list[str],
    certificate_entries: list[str],
    manifest_format: str,
) -> list[str]:
    flags: list[str] = []
    dangerous = dangerous_permissions(permissions)
    if dangerous:
        flags.append("dangerous-permissions")
    if any(permission.endswith("REQUEST_INSTALL_PACKAGES") for permission in permissions):
        flags.append("can-install-packages")
    if any(permission.endswith("BIND_ACCESSIBILITY_SERVICE") for permission in permissions):
        flags.append("accessibility-service-capability")
    if any(permission.endswith("RECEIVE_BOOT_COMPLETED") for permission in permissions):
        flags.append("boot-persistence-capability")
    if len(dex_entries) > 1:
        flags.append("multiple-dex-files")
    if native_libraries:
        flags.append("native-code")
    if not certificate_entries:
        flags.append("missing-certificate-entry")
    if manifest_format != "xml":
        flags.append("manifest-not-decoded")
    return flags


def score_risk(
    risk_flags: list[str],
    permissions: list[str],
    native_libraries: list[str],
    dex_entries: list[str],
) -> int:
    score = len(dangerous_permissions(permissions)) * 8
    score += len(risk_flags) * 7
    if native_libraries:
        score += 10
    if len(dex_entries) > 1:
        score += 8
    return min(score, 100)
