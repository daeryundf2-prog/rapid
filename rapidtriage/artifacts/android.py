from __future__ import annotations

import hashlib
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "android-apk-v4"
ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"
APK_STRING_SCAN_LIMIT = 1024 * 1024
MAX_APP_DATA_FILES = 25_000
APK_SUSPICIOUS_STRING_TERMS = (
    "DexClassLoader",
    "PathClassLoader",
    "Runtime.getRuntime",
    "ProcessBuilder",
    "su",
    "chmod",
    "pm install",
    "content://sms",
    "content://contacts",
    "AccessibilityService",
    "BIND_ACCESSIBILITY_SERVICE",
)
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
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
ANDROID_NATIVE_CAPABILITIES = {
    "apk_zip_inventory": True,
    "text_manifest_decode": True,
    "permission_component_inventory": True,
    "dex_native_library_string_pivots": True,
    "android_app_data_path_inventory": True,
    "source_hashing": True,
    "binary_manifest_decode": False,
    "dex_control_flow_analysis": False,
    "signature_chain_validation": False,
    "app_specific_database_decode": False,
    "encrypted_store_decryption": False,
    "deleted_record_recovery": False,
    "known_answer_android_corpus": False,
}
ANDROID_REPORT_GRADE_BLOCKERS = [
    "binary-android-manifest-decoding-not-implemented",
    "signature-chain-validation-not-implemented",
    "dex-control-flow-and-malware-behavior-analysis-not-implemented",
    "app-specific-database-schema-decoding-not-implemented",
    "encrypted-store-and-deleted-record-recovery-not-implemented",
    "known-answer-android-corpus-required",
]


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
        yield from collect_android_app_data_exports(root)


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
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#30"],
        "android_native_capabilities": dict(ANDROID_NATIVE_CAPABILITIES),
        "legal_warning": "APK triage is inventory/risk scoring only. Confirm malware or app-behavior conclusions with validated mobile/malware tooling.",
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
                "validation_checks": {"valid_zip": False, "manifest_decoded": False, "commercial_validation_corpus": False},
                "android_validation_matrix": android_validation_matrix(
                    {"valid_zip": False, "manifest_decoded": False, "commercial_validation_corpus": False}
                ),
                "android_report_grade_assessment": android_report_grade_assessment(["#30"]),
                "commercial_grade_blockers": apk_blockers(),
                "core_accuracy_gates": android_core_accuracy_gates(30, details),
                "forensic_review": android_forensic_review(
                    gap_ids=["#30"],
                    artifact_goal="Android APK ZIP/manifest/permission/component/string-pivot triage",
                    primary_evidence=[
                        f"package={details.get('package', '')}",
                        f"entry_name={resolved.name}",
                        "valid_zip=False",
                    ],
                ),
            }
        )
    details.setdefault(
        "forensic_review",
        android_forensic_review(
            gap_ids=["#30"],
            artifact_goal="Android APK ZIP/manifest/permission/component/string-pivot triage",
            primary_evidence=[
                f"package={details.get('package', '')}",
                f"entry_name={resolved.name}",
                f"dex_count={details.get('dex_count', 0)}",
                f"dangerous_permissions={len(details.get('dangerous_permissions', [])) if isinstance(details.get('dangerous_permissions'), list) else 0}",
            ],
        ),
    )
    details.setdefault("core_accuracy_gates", android_core_accuracy_gates(30, details))
    details["commercial_uplift_evidence"] = android_commercial_uplift_evidence(details, gap_ids=[30])
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
    string_pivots = scan_apk_string_pivots(archive, [*dex_entries, *native_libraries])
    risk_flags = build_risk_flags(
        permissions=permissions,
        dex_entries=dex_entries,
        native_libraries=native_libraries,
        certificate_entries=certificate_entries,
        manifest_format=str(manifest.get("manifest_format", "")),
        string_pivots=string_pivots,
    )
    validation_checks = apk_validation_checks(names, manifest, permissions, dex_entries, certificate_entries)
    return {
        "valid_zip": True,
        "zip_entry_count": len(names),
        "dex_count": len(dex_entries),
        "dex_entries": dex_entries[:25],
        "native_library_count": len(native_libraries),
        "native_libraries": native_libraries[:25],
        "certificate_entries": certificate_entries[:10],
        "entry_hashes": apk_entry_hashes(archive, [*dex_entries[:25], *native_libraries[:25], *certificate_entries[:10]]),
        "native_architectures": native_architectures(native_libraries),
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions(permissions),
        "string_pivots": string_pivots,
        "risk_flags": risk_flags,
        "risk_score": score_risk(risk_flags, permissions, native_libraries, dex_entries, string_pivots),
        "validation_checks": validation_checks,
        "android_validation_matrix": android_validation_matrix(validation_checks),
        "android_report_grade_assessment": android_report_grade_assessment(["#30"]),
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#30"],
        "android_native_capabilities": dict(ANDROID_NATIVE_CAPABILITIES),
        "commercial_grade_blockers": apk_blockers(),
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
    uses_features = []
    components: dict[str, list[dict[str, str]]] = {
        "activity": [],
        "service": [],
        "receiver": [],
        "provider": [],
    }
    for element in root.iter():
        tag = local_name(element.tag)
        if tag == "uses-permission":
            name = element.attrib.get(f"{ANDROID_NAMESPACE}name") or element.attrib.get("name")
            if name:
                permissions.append(name)
            continue
        if tag == "uses-feature":
            name = element.attrib.get(f"{ANDROID_NAMESPACE}name") or element.attrib.get("name")
            if name:
                uses_features.append(name)
            continue
        if tag in components:
            components[tag].append(component_summary(element))
            continue
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
        "uses_features": sorted(uses_features)[:50],
        "components": {key: value[:50] for key, value in components.items()},
        "component_counts": {key: len(value) for key, value in components.items()},
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


def component_summary(element: ET.Element) -> dict[str, str]:
    return {
        "name": sdk_attr(element, "name"),
        "exported": sdk_attr(element, "exported"),
        "permission": sdk_attr(element, "permission"),
        "enabled": sdk_attr(element, "enabled"),
    }


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
    string_pivots: list[dict[str, str]],
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
    if any(permission.endswith("READ_SMS") or permission.endswith("SEND_SMS") for permission in permissions):
        flags.append("sms-access")
    if any(permission.endswith("READ_CONTACTS") or permission.endswith("READ_CALL_LOG") for permission in permissions):
        flags.append("personal-data-access")
    pivot_types = {item["type"] for item in string_pivots}
    if "suspicious-string" in pivot_types:
        flags.append("suspicious-code-strings")
    if "url" in pivot_types or "ip" in pivot_types:
        flags.append("network-indicators")
    return flags


def collect_android_app_data_exports(root: Path) -> Iterable[ArtifactRecord]:
    emitted = 0
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if emitted >= MAX_APP_DATA_FILES:
            break
        if not path.is_file() or path.suffix.lower() == ".apk":
            continue
        package = package_from_android_data_path(path)
        if not package:
            continue
        emitted += 1
        yield build_android_app_data_record(path, package)


def build_android_app_data_record(path: Path, package: str) -> ArtifactRecord:
    resolved = path.resolve()
    stat_result = resolved.stat()
    category = android_app_data_category(path)
    details = {
        "parser": "android-app-data-export",
        "parser_version": PARSER_VERSION,
        "source_path": str(resolved),
        "source_format": "android-export-file",
        "source_size": stat_result.st_size,
        "source_mtime": stat_result.st_mtime,
        "hashes": compute_hashes(resolved),
        "package": package,
        "data_category": category,
        "risk_flags": android_app_data_risk_flags(path, category),
        "validation_checks": {
            "package_inferred_from_path": True,
            "file_payload_parsed": False,
            "secret_values_extracted": False,
            "source_hash_present": True,
            "app_specific_schema_version_tracked": True,
        },
        "app_schema_profile": {
            "package": package,
            "data_category": category,
            "known_schema_validated": False,
            "schema_version": "unknown-exported-file",
        },
        "android_validation_matrix": android_validation_matrix(
            {
                "valid_zip": True,
                "manifest_decoded": False,
                "package_inferred_from_path": True,
                "source_hash_present": True,
                "app_specific_database_decoded": False,
                "commercial_validation_corpus": False,
            }
        ),
        "android_report_grade_assessment": android_report_grade_assessment(["#29", "#30"]),
        "android_native_capabilities": dict(ANDROID_NATIVE_CAPABILITIES),
        "forensic_review": android_forensic_review(
            gap_ids=["#29", "#30"],
            artifact_goal="Android backup/export app-data file inventory and package attribution",
            primary_evidence=[
                f"package={package}",
                f"category={category}",
                f"entry_name={resolved.name}",
                f"source_size={stat_result.st_size}",
            ],
        ),
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#29", "#30"],
        "commercial_grade_blockers": [
            "Android app data is inventoried from exported files only; app-specific database schemas are not decoded here.",
            "Encrypted stores, deleted records, and credential/cookie contents are intentionally not extracted.",
            "Package/path attribution must be verified against acquisition logs and original filesystem metadata.",
        ],
        "legal_warning": "Inventory only. Do not infer app message/account contents from this row without authorized, validated app-specific parsing.",
    }
    details["core_accuracy_gates"] = [
        *android_core_accuracy_gates(29, details),
        *android_core_accuracy_gates(30, details),
    ]
    details["commercial_uplift_evidence"] = android_commercial_uplift_evidence(details, gap_ids=[29, 30])
    return ArtifactRecord(
        provider=AndroidApkProvider.name,
        artifact_type="android-app-data",
        path=str(resolved),
        supported=True,
        details=details,
    )


def package_from_android_data_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    for marker in (("android", "data"), ("android", "media"), ("data", "data")):
        for index in range(0, len(parts) - len(marker)):
            if tuple(lowered[index : index + len(marker)]) == marker:
                candidate_index = index + len(marker)
                if candidate_index < len(parts):
                    candidate = parts[candidate_index]
                    if looks_like_android_package(candidate):
                        return candidate
    return ""


def looks_like_android_package(value: str) -> bool:
    return "." in value and all(part and part.replace("_", "").isalnum() for part in value.split("."))


def android_app_data_category(path: Path) -> str:
    lowered = str(path).lower()
    if lowered.endswith((".db", ".sqlite", ".sqlite3")):
        return "database"
    if any(token in lowered for token in ("shared_prefs", ".xml", ".json", ".plist")):
        return "configuration"
    if any(token in lowered for token in ("cache", "tmp")):
        return "cache"
    if any(token in lowered for token in ("media", "image", "video", "audio", ".jpg", ".png", ".mp4", ".m4a")):
        return "media"
    return "file"


def android_app_data_risk_flags(path: Path, category: str) -> list[str]:
    lowered = str(path).lower()
    flags = ["android-app-data-export", f"android-app-data-{category}"]
    if any(token in lowered for token in ("shared_prefs", "account", "cookie", "token", "credential", "key")):
        flags.append("sensitive-store-candidate")
    if any(token in lowered for token in ("sms", "call", "contact", "message", "chat")):
        flags.append("communication-store-candidate")
    if any(token in lowered for token in ("browser", "history", "url", "chrome", "firefox", "safari")):
        flags.append("browser-store-candidate")
    if any(token in lowered for token in ("media", "image", "video", "audio", "attachment")):
        flags.append("media-store-candidate")
    if category == "database":
        flags.append("structured-data-file")
    return flags


def apk_entry_hashes(archive: zipfile.ZipFile, entries: list[str]) -> list[dict[str, object]]:
    hashes: list[dict[str, object]] = []
    for entry in entries[:75]:
        try:
            blob = archive.read(entry)
        except (KeyError, OSError, zipfile.BadZipFile):
            continue
        hashes.append(
            {
                "entry": entry,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
        )
    return hashes


def native_architectures(native_libraries: list[str]) -> list[str]:
    architectures = set()
    for entry in native_libraries:
        parts = entry.split("/")
        if len(parts) >= 3 and parts[0] == "lib":
            architectures.add(parts[1])
    return sorted(architectures)


def apk_validation_checks(
    names: list[str],
    manifest: dict[str, object],
    permissions: list[str],
    dex_entries: list[str],
    certificate_entries: list[str],
) -> dict[str, object]:
    components = manifest.get("component_counts")
    return {
        "valid_zip": True,
        "manifest_present": "AndroidManifest.xml" in names,
        "manifest_decoded": manifest.get("manifest_format") == "xml",
        "package_present": bool(manifest.get("package")),
        "dex_present": bool(dex_entries),
        "certificate_entry_present": bool(certificate_entries),
        "permission_count": len(permissions),
        "component_counts": components if isinstance(components, dict) else {},
        "binary_manifest_decoder_available": False,
        "commercial_validation_corpus": False,
    }


def android_validation_matrix(checks: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "id": "source-readable",
            "label": "APK/export source is readable and hashed",
            "passed": bool(checks.get("valid_zip", True) or checks.get("source_hash_present")),
            "severity": "critical",
        },
        {
            "id": "manifest-or-package-context",
            "label": "Package or manifest context is available",
            "passed": bool(checks.get("manifest_decoded") or checks.get("package_present") or checks.get("package_inferred_from_path")),
            "severity": "high",
        },
        {
            "id": "payload-inventory",
            "label": "Executable/app-data payload is inventoried",
            "passed": bool(checks.get("dex_present") or checks.get("file_payload_parsed") is False),
            "severity": "medium",
        },
        {
            "id": "signature-and-binary-manifest",
            "label": "Binary manifest and signature/certificate chain are validated",
            "passed": bool(checks.get("binary_manifest_decoder_available")) and bool(checks.get("certificate_entry_present")),
            "severity": "critical",
        },
        {
            "id": "app-data-report-grade",
            "label": "App databases, encrypted stores, and deleted records are decoded with known-answer validation",
            "passed": bool(checks.get("app_specific_database_decoded")) and bool(checks.get("commercial_validation_corpus")),
            "severity": "critical",
        },
    ]


def android_commercial_uplift_evidence(details: dict[str, object], *, gap_ids: list[int]) -> dict[str, object]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    matrix = details.get("android_validation_matrix")
    if not isinstance(matrix, list):
        matrix = android_validation_matrix(checks)
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    objectives = {
        29: "Expose Android backup/app-data package attribution, source hashing, category risk flags, and encrypted-store/app-schema blockers.",
        30: "Expose Android APK package metadata, permission/component inventory, DEX/native string pivots, and signature/binary-manifest blockers.",
    }
    passed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, dict) and item.get("passed")
    ]
    failed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, dict) and not item.get("passed")
    ]
    return {
        "batch_id": "commercial-uplift-026-030",
        "item_numbers": sorted(gap_ids),
        "implementation_track": "android-app-and-backup-validation",
        "objective": " ".join(objectives[number] for number in sorted(gap_ids) if number in objectives),
        "reportability_decision": android_reportability_decision(
            details,
            gap_ids=sorted(gap_ids),
            checks=checks,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
        ),
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_format:{details.get('source_format', '')}",
            f"package:{details.get('package', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
        ],
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "commercial_blockers": list(ANDROID_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "apk_string_scan_limit": APK_STRING_SCAN_LIMIT,
            "max_app_data_files": MAX_APP_DATA_FILES,
            "source_size": int(details.get("source_size") or 0),
            "dex_count": int(details.get("dex_count") or 0),
            "native_library_count": int(details.get("native_library_count") or 0),
            "secret_values_extracted": bool(checks.get("secret_values_extracted")),
            "known_answer_android_corpus_required": True,
        },
        "next_internal_step": "Add binary AndroidManifest decoding, signature-chain verification, app-specific schema decoders, and Android known-answer validation.",
        "external_evidence_required": True,
    }


def android_reportability_decision(
    details: dict[str, object],
    *,
    gap_ids: list[int],
    checks: dict[str, object],
    failed_validation_matrix_ids: list[str],
) -> dict[str, object]:
    blockers = set(ANDROID_REPORT_GRADE_BLOCKERS)
    if "signature-and-binary-manifest" in failed_validation_matrix_ids:
        blockers.add("binary-manifest-or-signature-not-validated")
    if "app-data-report-grade" in failed_validation_matrix_ids:
        blockers.add("app-data-schema-or-deleted-record-validation-missing")
    if not checks.get("commercial_validation_corpus"):
        blockers.add("known-answer-android-corpus-not-attached")
    if not checks.get("binary_manifest_decoder_available"):
        blockers.add("binary-android-manifest-decoder-not-available")
    if not checks.get("secret_values_extracted", False):
        blockers.add("secret-values-not-extracted-in-inventory-mode")
    primary = gap_ids[0] if gap_ids else 30
    return {
        "profile_version": "android-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}" for number in gap_ids],
        "decision": (
            "do-not-report-android-app-data-as-decoded-content"
            if primary == 29
            else "do-not-report-android-apk-as-malware-or-signature-validated"
        ),
        "allowed_use": (
            "android-app-data-inventory-triage-pivot"
            if primary == 29
            else "android-apk-risk-inventory-triage-pivot"
        ),
        "blockers": sorted(blockers),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "package": str(details.get("package") or ""),
        "source_format": str(details.get("source_format") or ""),
        "secret_values_redacted_by_default": not bool(checks.get("secret_values_extracted")),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate binary AndroidManifest parsing and package identity against known-good APKs",
            "verify signature/certificate chain and signing lineage with trusted Android tooling",
            "decode app-specific databases with schema-version fixtures before claiming content",
            "validate malware or behavior conclusions with dedicated mobile/malware-analysis tooling",
        ],
    }


def android_report_grade_assessment(gap_ids: list[str]) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": list(gap_ids),
        "blockers": list(ANDROID_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Validate APK/app-data findings with Android-specific mobile forensic or malware-analysis tooling.",
            "Preserve acquisition/export logs, package source, signature data, and app version context before reporting.",
        ],
    }


def android_core_accuracy_gates(number: int, details: dict[str, object]) -> list[dict[str, object]]:
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"package:{details.get('package', '')}",
        f"source_format:{details.get('source_format', '')}",
    ]
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    satisfied: list[str] = []
    if number == 29:
        if details.get("package") and details.get("source_path"):
            satisfied.append("package/path attribution")
        if any(flag in risk_flags for flag in ("communication-store-candidate", "android-app-data-database")):
            satisfied.append("SMS/call/contact row validation")
        if any(flag in risk_flags for flag in ("browser-store-candidate", "media-store-candidate")):
            satisfied.append("browser/media source linkage")
        if not validation.get("secret_values_extracted") and details.get("commercial_grade_blockers"):
            satisfied.append("encrypted-store limitation")
        if details.get("app_schema_profile") or validation.get("app_specific_schema_version_tracked"):
            satisfied.append("app-specific schema version tracking")
    elif number == 30:
        if details.get("manifest_format") or not details.get("android_native_capabilities", {}).get("binary_manifest_decode", True):
            satisfied.append("binary manifest decode or limitation")
        if details.get("permissions") is not None and details.get("component_counts") is not None:
            satisfied.append("permission/component normalization")
        if details.get("certificate_entries") is not None or not details.get("android_native_capabilities", {}).get("signature_chain_validation", True):
            satisfied.append("signature chain validation")
        if details.get("string_pivots") is not None or details.get("dex_count") is not None or details.get("native_library_count") is not None:
            satisfied.append("DEX/native string pivot bounds")
        if details.get("legal_warning") and details.get("commercial_grade_blockers"):
            satisfied.append("app-data schema and secret-handling warnings")
    return [build_accuracy_gate(number, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def android_forensic_review(
    *,
    gap_ids: list[str],
    artifact_goal: str,
    primary_evidence: list[str],
) -> dict[str, object]:
    return build_forensic_review(
        gap_id=gap_ids[0] if gap_ids else "#30",
        artifact_goal=artifact_goal,
        primary_evidence=primary_evidence,
        validation_required=True,
        report_grade_assessment=android_report_grade_assessment(gap_ids),
        blockers=ANDROID_REPORT_GRADE_BLOCKERS,
        caveats=[
            "Android outputs are triage-grade until binary manifest, signature chain, DEX behavior, and app schema parsing are validated.",
            "Encrypted stores, secrets, and deleted records are not extracted by this parser.",
        ],
    )


def apk_blockers() -> list[str]:
    return [
        "Binary AndroidManifest.xml is not fully decoded without an external validated decoder.",
        "DEX bytecode is scanned for bounded strings only; code flow, packed payloads, and native behavior are not analyzed.",
        "Signature/certificate trust, malware verdicts, and app-specific data schemas require independent validated tooling.",
    ]


def scan_apk_string_pivots(archive: zipfile.ZipFile, entries: list[str]) -> list[dict[str, str]]:
    pivots: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries[:50]:
        try:
            blob = archive.read(entry)[:APK_STRING_SCAN_LIMIT]
        except (KeyError, OSError, zipfile.BadZipFile):
            continue
        text = blob.decode("latin-1", errors="ignore")
        for term in APK_SUSPICIOUS_STRING_TERMS:
            if term.lower() in text.lower():
                add_pivot(pivots, seen, entry, "suspicious-string", term)
        for match in URL_RE.finditer(blob):
            add_pivot(pivots, seen, entry, "url", match.group(0).decode("latin-1", errors="ignore"))
        for match in IP_RE.finditer(blob):
            value = match.group(0).decode("ascii", errors="ignore")
            if valid_ipv4(value):
                add_pivot(pivots, seen, entry, "ip", value)
        if len(pivots) >= 50:
            break
    return pivots[:50]


def add_pivot(
    pivots: list[dict[str, str]],
    seen: set[tuple[str, str, str]],
    entry: str,
    pivot_type: str,
    value: str,
) -> None:
    key = (entry, pivot_type, value)
    if key in seen:
        return
    seen.add(key)
    pivots.append({"entry": entry, "type": pivot_type, "value": value})


def valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def score_risk(
    risk_flags: list[str],
    permissions: list[str],
    native_libraries: list[str],
    dex_entries: list[str],
    string_pivots: list[dict[str, str]],
) -> int:
    score = len(dangerous_permissions(permissions)) * 8
    score += len(risk_flags) * 7
    if native_libraries:
        score += 10
    if len(dex_entries) > 1:
        score += 8
    score += min(20, len(string_pivots) * 3)
    return min(score, 100)
