from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Mapping

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "android-apk-v4"
FUNCTIONAL_EXPANSION_BATCH_ID = "commercial-uplift-051-055"
ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"
APK_STRING_SCAN_LIMIT = 1024 * 1024
MAX_APP_DATA_FILES = 25_000
MAX_ANDROID_SQLITE_TABLES = 80
MAX_ANDROID_SQLITE_COLUMNS = 80
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
ANDROID_TRUSTED_TOOLS = {
    "aleapp",
    "aapt",
    "apkanalyzer",
    "jadx",
    "mobsf",
    "androguard",
    "android studio",
    "vendor export",
}
ANDROID_TRUSTED_DIFF_BLOCKERS = {
    29: "android-artifact-export-trusted-diff-required",
    30: "apk-tool-analysis-trusted-diff-required",
}
ANDROID_APP_DATA_REPORT_GRADE_VALIDATION_PLAN_VERSION = "android-app-data-report-grade-validation-plan-v1"
ANDROID_APP_DATA_REPORT_GRADE_BLOCKERS = [
    "trusted-android-app-data-export-diff-required",
    "android-acquisition-manifest-package-attribution-required",
    "android-backup-payload-decoder-known-answer-required",
    "app-specific-schema-version-fixture-required",
    "encrypted-store-and-deleted-record-validation-required",
    "independent-android-app-data-review-required",
]
ANDROID_QC_PREP_ITEM_NUMBER = 47
ANDROID_QC_PREP_GOAL = (
    "Deepen Android artifact parser for SMS, call log, contacts, browser, media, app DBs, packages, signatures, and permissions."
)
ANDROID_QC_PREP_CONTRACT = {
    "item_number": ANDROID_QC_PREP_ITEM_NUMBER,
    "goal": ANDROID_QC_PREP_GOAL,
    "implemented_outputs": [
        "APK ZIP inventory, manifest text metadata, permissions, components, DEX/native pivots, and signing-entry inventory",
        "Android app-data path/package attribution with SQLite table and artifact-family matrix",
        "SMS/browser/media/app DB candidate detection with secret-value redaction and source viewer locators",
    ],
    "commercial_blockers": [
        "binary AndroidManifest decoder and signature-chain validation",
        "native Android backup payload decoding",
        "app-specific schema fixtures and deleted-record validation",
        "trusted Android export/APK tool diff and known-answer corpus",
    ],
}


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
    details["android_apk_deep_analysis_manifest"] = build_android_apk_deep_analysis_manifest(details)
    details["android_apk_deep_analysis_manifest_hash"] = details["android_apk_deep_analysis_manifest"][
        "manifest_sha256"
    ]
    details["android_parser_manifest"] = build_android_parser_manifest(details)
    details["android_parser_manifest_hash"] = details["android_parser_manifest"]["manifest_sha256"]
    details["core_accuracy_gates"] = android_core_accuracy_gates(30, details)
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
    details["commercial_uplift_evidence"] = android_commercial_uplift_evidence(details, gap_ids=[30])
    details["android_analyst_review_profile"] = build_android_analyst_review_profile(details, gap_ids=["#30"])
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
    signing_inventory = build_apk_signing_inventory(archive, names)
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
    apk_profile = build_apk_analysis_profile(
        names=names,
        manifest=manifest,
        permissions=permissions,
        dex_entries=dex_entries,
        native_libraries=native_libraries,
        certificate_entries=certificate_entries,
        signing_inventory=signing_inventory,
        string_pivots=string_pivots,
    )
    return {
        "valid_zip": True,
        "zip_entry_count": len(names),
        "dex_count": len(dex_entries),
        "dex_entries": dex_entries[:25],
        "native_library_count": len(native_libraries),
        "native_libraries": native_libraries[:25],
        "certificate_entries": certificate_entries[:10],
        "apk_signing_inventory": signing_inventory,
        "entry_hashes": apk_entry_hashes(archive, [*dex_entries[:25], *native_libraries[:25], *certificate_entries[:10]]),
        "native_architectures": native_architectures(native_libraries),
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions(permissions),
        "string_pivots": string_pivots,
        "risk_flags": risk_flags,
        "risk_score": score_risk(risk_flags, permissions, native_libraries, dex_entries, string_pivots),
        "apk_analysis_profile": apk_profile,
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
    app_data_profile = build_android_app_data_profile(path, package, category)
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
        "android_app_data_profile": app_data_profile,
        "validation_checks": {
            "package_inferred_from_path": True,
            "file_payload_parsed": False,
            "secret_values_extracted": False,
            "source_hash_present": True,
            "app_specific_schema_version_tracked": True,
            "sqlite_schema_inventory_present": bool(app_data_profile.get("sqlite_schema_inventory", {}).get("opened_readonly")),
            "sample_values_redacted": True,
            "android_artifact_matrix_present": True,
            "backup_or_filesystem_layout_classified": bool(app_data_profile.get("source_layout_profile")),
        },
        "app_schema_profile": {
            "package": package,
            "data_category": category,
            "known_schema_validated": False,
            "schema_version": "unknown-exported-file",
            "candidate_store_family": app_data_profile["candidate_store_family"],
            "sqlite_table_count": app_data_profile.get("sqlite_schema_inventory", {}).get("table_count", 0),
            "artifact_family_hints": app_data_profile.get("artifact_family_matrix", {}),
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
    details["android_app_data_deep_parser_manifest"] = build_android_app_data_deep_parser_manifest(details)
    details["android_app_data_deep_parser_manifest_hash"] = details["android_app_data_deep_parser_manifest"][
        "manifest_sha256"
    ]
    details["android_parser_manifest"] = build_android_parser_manifest(details)
    details["android_parser_manifest_hash"] = details["android_parser_manifest"]["manifest_sha256"]
    details["android_app_data_report_grade_validation_plan"] = build_android_app_data_report_grade_validation_plan(
        details
    )
    details["android_app_data_report_grade_validation_plan_hash"] = details[
        "android_app_data_report_grade_validation_plan"
    ]["manifest_sha256"]
    details["core_accuracy_gates"] = [
        *android_core_accuracy_gates(29, details),
        *android_core_accuracy_gates(30, details),
    ]
    details["commercial_uplift_evidence"] = android_commercial_uplift_evidence(details, gap_ids=[29, 30])
    details["android_analyst_review_profile"] = build_android_analyst_review_profile(details, gap_ids=["#29", "#30"])
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


def build_android_app_data_profile(path: Path, package: str, category: str) -> dict[str, object]:
    lowered = str(path).lower()
    candidate_family = "other"
    if any(token in lowered for token in ("sms", "message", "chat", "conversation", "whatsapp", "kakao", "telegram", "line")):
        candidate_family = "communication"
    elif any(token in lowered for token in ("browser", "history", "cookie", "webview", "cache")):
        candidate_family = "browser"
    elif any(token in lowered for token in ("media", "image", "video", "audio", "thumb")):
        candidate_family = "media"
    sqlite_header = False
    try:
        sqlite_header = path.read_bytes()[:16] == b"SQLite format 3\x00"
    except OSError:
        sqlite_header = False
    sqlite_inventory = build_android_sqlite_schema_inventory(path) if sqlite_header else {
        "profile_version": "android-sqlite-schema-inventory-v1",
        "opened_readonly": False,
        "table_count": 0,
        "total_row_count": 0,
        "tables": [],
        "values_redacted": True,
        "read_policy": "schema-and-counts-only",
    }
    artifact_family_matrix = build_android_artifact_family_matrix(path, sqlite_inventory)
    return {
        "profile_version": "android-app-data-profile-v1",
        "package": package,
        "relative_path_hint": "/".join(path.parts[-6:]),
        "data_category": category,
        "candidate_store_family": candidate_family,
        "sqlite_header_present": sqlite_header,
        "sqlite_schema_inventory": sqlite_inventory,
        "artifact_family_matrix": artifact_family_matrix,
        "source_layout_profile": build_android_source_layout_profile(path, package),
        "payload_decode_status": "not-decoded",
        "secret_extraction_status": "not-performed",
        "deleted_record_recovery_status": "not-validated",
        "schema_validation_status": "known-answer-required",
        "reporting_status": "inventory-only-validation-required",
        "required_before_report": [
            "validate package/path attribution against Android acquisition or backup manifest",
            "decode only app-specific schemas with versioned known-answer fixtures",
            "compare table/row inventory against ALEAPP/vendor export for the same source",
            "preserve encrypted-store and deleted-record limitations if payload decoding is unavailable",
        ],
    }


def build_android_parser_manifest(details: dict[str, object]) -> dict[str, object]:
    apk_profile = details.get("apk_analysis_profile") if isinstance(details.get("apk_analysis_profile"), dict) else {}
    app_data_profile = (
        details.get("android_app_data_profile") if isinstance(details.get("android_app_data_profile"), dict) else {}
    )
    sqlite_inventory = (
        app_data_profile.get("sqlite_schema_inventory")
        if isinstance(app_data_profile.get("sqlite_schema_inventory"), dict)
        else {}
    )
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    artifact_type = "android-app-data" if details.get("source_format") == "android-export-file" else "android-apk"
    viewer = "android-app-data-inventory" if artifact_type == "android-app-data" else "android-apk-inventory"
    manifest: dict[str, object] = {
        "manifest_version": "android-backup-app-data-parser-manifest-v1",
        "item_number": 54,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "qc_prep_item_number": ANDROID_QC_PREP_ITEM_NUMBER,
        "qc_prep_item_goal": ANDROID_QC_PREP_GOAL,
        "qc_prep_contract": dict(ANDROID_QC_PREP_CONTRACT),
        "artifact_type": artifact_type,
        "source_path": str(details.get("source_path") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_size": int(details.get("source_size") or 0),
        "source_sha256": str(hashes.get("sha256") or ""),
        "package": str(details.get("package") or ""),
        "data_category": str(details.get("data_category") or ""),
        "source_viewer_locator": {
            "viewer": viewer,
            "source_path": str(details.get("source_path") or ""),
            "package": str(details.get("package") or ""),
            "source_format": str(details.get("source_format") or ""),
        },
        "apk_inventory": {
            "manifest_format": str(details.get("manifest_format") or ""),
            "permission_count": len(details.get("permissions") or []) if isinstance(details.get("permissions"), list) else 0,
            "dangerous_permission_count": len(details.get("dangerous_permissions") or [])
            if isinstance(details.get("dangerous_permissions"), list)
            else 0,
            "component_counts": details.get("component_counts") if isinstance(details.get("component_counts"), dict) else {},
            "dex_count": int(details.get("dex_count") or 0),
            "native_library_count": int(details.get("native_library_count") or 0),
            "signing_inventory_present": isinstance(details.get("apk_signing_inventory"), dict),
            "risk_score": int(details.get("risk_score") or 0),
            "analysis_profile_status": apk_profile.get("validation_status", "inventory-only"),
        },
        "app_data_inventory": {
            "candidate_store_family": app_data_profile.get("candidate_store_family", ""),
            "sqlite_opened_readonly": bool(sqlite_inventory.get("opened_readonly")),
            "sqlite_table_count": int(sqlite_inventory.get("table_count") or 0),
            "sqlite_total_row_count": int(sqlite_inventory.get("total_row_count") or 0),
            "values_redacted": bool(sqlite_inventory.get("values_redacted", True)),
            "source_layout": (
                app_data_profile.get("source_layout_profile", {}).get("layout")
                if isinstance(app_data_profile.get("source_layout_profile"), dict)
                else ""
            ),
            "artifact_family_matrix": app_data_profile.get("artifact_family_matrix", {}),
        },
        "secret_and_schema_boundary": {
            "secret_values_extracted": bool(
                details.get("validation_checks", {}).get("secret_values_extracted")
                if isinstance(details.get("validation_checks"), dict)
                else False
            ),
            "encrypted_store_decryption": False,
            "deleted_record_recovery": False,
            "app_specific_schema_validated": bool(
                details.get("validation_checks", {}).get("app_schema_validated")
                if isinstance(details.get("validation_checks"), dict)
                else False
            ),
        },
        "large_data_controls": {
            "apk_string_scan_limit": APK_STRING_SCAN_LIMIT,
            "max_app_data_files": MAX_APP_DATA_FILES,
            "max_android_sqlite_tables": MAX_ANDROID_SQLITE_TABLES,
            "max_android_sqlite_columns": MAX_ANDROID_SQLITE_COLUMNS,
            "raw_values_redacted_by_default": True,
        },
        "commercial_blockers": [
            "android-backup-payload-decoder-required",
            "app-specific-schema-known-answer-required",
            "binary-manifest-and-signature-chain-validation-required",
            "deleted-record-and-encrypted-store-validation-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_android_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_android_app_data_deep_parser_manifest(details: dict[str, object]) -> dict[str, object]:
    app_data_profile = (
        details.get("android_app_data_profile") if isinstance(details.get("android_app_data_profile"), dict) else {}
    )
    sqlite_inventory = (
        app_data_profile.get("sqlite_schema_inventory")
        if isinstance(app_data_profile.get("sqlite_schema_inventory"), dict)
        else {}
    )
    artifact_family_matrix = (
        app_data_profile.get("artifact_family_matrix")
        if isinstance(app_data_profile.get("artifact_family_matrix"), dict)
        else {}
    )
    source_layout = (
        app_data_profile.get("source_layout_profile")
        if isinstance(app_data_profile.get("source_layout_profile"), dict)
        else {}
    )
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    table_summaries: list[dict[str, object]] = []
    for table in sqlite_inventory.get("tables", []) if isinstance(sqlite_inventory.get("tables"), list) else []:
        if not isinstance(table, dict):
            continue
        table_summaries.append(
            {
                "table": str(table.get("table") or ""),
                "row_count": int(table.get("row_count") or 0),
                "column_count": len(table.get("columns") or []) if isinstance(table.get("columns"), list) else 0,
                "columns_sample": list(table.get("columns") or [])[:40] if isinstance(table.get("columns"), list) else [],
                "artifact_family": str(table.get("artifact_family") or "other"),
                "values_redacted": True,
                "row_values_read": False,
            }
        )
    candidate_family_counts: dict[str, int] = {}
    for table in table_summaries:
        family = str(table.get("artifact_family") or "other")
        candidate_family_counts[family] = candidate_family_counts.get(family, 0) + 1
    manifest: dict[str, object] = {
        "manifest_version": "android-app-data-deep-parser-manifest-v1",
        "item_number": 29,
        "gap_id": "#29",
        "artifact_goal": "Android backup/export app-data package attribution, SQLite/table inventory, family classification, and protected-store boundary",
        "parser_version": PARSER_VERSION,
        "source_path": str(details.get("source_path") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_size": int(details.get("source_size") or 0),
        "source_sha256": str(hashes.get("sha256") or ""),
        "package": str(details.get("package") or ""),
        "data_category": str(details.get("data_category") or ""),
        "source_viewer_locator": {
            "viewer": "android-app-data-deep-parser",
            "source_path": str(details.get("source_path") or ""),
            "package": str(details.get("package") or ""),
            "data_category": str(details.get("data_category") or ""),
        },
        "source_layout": {
            "layout": str(source_layout.get("layout") or ""),
            "relative_path_hint": str(source_layout.get("relative_path_hint") or ""),
            "package_path_attribution_status": str(source_layout.get("package_path_attribution_status") or ""),
            "requires_acquisition_manifest": bool(source_layout.get("requires_acquisition_manifest", True)),
        },
        "sqlite_inventory": {
            "sqlite_header_present": bool(app_data_profile.get("sqlite_header_present")),
            "opened_readonly": bool(sqlite_inventory.get("opened_readonly")),
            "table_count": int(sqlite_inventory.get("table_count") or 0),
            "total_row_count": int(sqlite_inventory.get("total_row_count") or 0),
            "values_redacted": bool(sqlite_inventory.get("values_redacted", True)),
            "read_policy": str(sqlite_inventory.get("read_policy") or "schema-and-counts-only"),
            "table_summaries": table_summaries,
            "candidate_family_counts": dict(sorted(candidate_family_counts.items())),
        },
        "artifact_family_matrix": {
            "positive_families": list(artifact_family_matrix.get("positive_families") or []),
            "families": artifact_family_matrix.get("families", {}),
            "classification_basis": str(artifact_family_matrix.get("classification_basis") or "path-table-column-names-only"),
            "content_claim_status": str(artifact_family_matrix.get("content_claim_status") or "not-decoded"),
        },
        "capability_statement": {
            "package_path_attribution": True,
            "sqlite_schema_inventory": bool(sqlite_inventory.get("opened_readonly")),
            "sms_call_contact_browser_media_hinting": True,
            "source_hashing": bool(hashes.get("sha256")),
            "app_specific_database_decode": False,
            "encrypted_store_decryption": False,
            "deleted_record_recovery": False,
            "android_backup_payload_decode": False,
        },
        "redaction_and_secret_boundary": {
            "values_redacted": bool(sqlite_inventory.get("values_redacted", True)),
            "secret_values_extracted": bool(
                details.get("validation_checks", {}).get("secret_values_extracted")
                if isinstance(details.get("validation_checks"), dict)
                else False
            ),
            "row_values_read": False,
            "payload_decode_status": str(app_data_profile.get("payload_decode_status") or "not-decoded"),
            "secret_extraction_status": str(app_data_profile.get("secret_extraction_status") or "not-performed"),
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "package_inferred_from_path": bool(
                details.get("validation_checks", {}).get("package_inferred_from_path")
                if isinstance(details.get("validation_checks"), dict)
                else False
            ),
            "android_artifact_matrix_present": bool(artifact_family_matrix),
            "sqlite_schema_inventory_present": bool(sqlite_inventory.get("opened_readonly")),
            "trusted_android_diff_attached": False,
            "app_specific_schema_known_answer_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "max_app_data_files": MAX_APP_DATA_FILES,
            "max_android_sqlite_tables": MAX_ANDROID_SQLITE_TABLES,
            "max_android_sqlite_columns": MAX_ANDROID_SQLITE_COLUMNS,
            "raw_values_redacted_by_default": True,
        },
        "commercial_blockers": [
            "android-backup-payload-decoder-required",
            "app-specific-schema-known-answer-required",
            "encrypted-store-decryption-validation-required",
            "deleted-record-recovery-known-answer-required",
            "trusted-aleapp-or-vendor-export-diff-required",
        ],
        "reporting_status": "android-app-data-inventory-not-content-decode",
    }
    manifest["manifest_sha256"] = stable_android_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_android_app_data_report_grade_validation_plan(details: dict[str, object]) -> dict[str, object]:
    app_data_profile = (
        details.get("android_app_data_profile") if isinstance(details.get("android_app_data_profile"), dict) else {}
    )
    sqlite_inventory = (
        app_data_profile.get("sqlite_schema_inventory")
        if isinstance(app_data_profile.get("sqlite_schema_inventory"), dict)
        else {}
    )
    artifact_family_matrix = (
        app_data_profile.get("artifact_family_matrix")
        if isinstance(app_data_profile.get("artifact_family_matrix"), dict)
        else {}
    )
    source_layout = (
        app_data_profile.get("source_layout_profile")
        if isinstance(app_data_profile.get("source_layout_profile"), dict)
        else {}
    )
    deep_manifest = (
        details.get("android_app_data_deep_parser_manifest")
        if isinstance(details.get("android_app_data_deep_parser_manifest"), dict)
        else {}
    )
    parser_manifest = (
        details.get("android_parser_manifest") if isinstance(details.get("android_parser_manifest"), dict) else {}
    )
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    source_locator = (
        deep_manifest.get("source_viewer_locator")
        if isinstance(deep_manifest.get("source_viewer_locator"), dict)
        else parser_manifest.get("source_viewer_locator")
        if isinstance(parser_manifest.get("source_viewer_locator"), dict)
        else {}
    )
    source_path = str(details.get("source_path") or "")
    source_sha256 = str(hashes.get("sha256") or "")
    package = str(details.get("package") or "")
    sqlite_opened = bool(sqlite_inventory.get("opened_readonly"))
    values_redacted = bool(sqlite_inventory.get("values_redacted", True))
    secret_values_extracted = bool(validation_checks.get("secret_values_extracted"))
    positive_families = list(artifact_family_matrix.get("positive_families") or [])
    evidence_slots = [
        {
            "id": "source-app-data-integrity",
            "label": "Source app-data file hash and size are fixed before reporting",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [f"source_sha256:{source_sha256}", f"source_path:{source_path}"],
        },
        {
            "id": "package-path-attribution",
            "label": "Package identity is derived from Android/data, Android/media, or data/data layout",
            "status": "complete" if package and source_layout else "review-required",
            "blocking": not bool(package and source_layout),
            "evidence_refs": [
                f"package:{package}",
                f"source_layout:{source_layout.get('layout', '')}",
                f"relative_path_hint:{source_layout.get('relative_path_hint', '')}",
            ],
        },
        {
            "id": "read-only-sqlite-schema-inventory",
            "label": "SQLite app DB candidates are opened read-only for schema and counts only",
            "status": "complete" if sqlite_opened else "not-applicable-or-not-sqlite",
            "blocking": False,
            "evidence_refs": [
                f"sqlite_opened_readonly:{sqlite_opened}",
                f"sqlite_table_count:{sqlite_inventory.get('table_count', 0)}",
                f"sqlite_total_row_count:{sqlite_inventory.get('total_row_count', 0)}",
            ],
        },
        {
            "id": "artifact-family-matrix",
            "label": "SMS, call, contact, browser, media, and app DB hints are classified without row values",
            "status": "complete" if artifact_family_matrix else "missing-family-matrix",
            "blocking": not bool(artifact_family_matrix),
            "evidence_refs": [f"positive_families:{','.join(map(str, positive_families))}"],
        },
        {
            "id": "redaction-policy-enforced",
            "label": "Row values, credentials, cookies, and secrets are not extracted in inventory mode",
            "status": "complete" if values_redacted and not secret_values_extracted else "failed-redaction-boundary",
            "blocking": not (values_redacted and not secret_values_extracted),
            "evidence_refs": [
                f"values_redacted:{values_redacted}",
                f"secret_values_extracted:{secret_values_extracted}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can jump back to the source file and package context",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '')}" if isinstance(source_locator, dict) else "viewer:",
                f"manifest_sha256:{deep_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "acquisition-manifest-package-attribution",
            "label": "Package/path attribution is checked against acquisition manifest or vendor export metadata",
            "status": "pending-external-acquisition-log",
            "blocking": True,
            "evidence_refs": ["expected_tooling:Android acquisition manifest,Cellebrite/XRY/GrayKey/AXIOM,ALEAPP"],
        },
        {
            "id": "trusted-android-app-data-export-diff",
            "label": "RapidTriage app-data inventory is diffed against ALEAPP or vendor Android export rows",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 29"],
        },
        {
            "id": "app-specific-schema-known-answer",
            "label": "App DB schemas and version-specific table semantics are validated with known-answer fixtures",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:app-specific schema fixture corpus"],
        },
        {
            "id": "encrypted-store-and-deleted-record-validation",
            "label": "Encrypted stores and deleted rows are validated before decoded-content claims",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:encrypted/deleted Android store known-answer corpus"],
        },
        {
            "id": "independent-android-app-data-review",
            "label": "Independent reviewer signs off on package attribution, schema limits, and trusted diffs",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent review report"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
        or str(slot.get("status")) == "not-applicable-or-not-sqlite"
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": ANDROID_APP_DATA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 29,
        "gap_id": "#29",
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "Android backup/export app, file, SMS, call, contact, browser, media, and app DB evidence validation",
        "source_path": source_path,
        "source_format": str(details.get("source_format") or ""),
        "source_sha256": source_sha256,
        "package": package,
        "data_category": str(details.get("data_category") or ""),
        "validation_commands": [
            {
                "id": "source-app-data-manifest",
                "purpose": "Freeze source file hashes and acquisition/package path metadata",
                "command": "rapidtriage manifest <android-export-root> --output <case>/android-source-manifest.json",
            },
            {
                "id": "android-app-data-inventory-import",
                "purpose": "Recreate RapidTriage Android app-data inventory",
                "command": "rapidtriage artifacts <android-export-root> --kind android-apk --output <case>/android-app-data.json",
            },
            {
                "id": "trusted-android-app-data-export-diff",
                "purpose": "Compare package/path/category/hash rows with ALEAPP or vendor Android export output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/android-app-data.json --reference-output aleapp=<trusted-android-export.json> --backlog-item 29 --json",
            },
            {
                "id": "app-schema-fixture-run",
                "purpose": "Attach version-specific app DB known-answer fixtures before decoded-content claims",
                "command": "rapidtriage commercial-readiness --validation-package <android-app-schema-known-answer.json> --limit 30 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(ANDROID_APP_DATA_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use #29 rows as package/path/schema inventory pivots only until acquisition metadata, trusted diffs, app-schema fixtures, encrypted/deleted-store validation, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_android_json_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def build_android_apk_deep_analysis_manifest(details: dict[str, object]) -> dict[str, object]:
    apk_profile = details.get("apk_analysis_profile") if isinstance(details.get("apk_analysis_profile"), dict) else {}
    signing_inventory = (
        details.get("apk_signing_inventory") if isinstance(details.get("apk_signing_inventory"), dict) else {}
    )
    hashes = details.get("hashes") if isinstance(details.get("hashes"), dict) else {}
    string_pivots = details.get("string_pivots") if isinstance(details.get("string_pivots"), list) else []
    pivot_counts: dict[str, int] = {}
    for pivot in string_pivots:
        if isinstance(pivot, dict):
            pivot_type = str(pivot.get("type") or "")
            if pivot_type:
                pivot_counts[pivot_type] = pivot_counts.get(pivot_type, 0) + 1
    manifest: dict[str, object] = {
        "manifest_version": "android-apk-deep-analysis-manifest-v1",
        "item_number": 30,
        "gap_id": "#30",
        "artifact_goal": "Android APK manifest, permission, component, DEX/native, signing inventory, and risk-pivot evidence",
        "parser_version": PARSER_VERSION,
        "source_path": str(details.get("source_path") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_size": int(details.get("source_size") or 0),
        "source_sha256": str(hashes.get("sha256") or ""),
        "package": str(details.get("package") or ""),
        "version_name": str(details.get("version_name") or ""),
        "source_viewer_locator": {
            "viewer": "android-apk-deep-analysis",
            "source_path": str(details.get("source_path") or ""),
            "package": str(details.get("package") or ""),
        },
        "manifest_inventory": {
            "manifest_format": str(details.get("manifest_format") or ""),
            "package_present": bool(details.get("package")),
            "version_name": str(details.get("version_name") or ""),
            "version_code": str(details.get("version_code") or ""),
            "binary_manifest_decode_status": str(apk_profile.get("binary_manifest_decode_status") or "not-decoded"),
            "permission_count": len(details.get("permissions") or []) if isinstance(details.get("permissions"), list) else 0,
            "dangerous_permission_count": len(details.get("dangerous_permissions") or [])
            if isinstance(details.get("dangerous_permissions"), list)
            else 0,
            "dangerous_permissions": list(details.get("dangerous_permissions") or [])[:50]
            if isinstance(details.get("dangerous_permissions"), list)
            else [],
            "component_counts": details.get("component_counts") if isinstance(details.get("component_counts"), dict) else {},
        },
        "code_inventory": {
            "dex_count": int(details.get("dex_count") or 0),
            "dex_entries": list(details.get("dex_entries") or [])[:50] if isinstance(details.get("dex_entries"), list) else [],
            "native_library_count": int(details.get("native_library_count") or 0),
            "native_architectures": list(details.get("native_architectures") or [])
            if isinstance(details.get("native_architectures"), list)
            else [],
            "native_libraries": list(details.get("native_libraries") or [])[:50]
            if isinstance(details.get("native_libraries"), list)
            else [],
            "dex_control_flow_status": str(apk_profile.get("dex_control_flow_status") or "not-performed"),
        },
        "signing_inventory": {
            "entry_count": int(signing_inventory.get("entry_count") or 0),
            "entry_types": list(signing_inventory.get("entry_types") or []),
            "signature_block_present": bool(signing_inventory.get("signature_block_present")),
            "signature_file_present": bool(signing_inventory.get("signature_file_present")),
            "jar_manifest_present": bool(signing_inventory.get("jar_manifest_present")),
            "certificate_chain_parsed": bool(signing_inventory.get("certificate_chain_parsed")),
            "signer_lineage_verified": bool(signing_inventory.get("signer_lineage_verified")),
            "validation_status": str(signing_inventory.get("validation_status") or "review-required"),
        },
        "string_pivots": {
            "scan_limit_bytes": APK_STRING_SCAN_LIMIT,
            "pivot_count": len(string_pivots),
            "pivot_counts": dict(sorted(pivot_counts.items())),
            "pivot_sample": [
                {
                    "type": str(pivot.get("type") or ""),
                    "value": str(pivot.get("value") or ""),
                    "entry": str(pivot.get("entry") or ""),
                }
                for pivot in string_pivots[:50]
                if isinstance(pivot, dict)
            ],
        },
        "risk_and_reportability": {
            "risk_score": int(details.get("risk_score") or 0),
            "risk_flags": list(details.get("risk_flags") or []) if isinstance(details.get("risk_flags"), list) else [],
            "malware_verdict": "not-assessed",
            "trust_verdict": "not-assessed",
            "allowed_use": "android-apk-risk-inventory-triage-pivot",
        },
        "capability_statement": {
            "apk_zip_inventory": True,
            "text_manifest_decode": bool(details.get("manifest_format") == "xml"),
            "permission_component_inventory": True,
            "dex_native_library_string_pivots": True,
            "signing_entry_inventory": bool(signing_inventory),
            "binary_manifest_decode": bool(
                details.get("android_native_capabilities", {}).get("binary_manifest_decode")
                if isinstance(details.get("android_native_capabilities"), dict)
                else False
            ),
            "signature_chain_validation": False,
            "dex_control_flow_analysis": False,
            "malware_behavior_validation": False,
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "valid_zip": bool(details.get("valid_zip", True)),
            "manifest_or_package_context": bool(details.get("package") or details.get("manifest_format")),
            "string_pivots_bounded": True,
            "trusted_apk_tool_diff_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "apk_string_scan_limit": APK_STRING_SCAN_LIMIT,
            "entry_hash_sample_bounded": True,
            "dex_native_sample_bounded": True,
            "raw_values_redacted_by_default": True,
        },
        "commercial_blockers": [
            "binary-android-manifest-decoder-required",
            "signature-chain-and-lineage-validation-required",
            "dex-control-flow-analysis-required",
            "malware-behavior-known-answer-required",
            "trusted-aapt-apkanalyzer-mobsf-diff-required",
        ],
        "reporting_status": "android-apk-risk-inventory-not-malware-verdict",
    }
    manifest["manifest_sha256"] = stable_android_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_android_json_sha256(value: dict[str, object] | list[object] | str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def build_android_source_layout_profile(path: Path, package: str) -> dict[str, object]:
    parts = list(path.parts)
    lowered = [part.lower() for part in parts]
    layout = "unknown-export-layout"
    for marker, label in (
        (("android", "data"), "external-app-data"),
        (("android", "media"), "external-app-media"),
        (("data", "data"), "private-app-data"),
    ):
        for index in range(0, len(parts) - len(marker)):
            if tuple(lowered[index : index + len(marker)]) == marker:
                layout = label
                break
        if layout != "unknown-export-layout":
            break
    if "backup" in lowered or "apps" in lowered:
        layout = f"{layout}+backup-export-hint" if layout != "unknown-export-layout" else "backup-export-hint"
    return {
        "profile_version": "android-source-layout-v1",
        "layout": layout,
        "package": package,
        "package_path_attribution_status": "path-derived-review-required",
        "relative_path_hint": "/".join(path.parts[-8:]),
        "requires_acquisition_manifest": True,
    }


def build_android_sqlite_schema_inventory(path: Path) -> dict[str, object]:
    tables: list[dict[str, object]] = []
    opened = False
    error = ""
    try:
        with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            opened = True
            for table_name in android_sqlite_table_names(connection)[:MAX_ANDROID_SQLITE_TABLES]:
                columns = android_sqlite_columns(connection, table_name)[:MAX_ANDROID_SQLITE_COLUMNS]
                tables.append(
                    {
                        "table": table_name,
                        "row_count": android_sqlite_row_count(connection, table_name),
                        "columns": columns,
                        "artifact_family": android_table_artifact_family(table_name, columns),
                    }
                )
    except sqlite3.Error as exc:
        error = str(exc)[:240]
    total_rows = sum(int(table.get("row_count") or 0) for table in tables)
    return {
        "profile_version": "android-sqlite-schema-inventory-v1",
        "opened_readonly": opened,
        "table_count": len(tables),
        "total_row_count": total_rows,
        "tables": tables[:MAX_ANDROID_SQLITE_TABLES],
        "values_redacted": True,
        "read_policy": "schema-and-counts-only",
        "sqlite_error": error,
        "validation_status": "inventory-ready" if opened else "review-required",
    }


def build_android_artifact_family_matrix(path: Path, sqlite_inventory: dict[str, object]) -> dict[str, object]:
    haystack = " ".join(
        [
            str(path).lower(),
            *[
                f"{table.get('table', '')} {' '.join(str(column) for column in table.get('columns', []))}".lower()
                for table in sqlite_inventory.get("tables", [])
                if isinstance(table, dict)
            ],
        ]
    )
    families = {
        "sms": any(token in haystack for token in ("sms", "mms", "message", "thread")),
        "call_log": any(token in haystack for token in ("call", "calls", "calllog")),
        "contacts": any(token in haystack for token in ("contact", "contacts", "phonebook", "addr")),
        "browser": any(token in haystack for token in ("browser", "history", "cookie", "webview", "url")),
        "media": any(token in haystack for token in ("media", "image", "video", "audio", "thumbnail")),
        "app_database": bool(sqlite_inventory.get("opened_readonly")),
    }
    return {
        "profile_version": "android-artifact-family-matrix-v1",
        "families": families,
        "positive_families": [family for family, present in sorted(families.items()) if present],
        "classification_basis": "path-table-column-names-only",
        "values_redacted": True,
        "content_claim_status": "not-decoded",
    }


def android_table_artifact_family(table_name: str, columns: list[str]) -> str:
    haystack = f"{table_name} {' '.join(columns)}".lower()
    if any(token in haystack for token in ("sms", "mms", "message", "thread", "chat", "conversation")):
        return "message-or-chat"
    if any(token in haystack for token in ("call", "calllog")):
        return "call-log"
    if any(token in haystack for token in ("contact", "phone", "addressbook", "addr")):
        return "contacts"
    if any(token in haystack for token in ("browser", "history", "cookie", "url", "webview")):
        return "browser"
    if any(token in haystack for token in ("media", "image", "video", "audio", "thumbnail")):
        return "media"
    if any(token in haystack for token in ("account", "token", "password", "secret", "credential")):
        return "credential-or-account"
    return "other"


def android_sqlite_table_names(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(row[0]) for row in rows]


def android_sqlite_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    safe_name = table_name.replace('"', '""')
    rows = connection.execute(f'PRAGMA table_info("{safe_name}")').fetchall()
    return [str(row[1]) for row in rows]


def android_sqlite_row_count(connection: sqlite3.Connection, table_name: str) -> int | None:
    safe_name = table_name.replace('"', '""')
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{safe_name}"').fetchone()
    except sqlite3.Error:
        return None
    return int(row[0]) if row else None


def build_apk_analysis_profile(
    *,
    names: list[str],
    manifest: dict[str, object],
    permissions: list[str],
    dex_entries: list[str],
    native_libraries: list[str],
    certificate_entries: list[str],
    signing_inventory: dict[str, object],
    string_pivots: list[dict[str, str]],
) -> dict[str, object]:
    pivot_counts: dict[str, int] = {}
    for pivot in string_pivots:
        pivot_type = str(pivot.get("type") or "")
        pivot_counts[pivot_type] = pivot_counts.get(pivot_type, 0) + 1
    return {
        "profile_version": "apk-analysis-profile-v1",
        "zip_entry_count": len(names),
        "manifest_format": str(manifest.get("manifest_format") or ""),
        "package": str(manifest.get("package") or ""),
        "permission_count": len(permissions),
        "dangerous_permission_count": len(dangerous_permissions(permissions)),
        "dex_count": len(dex_entries),
        "native_library_count": len(native_libraries),
        "certificate_entry_count": len(certificate_entries),
        "signing_block_entry_count": int(signing_inventory.get("entry_count") or 0),
        "signing_inventory_status": str(signing_inventory.get("validation_status") or "review-required"),
        "string_pivot_counts": dict(sorted(pivot_counts.items())),
        "binary_manifest_decode_status": "decoded" if manifest.get("manifest_format") == "xml" else "not-decoded",
        "signature_chain_validation_status": "signature-entry-inventory-only",
        "dex_control_flow_status": "not-performed",
        "reporting_status": "apk-risk-inventory-validation-required",
    }


def build_android_trusted_diff(
    number: int,
    rapid_rows: list[dict[str, object]],
    trusted_rows: list[dict[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = ANDROID_TRUSTED_DIFF_BLOCKERS.get(number, "android-trusted-diff-required")
    rapid_index = index_android_trusted_rows(rapid_rows)
    trusted_index = index_android_trusted_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in ANDROID_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        "android_row_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "android-trusted-diff-v1",
        "gap_id": f"#{number}",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-android-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_android_trusted_rows(rows: list[dict[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        package = normalized_android_diff_value(first_android_alias(row, "package", "package_name", "application_id"))
        source_path = normalized_android_diff_value(first_android_alias(row, "source_path", "path", "file_path"))
        data_category = normalized_android_diff_value(first_android_alias(row, "data_category", "category"))
        manifest_format = normalized_android_diff_value(first_android_alias(row, "manifest_format", "manifest"))
        permission_count = normalized_android_diff_value(first_android_alias(row, "permission_count", "permissions"))
        component_count = normalized_android_diff_value(first_android_alias(row, "component_count", "components"))
        dex_count = normalized_android_diff_value(first_android_alias(row, "dex_count"))
        native_library_count = normalized_android_diff_value(first_android_alias(row, "native_library_count", "native_libraries"))
        source_sha256 = normalized_android_diff_value(first_android_alias(row, "source_sha256", "sha256"))
        key = "|".join(item for item in (package, source_path, data_category, manifest_format) if item)
        if not key:
            continue
        indexed[key] = {
            "package": package,
            "source_path": source_path,
            "data_category": data_category,
            "manifest_format": manifest_format,
            "permission_count": permission_count,
            "component_count": component_count,
            "dex_count": dex_count,
            "native_library_count": native_library_count,
            "source_sha256": source_sha256,
        }
    return indexed


def first_android_alias(row: dict[str, object], *aliases: str) -> object:
    normalized = {normalize_android_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_android_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_android_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_android_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


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


def build_apk_signing_inventory(archive: zipfile.ZipFile, names: list[str]) -> dict[str, object]:
    signing_entries = sorted(
        name
        for name in names
        if name.startswith("META-INF/")
        and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF", "MANIFEST.MF"))
    )
    entry_profiles: list[dict[str, object]] = []
    for entry in signing_entries[:25]:
        try:
            blob = archive.read(entry)
        except (KeyError, OSError, zipfile.BadZipFile):
            continue
        upper = entry.upper()
        if upper.endswith((".RSA", ".DSA", ".EC")):
            entry_type = "signature-block"
        elif upper.endswith(".SF"):
            entry_type = "signature-file"
        elif upper.endswith("MANIFEST.MF"):
            entry_type = "jar-manifest"
        else:
            entry_type = "other-meta-inf"
        entry_profiles.append(
            {
                "entry": entry,
                "entry_type": entry_type,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
        )
    entry_types = sorted({str(profile.get("entry_type")) for profile in entry_profiles})
    return {
        "profile_version": "apk-signing-inventory-v1",
        "entry_count": len(entry_profiles),
        "entry_types": entry_types,
        "entries": entry_profiles,
        "signature_block_present": any(profile.get("entry_type") == "signature-block" for profile in entry_profiles),
        "signature_file_present": any(profile.get("entry_type") == "signature-file" for profile in entry_profiles),
        "jar_manifest_present": any(profile.get("entry_type") == "jar-manifest" for profile in entry_profiles),
        "certificate_chain_parsed": False,
        "signer_lineage_verified": False,
        "validation_status": "entry-inventory-ready" if entry_profiles else "missing-or-v2-v3-only-review-required",
        "required_before_report": [
            "verify signer certificate chain and APK signing scheme with apksigner or apkanalyzer",
            "compare signer digest, certificate subject, and signing lineage against trusted tool output",
            "do not infer APK trust or malware status from META-INF entry presence alone",
        ],
    }


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
    trusted_diff = (
        details.get("android_trusted_diff")
        if isinstance(details.get("android_trusted_diff"), dict)
        else {"status": "not-attached", "commercial_grade_evidence": False}
    )
    android_manifest = details.get("android_parser_manifest") if isinstance(details.get("android_parser_manifest"), dict) else {}
    app_data_deep_manifest = (
        details.get("android_app_data_deep_parser_manifest")
        if isinstance(details.get("android_app_data_deep_parser_manifest"), dict)
        else {}
    )
    apk_deep_manifest = (
        details.get("android_apk_deep_analysis_manifest")
        if isinstance(details.get("android_apk_deep_analysis_manifest"), dict)
        else {}
    )
    app_data_validation_plan = (
        details.get("android_app_data_report_grade_validation_plan")
        if isinstance(details.get("android_app_data_report_grade_validation_plan"), dict)
        else {}
    )
    return {
        "batch_id": "commercial-uplift-026-030",
        "item_numbers": sorted(gap_ids),
        "qc_prep_item_numbers": [ANDROID_QC_PREP_ITEM_NUMBER],
        "qc_prep_contracts": [dict(ANDROID_QC_PREP_CONTRACT)],
        "implementation_track": "android-app-and-backup-validation",
        "objective": " ".join(objectives[number] for number in sorted(gap_ids) if number in objectives),
        "reportability_decision": android_reportability_decision(
            details,
            gap_ids=sorted(gap_ids),
            checks=checks,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
            trusted_diff=trusted_diff,
        ),
        "android_trusted_diff": trusted_diff,
        "functional_priority_profiles": android_functional_expansion_profiles(
            details,
            gap_ids=sorted(gap_ids),
            checks=checks,
            hashes=hashes,
            trusted_diff=trusted_diff,
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
            "apk_profile_present": isinstance(details.get("apk_analysis_profile"), dict),
            "android_app_data_profile_present": isinstance(details.get("android_app_data_profile"), dict),
            "android_parser_manifest_hash": str(android_manifest.get("manifest_sha256") or ""),
            "android_source_locator_present": isinstance(android_manifest.get("source_viewer_locator"), dict),
            "android_app_data_deep_parser_manifest_hash": str(app_data_deep_manifest.get("manifest_sha256") or ""),
            "android_app_data_deep_parser_source_locator_present": isinstance(
                app_data_deep_manifest.get("source_viewer_locator"), dict
            ),
            "android_app_data_report_grade_validation_plan_hash": str(
                app_data_validation_plan.get("manifest_sha256") or ""
            ),
            "android_app_data_report_grade_validation_ready_slot_count": int(
                app_data_validation_plan.get("ready_slot_count") or 0
            ),
            "android_app_data_report_grade_validation_blocking_slot_count": int(
                app_data_validation_plan.get("blocking_slot_count") or 0
            ),
            "android_apk_deep_analysis_manifest_hash": str(apk_deep_manifest.get("manifest_sha256") or ""),
            "android_apk_deep_analysis_source_locator_present": isinstance(
                apk_deep_manifest.get("source_viewer_locator"), dict
            ),
            "secret_values_extracted": bool(checks.get("secret_values_extracted")),
            "known_answer_android_corpus_required": True,
        },
        "next_internal_step": "Add binary AndroidManifest decoding, signature-chain verification, app-specific schema decoders, and Android known-answer validation.",
        "external_evidence_required": True,
    }


def android_functional_expansion_profiles(
    details: dict[str, object],
    *,
    gap_ids: list[int],
    checks: dict[str, object],
    hashes: dict[str, object],
    trusted_diff: dict[str, object],
) -> list[dict[str, object]]:
    android_manifest = details.get("android_parser_manifest") if isinstance(details.get("android_parser_manifest"), dict) else {}
    app_data_deep_manifest = (
        details.get("android_app_data_deep_parser_manifest")
        if isinstance(details.get("android_app_data_deep_parser_manifest"), dict)
        else {}
    )
    apk_deep_manifest = (
        details.get("android_apk_deep_analysis_manifest")
        if isinstance(details.get("android_apk_deep_analysis_manifest"), dict)
        else {}
    )
    app_data_validation_plan = (
        details.get("android_app_data_report_grade_validation_plan")
        if isinstance(details.get("android_app_data_report_grade_validation_plan"), dict)
        else {}
    )
    profiles = [
        {
            "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
            "item_number": 52,
            "implementation_track": "mobile-vendor-export-import",
            "status": "usable-internal-triage-not-commercial-grade",
            "source_tool": "android-apk-app-data",
            "source_format": str(details.get("source_format") or ""),
            "source_index": int(details.get("source_index") or 0),
            "source_sha256": str(hashes.get("sha256") or ""),
            "implemented_controls": {
                "source_hash_preserved": bool(hashes.get("sha256")),
                "source_row_identity_preserved": bool(details.get("source_path")),
                "vendor_export_settings_verified": False,
                "schema_version_registry_present": bool(details.get("package") or details.get("data_category")),
                "android_parser_manifest_hash": str(android_manifest.get("manifest_sha256") or ""),
                "android_parser_manifest_emitted": bool(android_manifest),
                "source_viewer_locator_emitted": isinstance(android_manifest.get("source_viewer_locator"), dict),
            },
            "trusted_diff_status": str(trusted_diff.get("status") or "not-attached"),
            "failed_validation_check_ids": [
                "vendor-export-settings-not-verified",
                "vendor-schema-not-validated",
                "trusted-vendor-export-diff-required",
            ],
            "ready_for_court_report": False,
        }
    ]
    if any(number in gap_ids for number in (29, 30)):
        profiles.append(
            {
                "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
                "item_number": 54,
                "qc_prep_item_numbers": [ANDROID_QC_PREP_ITEM_NUMBER],
                "qc_prep_contracts": [dict(ANDROID_QC_PREP_CONTRACT)],
                "implementation_track": "android-backup-app-data-parser",
                "status": "usable-internal-inventory-not-app-specific-commercial-grade",
                "package": str(details.get("package") or ""),
                "data_category": str(details.get("data_category") or ""),
                "implemented_controls": {
                    "sms_call_contact_browser_media_app_db_inventory": True,
                    "package_path_attribution": bool(details.get("package") or details.get("source_path")),
                    "apk_manifest_permission_inventory": True,
                    "secret_values_extracted": bool(checks.get("secret_values_extracted")),
                    "encrypted_store_limitation_recorded": True,
                    "android_parser_manifest_hash": str(android_manifest.get("manifest_sha256") or ""),
                    "android_parser_manifest_emitted": bool(android_manifest),
                    "android_app_data_deep_parser_manifest_hash": str(
                        app_data_deep_manifest.get("manifest_sha256") or ""
                    ),
                    "android_app_data_deep_parser_manifest_emitted": bool(app_data_deep_manifest),
                    "android_app_data_report_grade_validation_plan_hash": str(
                        app_data_validation_plan.get("manifest_sha256") or ""
                    ),
                    "android_app_data_report_grade_validation_plan_emitted": bool(app_data_validation_plan),
                    "android_apk_deep_analysis_manifest_hash": str(apk_deep_manifest.get("manifest_sha256") or ""),
                    "android_apk_deep_analysis_manifest_emitted": bool(apk_deep_manifest),
                    "source_viewer_locator_emitted": isinstance(android_manifest.get("source_viewer_locator"), dict),
                },
                "failed_validation_check_ids": [
                    check
                    for check, failed in {
                        "android-backup-payload-not-natively-decoded": not checks.get("android_backup_payload_decoded"),
                        "app-specific-schema-not-validated": not checks.get("app_schema_validated"),
                        "android-parser-manifest-not-emitted": not android_manifest,
                        "android-app-data-deep-parser-manifest-not-emitted": 29 in gap_ids
                        and not app_data_deep_manifest,
                        "android-app-data-report-grade-validation-plan-not-emitted": 29 in gap_ids
                        and not app_data_validation_plan,
                        "android-apk-deep-analysis-manifest-not-emitted": 30 in gap_ids and not apk_deep_manifest,
                        "deleted-record-known-answer-corpus-required": not checks.get("commercial_validation_corpus"),
                    }.items()
                    if failed
                ],
                "passed_validation_check_ids": [
                    check
                    for check, passed in {
                        "android-parser-manifest-emitted": bool(android_manifest),
                        "android-source-locator-emitted": isinstance(android_manifest.get("source_viewer_locator"), dict),
                        "android-app-data-deep-parser-manifest-emitted": bool(app_data_deep_manifest),
                        "android-app-data-report-grade-validation-plan-emitted": bool(app_data_validation_plan),
                        "android-apk-deep-analysis-manifest-emitted": bool(apk_deep_manifest),
                        "android-secret-boundary-recorded": not checks.get("secret_values_extracted"),
                    }.items()
                    if passed
                ],
                "ready_for_court_report": False,
            }
        )
    return profiles


def android_reportability_decision(
    details: dict[str, object],
    *,
    gap_ids: list[int],
    checks: dict[str, object],
    failed_validation_matrix_ids: list[str],
    trusted_diff: dict[str, object] | None = None,
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
    if not trusted_diff or trusted_diff.get("status") != "pass":
        for number in gap_ids:
            blocker = ANDROID_TRUSTED_DIFF_BLOCKERS.get(number)
            if blocker:
                blockers.add(blocker)
    primary = gap_ids[0] if gap_ids else 30
    return {
        "profile_version": "android-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}" for number in gap_ids],
        "qc_prep_item_numbers": [ANDROID_QC_PREP_ITEM_NUMBER],
        "qc_prep_contracts": [dict(ANDROID_QC_PREP_CONTRACT)],
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
    android_manifest = details.get("android_parser_manifest") if isinstance(details.get("android_parser_manifest"), dict) else {}
    if android_manifest.get("manifest_sha256"):
        evidence_refs.append(f"android_parser_manifest_sha256:{android_manifest['manifest_sha256']}")
    app_data_deep_manifest = (
        details.get("android_app_data_deep_parser_manifest")
        if isinstance(details.get("android_app_data_deep_parser_manifest"), dict)
        else {}
    )
    if app_data_deep_manifest.get("manifest_sha256"):
        evidence_refs.append(
            f"android_app_data_deep_parser_manifest_sha256:{app_data_deep_manifest['manifest_sha256']}"
        )
    app_data_validation_plan = (
        details.get("android_app_data_report_grade_validation_plan")
        if isinstance(details.get("android_app_data_report_grade_validation_plan"), dict)
        else {}
    )
    if app_data_validation_plan.get("manifest_sha256"):
        evidence_refs.append(
            f"android_app_data_report_grade_validation_plan_sha256:{app_data_validation_plan['manifest_sha256']}"
        )
    apk_deep_manifest = (
        details.get("android_apk_deep_analysis_manifest")
        if isinstance(details.get("android_apk_deep_analysis_manifest"), dict)
        else {}
    )
    if apk_deep_manifest.get("manifest_sha256"):
        evidence_refs.append(f"android_apk_deep_analysis_manifest_sha256:{apk_deep_manifest['manifest_sha256']}")
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    trusted_diff = details.get("android_trusted_diff") if isinstance(details.get("android_trusted_diff"), dict) else {}
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
        if details.get("android_app_data_profile"):
            satisfied.append("android app-data profile")
        profile = details.get("android_app_data_profile") if isinstance(details.get("android_app_data_profile"), dict) else {}
        sqlite_inventory = profile.get("sqlite_schema_inventory") if isinstance(profile.get("sqlite_schema_inventory"), dict) else {}
        if sqlite_inventory.get("opened_readonly") and sqlite_inventory.get("values_redacted"):
            satisfied.append("SQLite schema inventory without value extraction")
        if profile.get("artifact_family_matrix"):
            satisfied.append("Android artifact family matrix")
        if profile.get("source_layout_profile"):
            satisfied.append("backup/filesystem layout classification")
        if android_manifest:
            satisfied.append("Android parser manifest")
            if isinstance(android_manifest.get("source_viewer_locator"), dict):
                satisfied.append("Android source locator")
        if app_data_deep_manifest:
            satisfied.append("Android app-data deep parser manifest")
            if isinstance(app_data_deep_manifest.get("source_viewer_locator"), dict):
                satisfied.append("Android app-data deep parser source locator")
        if app_data_validation_plan:
            satisfied.append("Android app-data report-grade validation plan")
            if int(app_data_validation_plan.get("ready_slot_count") or 0) >= 5:
                satisfied.append("Android app-data validation ready slots")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted Android artifact export diff pass")
    elif number == 30:
        if details.get("manifest_format") or not details.get("android_native_capabilities", {}).get("binary_manifest_decode", True):
            satisfied.append("binary manifest decode or limitation")
        if details.get("permissions") is not None and details.get("component_counts") is not None:
            satisfied.append("permission/component normalization")
        if details.get("certificate_entries") is not None or not details.get("android_native_capabilities", {}).get("signature_chain_validation", True):
            satisfied.append("signature chain validation")
        if details.get("string_pivots") is not None or details.get("dex_count") is not None or details.get("native_library_count") is not None:
            satisfied.append("DEX/native string pivot bounds")
        if details.get("apk_analysis_profile"):
            satisfied.append("APK analysis profile")
        signing_inventory = details.get("apk_signing_inventory")
        if isinstance(signing_inventory, dict) and signing_inventory.get("entry_count"):
            satisfied.append("APK signing entry inventory")
        if details.get("legal_warning") and details.get("commercial_grade_blockers"):
            satisfied.append("app-data schema and secret-handling warnings")
        if android_manifest:
            satisfied.append("Android parser manifest")
            if isinstance(android_manifest.get("source_viewer_locator"), dict):
                satisfied.append("Android source locator")
        if apk_deep_manifest:
            satisfied.append("Android APK deep analysis manifest")
            if isinstance(apk_deep_manifest.get("source_viewer_locator"), dict):
                satisfied.append("Android APK deep analysis source locator")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted APK/tool analysis diff pass")
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


def build_android_analyst_review_profile(details: Mapping[str, object], *, gap_ids: list[str]) -> dict[str, object]:
    artifact_type = "android-app-data" if details.get("source_format") == "android-export-file" else "android-apk"
    parser_manifest = details.get("android_parser_manifest") if isinstance(details.get("android_parser_manifest"), Mapping) else {}
    app_data_manifest = (
        details.get("android_app_data_deep_parser_manifest")
        if isinstance(details.get("android_app_data_deep_parser_manifest"), Mapping)
        else {}
    )
    apk_manifest = (
        details.get("android_apk_deep_analysis_manifest")
        if isinstance(details.get("android_apk_deep_analysis_manifest"), Mapping)
        else {}
    )
    viewer_locator = parser_manifest.get("source_viewer_locator") if isinstance(parser_manifest.get("source_viewer_locator"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
    package = str(details.get("package") or "")
    not_proof_of = [
        "malware verdict",
        "signature trust or certificate chain validation",
        "complete DEX/native behavior analysis",
        "encrypted store decryption",
        "deleted record recovery",
    ]
    if artifact_type == "android-app-data":
        not_proof_of.append("decoded app-specific message/account contents")
    else:
        not_proof_of.append("binary AndroidManifest equivalence when manifest is unsupported")
    manifest_hashes = [
        str(value)
        for value in (
            parser_manifest.get("manifest_sha256"),
            app_data_manifest.get("manifest_sha256"),
            apk_manifest.get("manifest_sha256"),
        )
        if value
    ]
    return {
        "profile_version": "android-analyst-review-profile-v1",
        "gap_ids": list(gap_ids),
        "artifact_type": artifact_type,
        "package": package,
        "severity": "high" if risk_flags else "medium",
        "summary": f"{artifact_type} / {package or 'unknown-package'} / risk={details.get('risk_score', 0)}",
        "evidence_interpretation": (
            "Android app-data inventory and schema redaction pivot"
            if artifact_type == "android-app-data"
            else "Android APK manifest/permission/signing/string pivot inventory"
        ),
        "not_proof_of": not_proof_of,
        "analyst_questions": [
            "Does package identity match the acquisition path and trusted Android tooling?",
            "Are binary manifest, signature chain, and app schema results verified by known-answer fixtures?",
            "Do risky permissions or string pivots need malware-tool correlation?",
            "Should app data be correlated with mobile messages, browser records, media, or contacts?",
        ],
        "primary_pivots": [
            value
            for value in (
                package,
                str(details.get("source_path") or ""),
                str(details.get("data_category") or ""),
                str(details.get("manifest_format") or ""),
            )
            if value
        ],
        "source_field_values": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "source_format": str(details.get("source_format") or ""),
            "package": package,
            "manifest_format": str(details.get("manifest_format") or ""),
            "data_category": str(details.get("data_category") or ""),
            "dex_count": int(details.get("dex_count") or 0),
            "native_library_count": int(details.get("native_library_count") or 0),
            "dangerous_permission_count": len(details.get("dangerous_permissions") or [])
            if isinstance(details.get("dangerous_permissions"), list)
            else 0,
            "sqlite_table_count": int(
                (
                    details.get("android_app_data_profile", {}).get("sqlite_schema_inventory", {}).get("table_count")
                    if isinstance(details.get("android_app_data_profile"), Mapping)
                    and isinstance(details.get("android_app_data_profile", {}).get("sqlite_schema_inventory"), Mapping)
                    else 0
                )
                or 0
            ),
            "manifest_hashes": manifest_hashes,
            "viewer": str(viewer_locator.get("viewer") or ""),
        },
        "correlation_targets": [
            "aapt/apkanalyzer/MobSF/ALEAPP diff",
            "Android acquisition manifest",
            "package signature lineage",
            "mobile timeline",
            "network IOC/string pivot review",
        ],
        "risk_tags": sorted(set(map(str, risk_flags)) | {"android-validation-required"}),
        "validation_required": True,
        "report_grade_ready": False,
        "validation_snapshot": dict(validation_checks),
        "commercial_blockers": list(ANDROID_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use as a triage/review pivot until trusted Android tooling, known-answer corpora, and acquisition metadata validate the row.",
    }


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
