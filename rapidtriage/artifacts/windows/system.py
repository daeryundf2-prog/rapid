from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shlex
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import unquote_plus

from ...core.audit import compute_sha256
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp, open_sqlite_snapshot

PARSER_VERSION = "windows-system-v7"
TASKS_ROOT = ("Windows", "System32", "Tasks")
TASK_SUSPICIOUS_TERMS = (
    "powershell",
    "pwsh",
    "-enc",
    "-encodedcommand",
    "executionpolicy bypass",
    "hidden",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "curl",
    "http://",
    "https://",
)
TASK_USER_WRITABLE_PATH_TERMS = (
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "%appdata%",
    "%localappdata%",
    "%temp%",
    "%tmp%",
)
TASK_LOLBINS = {
    "bitsadmin.exe",
    "certutil.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "schtasks.exe",
    "wscript.exe",
}
DEFENDER_SUPPORT_ROOT = ("ProgramData", "Microsoft", "Windows Defender", "Support")
WMI_REPOSITORY_ROOT = ("Windows", "System32", "wbem", "Repository")
WMI_REPOSITORY_NAMES = {"OBJECTS.DATA", "INDEX.BTR", "MAPPING.VER"}
WMI_REPOSITORY_SUFFIXES = {".MAP", ".BTR", ".DATA"}
WMI_SCAN_LIMIT = 8 * 1024 * 1024
SPOOLER_SCAN_LIMIT = 2 * 1024 * 1024
REMOTE_CONTROL_SCAN_LIMIT = 2 * 1024 * 1024
BITS_QMGR_SCAN_LIMIT = 2 * 1024 * 1024
WMI_PERSISTENCE_TERMS = (
    "__eventfilter",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "__filtertoconsumerbinding",
    "powershell",
    "wmic",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
)
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\|\\device\\)[^\x00\r\n\t\"'<>|]{4,260}")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")
FIREWALL_LOG_PATHS = (
    ("Windows", "System32", "LogFiles", "Firewall", "pfirewall.log"),
    ("Windows", "System32", "LogFiles", "Firewall", "pfirewall.log.old"),
)
WER_ROOTS = (
    ("ProgramData", "Microsoft", "Windows", "WER"),
    ("Users",),
)
WER_REPORT_GRADE_BLOCKERS = [
    "wer-dump-file-correlation-not-implemented",
    "wer-reportqueue-state-validation-not-implemented",
    "wer-cab-metadata-validation-not-implemented",
]
SYSTEM_NATIVE_CAPABILITIES = {
    "task_xml_normalization": True,
    "task_action_trigger_principal_pivots": True,
    "defender_mplog_triage": True,
    "firewall_w3c_log_parsing": True,
    "wer_key_value_normalization": True,
    "wmi_repository_string_pivots": True,
    "taskcache_registry_correlation": False,
    "task_security_descriptor_validation": False,
    "defender_event_mpcmdrun_correlation": False,
    "firewall_rule_store_correlation": False,
    "wer_dump_cab_reportqueue_correlation": False,
    "native_wmi_repository_decode": False,
}
SYSTEM_REPORT_GRADE_BLOCKERS = [
    "task-cache-registry-correlation-not-implemented",
    "task-security-descriptor-validation-not-implemented",
    "task-history-event-correlation-not-implemented",
    "defender-event-and-mpcmdrun-correlation-not-implemented",
    "firewall-rule-store-correlation-not-implemented",
    "wer-dump-cab-reportqueue-correlation-not-implemented",
    "native-wmi-repository-decoding-not-implemented",
    "known-answer-system-artifact-corpus-required",
    "windows-system-trusted-artifact-diff-required",
]
SYSTEM_TRUSTED_TOOLS = {
    "velociraptor",
    "chainsaw",
    "hayabusa",
    "autoruns",
    "sysinternals autoruns",
    "task scheduler",
    "mpcmdrun",
    "windows defender",
    "wmi explorer",
}
ZONE_IDENTIFIER_PATTERN = re.compile(r"(?i)(?P<target>.+)(?::Zone\.Identifier|\.Zone\.Identifier)$")
REMOTE_CONTROL_PRODUCTS = {
    "anydesk": ("anydesk", "ad_svc.trace"),
    "teamviewer": ("teamviewer", "connections_incoming", "tvnetwork"),
    "rustdesk": ("rustdesk", "rustdesk.toml", "config/rustdesk"),
    "chrome-remote-desktop": ("chrome remote desktop", "chromoting", "remoting_host"),
}
BITS_QMGR_NAMES = {"qmgr0.dat", "qmgr1.dat", "qmgr.db", "qmgr.dat"}


class WindowsSystemArtifactsProvider:
    collector_kind = "windows-system"
    name = "windows-system-artifacts"
    description = "Windows Task Scheduler, Defender, Firewall, WER, and Zone.Identifier artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_task_scheduler(root)
        yield from collect_defender_support(root)
        yield from collect_firewall_logs(root)
        yield from collect_wer_reports(root)
        yield from collect_wmi_repository(root)
        yield from collect_print_spooler_artifacts(root)
        yield from collect_bits_qmgr_artifacts(root)
        yield from collect_third_party_remote_control_artifacts(root)
        yield from collect_zone_identifier_ads(root)
        yield from collect_explorer_cache_artifacts(root)
        yield from collect_activity_notification_uwp_artifacts(root)
        yield from collect_webshell_and_server_log_artifacts(root)


def collect_print_spooler_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in {".spl", ".shd"}:
            continue
        lower = str(path).lower()
        if "spool" not in lower and "printer" not in lower:
            continue
        stat_result = path.stat()
        blob = read_prefix(path, SPOOLER_SCAN_LIMIT)
        strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
        path_candidates = regex_candidates(strings, WINDOWS_PATH_RE)[:20]
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="print-spooler-job",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "print-spooler-file"),
                "source_hashes": {"sha256": compute_sha256(path)},
                "spooler_file_kind": path.suffix.lower().lstrip("."),
                "job_name_hint": path.stem,
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "spooler_file_modified_at",
                "scan_bytes": len(blob),
                "extracted_string_count": len(strings),
                "string_samples": strings[:40],
                "path_candidates": path_candidates,
                "coverage_status": "spooler-file-string-inventory",
                "reportability": "triage",
                "parser_confidence": "medium" if strings else "low",
                "risk_flags": ["possible-printed-document"],
                "validation_required": True,
                "validation_guidance": "SPL/SHD file is inventoried with bounded strings and timestamps. Validate printed document identity with a spool parser, printer logs, and source document metadata before report-grade claims.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "spl-shd-structure-decoder-not-implemented",
                    "printer-driver-spool-fixture-required",
                    "print-eventlog-correlation-required",
                ],
            },
        )


def collect_third_party_remote_control_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        product = remote_control_product_for_path(path)
        if not product:
            continue
        stat_result = path.stat()
        blob = read_prefix(path, REMOTE_CONTROL_SCAN_LIMIT)
        strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
        urls = regex_candidates(strings, URL_RE)[:20]
        ips = sorted(set(re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", " ".join(strings))))[:20]
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="third-party-remote-control-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "third-party-remote-control"),
                "source_hashes": {"sha256": compute_sha256(path)},
                "product": product,
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "remote_control_file_modified_at",
                "scan_bytes": len(blob),
                "extracted_string_count": len(strings),
                "string_samples": strings[:40],
                "url_candidates": urls,
                "ip_candidates": ips,
                "coverage_status": "remote-control-file-inventory",
                "reportability": "triage",
                "parser_confidence": "medium",
                "risk_flags": [f"remote-control:{product}"],
                "validation_required": True,
                "validation_guidance": "Third-party remote-control file is a triage pivot. Validate session time, peer ID/IP, transfer logs, and account attribution with product-specific parsers before report-grade use.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "product-specific-session-decoder-required",
                    "remote-peer-attribution-validation-required",
                    "file-transfer-log-validation-required",
                ],
            },
        )


def remote_control_product_for_path(path: Path) -> str:
    lower = str(path).lower().replace("\\", "/")
    for product, terms in REMOTE_CONTROL_PRODUCTS.items():
        if any(term in lower for term in terms):
            return product
    return ""


def collect_bits_qmgr_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        lower = str(path).lower().replace("\\", "/")
        if path.name.lower() not in BITS_QMGR_NAMES and not (
            "network/downloader" in lower and path.suffix.lower() in {".dat", ".db"}
        ):
            continue
        stat_result = path.stat()
        blob = read_prefix(path, BITS_QMGR_SCAN_LIMIT)
        strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
        urls = regex_candidates(strings, URL_RE)[:30]
        paths = regex_candidates(strings, WINDOWS_PATH_RE)[:30]
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="bits-qmgr-transfer-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "bits-qmgr-file"),
                "source_hashes": {"sha256": compute_sha256(path)},
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "qmgr_file_modified_at",
                "scan_bytes": len(blob),
                "url_candidates": urls,
                "path_candidates": paths,
                "extracted_string_count": len(strings),
                "string_samples": strings[:50],
                "coverage_status": "bits-qmgr-bounded-string-inventory",
                "reportability": "triage",
                "parser_confidence": "medium" if urls or paths else "low",
                "risk_flags": bits_qmgr_risk_flags(urls, paths),
                "validation_required": True,
                "validation_guidance": (
                    "BITS qmgr file is scanned for transfer pivots. Validate job IDs, owners, retry state, and "
                    "complete URL/path fields with a BITS structure decoder before report-grade exfil/download claims."
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "bits-qmgr-structure-decoder-not-implemented",
                    "job-owner-and-state-validation-required",
                    "trusted-bits-parser-diff-required",
                ],
            },
        )


def bits_qmgr_risk_flags(urls: Sequence[str], paths: Sequence[str]) -> list[str]:
    flags = ["bits-qmgr-file"]
    if urls:
        flags.append("bits-url-candidate")
    if paths:
        flags.append("bits-local-path-candidate")
    lowered_urls = " ".join(urls).lower()
    if any(term in lowered_urls for term in ("http://", "pastebin", "discord", "mega.", "anonfiles", "transfer")):
        flags.append("possible-suspicious-bits-transfer")
    return flags


def collect_explorer_cache_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        name = path.name.lower()
        if not (name.startswith("thumbcache_") or name.startswith("iconcache_")):
            continue
        if path.suffix.lower() not in {".db", ".dat"}:
            continue
        artifact_type = "thumbnail-cache-file" if name.startswith("thumbcache_") else "icon-cache-file"
        stat_result = path.stat()
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type=artifact_type,
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "windows-explorer-cache"),
                "source_hashes": {"sha256": compute_sha256(path)},
                "cache_signature_profile": explorer_cache_signature_profile(path),
                "cache_family": "thumbnail" if artifact_type == "thumbnail-cache-file" else "icon",
                "cache_name": path.name,
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "coverage_status": "cache-file-inventory",
                "reportability": "triage",
                "parser_confidence": "medium",
                "validation_required": True,
                "validation_guidance": (
                    "Explorer thumbnail/icon cache file is inventoried for review. Full cache entry decoding, "
                    "image extraction, and trusted thumbnail-cache diff validation are still required before "
                    "report-grade image-viewing conclusions."
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "thumbnail-cache-entry-decoder-not-implemented",
                    "thumbnail-cache-known-answer-corpus-required",
                ],
            },
        )


def collect_activity_notification_uwp_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    emitted_packages = 0
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        name = path.name.lower()
        if path.is_file() and name == "activitiescache.db":
            yield build_activity_style_record(path, "activities-cache-db", "connected-devices-activities", root=root)
        elif path.is_file() and name in {"wpndatabase.db", "notifications.db"}:
            yield build_activity_style_record(path, "notification-database", "windows-notifications", root=root)
        elif path.is_dir() and path.parent.name.lower() == "packages" and "appdata" in str(path).lower():
            if emitted_packages >= 500:
                continue
            emitted_packages += 1
            stat_result = path.stat()
            child_names = safe_child_names(path)
            profile_attribution = windows_user_profile_attribution(path, root=root)
            yield ArtifactRecord(
                provider=WindowsSystemArtifactsProvider.name,
                artifact_type="uwp-package",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-system-artifacts",
                    "parser_version": PARSER_VERSION,
                    "source_path": str(path.resolve()),
                    "source_format": "uwp-package-directory",
                    "package_name": path.name,
                    "package_identity": uwp_package_identity(path.name),
                    "profile_attribution": profile_attribution,
                    "child_names": child_names,
                    "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                    "coverage_status": "package-directory-inventory",
                    "reportability": "triage",
                    "parser_confidence": "medium",
                    "validation_required": True,
                    "validation_guidance": (
                        "UWP package directory is inventoried for app-activity pivots. App-specific schema parsing, "
                        "ActivitiesCache correlation, and notification DB row decoding are required before report-grade claims."
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": [
                        "uwp-app-specific-schema-parsers-required",
                        "activities-notifications-correlation-required",
                    ],
                },
            )


def build_activity_style_record(path: Path, artifact_type: str, source_format: str, *, root: Path | None = None) -> ArtifactRecord:
    stat_result = path.stat()
    schema_inventory = sqlite_schema_inventory(path)
    profile_attribution = windows_user_profile_attribution(path, root=root)
    package_index = uwp_package_index(root) if root else []
    apply_profile_attribution_to_schema_inventory(schema_inventory, profile_attribution)
    apply_uwp_package_correlation_to_schema_inventory(schema_inventory, package_index)
    return ArtifactRecord(
        provider=WindowsSystemArtifactsProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            **source_details(path, source_format),
            "source_hashes": {"sha256": compute_sha256(path)},
            "profile_attribution": profile_attribution,
            "uwp_package_index_count": len(package_index),
            "sqlite_schema_inventory": schema_inventory,
            "table_count": schema_inventory.get("table_count", 0),
            "total_row_count": schema_inventory.get("total_row_count", 0),
            "size": stat_result.st_size,
            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
            "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
            "coverage_status": "sqlite-schema-inventory" if schema_inventory.get("opened_readonly") else "database-file-inventory",
            "reportability": "triage",
            "parser_confidence": "medium",
            "validation_required": True,
            "validation_guidance": (
                "Database file is inventoried. Full table/schema decoding, account attribution, and timeline "
                "correlation are required before report-grade Activities/Notifications conclusions."
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "activities-notifications-native-table-parser-required",
                "known-answer-activities-notifications-corpus-required",
            ],
        },
    )


def windows_user_profile_attribution(path: Path, *, root: Path | None = None) -> dict[str, object]:
    parts = list(path.resolve().parts)
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part == "users" and index + 1 < len(parts):
            user_name = parts[index + 1]
            relative_parts = parts[index + 2 :]
            sid_candidates = profile_sid_candidates(root, user_name) if root else []
            return {
                "profile_name": user_name,
                "profile_root": str(Path(*parts[: index + 2])) if index + 2 > 0 else "",
                "relative_path": str(Path(*relative_parts)) if relative_parts else "",
                "attribution_basis": "path-under-users-profile",
                "sid_candidates": sid_candidates,
                "sid": sid_candidates[0]["sid"] if sid_candidates else "",
                "sid_correlation_status": "profilelist-match" if sid_candidates else "profilelist-not-found",
                "confidence": "high" if sid_candidates else "medium",
                "validation_required": True,
            }
    return {
        "profile_name": "",
        "profile_root": "",
        "relative_path": str(path),
        "attribution_basis": "not-under-users-profile",
        "sid_candidates": [],
        "sid": "",
        "sid_correlation_status": "not-applicable",
        "confidence": "low",
        "validation_required": True,
    }


def profile_sid_candidates(root: Path | None, profile_name: str, *, max_files: int = 80, max_bytes: int = 2 * 1024 * 1024) -> list[dict[str, object]]:
    if root is None or not profile_name:
        return []
    profile_token = rf"\\users\\{re.escape(profile_name.lower())}"
    sid_candidates: list[dict[str, object]] = []
    scanned = 0
    for candidate in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if scanned >= max_files:
            break
        if not candidate.is_file():
            continue
        lowered_name = candidate.name.lower()
        lowered_path = str(candidate).lower()
        if not (
            (
                lowered_name.endswith((".reg", ".txt", ".log"))
                or lowered_name in {"software", "software.dat"}
            )
            and any(token in lowered_path for token in ("software", "profilelist", "registry", "system32/config"))
        ):
            continue
        try:
            if candidate.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        scanned += 1
        if lowered_name in {"software", "software.dat"}:
            sid_candidates.extend(profile_sid_candidates_from_native_blob(candidate, profile_token))
        else:
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sid_candidates.extend(profile_sid_candidates_from_text(text, candidate, profile_token))
    deduped: dict[str, dict[str, object]] = {}
    for item in sid_candidates:
        sid = str(item.get("sid") or "")
        if sid and sid not in deduped:
            deduped[sid] = item
    return list(deduped.values())[:10]


def profile_sid_candidates_from_text(text: str, source_path: Path, profile_token: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    current_sid = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        sid_match = re.search(r"ProfileList\\(?P<sid>S-\d-\d+(?:-\d+){1,14})", line, flags=re.IGNORECASE)
        if sid_match:
            current_sid = sid_match.group("sid")
        if "profileimagepath" not in line.lower():
            continue
        normalized_line = line.lower().replace("/", "\\")
        if not current_sid or not re.search(profile_token, normalized_line):
            continue
        candidates.append(
            {
                "sid": current_sid,
                "source_path": str(source_path.resolve()),
                "line_number": line_number,
                "source_sha256": compute_sha256(source_path),
                "basis": "profilelist-profileimagepath-reg-export",
                "validation_required": True,
            }
        )
    return candidates


def profile_sid_candidates_from_native_blob(source_path: Path, profile_token: str) -> list[dict[str, object]]:
    try:
        blob = source_path.read_bytes()
    except OSError:
        return []
    candidates: list[dict[str, object]] = []
    profile_fragment = profile_token.replace("\\\\", "\\")
    for encoding, text in (
        ("utf-16le", blob.decode("utf-16le", errors="ignore")),
        ("latin1", blob.decode("latin1", errors="ignore")),
    ):
        normalized_text = text.replace("\x00", "\n")
        for candidate in profile_sid_candidates_from_text(normalized_text, source_path, profile_token):
            candidate["basis"] = "profilelist-profileimagepath-native-string-scan"
            candidate["encoding"] = encoding
            annotate_native_profile_candidate_offsets(
                candidate,
                original_text=text,
                encoding=encoding,
                profile_fragment=profile_fragment,
            )
            candidates.append(candidate)
        compact_text = re.sub(r"\s+", " ", normalized_text)
        for match in re.finditer(
            r"ProfileList\\(?P<sid>S-\d-\d+(?:-\d+){1,14}).{0,400}?ProfileImagePath.{0,400}?"
            + profile_token,
            compact_text,
            flags=re.IGNORECASE,
        ):
            candidate = {
                "sid": match.group("sid"),
                "source_path": str(source_path.resolve()),
                "line_number": None,
                "source_sha256": compute_sha256(source_path),
                "basis": "profilelist-profileimagepath-native-string-scan",
                "encoding": encoding,
                "validation_required": True,
            }
            annotate_native_profile_candidate_offsets(
                candidate,
                original_text=text,
                encoding=encoding,
                profile_fragment=profile_fragment,
            )
            candidates.append(candidate)
    return candidates


def annotate_native_profile_candidate_offsets(
    candidate: dict[str, object],
    *,
    original_text: str,
    encoding: str,
    profile_fragment: str,
) -> None:
    sid = str(candidate.get("sid") or "")
    candidate["sid_byte_offset"] = decoded_text_byte_offset(original_text, sid, encoding)
    candidate["profile_path_byte_offset"] = decoded_text_byte_offset(original_text, profile_fragment, encoding)
    candidate["offset_basis"] = "decoded-native-hive-string-offset"


def decoded_text_byte_offset(text: str, needle: str, encoding: str) -> int | None:
    if not needle:
        return None
    index = text.lower().find(needle.lower())
    if index < 0:
        return None
    if encoding == "utf-16le":
        return index * 2
    if encoding == "latin1":
        return index
    return None


def uwp_package_identity(package_name: str) -> dict[str, object]:
    if "_" not in package_name:
        return {"name": package_name, "publisher_id": "", "parse_status": "no-publisher-suffix"}
    name, publisher_id = package_name.rsplit("_", 1)
    return {
        "name": name,
        "publisher_id": publisher_id,
        "parse_status": "name-publisher-split",
    }


def uwp_package_index(root: Path, *, limit: int = 500) -> list[dict[str, object]]:
    packages: list[dict[str, object]] = []
    if root is None:
        return packages
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if len(packages) >= limit:
            break
        if not path.is_dir() or path.parent.name.lower() != "packages" or "appdata" not in str(path).lower():
            continue
        identity = uwp_package_identity(path.name)
        packages.append(
            {
                "package_name": path.name,
                "identity": identity,
                "source_path": str(path.resolve()),
                "package_name_sha256": hashlib.sha256(path.name.encode("utf-8", errors="replace")).hexdigest(),
            }
        )
    return packages


def apply_profile_attribution_to_schema_inventory(
    schema_inventory: dict[str, object],
    profile_attribution: Mapping[str, object],
) -> None:
    tables = schema_inventory.get("tables")
    if not isinstance(tables, list):
        return
    for table in tables:
        if not isinstance(table, dict):
            continue
        samples = table.get("normalized_timeline_samples")
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if isinstance(sample, dict):
                sample["profile_attribution"] = dict(profile_attribution)


def apply_uwp_package_correlation_to_schema_inventory(
    schema_inventory: dict[str, object],
    package_index: Sequence[Mapping[str, object]],
) -> None:
    tables = schema_inventory.get("tables")
    if not isinstance(tables, list):
        return
    match_count = 0
    for table in tables:
        if not isinstance(table, dict):
            continue
        samples = table.get("normalized_timeline_samples")
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            correlation = correlate_app_preview_to_uwp_package(sample, package_index)
            sample["uwp_package_correlation"] = correlation
            if correlation.get("status") == "matched":
                match_count += 1
    schema_inventory["uwp_package_correlation_summary"] = {
        "profile_version": "uwp-package-correlation-summary-v1",
        "package_index_count": len(package_index),
        "matched_timeline_sample_count": match_count,
        "correlation_status": "matched" if match_count else ("no-matches" if package_index else "no-package-index"),
        "validation_required": True,
    }


def correlate_app_preview_to_uwp_package(
    sample: Mapping[str, object],
    package_index: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    app_preview = sample.get("app_preview") if isinstance(sample.get("app_preview"), Mapping) else {}
    preview = str(app_preview.get("preview") or "").lower() if isinstance(app_preview, Mapping) else ""
    if not preview or not package_index:
        return {
            "status": "not-evaluated" if not preview else "no-package-index",
            "matched_package": "",
            "match_basis": "",
            "validation_required": True,
        }
    for package in package_index:
        package_name = str(package.get("package_name") or "")
        identity = package.get("identity") if isinstance(package.get("identity"), Mapping) else {}
        identity_name = str(identity.get("name") or "") if isinstance(identity, Mapping) else ""
        candidates = [package_name.lower(), identity_name.lower()]
        if any(candidate and candidate in preview for candidate in candidates):
            return {
                "status": "matched",
                "matched_package": package_name,
                "matched_identity_name": identity_name,
                "matched_package_sha256": package.get("package_name_sha256", ""),
                "source_path": package.get("source_path", ""),
                "match_basis": "app-preview-contains-package-identity",
                "validation_required": True,
            }
    return {
        "status": "unmatched",
        "matched_package": "",
        "match_basis": "no-package-identity-in-app-preview",
        "validation_required": True,
    }


def explorer_cache_signature_profile(path: Path) -> dict[str, object]:
    blob = read_prefix(path, 2 * 1024 * 1024)
    embedded_media_candidates = extract_embedded_media_candidates(blob)
    cache_entry_candidates = explorer_cache_entry_candidates(blob, embedded_media_candidates)
    signatures = {
        "cmmm_count": blob.count(b"CMMM"),
        "jpeg_count": blob.count(b"\xff\xd8\xff"),
        "png_count": blob.count(b"\x89PNG\r\n\x1a\n"),
        "bmp_count": blob.count(b"BM"),
    }
    embedded_offsets = {
        "cmmm": find_signature_offsets(blob, b"CMMM"),
        "jpeg": find_signature_offsets(blob, b"\xff\xd8\xff"),
        "png": find_signature_offsets(blob, b"\x89PNG\r\n\x1a\n"),
        "bmp": find_signature_offsets(blob, b"BM"),
    }
    return {
        "profile_version": "explorer-cache-signature-profile-v1",
        "scan_bytes": len(blob),
        "signatures": signatures,
        "embedded_offsets": embedded_offsets,
        "embedded_media_signature_count": signatures["jpeg_count"] + signatures["png_count"] + signatures["bmp_count"],
        "embedded_media_candidate_count": len(embedded_media_candidates),
        "embedded_media_candidates": embedded_media_candidates,
        "candidate_cache_entry_count": signatures["cmmm_count"],
        "cache_entry_candidate_count": len(cache_entry_candidates),
        "cache_entry_candidates": cache_entry_candidates,
        "entry_decode_status": "cmmm-entry-candidates" if cache_entry_candidates else ("bounded-embedded-media-candidates" if embedded_media_candidates else "signature-only"),
        "validation_required": True,
    }


def explorer_cache_entry_candidates(
    blob: bytes,
    embedded_media_candidates: list[dict[str, object]],
    *,
    limit: int = 25,
) -> list[dict[str, object]]:
    cmmm_offsets = find_signature_offsets(blob, b"CMMM", limit=limit)
    entries: list[dict[str, object]] = []
    for index, offset in enumerate(cmmm_offsets):
        next_offset = cmmm_offsets[index + 1] if index + 1 < len(cmmm_offsets) else min(len(blob), offset + 4096)
        end_offset = max(offset + 4, min(len(blob), next_offset))
        context_end = min(len(blob), offset + 256)
        context = blob[offset:context_end]
        nearest_media = nearest_embedded_media_candidate(offset, embedded_media_candidates)
        entries.append(
            {
                "entry_index": index,
                "signature": "CMMM",
                "offset": offset,
                "candidate_end_offset": end_offset,
                "candidate_length": end_offset - offset,
                "context_sha256": hashlib.sha256(context).hexdigest(),
                "context_preview_hex": context[:64].hex(),
                "nearest_embedded_media": nearest_media,
                "decode_status": "signature-window-candidate",
                "reportability": "triage-cache-entry-candidate",
                "validation_required": True,
            }
        )
    return entries


def nearest_embedded_media_candidate(offset: int, embedded_media_candidates: list[dict[str, object]]) -> dict[str, object] | None:
    nearest: dict[str, object] | None = None
    nearest_distance: int | None = None
    for candidate in embedded_media_candidates:
        candidate_offset = candidate.get("offset")
        if not isinstance(candidate_offset, int):
            continue
        distance = abs(candidate_offset - offset)
        if nearest_distance is None or distance < nearest_distance:
            nearest_distance = distance
            nearest = {
                "type": candidate.get("type"),
                "offset": candidate_offset,
                "length": candidate.get("length"),
                "sha256": candidate.get("sha256"),
                "distance_from_entry": distance,
            }
    return nearest


def extract_embedded_media_candidates(blob: bytes, *, limit: int = 25, max_candidate_bytes: int = 10 * 1024 * 1024) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for media_type, start, end in iter_embedded_media_ranges(blob):
        if len(candidates) >= limit:
            break
        length = end - start
        if length <= 0 or length > max_candidate_bytes:
            continue
        sample = blob[start:end]
        candidates.append(
            {
                "type": media_type,
                "offset": start,
                "end_offset": end,
                "length": length,
                "sha256": hashlib.sha256(sample).hexdigest(),
                "header_hex": sample[:16].hex(),
                "footer_hex": sample[-16:].hex() if len(sample) >= 16 else sample.hex(),
                "extraction_status": "bounded-candidate",
                "reportability": "triage-preview-candidate",
                "validation_required": True,
            }
        )
    return candidates


def iter_embedded_media_ranges(blob: bytes) -> Iterable[tuple[str, int, int]]:
    for offset in find_signature_offsets(blob, b"\xff\xd8\xff", limit=100):
        end_marker = blob.find(b"\xff\xd9", offset + 3)
        if end_marker > offset:
            yield ("jpeg", offset, end_marker + 2)
    for offset in find_signature_offsets(blob, b"\x89PNG\r\n\x1a\n", limit=100):
        iend = blob.find(b"IEND", offset + 8)
        if iend > offset and iend + 8 <= len(blob):
            yield ("png", offset, iend + 8)
    for offset in find_signature_offsets(blob, b"BM", limit=100):
        if offset + 6 > len(blob):
            continue
        size = int.from_bytes(blob[offset + 2 : offset + 6], "little", signed=False)
        if size >= 14 and offset + size <= len(blob):
            yield ("bmp", offset, offset + size)


def find_signature_offsets(blob: bytes, signature: bytes, *, limit: int = 25) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        offset = blob.find(signature, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + max(1, len(signature))
    return offsets


def sqlite_schema_inventory(path: Path, *, max_tables: int = 40, max_columns: int = 80) -> dict[str, object]:
    inventory: dict[str, object] = {
        "profile_version": "windows-system-sqlite-schema-inventory-v1",
        "opened_readonly": False,
        "table_count": 0,
        "total_row_count": 0,
        "tables": [],
        "values_redacted": True,
    }
    if read_prefix(path, 16) != b"SQLite format 3\x00":
        inventory["open_status"] = "not-sqlite-header"
        return inventory
    try:
        with open_sqlite_snapshot(path) as connection:
            table_names = [
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            ][:max_tables]
            tables = []
            total_rows = 0
            for table_name in table_names:
                columns = sqlite_table_columns(connection, table_name)[:max_columns]
                row_count = sqlite_row_count(connection, table_name)
                if isinstance(row_count, int):
                    total_rows += row_count
                tables.append(
                    {
                        "name": table_name,
                        "columns": columns,
                        "row_count": row_count,
                        "semantic_profile": sqlite_table_semantic_profile(table_name, columns),
                        "redacted_row_samples": sqlite_redacted_row_samples(connection, table_name, columns),
                        "normalized_timeline_samples": sqlite_normalized_timeline_samples(
                            connection,
                            table_name,
                            columns,
                        ),
                    }
                )
            inventory.update(
                {
                    "opened_readonly": True,
                    "open_status": "opened",
                    "table_count": len(table_names),
                    "total_row_count": total_rows,
                    "tables": tables,
                    "semantic_summary": sqlite_semantic_summary(tables),
                }
            )
    except (sqlite3.Error, OSError) as exc:
        inventory["open_status"] = "sqlite-open-failed"
        inventory["sqlite_error"] = str(exc)[:240]
    return inventory


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    if not safe_sqlite_identifier(table_name):
        return []
    try:
        return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()]
    except sqlite3.Error:
        return []


def sqlite_row_count(connection: sqlite3.Connection, table_name: str) -> int | None:
    if not safe_sqlite_identifier(table_name):
        return None
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()
        return int(row[0]) if row else None
    except sqlite3.Error:
        return None


def safe_sqlite_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value))


def sqlite_table_semantic_profile(table_name: str, columns: list[str]) -> dict[str, object]:
    lowered_name = table_name.lower()
    lowered_columns = {column.lower(): column for column in columns}
    app_columns = [original for lowered, original in lowered_columns.items() if any(token in lowered for token in ("app", "package", "aumid"))]
    text_columns = [
        original
        for lowered, original in lowered_columns.items()
        if any(token in lowered for token in ("title", "text", "payload", "message", "body", "display", "description"))
    ]
    time_columns = [
        original
        for lowered, original in lowered_columns.items()
        if any(token in lowered for token in ("time", "date", "created", "updated", "modified", "expiry", "expiration"))
    ]
    id_columns = [original for lowered, original in lowered_columns.items() if lowered in {"id", "activityid", "notificationid"} or lowered.endswith("id")]
    if "activity" in lowered_name:
        family = "activity"
    elif "notification" in lowered_name or "toast" in lowered_name or "wpn" in lowered_name:
        family = "notification"
    else:
        family = "generic-system-sqlite"
    return {
        "family": family,
        "app_columns": app_columns[:12],
        "text_columns": text_columns[:12],
        "time_columns": time_columns[:12],
        "id_columns": id_columns[:12],
        "semantic_confidence": "medium" if app_columns or text_columns or time_columns else "low",
    }


def sqlite_semantic_summary(tables: list[dict[str, object]]) -> dict[str, object]:
    families: dict[str, int] = {}
    app_column_count = 0
    text_column_count = 0
    time_column_count = 0
    timeline_candidate_count = 0
    for table in tables:
        profile = table.get("semantic_profile") if isinstance(table.get("semantic_profile"), Mapping) else {}
        family = str(profile.get("family") or "unknown")
        families[family] = families.get(family, 0) + 1
        app_column_count += len(profile.get("app_columns", [])) if isinstance(profile.get("app_columns"), list) else 0
        text_column_count += len(profile.get("text_columns", [])) if isinstance(profile.get("text_columns"), list) else 0
        time_column_count += len(profile.get("time_columns", [])) if isinstance(profile.get("time_columns"), list) else 0
        samples = table.get("normalized_timeline_samples")
        timeline_candidate_count += len(samples) if isinstance(samples, list) else 0
    return {
        "families": families,
        "app_column_count": app_column_count,
        "text_column_count": text_column_count,
        "time_column_count": time_column_count,
        "timeline_candidate_count": timeline_candidate_count,
        "semantic_decode_status": "schema-guided-redacted-samples",
    }


def sqlite_redacted_row_samples(
    connection: sqlite3.Connection,
    table_name: str,
    columns: list[str],
    *,
    limit: int = 3,
) -> list[dict[str, object]]:
    if not safe_sqlite_identifier(table_name) or not columns:
        return []
    try:
        rows = connection.execute(f'SELECT * FROM "{table_name}" LIMIT {int(limit)}').fetchall()
    except sqlite3.Error:
        return []
    samples: list[dict[str, object]] = []
    for row in rows:
        sample: dict[str, object] = {}
        for column in columns[:20]:
            value = row[column] if column in row.keys() else None
            sample[column] = redacted_sqlite_value(value)
        samples.append(sample)
    return samples


def sqlite_normalized_timeline_samples(
    connection: sqlite3.Connection,
    table_name: str,
    columns: list[str],
    *,
    limit: int = 10,
) -> list[dict[str, object]]:
    if not safe_sqlite_identifier(table_name) or not columns:
        return []
    profile = sqlite_table_semantic_profile(table_name, columns)
    app_column = first_semantic_column(profile, "app_columns")
    text_column = first_semantic_column(profile, "text_columns")
    time_column = first_semantic_column(profile, "time_columns")
    id_column = first_semantic_column(profile, "id_columns")
    if not any((app_column, text_column, time_column, id_column)):
        return []
    try:
        rows = connection.execute(f'SELECT rowid AS "__rapid_rowid__", * FROM "{table_name}" LIMIT {int(limit)}').fetchall()
    except sqlite3.Error:
        try:
            rows = connection.execute(f'SELECT * FROM "{table_name}" LIMIT {int(limit)}').fetchall()
        except sqlite3.Error:
            return []
    samples: list[dict[str, object]] = []
    for row in rows:
        row_keys = set(row.keys())
        row_id = row["__rapid_rowid__"] if "__rapid_rowid__" in row_keys else None
        app_value = row[app_column] if app_column and app_column in row_keys else None
        text_value = row[text_column] if text_column and text_column in row_keys else None
        time_value = row[time_column] if time_column and time_column in row_keys else None
        id_value = row[id_column] if id_column and id_column in row_keys else None
        normalized_time = normalize_sqlite_time_value(time_value)
        decoded_text_hint = decode_activity_notification_text_hint(text_value)
        source_values = {
            column: row[column]
            for column in columns[:20]
            if column in row_keys
        }
        row_digest = hashlib.sha256(
            repr(sorted((key, str(value)) for key, value in source_values.items())).encode("utf-8", errors="replace")
        ).hexdigest()
        samples.append(
            {
                "timeline_type": str(profile.get("family") or "generic-system-sqlite"),
                "table": table_name,
                "rowid": row_id,
                "id_column": id_column,
                "id_preview": redact_scalar_preview(id_value),
                "app_column": app_column,
                "app_preview": redact_scalar_preview(app_value),
                "text_column": text_column,
                "text_preview": redact_scalar_preview(text_value),
                "decoded_text_hint": decoded_text_hint,
                "time_column": time_column,
                "time_preview": redact_scalar_preview(time_value),
                "normalized_time": normalized_time.get("iso8601"),
                "time_parse_status": normalized_time.get("parse_status"),
                "row_hash": row_digest,
                "source_locator": {
                    "viewer": "sqlite",
                    "table": table_name,
                    "rowid": row_id,
                    "id_column": id_column,
                    "time_column": time_column,
                },
                "reportability": "triage-timeline-candidate",
                "validation_required": True,
            }
        )
    return samples


def decode_activity_notification_text_hint(value: object) -> dict[str, object]:
    if value in (None, b""):
        return {"status": "empty", "format": "none", "preview": "", "text_sha256": ""}
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
        value_format = "bytes-text"
    else:
        text = str(value)
        value_format = "plain-text"
    stripped = text.strip()
    if not stripped:
        return {"status": "empty", "format": value_format, "preview": "", "text_sha256": ""}
    if "<" in stripped and ">" in stripped:
        value_format = "xml-or-html-text"
        stripped = re.sub(r"<[^>]+>", " ", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    return {
        "status": "decoded" if stripped else "empty-after-tag-strip",
        "format": value_format,
        "preview": stripped[:300],
        "text_sha256": hashlib.sha256(stripped.encode("utf-8", errors="replace")).hexdigest() if stripped else "",
        "validation_status": "triage-text-hint-unvalidated",
    }


def first_semantic_column(profile: Mapping[str, object], key: str) -> str | None:
    values = profile.get(key)
    if isinstance(values, list) and values:
        return str(values[0])
    return None


def redact_scalar_preview(value: object) -> dict[str, object]:
    redacted = redacted_sqlite_value(value)
    return {
        "type": redacted["type"],
        "preview": redacted["preview"],
        "sha256": redacted["sha256"],
    }


def normalize_sqlite_time_value(value: object) -> dict[str, object]:
    if value in (None, ""):
        return {"iso8601": None, "parse_status": "empty"}
    if isinstance(value, bytes):
        return {"iso8601": None, "parse_status": "bytes-not-decoded"}
    text = str(value).strip()
    if not text:
        return {"iso8601": None, "parse_status": "empty"}
    parsed = parse_numeric_timestamp(text)
    if parsed:
        return parsed
    try:
        normalized = text.replace("Z", "+00:00")
        return {"iso8601": dt.datetime.fromisoformat(normalized).astimezone(dt.timezone.utc).isoformat(), "parse_status": "iso8601"}
    except ValueError:
        return {"iso8601": None, "parse_status": "unrecognized"}


def parse_numeric_timestamp(text: str) -> dict[str, object] | None:
    if not re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    candidates: list[tuple[str, float]] = []
    if value > 11_644_473_600_000_000:
        candidates.append(("windows-filetime-100ns", (value - 116_444_736_000_000_000) / 10_000_000))
    if value > 11_644_473_600_000:
        candidates.append(("webkit-microseconds", (value / 1_000_000) - 11_644_473_600))
    if value > 1_000_000_000_000:
        candidates.append(("unix-milliseconds", value / 1_000))
    if 0 < value < 4_102_444_800:
        candidates.append(("unix-seconds", value))
    for parse_status, seconds in candidates:
        try:
            moment = dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            continue
        if 1970 <= moment.year <= 2100:
            return {"iso8601": moment.isoformat(), "parse_status": parse_status}
    return {"iso8601": None, "parse_status": "numeric-out-of-range"}


def redacted_sqlite_value(value: object) -> dict[str, object]:
    if value is None:
        return {"type": "null", "preview": "", "sha256": ""}
    if isinstance(value, bytes):
        preview = value[:16].hex()
        digest_source = value
        value_type = "bytes"
    else:
        text = str(value)
        preview = text[:80]
        digest_source = text.encode("utf-8", errors="replace")
        value_type = type(value).__name__
    return {
        "type": value_type,
        "preview": preview,
        "sha256": hashlib.sha256(digest_source).hexdigest(),
    }


def parse_web_server_log_lines(lines: list[str], *, max_rows: int = 200) -> dict[str, object]:
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    apache_rows: list[dict[str, str]] = []
    json_rows: list[dict[str, str]] = []
    key_value_rows: list[dict[str, str]] = []
    for line in lines:
        if line.startswith("#Fields:"):
            fields = line.split(":", 1)[1].strip().split()
            continue
        if line.startswith("#") or not line.strip():
            continue
        if fields:
            values = line.split()
            rows.append({field: values[index] if index < len(values) else "" for index, field in enumerate(fields)})
        else:
            json_row = parse_json_web_log_line(line)
            if json_row:
                json_rows.append(json_row)
            else:
                apache = parse_apache_combined_line(line)
                if apache:
                    apache_rows.append(apache)
                else:
                    key_value_row = parse_key_value_web_log_line(line)
                    if key_value_row:
                        key_value_rows.append(key_value_row)
        if len(rows) + len(apache_rows) + len(json_rows) + len(key_value_rows) >= max_rows:
            break
    normalized = rows or apache_rows or json_rows or key_value_rows
    status_counts: dict[str, int] = {}
    methods: dict[str, int] = {}
    uri_samples: list[str] = []
    suspicious_requests: list[dict[str, object]] = []
    timeline_samples: list[dict[str, object]] = []
    for row in normalized:
        status = row.get("sc-status") or row.get("status") or ""
        method = row.get("cs-method") or row.get("method") or ""
        uri = normalized_request_uri(row)
        time_profile = normalize_web_log_time(row)
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
        if method:
            methods[method] = methods.get(method, 0) + 1
        if uri and len(uri_samples) < 25:
            uri_samples.append(uri)
        if time_profile["iso8601"] and len(timeline_samples) < 50:
            timeline_samples.append(web_log_timeline_sample(row, uri, time_profile))
        suspicious_profile = web_request_suspicion_profile(row, uri, time_profile=time_profile)
        if suspicious_profile["risk_flags"] and len(suspicious_requests) < 25:
            suspicious_requests.append(suspicious_profile)
    return {
        "profile_version": "web-server-log-parse-profile-v1",
        "format": "iis-w3c" if rows else ("apache-nginx-combined" if apache_rows else ("json-lines" if json_rows else ("key-value" if key_value_rows else "unknown"))),
        "fields": fields,
        "parsed_row_count": len(normalized),
        "status_counts": status_counts,
        "method_counts": methods,
        "uri_samples": uri_samples,
        "timeline_sample_count": len(timeline_samples),
        "timeline_samples": timeline_samples,
        "suspicious_request_count": len(suspicious_requests),
        "suspicious_requests": suspicious_requests,
        "row_samples": normalized[:25],
        "field_parse_status": "parsed" if normalized else "sample-only",
    }


APACHE_COMBINED_RE = re.compile(
    r'(?P<remote>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_apache_combined_line(line: str) -> dict[str, str] | None:
    match = APACHE_COMBINED_RE.search(line)
    if not match:
        return None
    return match.groupdict()


def parse_json_web_log_line(line: str) -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    uri = first_json_log_value(payload, "uri", "request_uri", "path", "url", "request")
    method = first_json_log_value(payload, "method", "request_method", "http_method")
    status = first_json_log_value(payload, "status", "status_code", "response_status")
    timestamp = first_json_log_value(payload, "time", "timestamp", "@timestamp", "time_iso8601", "datetime")
    remote = first_json_log_value(payload, "remote", "remote_addr", "client_ip", "source_ip", "ip")
    user_agent = first_json_log_value(payload, "user_agent", "http_user_agent", "agent")
    referer = first_json_log_value(payload, "referer", "http_referer", "referrer")
    if not any((uri, method, status, timestamp, remote)):
        return None
    return {
        "uri": uri,
        "method": method,
        "status": status,
        "time": timestamp,
        "remote": remote,
        "user_agent": user_agent,
        "referer": referer,
        "json_log": "true",
    }


def first_json_log_value(payload: Mapping[str, object], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def parse_key_value_web_log_line(line: str) -> dict[str, str] | None:
    if "=" not in line:
        return None
    try:
        parts = shlex.split(line, posix=True)
    except ValueError:
        parts = line.split()
    pairs: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip().strip('"')
        if key:
            pairs[key] = value
    if len(pairs) < 2:
        return None
    uri = first_key_value_log_value(pairs, "uri", "request_uri", "path", "url", "request", "cs_uri_stem")
    method = first_key_value_log_value(pairs, "method", "request_method", "http_method", "cs_method")
    status = first_key_value_log_value(pairs, "status", "status_code", "response_status", "sc_status")
    timestamp = first_key_value_log_value(pairs, "time", "ts", "timestamp", "datetime", "time_iso8601", "@timestamp")
    remote = first_key_value_log_value(pairs, "remote", "remote_addr", "client_ip", "source_ip", "src", "ip", "c_ip")
    user_agent = first_key_value_log_value(pairs, "user_agent", "ua", "agent", "http_user_agent")
    referer = first_key_value_log_value(pairs, "referer", "referrer", "http_referer")
    query = first_key_value_log_value(pairs, "query", "cs_uri_query")
    if not any((uri, method, status, timestamp, remote)):
        return None
    return {
        "uri": uri,
        "method": method,
        "status": status,
        "time": timestamp,
        "remote": remote,
        "user_agent": user_agent,
        "referer": referer,
        "cs-uri-query": query,
        "key_value_log": "true",
        "raw_key_count": str(len(pairs)),
    }


def first_key_value_log_value(payload: Mapping[str, str], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


WEB_REQUEST_SUSPICIOUS_TOKENS = (
    "cmd=",
    "powershell",
    "whoami",
    "base64",
    "../",
    "..%2f",
    "eval",
    "upload",
    "shell",
    "passwd",
    "proc/self",
)


def normalized_request_uri(row: Mapping[str, str]) -> str:
    stem = row.get("cs-uri-stem") or row.get("uri") or row.get("request_uri") or row.get("path") or row.get("url") or ""
    query = row.get("cs-uri-query") or ""
    if query and query != "-" and "?" not in stem:
        return f"{stem}?{query}"
    return stem


def normalize_web_log_time(row: Mapping[str, str]) -> dict[str, object]:
    date_value = row.get("date") or ""
    time_value = row.get("time") or ""
    if date_value and time_value and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_value):
        raw = f"{date_value} {time_value}"
        try:
            moment = dt.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
            return {"raw": raw, "iso8601": moment.isoformat(), "parse_status": "iis-w3c-utc"}
        except ValueError:
            return {"raw": raw, "iso8601": None, "parse_status": "iis-w3c-unrecognized"}
    if time_value:
        normalized = time_value.replace("Z", "+00:00")
        try:
            moment = dt.datetime.fromisoformat(normalized)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=dt.timezone.utc)
            return {"raw": time_value, "iso8601": moment.astimezone(dt.timezone.utc).isoformat(), "parse_status": "json-iso8601"}
        except ValueError:
            pass
        try:
            moment = dt.datetime.strptime(time_value, "%d/%b/%Y:%H:%M:%S %z")
            return {"raw": time_value, "iso8601": moment.astimezone(dt.timezone.utc).isoformat(), "parse_status": "apache-nginx-offset"}
        except ValueError:
            return {"raw": time_value, "iso8601": None, "parse_status": "apache-nginx-unrecognized"}
    return {"raw": "", "iso8601": None, "parse_status": "missing"}


def web_log_timeline_sample(row: Mapping[str, str], uri: str, time_profile: Mapping[str, object]) -> dict[str, object]:
    method = row.get("cs-method") or row.get("method") or ""
    status = row.get("sc-status") or row.get("status") or ""
    source_ip = row.get("c-ip") or row.get("remote") or row.get("remote_addr") or row.get("client_ip") or row.get("source_ip") or ""
    row_material = {
        "time": time_profile.get("raw"),
        "method": method,
        "uri": uri,
        "status": status,
        "source_ip": source_ip,
    }
    return {
        "timeline_type": "web-request",
        "normalized_time": time_profile.get("iso8601"),
        "time_parse_status": time_profile.get("parse_status"),
        "method": method,
        "status": status,
        "source_ip": source_ip,
        "uri": uri[:500],
        "uri_sha256": hashlib.sha256(uri.encode("utf-8", errors="replace")).hexdigest(),
        "row_hash": hashlib.sha256(repr(sorted(row_material.items())).encode("utf-8", errors="replace")).hexdigest(),
        "reportability": "triage-timeline-candidate",
        "validation_required": True,
    }


def web_request_suspicion_profile(row: Mapping[str, str], uri: str, *, time_profile: Mapping[str, object] | None = None) -> dict[str, object]:
    decoded_uri = decode_url_for_triage(uri)
    decoded_query = decode_url_for_triage(row.get("cs-uri-query", ""))
    haystack = " ".join(
        str(value)
        for value in [
            uri,
            decoded_uri,
            row.get("cs-uri-query", ""),
            decoded_query,
            row.get("user_agent", ""),
            row.get("referer", ""),
        ]
    ).lower()
    flags = [token for token in WEB_REQUEST_SUSPICIOUS_TOKENS if token in haystack]
    query_keys = extract_query_keys(uri)
    method = row.get("cs-method") or row.get("method") or ""
    status = row.get("sc-status") or row.get("status") or ""
    current_time_profile = time_profile or normalize_web_log_time(row)
    return {
        "method": method,
        "status": status,
        "uri": uri[:500],
        "decoded_uri_preview": decoded_uri[:500],
        "decoded_uri_sha256": hashlib.sha256(decoded_uri.encode("utf-8", errors="replace")).hexdigest(),
        "url_decode_applied": decoded_uri != uri,
        "uri_sha256": hashlib.sha256(uri.encode("utf-8", errors="replace")).hexdigest(),
        "query_keys": query_keys,
        "risk_flags": flags,
        "risk_score": min(100, len(flags) * 20 + (10 if method.upper() == "POST" else 0)),
        "source_ip": row.get("c-ip") or row.get("remote") or row.get("remote_addr") or row.get("client_ip") or row.get("source_ip") or "",
        "time": current_time_profile.get("raw"),
        "normalized_time": current_time_profile.get("iso8601"),
        "time_parse_status": current_time_profile.get("parse_status"),
    }


def decode_url_for_triage(value: str, *, rounds: int = 2, limit: int = 2000) -> str:
    decoded = str(value or "")[:limit]
    for _ in range(max(1, rounds)):
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded[:limit]
    return decoded


def extract_query_keys(uri: str, *, limit: int = 25) -> list[str]:
    decoded_uri = decode_url_for_triage(uri)
    query_source = uri if "?" in uri else decoded_uri
    if "?" not in query_source:
        return []
    query = query_source.split("?", 1)[1]
    keys: list[str] = []
    for pair in re.split(r"[&;]", query):
        if not pair:
            continue
        decoded_pair = decode_url_for_triage(pair)
        key = decoded_pair.split("=", 1)[0]
        if key and key not in keys:
            keys.append(key[:80])
        if len(keys) >= limit:
            break
    return keys


def correlate_web_requests_to_files(root: Path, parsed_log: Mapping[str, object]) -> dict[str, object]:
    uri_samples = parsed_log.get("uri_samples") if isinstance(parsed_log.get("uri_samples"), list) else []
    basename_sources = web_request_basename_sources(uri_samples)
    basenames = set(basename_sources)
    matches: list[dict[str, object]] = []
    if basenames:
        for candidate in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if len(matches) >= 50:
                break
            if not candidate.is_file() or candidate.name.lower() not in basenames:
                continue
            basename_source = basename_sources.get(candidate.name.lower(), {})
            matches.append(
                {
                    "request_basename": candidate.name,
                    "request_basename_source": basename_source.get("source", "raw"),
                    "request_uri_sample": basename_source.get("uri", ""),
                    "request_decoded_uri_sample": basename_source.get("decoded_uri", ""),
                    "source_path": str(candidate.resolve()),
                    "source_sha256": compute_sha256(candidate),
                    "extension": candidate.suffix.lower(),
                    "webshell_extension": candidate.suffix.lower() in {".asp", ".aspx", ".ashx", ".asmx", ".php", ".jsp", ".jspx", ".cshtml"},
                }
            )
    return {
        "profile_version": "web-request-file-correlation-v1",
        "matched_source_count": len(matches),
        "matches": matches,
        "correlation_status": "matched" if matches else "no-source-match",
    }


def web_request_basename_sources(uri_samples: Sequence[object]) -> dict[str, dict[str, str]]:
    sources: dict[str, dict[str, str]] = {}
    for value in uri_samples:
        uri = str(value)
        decoded_uri = decode_url_for_triage(uri)
        for source, candidate_uri in (("raw", uri), ("decoded", decoded_uri)):
            basename = Path(candidate_uri.split("?", 1)[0]).name.lower()
            if basename and basename not in sources:
                sources[basename] = {
                    "source": source,
                    "uri": uri[:500],
                    "decoded_uri": decoded_uri[:500],
                }
    return sources


def collect_webshell_and_server_log_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        lowered = str(path).lower()
        suffix = path.suffix.lower()
        if suffix in {".asp", ".aspx", ".ashx", ".asmx", ".php", ".jsp", ".jspx", ".cshtml"}:
            yield build_webshell_candidate(path, root=root)
        elif suffix in {".log", ".txt"} and any(token in lowered for token in ("inetpub", "logfiles", "apache", "nginx")):
            yield build_web_server_log_record(path, root)


def build_webshell_candidate(path: Path, *, root: Path | None = None) -> ArtifactRecord:
    text = preview_text(path, limit=20_000)
    lowered = text.lower()
    semantic_profile = webshell_semantic_profile(path, text)
    suspicious_terms = [
        term
        for term in (
            "eval(",
            "base64_decode",
            "cmd.exe",
            "powershell",
            "wscript.shell",
            "request[",
            "request.form",
            "request.querystring",
            "system(",
            "passthru(",
            "shell_exec",
            "processstartinfo",
        )
        if term in lowered
    ]
    suspicious_terms = sorted(set(suspicious_terms + list(semantic_profile.get("execution_primitives", []))))
    evidence_spans = webshell_evidence_spans(text, suspicious_terms)
    rule_sidecars = find_webshell_rule_sidecars(path)
    iis_site_correlation = correlate_webshell_to_iis_config(root, path) if root else {"status": "not-evaluated", "matches": []}
    web_log_correlation = correlate_webshell_to_web_logs(root, path) if root else {"status": "not-evaluated", "matches": []}
    stat_result = path.stat()
    timeline_correlation = webshell_timeline_correlation(stat_result, web_log_correlation)
    source_hash = compute_sha256(path)
    risk_score = webshell_risk_score(suspicious_terms, semantic_profile, rule_sidecars=rule_sidecars)
    citation_package = webshell_report_citation_package(
        path=path,
        source_hash=source_hash,
        stat_result=stat_result,
        semantic_profile=semantic_profile,
        evidence_spans=evidence_spans,
        rule_sidecars=rule_sidecars,
        iis_site_correlation=iis_site_correlation,
        web_log_correlation=web_log_correlation,
        timeline_correlation=timeline_correlation,
        risk_score=risk_score,
    )
    return ArtifactRecord(
        provider=WindowsSystemArtifactsProvider.name,
        artifact_type="webshell-source-candidate",
        path=str(path.resolve()),
        supported=True,
        details={
            **source_details(path, "web-source"),
            "source_hashes": {"sha256": source_hash},
            "extension": path.suffix.lower(),
            "suspicious_terms": suspicious_terms,
            "webshell_semantic_profile": semantic_profile,
            "webshell_evidence_spans": evidence_spans,
            "webshell_evidence_span_count": len(evidence_spans),
            "webshell_rule_sidecars": rule_sidecars,
            "webshell_rule_sidecar_count": len(rule_sidecars),
            "webshell_rule_validation_status": "sidecar-linked" if rule_sidecars else "not-attached",
            "iis_site_correlation": iis_site_correlation,
            "webshell_log_correlation": web_log_correlation,
            "webshell_timeline_correlation": timeline_correlation,
            "webshell_report_citation_package": citation_package,
            "webshell_report_citation_package_hash": citation_package["manifest_sha256"],
            "risk_score": risk_score,
            "preview": text[:1000],
            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
            "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
            "coverage_status": "source-rule-triage",
            "reportability": "triage",
            "parser_confidence": "medium" if suspicious_terms else "low",
            "validation_required": True,
            "validation_guidance": (
                "Web source file is rule-scored only. Confirm with web logs, filesystem timeline, malware analysis, "
                "and trusted webshell rule packs before report-grade attribution."
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "webshell-rule-pack-validation-required",
                "web-server-log-correlation-required",
            ],
        },
    )


def webshell_report_citation_package(
    *,
    path: Path,
    source_hash: str,
    stat_result,
    semantic_profile: Mapping[str, object],
    evidence_spans: Sequence[Mapping[str, object]],
    rule_sidecars: Sequence[Mapping[str, object]],
    iis_site_correlation: Mapping[str, object],
    web_log_correlation: Mapping[str, object],
    timeline_correlation: Mapping[str, object],
    risk_score: int,
) -> dict[str, object]:
    evidence_refs: list[dict[str, object]] = []
    for index, span in enumerate(evidence_spans[:10], start=1):
        evidence_refs.append(
            {
                "kind": "source-code-span",
                "ref_id": f"webshell-span-{index}",
                "source_sha256": source_hash,
                "term": str(span.get("term") or "")[:120],
                "line_number": span.get("line_number"),
                "column": span.get("column"),
                "text_offset": span.get("text_offset"),
                "line_sha256": span.get("line_sha256", ""),
                "source_viewer_locator": {
                    "viewer": "text-line-offset",
                    "line_number": span.get("line_number"),
                    "column": span.get("column"),
                    "text_offset": span.get("text_offset"),
                },
                "citation_text": (
                    f"{path.name}:L{span.get('line_number')}:"
                    f"C{span.get('column')} term={str(span.get('term') or '')[:80]}"
                ),
            }
        )
    for sidecar_index, sidecar in enumerate(rule_sidecars[:5], start=1):
        matches = sidecar.get("matches") if isinstance(sidecar.get("matches"), list) else []
        sidecar_hashes = sidecar.get("sidecar_hashes") if isinstance(sidecar.get("sidecar_hashes"), Mapping) else {}
        for match_index, match in enumerate(matches[:10], start=1):
            if not isinstance(match, Mapping):
                continue
            evidence_refs.append(
                {
                    "kind": "external-rule-sidecar",
                    "ref_id": f"webshell-rule-{sidecar_index}-{match_index}",
                    "rule": str(match.get("rule") or "")[:160],
                    "rule_sha256": str(match.get("rule_sha256") or ""),
                    "severity": str(match.get("severity") or "")[:80],
                    "tags": match.get("tags", []),
                    "sidecar_path": sidecar.get("path", ""),
                    "sidecar_sha256": sidecar_hashes.get("sha256", ""),
                    "validation_status": sidecar.get("validation_status", ""),
                    "source_viewer_locator": {
                        "viewer": "rule-sidecar-json",
                        "match_index": match_index - 1,
                    },
                }
            )
    iis_matches = iis_site_correlation.get("matches") if isinstance(iis_site_correlation.get("matches"), list) else []
    if iis_matches:
        match = iis_matches[0]
        if isinstance(match, Mapping):
            evidence_refs.append(
                {
                    "kind": "iis-site-correlation",
                    "ref_id": "webshell-iis-site-1",
                    "site_name": match.get("site_name", ""),
                    "application_pool": match.get("application_pool", ""),
                    "relative_webshell_path": match.get("relative_webshell_path", ""),
                    "config_path": match.get("config_path", ""),
                    "config_sha256": match.get("config_sha256", ""),
                    "match_basis": match.get("match_basis", ""),
                    "source_viewer_locator": {
                        "viewer": "iis-applicationhost-config",
                        "site_name": match.get("site_name", ""),
                        "application_path": match.get("application_path", ""),
                    },
                }
            )
    if web_log_correlation.get("status") == "matched":
        evidence_refs.append(
            {
                "kind": "web-log-correlation",
                "ref_id": "webshell-web-log-summary",
                "matched_request_count": web_log_correlation.get("matched_request_count", 0),
                "suspicious_request_count": web_log_correlation.get("suspicious_request_count", 0),
                "first_seen": web_log_correlation.get("first_seen"),
                "last_seen": web_log_correlation.get("last_seen"),
                "source_ips": web_log_correlation.get("source_ips", []),
                "source_viewer_locator": {
                    "viewer": "web-log-correlation",
                    "match_count": web_log_correlation.get("matched_request_count", 0),
                },
            }
        )
    if timeline_correlation.get("relation") and timeline_correlation.get("relation") != "log-correlation-not-available":
        evidence_refs.append(
            {
                "kind": "filesystem-log-timeline",
                "ref_id": "webshell-timeline-1",
                "relation": timeline_correlation.get("relation"),
                "source_modified_at": timeline_correlation.get("source_modified_at"),
                "first_log_seen": timeline_correlation.get("first_log_seen"),
                "seconds_from_modified_to_first_log": timeline_correlation.get("seconds_from_modified_to_first_log"),
                "source_viewer_locator": {
                    "viewer": "timeline",
                    "basis": "source-mtime-to-web-log-first-seen",
                },
            }
        )
    package: dict[str, object] = {
        "manifest_version": "webshell-report-citation-package-v1",
        "artifact_type": "webshell-source-candidate",
        "parser": PARSER_VERSION,
        "source": {
            "path": str(path.resolve()),
            "name": path.name,
            "sha256": source_hash,
            "size": stat_result.st_size,
            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
        },
        "primary_findings": {
            "language_family": semantic_profile.get("language_family", "unknown"),
            "risk_score": risk_score,
            "review_priority": semantic_profile.get("review_priority", ""),
            "execution_primitives": semantic_profile.get("execution_primitives", []),
            "request_parameter_count": len(semantic_profile.get("request_parameters", []))
            if isinstance(semantic_profile.get("request_parameters"), list)
            else 0,
            "rule_sidecar_count": len(rule_sidecars),
            "matched_request_count": web_log_correlation.get("matched_request_count", 0),
        },
        "evidence_refs": evidence_refs,
        "evidence_ref_count": len(evidence_refs),
        "reportability": {
            "allowed_use": "webshell-triage-correlation-package",
            "ready_for_court_report": False,
            "validation_required": True,
            "blockers": [
                "trusted-webshell-rule-pack-diff-required",
                "full-web-server-log-corpus-required",
                "mft-usn-timeline-required",
                "manual-malware-review-required",
            ],
        },
    }
    package["manifest_sha256"] = stable_windows_system_json_sha256(
        {key: value for key, value in package.items() if key != "manifest_sha256"}
    )
    return package


def stable_windows_system_json_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def find_webshell_rule_sidecars(path: Path) -> list[dict[str, object]]:
    candidates = [
        path.with_suffix(path.suffix + ".yara.json"),
        path.with_suffix(path.suffix + ".rulematch.json"),
        path.with_suffix(path.suffix + ".rules.json"),
        path.with_suffix(".yara.json"),
        path.with_suffix(".rulematch.json"),
    ]
    sidecars: list[dict[str, object]] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        payload, status, error = load_webshell_rule_sidecar(candidate)
        sidecar: dict[str, object] = {
            "path": str(candidate.resolve()),
            "sidecar_hashes": {"sha256": compute_sha256(candidate)},
            "source_sha256": compute_sha256(path),
            "parse_status": status,
            "validation_status": "external-rule-sidecar-untrusted",
            "tool_hint": webshell_rule_tool_hint(candidate),
        }
        if error:
            sidecar["error"] = error
        if isinstance(payload, Mapping):
            sidecar["matches"] = normalize_webshell_rule_matches(payload)
            sidecar["match_count"] = len(sidecar["matches"]) if isinstance(sidecar["matches"], list) else 0
        sidecars.append(sidecar)
    return sidecars


def load_webshell_rule_sidecar(path: Path, *, max_bytes: int = 2 * 1024 * 1024) -> tuple[object | None, str, str]:
    try:
        if path.stat().st_size > max_bytes:
            return None, "too-large", f"sidecar exceeds {max_bytes} bytes"
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, "parse-failed", str(exc)[:120]
    return payload, "parsed" if isinstance(payload, Mapping) else "unsupported-json-root", ""


def webshell_rule_tool_hint(path: Path) -> str:
    name = path.name.lower()
    if "yara" in name:
        return "yara-json"
    if "rule" in name:
        return "rulematch-json"
    return "generic-rule-json"


def normalize_webshell_rule_matches(payload: Mapping[str, object], *, limit: int = 50) -> list[dict[str, object]]:
    raw_matches = payload.get("matches")
    if raw_matches is None and payload.get("rule"):
        raw_matches = [payload]
    if not isinstance(raw_matches, Sequence) or isinstance(raw_matches, (str, bytes, bytearray)):
        return []
    matches: list[dict[str, object]] = []
    for raw_match in raw_matches[:limit]:
        if not isinstance(raw_match, Mapping):
            continue
        rule_name = str(raw_match.get("rule") or raw_match.get("rule_name") or raw_match.get("name") or "")[:160]
        tags = raw_match.get("tags") if isinstance(raw_match.get("tags"), Sequence) and not isinstance(raw_match.get("tags"), (str, bytes, bytearray)) else []
        meta = raw_match.get("meta") if isinstance(raw_match.get("meta"), Mapping) else {}
        matches.append(
            {
                "rule": rule_name,
                "rule_sha256": hashlib.sha256(rule_name.encode("utf-8", errors="replace")).hexdigest() if rule_name else "",
                "tags": [str(tag)[:80] for tag in tags[:20]],
                "meta_keys": sorted(str(key)[:80] for key in meta.keys())[:20],
                "severity": str(raw_match.get("severity") or meta.get("severity") or "")[:80],
                "namespace": str(raw_match.get("namespace") or "")[:120],
                "validation_required": True,
            }
        )
    return matches


def correlate_webshell_to_iis_config(root: Path, path: Path) -> dict[str, object]:
    config_profiles = iis_application_host_profiles(root)
    matches: list[dict[str, object]] = []
    resolved_path = path.resolve()
    for profile in config_profiles:
        for site in profile.get("sites", []):
            if not isinstance(site, Mapping):
                continue
            for application in site.get("applications", []):
                if not isinstance(application, Mapping):
                    continue
                physical_root = application.get("resolved_physical_path")
                if not isinstance(physical_root, str) or not physical_root:
                    continue
                try:
                    relative_path = resolved_path.relative_to(Path(physical_root).resolve())
                except (OSError, ValueError):
                    continue
                app_pool = str(application.get("application_pool") or site.get("application_pool") or "")
                matches.append(
                    {
                        "config_path": profile.get("config_path", ""),
                        "config_sha256": profile.get("config_sha256", ""),
                        "site_name": site.get("name", ""),
                        "site_id": site.get("id", ""),
                        "bindings": site.get("bindings", []),
                        "application_path": application.get("path", ""),
                        "virtual_path": application.get("virtual_path", ""),
                        "physical_path": application.get("physical_path", ""),
                        "resolved_physical_path": physical_root,
                        "relative_webshell_path": str(relative_path),
                        "application_pool": app_pool,
                        "application_pool_identity": profile.get("application_pools", {}).get(app_pool, {}),
                        "match_basis": "webshell-under-iis-virtual-directory-root",
                        "validation_required": True,
                    }
                )
    return {
        "profile_version": "iis-webshell-site-correlation-v1",
        "status": "matched" if matches else ("no-match" if config_profiles else "applicationhost-config-not-found"),
        "config_count": len(config_profiles),
        "matched_site_count": len(matches),
        "matches": matches[:10],
        "validation_required": True,
        "commercial_grade_blockers": [
            "iis-config-parser-is-bounded-correlation-not-full-configuration-audit",
            "app-pool-runtime-identity-and-event-log-correlation-required",
        ],
    }


def correlate_webshell_to_web_logs(root: Path, path: Path, *, max_logs: int = 80) -> dict[str, object]:
    target_basename = path.name.lower()
    matches: list[dict[str, object]] = []
    source_ips: set[str] = set()
    normalized_times: list[str] = []
    suspicious_count = 0
    scanned_logs = 0
    for log_path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if scanned_logs >= max_logs or not log_path.is_file():
            continue
        lowered = str(log_path).lower()
        if log_path.suffix.lower() not in {".log", ".txt"} or not any(token in lowered for token in ("inetpub", "logfiles", "apache", "nginx")):
            continue
        scanned_logs += 1
        text = preview_text(log_path, limit=20_000)
        parsed_log = parse_web_server_log_lines([line for line in text.splitlines() if line.strip()])
        rows = parsed_log.get("row_samples") if isinstance(parsed_log.get("row_samples"), list) else []
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            uri = normalized_request_uri(row)
            decoded_uri = decode_url_for_triage(uri)
            raw_basename = Path(uri.split("?", 1)[0]).name.lower()
            decoded_basename = Path(decoded_uri.split("?", 1)[0]).name.lower()
            if target_basename not in {raw_basename, decoded_basename}:
                continue
            time_profile = normalize_web_log_time(row)
            suspicion = web_request_suspicion_profile(row, uri, time_profile=time_profile)
            source_ip = web_log_source_ip(row)
            if source_ip:
                source_ips.add(source_ip)
            normalized_time = time_profile.get("iso8601")
            if isinstance(normalized_time, str) and normalized_time:
                normalized_times.append(normalized_time)
            risk_flags = suspicion.get("risk_flags") if isinstance(suspicion.get("risk_flags"), list) else []
            if risk_flags:
                suspicious_count += 1
            matches.append(
                {
                    "log_path": str(log_path.resolve()),
                    "log_sha256": compute_sha256(log_path),
                    "log_format": parsed_log.get("format", "unknown"),
                    "method": row.get("cs-method") or row.get("method") or "",
                    "status": row.get("sc-status") or row.get("status") or "",
                    "source_ip": source_ip,
                    "uri": uri[:500],
                    "decoded_uri": decoded_uri[:500],
                    "url_decode_applied": decoded_uri != uri,
                    "normalized_time": normalized_time,
                    "time_parse_status": time_profile.get("parse_status"),
                    "risk_flags": risk_flags,
                    "query_keys": suspicion.get("query_keys", []),
                    "match_basis": "web-log-request-basename",
                    "validation_required": True,
                }
            )
    sorted_times = sorted(normalized_times)
    return {
        "profile_version": "webshell-log-correlation-v1",
        "status": "matched" if matches else "no-log-match",
        "scanned_log_count": scanned_logs,
        "matched_request_count": len(matches),
        "suspicious_request_count": suspicious_count,
        "source_ips": sorted(source_ips)[:50],
        "first_seen": sorted_times[0] if sorted_times else None,
        "last_seen": sorted_times[-1] if sorted_times else None,
        "matches": matches[:25],
        "validation_required": True,
        "commercial_grade_blockers": [
            "bounded-log-scan-not-full-server-log-corpus",
            "timezone-and-log-retention-validation-required",
        ],
    }


def webshell_timeline_correlation(stat_result, web_log_correlation: Mapping[str, object]) -> dict[str, object]:
    modified_at = isoformat_from_timestamp(stat_result.st_mtime)
    accessed_at = isoformat_from_timestamp(stat_result.st_atime)
    created_at = isoformat_from_timestamp(stat_result.st_ctime)
    first_seen = web_log_correlation.get("first_seen")
    last_seen = web_log_correlation.get("last_seen")
    delta_seconds: float | None = None
    relation = "log-correlation-not-available"
    if isinstance(first_seen, str) and first_seen:
        try:
            modified_dt = dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc)
            first_seen_dt = dt.datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            if first_seen_dt.tzinfo is None:
                first_seen_dt = first_seen_dt.replace(tzinfo=dt.timezone.utc)
            delta_seconds = round((first_seen_dt.astimezone(dt.timezone.utc) - modified_dt).total_seconds(), 3)
            if delta_seconds > 0:
                relation = "file-modified-before-first-log-hit"
            elif delta_seconds < 0:
                relation = "file-modified-after-first-log-hit"
            else:
                relation = "file-modified-at-first-log-hit"
        except ValueError:
            relation = "first-log-time-unparseable"
    return {
        "profile_version": "webshell-filesystem-log-timeline-v1",
        "source_modified_at": modified_at,
        "source_accessed_at": accessed_at,
        "source_metadata_changed_at": created_at,
        "first_log_seen": first_seen,
        "last_log_seen": last_seen,
        "seconds_from_modified_to_first_log": delta_seconds,
        "relation": relation,
        "matched_request_count": web_log_correlation.get("matched_request_count", 0),
        "suspicious_request_count": web_log_correlation.get("suspicious_request_count", 0),
        "validation_required": True,
        "commercial_grade_blockers": [
            "filesystem-timestamps-need-timezone-and-acquisition-validation",
            "mft-usn-timeline-correlation-required",
        ],
    }


def web_log_source_ip(row: Mapping[str, str]) -> str:
    return row.get("c-ip") or row.get("remote") or row.get("remote_addr") or row.get("client_ip") or row.get("source_ip") or ""


def iis_application_host_profiles(root: Path, *, max_configs: int = 20) -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
    for candidate in sorted(root.rglob("applicationHost.config"), key=lambda item: str(item).lower()):
        if len(profiles) >= max_configs:
            break
        if not candidate.is_file():
            continue
        profiles.append(parse_iis_application_host_config(root, candidate))
    return profiles


def parse_iis_application_host_config(root: Path, config_path: Path) -> dict[str, object]:
    profile: dict[str, object] = {
        "config_path": str(config_path.resolve()),
        "config_sha256": compute_sha256(config_path),
        "parse_status": "not-parsed",
        "sites": [],
        "application_pools": {},
    }
    try:
        tree = ET.parse(config_path)
    except (OSError, ET.ParseError) as exc:
        profile["parse_status"] = "parse-failed"
        profile["error"] = str(exc)[:160]
        return profile
    root_element = tree.getroot()
    application_pools: dict[str, dict[str, object]] = {}
    for pool in root_element.findall(".//applicationPools/add"):
        name = str(pool.attrib.get("name", ""))
        process_model = pool.find("processModel")
        identity = str(process_model.attrib.get("identityType", "")) if process_model is not None else ""
        username = str(process_model.attrib.get("userName", "")) if process_model is not None else ""
        if name:
            application_pools[name] = {
                "identity_type": identity,
                "user_name_present": bool(username),
                "user_name_sha256": hashlib.sha256(username.encode("utf-8", errors="replace")).hexdigest() if username else "",
            }
    sites: list[dict[str, object]] = []
    for site in root_element.findall(".//sites/site"):
        site_profile: dict[str, object] = {
            "name": site.attrib.get("name", ""),
            "id": site.attrib.get("id", ""),
            "application_pool": "",
            "bindings": [
                {
                    "protocol": binding.attrib.get("protocol", ""),
                    "binding_information": binding.attrib.get("bindingInformation", ""),
                }
                for binding in site.findall("./bindings/binding")
            ],
            "applications": [],
        }
        applications: list[dict[str, object]] = []
        for application in site.findall("./application"):
            app_pool = application.attrib.get("applicationPool", "")
            if app_pool and not site_profile["application_pool"]:
                site_profile["application_pool"] = app_pool
            for virtual_directory in application.findall("./virtualDirectory"):
                physical_path = virtual_directory.attrib.get("physicalPath", "")
                applications.append(
                    {
                        "path": application.attrib.get("path", ""),
                        "application_pool": app_pool,
                        "virtual_path": virtual_directory.attrib.get("path", ""),
                        "physical_path": physical_path,
                        "resolved_physical_path": str(resolve_iis_physical_path(root, physical_path)),
                    }
                )
        site_profile["applications"] = applications
        sites.append(site_profile)
    profile.update(
        {
            "parse_status": "parsed",
            "sites": sites,
            "site_count": len(sites),
            "application_pools": application_pools,
            "application_pool_count": len(application_pools),
        }
    )
    return profile


def resolve_iis_physical_path(root: Path, physical_path: str) -> Path:
    value = physical_path.replace("/", "\\")
    lowered = value.lower()
    if lowered.startswith("%systemdrive%\\"):
        return root / value.split("\\", 1)[1].replace("\\", "/")
    drive_match = re.match(r"^[A-Za-z]:\\(?P<rest>.*)", value)
    if drive_match:
        return root / drive_match.group("rest").replace("\\", "/")
    candidate = Path(physical_path)
    if candidate.is_absolute():
        return candidate
    return root / physical_path.replace("\\", "/")


def webshell_evidence_spans(text: str, terms: Sequence[str], *, limit: int = 50) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    lowered_terms = sorted({term.lower() for term in terms if term}, key=len, reverse=True)
    offset = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered_line = line.lower()
        for term in lowered_terms:
            column = lowered_line.find(term)
            if column < 0:
                continue
            preview = line.strip()[:500]
            spans.append(
                {
                    "term": term,
                    "line_number": line_number,
                    "column": column + 1,
                    "text_offset": offset + column,
                    "line_preview": preview,
                    "line_sha256": hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest(),
                    "source_quote_status": "bounded-line-preview",
                    "validation_required": True,
                }
            )
            if len(spans) >= limit:
                return spans
        offset += len(line) + 1
    return spans


def webshell_semantic_profile(path: Path, text: str) -> dict[str, object]:
    lowered = text.lower()
    execution_primitives = sorted(
        token
        for token in (
            "eval",
            "assert",
            "system",
            "passthru",
            "shell_exec",
            "exec",
            "cmd.exe",
            "powershell",
            "wscript.shell",
            "processstartinfo",
            "runtime.getruntime",
        )
        if token in lowered
    )
    request_parameters = extract_webshell_request_parameters(text)
    obfuscation_indicators = sorted(
        token
        for token in (
            "base64_decode",
            "frombase64string",
            "chr(",
            "charcode",
            "xor",
            "gzip",
            "deflate",
            "rot13",
        )
        if token in lowered
    )
    file_operation_indicators = sorted(
        token
        for token in (
            "upload",
            "saveas",
            "writeallbytes",
            "file_put_contents",
            "move_uploaded_file",
            "deletefile",
            "unlink(",
        )
        if token in lowered
    )
    return {
        "profile_version": "webshell-semantic-profile-v1",
        "language_family": webshell_language_family(path),
        "execution_primitives": execution_primitives,
        "request_parameters": request_parameters,
        "request_parameter_count": len(request_parameters),
        "obfuscation_indicators": obfuscation_indicators,
        "file_operation_indicators": file_operation_indicators,
        "review_priority": "high" if execution_primitives and request_parameters else ("medium" if execution_primitives or request_parameters else "low"),
        "source_code_semantics_status": "rule-profile-triage",
        "validation_required": True,
        "commercial_grade_blockers": [
            "yara-signature-pack-validation-required",
            "manual-malware-review-required",
            "server-log-and-filesystem-timeline-correlation-required",
        ],
    }


def webshell_language_family(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".asp", ".aspx", ".ashx", ".asmx", ".cshtml"}:
        return "asp-dotnet"
    if suffix == ".php":
        return "php"
    if suffix in {".jsp", ".jspx"}:
        return "java-jsp"
    return "unknown-web-source"


def extract_webshell_request_parameters(text: str, *, limit: int = 25) -> list[dict[str, object]]:
    patterns = [
        ("asp-request-indexer", r"(?i)\bRequest\s*\[\s*['\"](?P<name>[A-Za-z0-9_.:-]{1,80})['\"]\s*\]"),
        ("asp-request-querystring", r"(?i)\bRequest\.(?:QueryString|Form)\s*\(\s*['\"](?P<name>[A-Za-z0-9_.:-]{1,80})['\"]\s*\)"),
        ("php-request-array", r"(?i)\$_(?:REQUEST|GET|POST)\s*\[\s*['\"](?P<name>[A-Za-z0-9_.:-]{1,80})['\"]\s*\]"),
        ("jsp-get-parameter", r"(?i)\brequest\.getParameter\s*\(\s*['\"](?P<name>[A-Za-z0-9_.:-]{1,80})['\"]\s*\)"),
    ]
    seen: set[tuple[str, str]] = set()
    parameters: list[dict[str, object]] = []
    for basis, pattern in patterns:
        for match in re.finditer(pattern, text):
            name = match.group("name")
            key = (basis, name.lower())
            if key in seen:
                continue
            seen.add(key)
            parameters.append(
                {
                    "name": name,
                    "name_sha256": hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest(),
                    "match_basis": basis,
                    "text_offset": match.start("name"),
                    "validation_required": True,
                }
            )
            if len(parameters) >= limit:
                return parameters
    return parameters


def webshell_risk_score(
    suspicious_terms: Sequence[str],
    semantic_profile: Mapping[str, object],
    *,
    rule_sidecars: Sequence[Mapping[str, object]] | None = None,
) -> int:
    score = len(suspicious_terms) * 12
    if semantic_profile.get("execution_primitives"):
        score += 25
    if semantic_profile.get("request_parameters"):
        score += 25
    if semantic_profile.get("obfuscation_indicators"):
        score += 15
    if semantic_profile.get("file_operation_indicators"):
        score += 10
    if rule_sidecars:
        match_count = sum(int(sidecar.get("match_count", 0)) for sidecar in rule_sidecars if isinstance(sidecar.get("match_count", 0), int))
        score += min(25, match_count * 10)
    return min(100, score)


def build_web_server_log_record(path: Path, root: Path) -> ArtifactRecord:
    text = preview_text(path, limit=20_000)
    lines = [line for line in text.splitlines() if line.strip()]
    parsed_log = parse_web_server_log_lines(lines)
    request_file_correlation = correlate_web_requests_to_files(root, parsed_log)
    suspicious_lines = [
        line
        for line in lines[:1000]
        if any(token in line.lower() for token in ("cmd=", "powershell", "../", "eval", "base64", "upload"))
    ][:25]
    stat_result = path.stat()
    return ArtifactRecord(
        provider=WindowsSystemArtifactsProvider.name,
        artifact_type="web-server-log",
        path=str(path.resolve()),
        supported=True,
        details={
            **source_details(path, "web-server-log"),
            "source_hashes": {"sha256": compute_sha256(path)},
            "line_count_sampled": len(lines),
            "parsed_log": parsed_log,
            "parsed_row_count": parsed_log.get("parsed_row_count", 0),
            "request_file_correlation": request_file_correlation,
            "correlated_source_count": request_file_correlation.get("matched_source_count", 0),
            "suspicious_line_count": len(suspicious_lines),
            "suspicious_line_samples": suspicious_lines,
            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
            "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
            "coverage_status": "server-log-triage",
            "reportability": "triage",
            "parser_confidence": "medium",
            "validation_required": True,
            "validation_guidance": (
                "Server log is sampled for webshell and intrusion pivots. Full IIS/Apache/Nginx field parsing, "
                "timezone handling, and request-to-file correlation are required before report-grade conclusions."
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "iis-apache-nginx-field-parser-required",
                "webshell-source-log-correlation-required",
            ],
        },
    )


def collect_task_scheduler(root: Path) -> Iterable[ArtifactRecord]:
    tasks_root = root.joinpath(*TASKS_ROOT)
    if not tasks_root.is_dir():
        return
    for path in sorted((item for item in tasks_root.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        try:
            xml_root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        stat_result = path.stat()
        command = first_text(xml_root, "Command")
        arguments = first_text(xml_root, "Arguments")
        working_directory = first_text(xml_root, "WorkingDirectory")
        uri = first_text(xml_root, "URI") or "\\" + str(path.relative_to(tasks_root)).replace("/", "\\")
        triggers = [local_name(child.tag) for child in find_children(xml_root, "Triggers")]
        trigger_details = task_trigger_details(xml_root)
        action_details = task_action_details(xml_root)
        principal_details = task_principal_details(xml_root)
        temporal_profile = task_temporal_profile(xml_root, stat_result.st_mtime, trigger_details)
        risk_flags = task_scheduler_risk_flags(command, arguments, working_directory, uri)
        validation_checks = task_scheduler_validation_checks(
            command=command,
            arguments=arguments,
            working_directory=working_directory,
            uri=uri,
            risk_flags=risk_flags,
            trigger_details=trigger_details,
            action_details=action_details,
            principal_details=principal_details,
            temporal_profile=temporal_profile,
        )
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="task-scheduler-task",
            path=str(path.resolve()),
            supported=True,
            details=with_system_deep_parser_manifest("task-scheduler", {
                **source_details(path, "task-xml"),
                "task_uri": uri,
                "command": command,
                "arguments": arguments,
                "working_directory": working_directory,
                "action_preview": " ".join(item for item in (command, arguments) if item).strip(),
                "command_line": " ".join(item for item in (command, arguments) if item).strip(),
                "executable_name": windows_executable_name(command),
                "normalized_action": normalized_task_action(command, arguments, working_directory),
                "actions": action_details,
                "action_count": len(action_details),
                "author": first_text(xml_root, "Author"),
                "user_id": first_text(xml_root, "UserId"),
                "run_level": first_text(xml_root, "RunLevel"),
                "logon_type": first_text(xml_root, "LogonType"),
                "principals": principal_details,
                "principal_count": len(principal_details),
                "hidden": parse_bool_text(first_text(xml_root, "Hidden")),
                "trigger_types": triggers,
                "trigger_details": trigger_details,
                "trigger_count": len(trigger_details),
                "start_boundaries": all_text(xml_root, "StartBoundary"),
                "task_temporal_profile": temporal_profile,
                "coverage_status": "task-xml-normalized",
                "evidence_strength": "persistence-configuration",
                "reportability": "triage",
                "parser_confidence": "high" if command and uri else "medium",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "task-scheduler",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "risk_flags": risk_flags,
                        "actions": action_details,
                        "trigger_details": trigger_details,
                        "task_temporal_profile": temporal_profile,
                        "normalized_action": normalized_task_action(command, arguments, working_directory),
                    },
                ),
                "system_validation_matrix": system_validation_matrix("task-scheduler", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("task-scheduler", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "commercial_uplift_evidence": system_commercial_uplift_evidence(
                    "task-scheduler",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "artifact_type": "task-scheduler-task",
                        "system_validation_matrix": system_validation_matrix("task-scheduler", validation_checks),
                        "system_report_grade_assessment": system_report_grade_assessment("task-scheduler", validation_checks),
                    },
                ),
                "forensic_review": system_forensic_review(
                    "task-scheduler",
                    [
                        f"task_uri={uri}",
                        f"command={command}",
                        f"trigger_count={len(trigger_details)}",
                        f"principal_count={len(principal_details)}",
                    ],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "task-cache-registry-correlation-not-implemented",
                    "task-security-descriptor-validation-not-implemented",
                    "task-history-event-correlation-not-implemented",
                ],
                "validation_guidance": (
                    "Task XML is normalized for triage. Correlate with TaskCache registry keys, task security descriptors, "
                    "and task operational events before report-grade conclusions about creation, tampering, or execution."
                ),
                "risk_flags": risk_flags,
                "risk_score": min(100, len(risk_flags) * 12),
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "task_file_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            }),
        )


def collect_defender_support(root: Path) -> Iterable[ArtifactRecord]:
    support_root = root.joinpath(*DEFENDER_SUPPORT_ROOT)
    if not support_root.is_dir():
        return
    for path in sorted(support_root.glob("MPLog*.log"), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        lines = read_lines(path, limit=400)
        interesting = [
            line
            for line in lines
            if any(token in line.lower() for token in ("threat", "malware", "quarantine", "exclusion", "remediation"))
        ][:25]
        stat_result = path.stat()
        validation_checks = {
            "log_readable": True,
            "interesting_entries_present": bool(interesting),
            "threat_or_quarantine_terms_present": any(
                any(token in line.lower() for token in ("threat", "malware", "quarantine"))
                for line in interesting
            ),
            "defender_eventlog_correlated": False,
            "mpcmdrun_history_correlated": False,
            "signature_version_validated": False,
        }
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="defender-support-log",
            path=str(path.resolve()),
            supported=True,
            details=with_system_deep_parser_manifest("defender", {
                **source_details(path, "text-log"),
                "entry_count": len(lines),
                "interesting_entry_count": len(interesting),
                "interesting_entries": interesting,
                "coverage_status": "defender-mplog-triage",
                "reportability": "triage",
                "parser_confidence": "medium",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "defender",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "interesting_entries": interesting,
                    },
                ),
                "system_validation_matrix": system_validation_matrix("defender", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("defender", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "commercial_uplift_evidence": system_commercial_uplift_evidence(
                    "defender",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "artifact_type": "defender-support-log",
                        "system_validation_matrix": system_validation_matrix("defender", validation_checks),
                        "system_report_grade_assessment": system_report_grade_assessment("defender", validation_checks),
                    },
                ),
                "forensic_review": system_forensic_review(
                    "defender",
                    [f"entry_count={len(lines)}", f"interesting_entry_count={len(interesting)}"],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "defender_support_log_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": "\n".join(lines[:5]),
            }),
        )


def collect_firewall_logs(root: Path) -> Iterable[ArtifactRecord]:
    for parts in FIREWALL_LOG_PATHS:
        path = root.joinpath(*parts)
        if not path.is_file():
            continue
        rows = parse_firewall_log(path)
        stat_result = path.stat()
        validation_checks = {
            "w3c_fields_present": bool(rows),
            "blocked_entries_present": any(row.get("action", "").upper() == "DROP" for row in rows),
            "allowed_entries_present": any(row.get("action", "").upper() == "ALLOW" for row in rows),
            "firewall_rule_store_correlated": False,
            "firewall_policy_export_validated": False,
        }
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="firewall-log",
            path=str(path.resolve()),
            supported=True,
            details=with_system_deep_parser_manifest("firewall", {
                **source_details(path, "w3c-log"),
                "entry_count": len(rows),
                "blocked_count": sum(1 for row in rows if row.get("action", "").upper() == "DROP"),
                "sample_entries": rows[:20],
                "coverage_status": "firewall-w3c-log-normalized",
                "reportability": "triage",
                "parser_confidence": "medium" if rows else "low",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "firewall",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "sample_entries": rows[:20],
                    },
                ),
                "system_validation_matrix": system_validation_matrix("firewall", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("firewall", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "commercial_uplift_evidence": system_commercial_uplift_evidence(
                    "firewall",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "artifact_type": "firewall-log",
                        "system_validation_matrix": system_validation_matrix("firewall", validation_checks),
                        "system_report_grade_assessment": system_report_grade_assessment("firewall", validation_checks),
                    },
                ),
                "forensic_review": system_forensic_review(
                    "firewall",
                    [
                        f"entry_count={len(rows)}",
                        f"blocked_count={sum(1 for row in rows if row.get('action', '').upper() == 'DROP')}",
                    ],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "firewall_log_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            }),
        )


def collect_wer_reports(root: Path) -> Iterable[ArtifactRecord]:
    candidates: list[Path] = []
    programdata = root.joinpath(*WER_ROOTS[0])
    if programdata.is_dir():
        candidates.extend(path for path in programdata.rglob("Report.wer") if path.is_file())
    users = root / "Users"
    if users.is_dir():
        candidates.extend(path for path in users.rglob("Report.wer") if path.is_file() and "WER" in str(path))
    for path in sorted(set(candidates), key=lambda item: str(item).lower()):
        fields = parse_key_value_file(path)
        stat_result = path.stat()
        normalized = normalized_wer_report(path, fields)
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="wer-report",
            path=str(path.resolve()),
            supported=True,
            details=with_system_deep_parser_manifest("wer", {
                **source_details(path, "wer"),
                "event_type": fields.get("EventType", ""),
                "application": fields.get("AppName", fields.get("FriendlyEventName", "")),
                "module": fields.get("FaultModuleName", ""),
                "bucket": fields.get("Bucket", fields.get("Response.BucketId", "")),
                **normalized,
                "fields": fields,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            }),
        )


def collect_wmi_repository(root: Path) -> Iterable[ArtifactRecord]:
    repository = root.joinpath(*WMI_REPOSITORY_ROOT)
    if not repository.is_dir():
        return
    for path in sorted((item for item in repository.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        if path.name.upper() not in WMI_REPOSITORY_NAMES and path.suffix.upper() not in WMI_REPOSITORY_SUFFIXES:
            continue
        stat_result = path.stat()
        pivots = wmi_repository_pivots(path)
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="wmi-repository-file",
            path=str(path.resolve()),
            supported=True,
            details=with_system_deep_parser_manifest("wmi", {
                **source_details(path, "wmi-repository"),
                "entry_name": path.name,
                "relative_repository_path": str(path.relative_to(repository)),
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "wmi_repository_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                **pivots,
                "note": "WMI repository file inventoried with bounded string pivots for persistence review; validate findings with a dedicated WMI repository parser.",
            }),
        )


def collect_zone_identifier_ads(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*Zone.Identifier"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        match = ZONE_IDENTIFIER_PATTERN.match(path.name)
        target_name = match.group("target") if match else path.name
        fields = parse_key_value_file(path)
        stat_result = path.stat()
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="zone-identifier",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "ini-ads-export"),
                "target_name": target_name,
                "zone_id": fields.get("ZoneId", ""),
                "referrer_url": fields.get("ReferrerUrl", ""),
                "host_url": fields.get("HostUrl", ""),
                "fields": fields,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "raw_preview": preview_text(path),
            },
        )


def source_details(path: Path, source_format: str) -> dict[str, object]:
    return {
        "parser": "windows-system-artifacts",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_size": path.stat().st_size,
    }


def first_text(root: ET.Element, target_name: str) -> str:
    for element in root.iter():
        if local_name(element.tag) == target_name and element.text:
            return element.text.strip()
    return ""


def all_text(root: ET.Element, target_name: str) -> list[str]:
    values: list[str] = []
    for element in root.iter():
        if local_name(element.tag) == target_name and element.text:
            values.append(element.text.strip())
    return values


def find_children(root: ET.Element, target_name: str) -> list[ET.Element]:
    for element in root.iter():
        if local_name(element.tag) == target_name:
            return list(element)
    return []


def first_element(root: ET.Element, target_name: str) -> ET.Element | None:
    for element in root.iter():
        if local_name(element.tag) == target_name:
            return element
    return None


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def parse_bool_text(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def task_scheduler_risk_flags(command: str, arguments: str, working_directory: str, uri: str) -> list[str]:
    haystack = " ".join((command, arguments, working_directory, uri)).lower()
    flags: list[str] = []
    for term in TASK_SUSPICIOUS_TERMS:
        if term in haystack:
            flags.append(f"task-string:{term.strip('-').replace('://', '')}")
    normalized_command = command.strip().lower().replace("/", "\\").rsplit("\\", 1)[-1]
    if normalized_command in TASK_LOLBINS:
        flags.append(f"task-lolbin:{normalized_command}")
    if any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS):
        flags.append("task-user-writable-path")
    if uri.lower().startswith(r"\microsoft\windows") and "task-user-writable-path" in flags:
        flags.append("task-microsoft-path-user-payload")
    return unique_preserve_order(flags)


def task_action_details(root: ET.Element) -> list[dict[str, object]]:
    actions_element = first_element(root, "Actions")
    if actions_element is None:
        return []
    context = actions_element.attrib.get("Context", "")
    actions: list[dict[str, object]] = []
    for action in list(actions_element):
        action_type = local_name(action.tag)
        command = first_text(action, "Command")
        arguments = first_text(action, "Arguments")
        working_directory = first_text(action, "WorkingDirectory")
        actions.append(
            {
                "action_type": action_type,
                "context": context,
                "command": command,
                "arguments": arguments,
                "working_directory": working_directory,
                "command_line": " ".join(item for item in (command, arguments) if item).strip(),
                "executable_name": windows_executable_name(command),
                "path_category": windows_path_category(command, " ".join((arguments, working_directory))),
            }
        )
    return actions


def task_trigger_details(root: ET.Element) -> list[dict[str, object]]:
    triggers_element = first_element(root, "Triggers")
    if triggers_element is None:
        return []
    details: list[dict[str, object]] = []
    for trigger in list(triggers_element):
        details.append(
            {
                "trigger_type": local_name(trigger.tag),
                "enabled": parse_bool_text(first_text(trigger, "Enabled")),
                "start_boundary": first_text(trigger, "StartBoundary"),
                "end_boundary": first_text(trigger, "EndBoundary"),
                "subscription": first_text(trigger, "Subscription"),
                "delay": first_text(trigger, "Delay"),
            }
        )
    return details


def task_principal_details(root: ET.Element) -> list[dict[str, str]]:
    principals_element = first_element(root, "Principals")
    if principals_element is None:
        return []
    principals: list[dict[str, str]] = []
    for principal in list(principals_element):
        principals.append(
            {
                "id": principal.attrib.get("id", ""),
                "user_id": first_text(principal, "UserId"),
                "group_id": first_text(principal, "GroupId"),
                "run_level": first_text(principal, "RunLevel"),
                "logon_type": first_text(principal, "LogonType"),
            }
        )
    return principals


def task_temporal_profile(
    root: ET.Element,
    file_modified_timestamp: float,
    trigger_details: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    registration_date = first_text(root, "Date")
    start_boundaries = [str(item.get("start_boundary") or "") for item in trigger_details if item.get("start_boundary")]
    end_boundaries = [str(item.get("end_boundary") or "") for item in trigger_details if item.get("end_boundary")]
    enabled_values = [item.get("enabled") for item in trigger_details if item.get("enabled") is not None]
    return {
        "profile_version": "task-temporal-profile-v1",
        "registration_date": registration_date,
        "file_modified_at": isoformat_from_timestamp(file_modified_timestamp),
        "start_boundaries": start_boundaries,
        "end_boundaries": end_boundaries,
        "enabled_trigger_count": sum(1 for value in enabled_values if bool(value)),
        "disabled_trigger_count": sum(1 for value in enabled_values if not bool(value)),
        "timestamp_sources": [
            item
            for item in [
            "RegistrationInfo/Date" if registration_date else "",
            "Triggers/*/StartBoundary" if start_boundaries else "",
            "Triggers/*/EndBoundary" if end_boundaries else "",
            "task_file_modified_at",
            ]
            if item
        ],
        "validation_status": "xml-time-candidates-not-execution-proof",
        "reportability_warning": "Task XML times describe configuration metadata and trigger schedule candidates; correlate with TaskScheduler Operational EVTX before claiming execution.",
    }


def normalized_task_action(command: str, arguments: str, working_directory: str) -> dict[str, str]:
    return {
        "command": command,
        "arguments": arguments,
        "working_directory": working_directory,
        "command_line": " ".join(item for item in (command, arguments) if item).strip(),
        "executable_name": windows_executable_name(command),
        "path_category": windows_path_category(command, " ".join((arguments, working_directory))),
    }


def task_scheduler_validation_checks(
    *,
    command: str,
    arguments: str,
    working_directory: str,
    uri: str,
    risk_flags: list[str],
    trigger_details: list[dict[str, object]],
    action_details: list[dict[str, object]],
    principal_details: list[dict[str, str]],
    temporal_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    haystack = " ".join((command, arguments, working_directory)).lower()
    temporal_profile = temporal_profile or {}
    return {
        "xml_parsed": True,
        "has_task_uri": bool(uri),
        "has_exec_action": any(action.get("action_type") == "Exec" for action in action_details),
        "has_command": bool(command),
        "has_arguments": bool(arguments),
        "has_trigger": bool(trigger_details),
        "has_principal": bool(principal_details),
        "has_task_temporal_metadata": bool(
            temporal_profile.get("registration_date")
            or temporal_profile.get("start_boundaries")
            or temporal_profile.get("file_modified_at")
        ),
        "microsoft_namespace": uri.lower().startswith(r"\microsoft\windows"),
        "command_uses_lolbin": any(flag.startswith("task-lolbin:") for flag in risk_flags),
        "references_user_writable_path": any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS),
        "taskcache_registry_validated": False,
        "security_descriptor_validated": False,
        "task_history_events_correlated": False,
    }


def system_validation_matrix(artifact_family: str, checks: dict[str, object]) -> list[dict[str, object]]:
    base = [
        {
            "id": f"{artifact_family}-source-parsed",
            "label": "Source artifact parsed into normalized triage fields",
            "passed": True,
            "severity": "medium",
        },
    ]
    if artifact_family == "task-scheduler":
        base.extend(
            [
                {
                    "id": "task-exec-action",
                    "label": "Task XML has an executable action and command pivot",
                    "passed": bool(checks.get("has_exec_action") and checks.get("has_command")),
                    "severity": "high",
                },
                {
                    "id": "task-temporal-metadata",
                    "label": "Task XML registration, trigger, and source file time metadata preserved",
                    "passed": bool(checks.get("has_task_temporal_metadata")),
                    "severity": "medium",
                },
                {
                    "id": "task-report-grade-correlation",
                    "label": "TaskCache registry, security descriptor, and TaskScheduler event history correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "defender":
        base.extend(
            [
                {
                    "id": "defender-interesting-entries",
                    "label": "Defender support log contains triage-worthy threat/quarantine/exclusion lines",
                    "passed": bool(checks.get("interesting_entries_present")),
                    "severity": "medium",
                },
                {
                    "id": "defender-report-grade-correlation",
                    "label": "Defender EVTX, MpCmdRun, quarantine metadata, and signature versions correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "firewall":
        base.extend(
            [
                {
                    "id": "firewall-w3c-rows",
                    "label": "Firewall W3C rows parsed",
                    "passed": bool(checks.get("w3c_fields_present")),
                    "severity": "medium",
                },
                {
                    "id": "firewall-report-grade-correlation",
                    "label": "Firewall policy/rule store and event-log context correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "wer":
        base.extend(
            [
                {
                    "id": "wer-core-fields",
                    "label": "WER report has application, exception, identifier, and event-time pivots",
                    "passed": bool(
                        checks.get("has_application")
                        and checks.get("has_exception_code")
                        and checks.get("has_report_identifier")
                    ),
                    "severity": "high",
                },
                {
                    "id": "wer-report-grade-correlation",
                    "label": "Dump files, CAB metadata, queue/archive state, and event logs correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "wmi":
        base.extend(
            [
                {
                    "id": "wmi-persistence-pivots",
                    "label": "WMI repository string pivots include persistence terms or path/URL pivots",
                    "passed": bool(
                        checks.get("persistence_terms_present") or checks.get("path_or_url_pivots_present")
                    ),
                    "severity": "high",
                },
                {
                    "id": "wmi-native-report-grade",
                    "label": "Native WMI repository namespaces/classes/consumer-filter bindings decoded",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    return base


def system_report_grade_assessment(artifact_family: str, checks: dict[str, object]) -> dict[str, object]:
    matrix = system_validation_matrix(artifact_family, checks)
    failed = [item for item in matrix if not item["passed"]]
    family_blockers = {
        "task-scheduler": [
            "task-cache-registry-correlation-not-implemented",
            "task-security-descriptor-validation-not-implemented",
            "task-history-event-correlation-not-implemented",
        ],
        "defender": ["defender-event-and-mpcmdrun-correlation-not-implemented"],
        "firewall": ["firewall-rule-store-correlation-not-implemented"],
        "wer": list(WER_REPORT_GRADE_BLOCKERS),
        "wmi": ["native-wmi-repository-decoding-not-implemented"],
    }
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#18"],
        "artifact_family": artifact_family,
        "failed_check_ids": [str(item["id"]) for item in failed],
        "blockers": family_blockers.get(artifact_family, SYSTEM_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Correlate this artifact family with EVTX, registry hives, filesystem timeline, and known-answer fixtures.",
            "Do not present this row as standalone report-grade attribution until failed critical checks are resolved.",
        ],
    }


def system_core_accuracy_gates(artifact_family: str, details: dict[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), dict) else {}
    trusted_diff = (
        details.get("system_trusted_diff")
        if isinstance(details.get("system_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [f"source_path:{details.get('source_path', '')}", f"family:{artifact_family}"]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("risk_flags") or checks.get("interesting_entries_present") or checks.get("blocked_entries_present") or checks.get("persistence_terms_present"):
        satisfied.append("event semantics and risk rules")
    if artifact_family == "task-scheduler" and checks.get("has_task_temporal_metadata"):
        satisfied.append("task temporal metadata provenance")
    if artifact_family == "task-scheduler" and checks.get("taskcache_registry_validated"):
        satisfied.append("Task XML/TaskCache correlation")
    if artifact_family in {"defender", "firewall"} and (details.get("interesting_entries") or details.get("sample_entries")):
        satisfied.append("Defender/Firewall field normalization")
    if artifact_family == "wer" and checks.get("dump_file_correlated") and checks.get("cab_metadata_validated"):
        satisfied.append("WER dump/cab linkage")
    if artifact_family == "wmi" and checks.get("consumer_filter_binding_reconstructed"):
        satisfied.append("WMI consumer/filter binding validation")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted system artifact diff pass")
    return [build_accuracy_gate(18, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def system_commercial_uplift_evidence(artifact_family: str, details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("system_validation_matrix") if isinstance(details.get("system_validation_matrix"), list) else []
    report_grade = (
        details.get("system_report_grade_assessment")
        if isinstance(details.get("system_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("system_trusted_diff")
        if isinstance(details.get("system_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    reportability_decision = system_reportability_decision(artifact_family, report_grade, details)
    return {
        "batch_id": "commercial-uplift-016-020",
        "item_numbers": [18],
        "implementation_track": "native-parser-depth",
        "objective": "Expose Windows system artifact semantics, risk-rule evidence, and correlation blockers.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
            f"artifact_family:{artifact_family}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "system_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_wmi_scan_bytes": WMI_SCAN_LIMIT if artifact_family == "wmi" else 0,
            "actual_scan_bytes": int(details.get("scan_bytes") or 0),
            "cross_artifact_correlation_required_for_commercial_claims": True,
            "native_repository_or_rule_store_decode_required": artifact_family in {"wmi", "firewall", "task-scheduler"},
        },
        "next_internal_step": "Finish TaskCache, Defender/EventLog, Firewall rule-store, WER dump/CAB, and WMI repository correlation validation.",
        "external_evidence_required": True,
    }


def with_system_deep_parser_manifest(artifact_family: str, details: dict[str, object]) -> dict[str, object]:
    enriched = dict(details)
    enriched["system_analyst_review_profile"] = system_analyst_review_profile(artifact_family, enriched)
    manifest = system_deep_parser_manifest(artifact_family, enriched)
    enriched["system_deep_parser_manifest"] = manifest
    enriched["system_deep_parser_manifest_hash"] = manifest["manifest_sha256"]
    return enriched


def system_analyst_review_profile(artifact_family: str, details: Mapping[str, object]) -> dict[str, object]:
    report_grade = (
        details.get("system_report_grade_assessment")
        if isinstance(details.get("system_report_grade_assessment"), Mapping)
        else {}
    )
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    semantics = system_manifest_semantics(artifact_family, details)
    family_guidance = {
        "task-scheduler": {
            "severity": "high" if details.get("risk_flags") else "medium",
            "not_proof_of": ["TaskCache registry state", "task execution without event-log correlation", "user intent"],
            "correlation_targets": ["TaskCache Registry", "Security EVTX", "TaskScheduler EVTX", "Prefetch", "Amcache", "MFT/USN"],
            "questions": [
                "Does TaskCache registry confirm the same task URI and action?",
                "Do TaskScheduler operational events show creation, update, or execution?",
                "Do execution artifacts corroborate the command line?",
            ],
        },
        "defender": {
            "severity": "high",
            "not_proof_of": ["final malware verdict", "quarantine state without Defender event/policy correlation"],
            "correlation_targets": ["Defender EVTX", "MpCmdRun logs", "Quarantine", "Firewall", "MFT/USN"],
            "questions": [
                "Do Defender operational events confirm the same detection/action?",
                "Is quarantine, exclusion, or signature state available?",
                "Does filesystem timeline support the detection time?",
            ],
        },
        "firewall": {
            "severity": "medium",
            "not_proof_of": ["policy rule intent", "complete network session attribution"],
            "correlation_targets": ["Firewall policy store", "Security EVTX", "SRUM", "Browser", "MFT/USN"],
            "questions": [
                "Does the policy/rule store explain this log row?",
                "Are source/destination IPs correlated with process, SRUM, or browser evidence?",
                "Is log rotation or dropped-field behavior documented?",
            ],
        },
        "wer": {
            "severity": "medium",
            "not_proof_of": ["malware attribution", "dump/CAB contents without linkage validation"],
            "correlation_targets": ["WER dump/CAB", "Application EVTX", "Prefetch", "Amcache", "MFT/USN"],
            "questions": [
                "Does a dump or CAB exist for this report ID?",
                "Do Application/System events confirm the same crash?",
                "Is the faulting module path present in filesystem evidence?",
            ],
        },
        "wmi": {
            "severity": "high" if details.get("interesting_strings") else "medium",
            "not_proof_of": ["complete WMI repository binding", "persistent consumer/filter relationship"],
            "correlation_targets": ["WMI repository decoder", "Autoruns", "EVTX", "Registry", "MFT/USN"],
            "questions": [
                "Can a WMI parser decode the namespace, class, consumer, filter, and binding?",
                "Do strings indicate persistence or only repository residue?",
                "Do event logs or Autoruns corroborate the same WMI object?",
            ],
        },
    }
    guidance = family_guidance.get(
        artifact_family,
        {
            "severity": "medium",
            "not_proof_of": ["fully correlated Windows system event"],
            "correlation_targets": ["EVTX", "Registry", "MFT/USN"],
            "questions": ["Which trusted parser validates this row?"],
        },
    )
    source_values = {key: value for key, value in semantics.items() if value not in ("", None, [], {})}
    failed_checks = sorted(str(key) for key, value in checks.items() if value is False)
    blockers = sorted(set(str(item) for item in report_grade.get("blockers", []) if str(item)) | set(SYSTEM_REPORT_GRADE_BLOCKERS))
    return {
        "profile_version": "windows-system-analyst-review-profile-v1",
        "artifact_family": artifact_family,
        "artifact_type": str(details.get("artifact_type") or ""),
        "severity": guidance["severity"],
        "summary": f"Windows {artifact_family} artifact pivot with normalized semantics and correlation blockers.",
        "evidence_interpretation": "system artifact triage row requiring registry/event/filesystem correlation before final testimony",
        "not_proof_of": guidance["not_proof_of"],
        "analyst_questions": guidance["questions"],
        "primary_pivots": list(source_values.keys())[:12],
        "source_field_values": source_values,
        "correlation_targets": guidance["correlation_targets"],
        "risk_tags": sorted(set(str(item) for item in details.get("risk_flags") or []) | {"windows-system-review"}),
        "validation_required": True,
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Use this system row as a triage/correlation pivot. Do not report full semantics until artifact-specific "
            "trusted diff and cross-source correlation are attached."
        ),
    }


def system_deep_parser_manifest(artifact_family: str, details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    report_grade = (
        details.get("system_report_grade_assessment")
        if isinstance(details.get("system_report_grade_assessment"), Mapping)
        else {}
    )
    reportability = system_reportability_decision(artifact_family, report_grade, details)
    validation_checks = (
        details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    )
    matrix = details.get("system_validation_matrix") if isinstance(details.get("system_validation_matrix"), list) else []
    capabilities = (
        details.get("system_native_capabilities")
        if isinstance(details.get("system_native_capabilities"), Mapping)
        else SYSTEM_NATIVE_CAPABILITIES
    )
    manifest_payload = {
        "manifest_version": "windows-system-deep-parser-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 18,
        "gap_id": "#18",
        "artifact_family": artifact_family,
        "artifact_type": str(details.get("artifact_type") or ""),
        "source": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "source_format": str(details.get("source_format") or ""),
            "entry_name": str(details.get("entry_name") or details.get("task_uri") or details.get("report_id") or ""),
        },
        "normalized_semantics": system_manifest_semantics(artifact_family, details),
        "risk_and_review": {
            "risk_flags": list(details.get("risk_flags") or [])[:50],
            "risk_score": int(details.get("risk_score") or 0),
            "coverage_status": str(details.get("coverage_status") or ""),
            "parser_confidence": str(details.get("parser_confidence") or ""),
            "validation_required": bool(details.get("validation_required", True)),
        },
        "validation": {
            "validation_checks": dict(validation_checks),
            "passed_validation_matrix_ids": [
                str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
            ],
            "failed_validation_matrix_ids": [
                str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
            ],
            "trusted_diff_attached": isinstance(details.get("system_trusted_diff"), Mapping),
            "known_answer_corpus_attached": False,
        },
        "native_depth": {
            "task_xml_normalization": bool(capabilities.get("task_xml_normalization")),
            "task_action_trigger_principal_pivots": bool(capabilities.get("task_action_trigger_principal_pivots")),
            "defender_mplog_triage": bool(capabilities.get("defender_mplog_triage")),
            "firewall_w3c_log_parsing": bool(capabilities.get("firewall_w3c_log_parsing")),
            "wer_key_value_normalization": bool(capabilities.get("wer_key_value_normalization")),
            "wmi_repository_string_pivots": bool(capabilities.get("wmi_repository_string_pivots")),
            "taskcache_registry_correlation": bool(capabilities.get("taskcache_registry_correlation")),
            "task_security_descriptor_validation": bool(capabilities.get("task_security_descriptor_validation")),
            "defender_event_mpcmdrun_correlation": bool(capabilities.get("defender_event_mpcmdrun_correlation")),
            "firewall_rule_store_correlation": bool(capabilities.get("firewall_rule_store_correlation")),
            "wer_dump_cab_reportqueue_correlation": bool(capabilities.get("wer_dump_cab_reportqueue_correlation")),
            "native_wmi_repository_decode": bool(capabilities.get("native_wmi_repository_decode")),
        },
        "citation_refs": system_manifest_citation_refs(artifact_family, details, hashes),
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "ready_for_court_report": bool(report_grade.get("ready_for_court_report")),
            "commercial_grade_ready": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "correlate Task Scheduler XML with TaskCache registry and operational EVTX",
            "correlate Defender support rows with Defender EVTX, MpCmdRun history, exclusions, quarantine, and signature state",
            "correlate Firewall W3C rows with policy/rule store and Security/Firewall EVTX context",
            "correlate WER reports with dump/CAB files, queue/archive state, and application/event timelines",
            "decode WMI repository namespaces/classes/consumer-filter bindings or attach trusted parser diff",
            "attach known-answer corpus and trusted-tool diff for every critical row used in a report",
        ],
    }
    manifest_payload["manifest_sha256"] = stable_windows_system_json_sha256(manifest_payload)
    return manifest_payload


def system_manifest_semantics(artifact_family: str, details: Mapping[str, object]) -> dict[str, object]:
    if artifact_family == "task-scheduler":
        return {
            "task_uri": str(details.get("task_uri") or ""),
            "command_line": str(details.get("command_line") or ""),
            "executable_name": str(details.get("executable_name") or ""),
            "action_count": int(details.get("action_count") or 0),
            "trigger_count": int(details.get("trigger_count") or 0),
            "principal_count": int(details.get("principal_count") or 0),
            "hidden": bool(details.get("hidden")),
        }
    if artifact_family == "defender":
        return {
            "entry_count": int(details.get("entry_count") or 0),
            "interesting_entry_count": int(details.get("interesting_entry_count") or 0),
            "interesting_entries": list(details.get("interesting_entries") or [])[:10],
        }
    if artifact_family == "firewall":
        return {
            "entry_count": int(details.get("entry_count") or 0),
            "blocked_count": int(details.get("blocked_count") or 0),
            "sample_entries": list(details.get("sample_entries") or [])[:10],
        }
    if artifact_family == "wer":
        return {
            "report_id": str(details.get("report_id") or ""),
            "report_store": str(details.get("report_store") or ""),
            "application_name": str(details.get("application_name") or details.get("application") or ""),
            "fault_module_name": str(details.get("fault_module_name") or ""),
            "exception_code": str(details.get("exception_code") or ""),
            "event_time": str(details.get("event_time") or ""),
            "bucket_id": str(details.get("bucket_id") or ""),
        }
    if artifact_family == "wmi":
        return {
            "entry_name": str(details.get("entry_name") or ""),
            "scan_bytes": int(details.get("scan_bytes") or 0),
            "extracted_string_count": int(details.get("extracted_string_count") or 0),
            "interesting_string_count": len(details.get("interesting_strings") or []),
            "path_candidate_count": len(details.get("path_candidates") or []),
            "url_candidate_count": len(details.get("url_candidates") or []),
        }
    return {"artifact_family": artifact_family}


def system_manifest_citation_refs(
    artifact_family: str,
    details: Mapping[str, object],
    hashes: Mapping[str, object],
) -> list[dict[str, object]]:
    refs = [
        {
            "kind": "windows-system-source",
            "artifact_family": artifact_family,
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
        }
    ]
    if artifact_family == "task-scheduler":
        refs.append(
            {
                "kind": "task-action-trigger-principal",
                "task_uri": str(details.get("task_uri") or ""),
                "action_count": int(details.get("action_count") or 0),
                "trigger_count": int(details.get("trigger_count") or 0),
                "principal_count": int(details.get("principal_count") or 0),
            }
        )
    elif artifact_family == "defender":
        refs.append(
            {
                "kind": "defender-support-interesting-lines",
                "interesting_entry_count": int(details.get("interesting_entry_count") or 0),
            }
        )
    elif artifact_family == "firewall":
        refs.append(
            {
                "kind": "firewall-w3c-rows",
                "entry_count": int(details.get("entry_count") or 0),
                "blocked_count": int(details.get("blocked_count") or 0),
            }
        )
    elif artifact_family == "wer":
        refs.append(
            {
                "kind": "wer-report-core-fields",
                "report_id": str(details.get("report_id") or ""),
                "application_name": str(details.get("application_name") or details.get("application") or ""),
                "exception_code": str(details.get("exception_code") or ""),
            }
        )
    elif artifact_family == "wmi":
        refs.append(
            {
                "kind": "wmi-repository-string-pivots",
                "scan_bytes": int(details.get("scan_bytes") or 0),
                "interesting_string_count": len(details.get("interesting_strings") or []),
                "path_candidate_count": len(details.get("path_candidates") or []),
                "url_candidate_count": len(details.get("url_candidates") or []),
            }
        )
    return refs


def system_reportability_decision(
    artifact_family: str,
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("windows-system-cross-artifact-correlation-required")
    blockers.add("windows-system-trusted-artifact-diff-required")
    if artifact_family == "task-scheduler":
        blockers.add("taskcache-registry-and-eventlog-correlation-required")
    elif artifact_family == "wmi":
        blockers.add("wmi-native-consumer-filter-binding-decode-required")
    elif artifact_family == "firewall":
        blockers.add("firewall-policy-store-correlation-required")
    elif artifact_family == "defender":
        blockers.add("defender-event-policy-and-quarantine-correlation-required")
    elif artifact_family == "wer":
        blockers.add("wer-dump-cab-linkage-validation-required")
    return {
        "profile_version": "windows-system-reportability-decision-v1",
        "commercial_gap_id": "#18",
        "artifact_family": artifact_family,
        "decision": "do-not-report-system-artifact-as-fully-correlated",
        "allowed_use": "windows-system-artifact-triage-pivot",
        "blockers": sorted(blockers),
        "required_before_report": [
            "source hashes and parser version captured",
            "artifact-specific event semantics validated",
            "registry/event/policy/dump/WMI correlation completed where applicable",
            "trusted-tool or known-answer diff attached for critical findings",
        ],
    }


def system_forensic_review(
    artifact_family: str,
    primary_evidence: list[str],
    validation_checks: dict[str, object],
) -> dict[str, object]:
    return build_forensic_review(
        gap_id="#18",
        artifact_goal=f"Windows {artifact_family} artifact semantics, risk rules, and correlation evidence",
        primary_evidence=primary_evidence,
        validation_required=True,
        report_grade_assessment=system_report_grade_assessment(artifact_family, validation_checks),
        blockers=SYSTEM_REPORT_GRADE_BLOCKERS,
        caveats=[
            "This row is triage-grade until correlated with EVTX, registry, filesystem timeline, and known-answer fixtures.",
            "Report conclusions should cite the source hash and unresolved critical validation checks.",
        ],
    )


def build_system_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_system_diff_payload(
        index_system_rows(rapid_rows),
        index_system_rows(trusted_rows),
        trusted_tool=trusted_tool,
    )


def index_system_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = system_diff_row_payload(row)
        family = system_diff_family(payload)
        key = system_diff_key(payload, family)
        if not key:
            continue
        row_payload: dict[str, str] = {
            "family": family,
            "timestamp": normalized_diff_value(first_alias(payload, "timestamp", "event_time", "created_at", "start_boundary")),
            "source_path": normalized_diff_value(first_alias(payload, "source_path", "source", "file_path")),
            "risk": normalized_diff_list(first_alias(payload, "risk_flag", "risk_flags", "severity")),
        }
        row_payload.update(system_family_diff_fields(payload, family))
        indexed[key] = row_payload
    return indexed


def system_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def system_diff_family(row: Mapping[str, object]) -> str:
    explicit = normalized_diff_value(first_alias(row, "artifact_family", "family", "type"))
    artifact_type = normalized_diff_value(first_alias(row, "artifact_type", "artifacttype"))
    if explicit:
        explicit = explicit.replace(" ", "-")
    if explicit in {"task", "taskscheduler", "task-scheduler-task"}:
        return "task-scheduler"
    if explicit in {"windows-defender", "defender-support-log"}:
        return "defender"
    if explicit in {"windows-firewall", "firewall-log-row"}:
        return "firewall"
    if explicit in {"windows-error-reporting", "wer-report"}:
        return "wer"
    if explicit in {"wmi-repository", "wmi-repository-inventory"}:
        return "wmi"
    if explicit:
        return explicit
    if "task-scheduler" in artifact_type or artifact_type.startswith("task-"):
        return "task-scheduler"
    if "defender" in artifact_type:
        return "defender"
    if "firewall" in artifact_type:
        return "firewall"
    if "wer" in artifact_type or "error-report" in artifact_type:
        return "wer"
    if "wmi" in artifact_type:
        return "wmi"
    if "zone-identifier" in artifact_type:
        return "zone-identifier"
    return artifact_type


def system_diff_key(row: Mapping[str, object], family: str) -> str:
    if family == "task-scheduler":
        identity = first_present(
            first_alias(row, "task_uri", "taskuri", "uri", "task_name", "name"),
            first_alias(row, "command_line", "command", "executable_name"),
        )
    elif family == "defender":
        identity = first_present(
            first_alias(row, "threat_name", "threat", "source_path", "log_path", "name"),
            first_list_value(first_alias(row, "interesting_entries", "interesting_entry", "entries")),
        )
    elif family == "firewall":
        identity = "|".join(
            item
            for item in (
                normalized_diff_value(first_alias(row, "timestamp", "date_time", "date", "time")),
                normalized_diff_value(first_alias(row, "src_ip", "source_ip", "source", "src")),
                normalized_diff_value(first_alias(row, "dst_ip", "destination_ip", "destination", "dst")),
                normalized_int_text(first_alias(row, "dst_port", "destination_port", "dpt")),
                normalized_diff_value(first_alias(row, "action")),
            )
            if item
        )
    elif family == "wer":
        identity = "|".join(
            item
            for item in (
                normalized_diff_value(first_alias(row, "application_name", "application", "app_name", "app")),
                normalized_diff_value(first_alias(row, "event_name", "eventname", "problem_event_name")),
                normalized_diff_value(first_alias(row, "event_time", "timestamp", "created_at")),
                normalized_diff_value(first_alias(row, "bucket_id", "report_id", "cab_id", "bucket")),
            )
            if item
        )
    elif family == "wmi":
        identity = first_present(
            first_alias(row, "source_path", "repository_file", "path"),
            normalized_diff_list(first_alias(row, "wmi_persistence_terms", "persistence_terms", "consumer", "filter")),
        )
    else:
        identity = first_present(
            first_alias(row, "name", "path", "source_path", "target_path"),
            first_alias(row, "command", "command_line"),
        )
    normalized_identity = normalized_diff_value(identity)
    return "|".join(item for item in (family, normalized_identity) if item)


def system_family_diff_fields(row: Mapping[str, object], family: str) -> dict[str, str]:
    if family == "task-scheduler":
        return {
            "task_uri": normalized_diff_value(first_alias(row, "task_uri", "taskuri", "uri", "task_name")),
            "command": normalized_diff_value(first_alias(row, "command_line", "command", "action_command", "executable_name")),
            "arguments": normalized_diff_value(first_alias(row, "arguments", "args", "action_arguments")),
            "working_directory": normalized_diff_value(first_alias(row, "working_directory", "working_dir")),
            "user_id": normalized_diff_value(first_alias(row, "user_id", "userid", "sid", "run_as")),
            "run_level": normalized_diff_value(first_alias(row, "run_level", "runlevel")),
            "logon_type": normalized_diff_value(first_alias(row, "logon_type", "logontype")),
            "hidden": normalized_bool_text(first_alias(row, "hidden", "is_hidden")),
            "trigger_types": normalized_diff_list(first_alias(row, "trigger_types", "triggers", "trigger")),
        }
    if family == "defender":
        return {
            "interesting_entry_count": normalized_int_text(
                first_alias(row, "interesting_entry_count", "entry_count", "detections", "count")
            ),
            "interesting_entries": normalized_diff_list(first_alias(row, "interesting_entries", "entries", "message")),
            "threat": normalized_diff_value(first_alias(row, "threat_name", "threat", "malware_name")),
            "action": normalized_diff_value(first_alias(row, "action", "remediation_action", "status")),
        }
    if family == "firewall":
        return {
            "action": normalized_diff_value(first_alias(row, "action")),
            "protocol": normalized_diff_value(first_alias(row, "protocol", "proto")),
            "src_ip": normalized_diff_value(first_alias(row, "src_ip", "source_ip", "source", "src")),
            "dst_ip": normalized_diff_value(first_alias(row, "dst_ip", "destination_ip", "destination", "dst")),
            "src_port": normalized_int_text(first_alias(row, "src_port", "source_port", "sport")),
            "dst_port": normalized_int_text(first_alias(row, "dst_port", "destination_port", "dport")),
            "direction": normalized_diff_value(first_alias(row, "direction", "dir")),
            "application": normalized_diff_value(first_alias(row, "application", "app", "path")),
        }
    if family == "wer":
        return {
            "application_name": normalized_diff_value(first_alias(row, "application_name", "application", "app_name", "app")),
            "event_name": normalized_diff_value(first_alias(row, "event_name", "eventname", "problem_event_name")),
            "exception_code": normalized_diff_value(first_alias(row, "exception_code", "exception", "fault_code")),
            "event_time": normalized_diff_value(first_alias(row, "event_time", "timestamp", "created_at")),
            "bucket_id": normalized_diff_value(first_alias(row, "bucket_id", "bucket", "report_id", "cab_id")),
            "module_path": normalized_diff_value(first_alias(row, "fault_module_path", "module_path", "application_path")),
        }
    if family == "wmi":
        return {
            "persistence_terms": normalized_diff_list(
                first_alias(row, "wmi_persistence_terms", "persistence_terms", "consumer", "filter", "binding")
            ),
            "path_pivots": normalized_diff_list(first_alias(row, "path_pivots", "paths", "command_paths", "command")),
            "url_pivots": normalized_diff_list(first_alias(row, "url_pivots", "urls", "url")),
        }
    return {
        "name": normalized_diff_value(first_alias(row, "name", "path", "source_path")),
        "command": normalized_diff_value(first_alias(row, "command_line", "command", "target_path")),
    }


def build_system_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in SYSTEM_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({"system_key": key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "windows-system-trusted-artifact-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-system-artifact-output-as-final",
            "blockers": [] if status == "pass" else ["windows-system-trusted-artifact-diff-required"],
        },
    }


def first_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def first_present(*values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def first_list_value(value: object) -> object:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[\r\n;|]", value) if part.strip()]
        return parts[0] if parts else value
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            if item not in (None, ""):
                return normalize_system_list_item(item)
        return ""
    return value


def normalized_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_diff_value(text)


def normalized_bool_text(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalized_diff_value(value)
    if text in {"1", "yes", "y", "true", "enabled"}:
        return "true"
    if text in {"0", "no", "n", "false", "disabled"}:
        return "false"
    return text


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[\r\n,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_system_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_system_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        return str(
            first_alias(
                value,
                "type",
                "name",
                "value",
                "path",
                "command",
                "message",
                "entry",
                "term",
                "url",
                "trigger_type",
            )
        )
    return str(value)


def windows_executable_name(command: str) -> str:
    cleaned = command.strip().strip('"').strip("'")
    if not cleaned:
        return ""
    return cleaned.replace("/", "\\").rsplit("\\", 1)[-1]


def windows_path_category(command: str, working_directory: str = "") -> str:
    haystack = " ".join((command, working_directory)).lower().replace("/", "\\")
    if any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS):
        return "user-writable"
    if "\\windows\\system32\\" in haystack or haystack.startswith(r"c:\windows\system32\\"):
        return "windows-system32"
    if "\\" not in command and "/" not in command:
        return "path-search"
    return "other"


def normalized_wer_report(path: Path, fields: dict[str, str]) -> dict[str, object]:
    app_name = first_field(fields, "AppName", "ApplicationName", "Sig[0].Value", "FriendlyEventName")
    module_name = first_field(fields, "FaultModuleName", "FaultingModule", "Sig[3].Value")
    exception_code = first_field(fields, "ExceptionCode", "Exception Code", "Sig[6].Value")
    event_time_raw = first_field(fields, "EventTime", "ReportTime")
    event_time = wer_time_to_iso(event_time_raw)
    report_id = first_field(fields, "ReportIdentifier", "ReportId", "CabId") or path.parent.name
    bucket = first_field(fields, "Bucket", "Response.BucketId", "BucketId")
    validation_checks = {
        "has_event_type": bool(first_field(fields, "EventType")),
        "has_application": bool(app_name),
        "has_fault_module": bool(module_name),
        "has_exception_code": bool(exception_code),
        "has_bucket": bool(bucket),
        "has_report_identifier": bool(report_id),
        "has_event_time": bool(event_time),
        "dump_file_correlated": False,
        "cab_metadata_validated": False,
        "reportqueue_state_validated": False,
    }
    return {
        "coverage_status": "wer-key-value-normalized",
        "reportability": "triage",
        "evidence_strength": "application-fault-report",
        "parser_confidence": "high" if app_name and first_field(fields, "EventType") else "medium",
        "report_id": report_id,
        "report_store": wer_report_store(path),
        "application_name": app_name,
        "application_path": first_field(fields, "ApplicationPath", "AppPath", "TargetAppId"),
        "fault_module_name": module_name,
        "fault_module_path": first_field(fields, "FaultModulePath", "ModulePath"),
        "exception_code": exception_code,
        "event_time": event_time,
        "timestamp": event_time or "",
        "timestamp_source": "wer_event_time" if event_time else "missing_wer_event_time",
        "bucket_id": bucket,
        "cab_id": first_field(fields, "CabId"),
        "problem_signature": wer_problem_signature(fields),
        "validation_required": True,
        "validation_checks": validation_checks,
        "core_accuracy_gates": system_core_accuracy_gates(
            "wer",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "validation_checks": validation_checks,
                "report_id": report_id,
                "problem_signature": wer_problem_signature(fields),
            },
        ),
        "system_validation_matrix": system_validation_matrix("wer", validation_checks),
        "system_report_grade_assessment": system_report_grade_assessment("wer", validation_checks),
        "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
        "commercial_uplift_evidence": system_commercial_uplift_evidence(
            "wer",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "artifact_type": "wer-report",
                "system_validation_matrix": system_validation_matrix("wer", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("wer", validation_checks),
            },
        ),
        "forensic_review": system_forensic_review(
            "wer",
            [
                f"application={app_name}",
                f"fault_module={module_name}",
                f"exception_code={exception_code}",
                f"report_id={report_id}",
            ],
            validation_checks,
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": WER_REPORT_GRADE_BLOCKERS,
        "validation_guidance": (
            "Report.wer key/value fields are normalized for triage. Correlate dumps, ReportQueue/ReportArchive state, "
            "cab metadata, and application/event-log timelines before report-grade crash attribution."
        ),
    }


def first_field(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name, "")
        if value:
            return value
    return ""


def wer_problem_signature(fields: dict[str, str]) -> list[dict[str, str]]:
    signatures: list[dict[str, str]] = []
    for index in range(10):
        name = fields.get(f"Sig[{index}].Name", "")
        value = fields.get(f"Sig[{index}].Value", "")
        if name or value:
            signatures.append({"name": name, "value": value})
    return signatures


def wer_report_store(path: Path) -> str:
    lowered = [part.lower() for part in path.parts]
    for store in ("reportarchive", "reportqueue", "reporttemp"):
        if store in lowered:
            return store
    if "users" in lowered:
        return "user-wer"
    return "unknown"


def wer_time_to_iso(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    if cleaned.isdigit():
        try:
            number = int(cleaned)
        except ValueError:
            return ""
        if number > 10_000_000_000:
            try:
                base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                return (base + dt.timedelta(microseconds=number // 10)).isoformat()
            except (OverflowError, ValueError):
                return ""
        return isoformat_from_timestamp(number) or ""
    try:
        parsed = dt.datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat()


def unique_preserve_order(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def read_lines(path: Path, *, limit: int) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[:limit]


def preview_text(path: Path, *, limit: int = 600) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def safe_child_names(path: Path, *, limit: int = 25) -> list[str]:
    try:
        return sorted(child.name for child in path.iterdir())[:limit]
    except OSError:
        return []


def parse_firewall_log(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    fields: list[str] = []
    for line in read_lines(path, limit=500):
        if line.startswith("#Fields:"):
            fields = line.removeprefix("#Fields:").strip().split()
            continue
        if not line or line.startswith("#") or not fields:
            continue
        values = line.split()
        rows.append(dict(zip(fields, values)))
    return rows


def parse_key_value_file(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in read_lines(path, limit=300):
        stripped = line.strip()
        if not stripped or stripped.startswith("[") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def wmi_repository_pivots(path: Path) -> dict[str, object]:
    blob = read_prefix(path, WMI_SCAN_LIMIT)
    strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
    interesting = [
        value
        for value in strings
        if any(term in value.lower() for term in WMI_PERSISTENCE_TERMS)
    ][:50]
    path_candidates = regex_candidates(strings, WINDOWS_PATH_RE)[:50]
    url_candidates = regex_candidates(strings, URL_RE)[:50]
    risk_flags = [f"wmi-string:{term}" for term in WMI_PERSISTENCE_TERMS if any(term in value.lower() for value in strings)]
    validation_checks = {
        "repository_file_readable": bool(blob),
        "bounded_strings_extracted": bool(strings),
        "persistence_terms_present": bool(interesting),
        "path_or_url_pivots_present": bool(path_candidates or url_candidates),
        "native_wmi_repository_decoded": False,
        "consumer_filter_binding_reconstructed": False,
    }
    return {
        "coverage_status": "bounded-string-pivot",
        "scan_bytes": len(blob),
        "extracted_string_count": len(strings),
        "interesting_strings": interesting,
        "path_candidates": path_candidates,
        "url_candidates": url_candidates,
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 15),
        "reportability": "triage",
        "parser_confidence": "medium" if interesting else "low",
        "validation_required": True,
        "validation_checks": validation_checks,
        "core_accuracy_gates": system_core_accuracy_gates(
            "wmi",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "validation_checks": validation_checks,
                "interesting_strings": interesting,
                "path_candidates": path_candidates,
                "url_candidates": url_candidates,
            },
        ),
        "system_validation_matrix": system_validation_matrix("wmi", validation_checks),
        "system_report_grade_assessment": system_report_grade_assessment("wmi", validation_checks),
        "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
        "commercial_uplift_evidence": system_commercial_uplift_evidence(
            "wmi",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "artifact_type": "wmi-repository-file",
                "scan_bytes": len(blob),
                "system_validation_matrix": system_validation_matrix("wmi", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("wmi", validation_checks),
            },
        ),
        "forensic_review": system_forensic_review(
            "wmi",
            [
                f"interesting_strings={len(interesting)}",
                f"path_candidates={len(path_candidates)}",
                f"url_candidates={len(url_candidates)}",
            ],
            validation_checks,
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
        "recommended_parsers": ["PyWMIPersistenceFinder", "python-cim", "Velociraptor WMI artifacts"],
    }


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def extract_ascii_strings(blob: bytes, *, min_chars: int = 5) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            strings.append(current.decode("ascii", errors="ignore"))
        current.clear()
    if len(current) >= min_chars:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def extract_utf16_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    for start in (0, 1):
        current = bytearray()
        for index in range(start, len(blob) - 1, 2):
            value = int.from_bytes(blob[index : index + 2], "little", signed=False)
            if 32 <= value <= 126:
                current.extend(blob[index : index + 2])
                continue
            if len(current) >= min_chars * 2:
                strings.append(current.decode("utf-16le", errors="ignore").strip())
            current.clear()
        if len(current) >= min_chars * 2:
            strings.append(current.decode("utf-16le", errors="ignore").strip())
    return strings


def unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(value.split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
        if len(unique) >= 500:
            break
    return unique


def regex_candidates(strings: list[str], pattern: re.Pattern[str]) -> list[str]:
    candidates: list[str] = []
    for value in strings:
        for match in pattern.finditer(value):
            candidate = match.group(0).rstrip(".,);]")
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates
