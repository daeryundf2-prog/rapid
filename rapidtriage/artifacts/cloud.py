from __future__ import annotations

import csv
import datetime as dt
import email
import hashlib
import io
import json
import re
import zipfile
from email import policy
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "cloud-export-v3"
FUNCTIONAL_EXPANSION_BATCH_ID = "commercial-uplift-051-055"
CLOUD_JSON_SUFFIXES = {".json"}
CLOUD_CSV_SUFFIXES = {".csv"}
CLOUD_ARCHIVE_SUFFIXES = {".zip"}
CLOUD_ARCHIVE_ENTRY_LIMIT = 1000
CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT = 25
CLOUD_ARCHIVE_PARSE_ENTRY_MAX_BYTES = 8 * 1024 * 1024
CLOUD_ARCHIVE_JSON_ROW_LIMIT = 100
CLOUD_ARCHIVE_CSV_ROW_LIMIT = 100
CLOUD_CSV_ROW_LIMIT = 1000
CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT = 50
CloudGap = tuple[list[str], str]
CLOUD_NATIVE_CAPABILITIES = {
    "google_takeout_location_activity_import": True,
    "gmail_json_export_import": True,
    "icloud_account_file_export_import": True,
    "microsoft_365_onedrive_teams_audit_import": True,
    "provider_archive_manifest_inventory": True,
    "source_hashing": True,
    "provider_api_native_acquisition": False,
    "provider_export_scope_verification": False,
    "deleted_cloud_object_recovery": False,
    "tenant_wide_permission_graph": False,
    "known_answer_cloud_corpus": False,
}
CLOUD_REPORT_GRADE_BLOCKERS = [
    "provider-export-scope-and-settings-not-verified",
    "provider-native-api-acquisition-not-complete",
    "deleted-cloud-object-recovery-not-implemented",
    "tenant-permission-sharing-graph-not-complete",
    "known-answer-cloud-export-corpus-required",
]
CLOUD_TRUSTED_DIFF_BLOCKERS = {
    37: "google-takeout-provider-diff-required",
    38: "icloud-provider-export-diff-required",
    39: "m365-ediscovery-provider-diff-required",
}
CLOUD_TRUSTED_DIFF_CHECKS = {
    37: "trusted Google Takeout/provider diff pass",
    38: "trusted iCloud/provider export diff pass",
    39: "trusted M365/eDiscovery export diff pass",
}
CLOUD_TRUSTED_DIFF_TOOLS = {
    37: {
        "google-takeout-native",
        "google-admin-export",
        "google-provider-api",
        "gmail-native-export",
        "provider-known-answer",
    },
    38: {
        "apple-privacy-export",
        "icloud-web-export",
        "apple-native-export",
        "provider-known-answer",
    },
    39: {
        "microsoft-purview-ediscovery",
        "microsoft-graph-api",
        "exchange-ediscovery-export",
        "teams-admin-export",
        "provider-known-answer",
    },
}
CLOUD_QC_PREP_ITEMS = {
    "google": 43,
    "apple-icloud": 44,
    "microsoft-365": 45,
}
CLOUD_QC_PREP_GOALS = {
    43: "Add Google Takeout product matrix for Gmail, Drive, Photos, Activity, Location, account, and device attribution.",
    44: "Add iCloud export parser for Photos, albums, shares, devices, EXIF, and account context.",
    45: "Add M365/Teams/OneDrive/eDiscovery parser for permissions, reactions, attachments, SharePoint, and audit exports.",
}
CLOUD_QC_PREP_CONTRACTS = {
    43: {
        "item_number": 43,
        "goal": CLOUD_QC_PREP_GOALS[43],
        "implemented_outputs": [
            "Google Takeout/Gmail/Drive/Photos/Activity/Location row normalization",
            "bounded ZIP provider archive manifest inventory with original archive hash",
            "product-family review profile, row pivots, parser manifest, and source viewer locator",
            "selected-products, sidecar, timezone, and provider-diff blockers",
        ],
        "commercial_blockers": [
            "selected Takeout product manifest and original archive hash",
            "Drive/Photos/Gmail sidecar and timezone validation",
            "provider-native/API or known-answer diff",
            "deleted/retention/sharing scope validation",
        ],
    },
    44: {
        "item_number": 44,
        "goal": CLOUD_QC_PREP_GOALS[44],
        "implemented_outputs": [
            "iCloud account, file, photo, and mail export row normalization",
            "bounded ZIP provider archive manifest inventory with original archive hash",
            "ADP/shared-album/container review profile, parser manifest, and source viewer locator",
            "Photos sidecar/EXIF/album/share blocker metadata",
        ],
        "commercial_blockers": [
            "Apple export scope and original archive hash",
            "Advanced Data Protection and shared album validation",
            "photo sidecar/EXIF merge validation",
            "Apple/iCloud provider-native diff",
        ],
    },
    45: {
        "item_number": 45,
        "goal": CLOUD_QC_PREP_GOALS[45],
        "implemented_outputs": [
            "M365/Teams/OneDrive/SharePoint/eDiscovery/audit row normalization",
            "bounded ZIP provider archive manifest inventory with original archive hash",
            "workload review profile, parser manifest, source viewer locator, and row pivots",
            "Teams, SharePoint permission, retention, deleted/version-state blocker metadata",
        ],
        "commercial_blockers": [
            "Purview/eDiscovery export manifest, tenant/custodian/query scope, and package hash",
            "Graph API scope/pagination/throttling validation",
            "Teams compliance record and SharePoint permission graph reconciliation",
            "retention/deleted/version history validation and provider diff",
        ],
    },
}
CLOUD_PROVIDER_PROFILES = {
    "iaas-cloud": {
        "services": ("aws-cloudtrail", "azure-activity-log", "gcp-audit-log"),
        "collection_modes": ("provider audit export", "SIEM export", "cloud API collector"),
        "known_gaps": (
            "organization-or-subscription-scope-not-verified",
            "retention-window-and-log-integrity-not-attached",
            "cross-account-resource-graph-not-complete",
            "provider-native-console-diff-required",
        ),
    },
    "google": {
        "services": ("google-takeout", "gmail-takeout", "google-drive", "google-photos", "google-activity"),
        "collection_modes": ("Takeout archive", "provider API", "admin export"),
        "known_gaps": (
            "selected-products-and-export-time-window",
            "archive-splitting-expiration",
            "photos-json-sidecar-exif-merge",
            "location-timeline-on-device-vs-cloud-drift",
        ),
    },
    "apple-icloud": {
        "services": ("apple-export", "apple-icloud-export", "icloud-drive", "icloud-photos", "icloud-mail"),
        "collection_modes": ("privacy export", "iCloud.com copy", "device/mac synchronized cache"),
        "known_gaps": (
            "advanced-data-protection-limits",
            "shared-album-resolution-comments-likes-loss",
            "third-party-icloud-container-visibility",
            "mail-calendar-contact-client-export-differences",
        ),
    },
    "microsoft-365": {
        "services": ("microsoft-365", "microsoft-teams", "microsoft-onedrive", "exchange-online", "sharepoint"),
        "collection_modes": ("Purview eDiscovery export", "Graph API", "audit log export"),
        "known_gaps": (
            "teams-cosmosdb-vs-exchange-compliance-records",
            "pst-packaging-and-items-csv-source-mapping",
            "retention-hold-policy-and-audit-retention",
            "sharepoint-onedrive-permission-graph",
        ),
    },
    "collaboration-saas": {
        "services": ("slack", "dropbox", "box", "zoom", "notion", "atlassian", "github"),
        "collection_modes": ("workspace export", "admin API", "custodian export"),
        "known_gaps": (
            "workspace-plan-dependent-export-scope",
            "threads-reactions-edits-deletes",
            "file-version-and-sharing-state",
            "legal-hold-and-admin-audit-scope",
        ),
    },
}


class CloudExportProvider:
    collector_kind = "cloud-export"
    name = "cloud-export-artifacts"
    description = "Cloud account export normalization for Google Takeout-style activity/location and account JSON"
    target_platform = "cloud"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if path.is_file() and path.suffix.lower() in CLOUD_JSON_SUFFIXES:
                yield from collect_cloud_json(path)
            elif path.is_file() and path.suffix.lower() in CLOUD_CSV_SUFFIXES:
                yield from collect_cloud_csv(path)
            elif path.is_file() and path.suffix.lower() in CLOUD_ARCHIVE_SUFFIXES:
                yield from collect_cloud_archive(path)


def collect_cloud_archive(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    yield build_record(
        path,
        artifact_type="cloud-export-archive",
        source_index=0,
        source_hashes=source_hashes,
        details=normalize_cloud_archive(path, source_hashes=source_hashes),
    )
    yield from collect_cloud_archive_embedded_rows(path, source_hashes=source_hashes)


def collect_cloud_archive_embedded_rows(
    path: Path,
    *,
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    """Parse small, reviewable provider-export rows without extracting the ZIP."""

    try:
        with zipfile.ZipFile(path) as archive:
            entries = [info for info in sorted(archive.infolist(), key=lambda item: item.filename.lower()) if not info.is_dir()]
            parsed_entries = 0
            for archive_index, info in enumerate(entries):
                if parsed_entries >= CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT:
                    return
                product = infer_cloud_archive_product(info.filename)
                suffix = Path(info.filename).suffix.lower()
                if suffix not in {".mbox", ".json", ".csv"}:
                    continue
                if info.file_size > CLOUD_ARCHIVE_PARSE_ENTRY_MAX_BYTES:
                    continue
                try:
                    data = archive.read(info)
                except (RuntimeError, OSError, zipfile.BadZipFile):
                    continue
                if product == "gmail" and suffix == ".mbox":
                    parsed_entries += 1
                    for message_index, row in enumerate(extract_mbox_message_rows(data)):
                        row = {
                            **row,
                            **cloud_archive_row_context(
                                info,
                                archive_index=archive_index,
                                row_index=message_index,
                                source_format="zip-mbox-entry",
                                row_index_key="archive_message_index",
                            ),
                        }
                        yield build_record(
                            path,
                            artifact_type="cloud-mail",
                            source_index=(archive_index * CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT) + message_index + 1,
                            source_hashes=source_hashes,
                            details=normalize_cloud_mail(row, source_path=f"{path.resolve()}::{info.filename}"),
                        )
                    continue
                if suffix == ".csv":
                    rows = load_csv_rows_bytes(data, limit=CLOUD_ARCHIVE_CSV_ROW_LIMIT)
                    if not rows:
                        continue
                    parsed_entries += 1
                    yield from collect_cloud_tabular_rows(
                        path,
                        rows,
                        source_hashes=source_hashes,
                        source_path=f"{path.resolve()}::{info.filename}",
                        source_index_base=(archive_index * CLOUD_ARCHIVE_CSV_ROW_LIMIT) + 1,
                        row_context=cloud_archive_row_context(
                            info,
                            archive_index=archive_index,
                            row_index=0,
                            source_format="zip-csv-entry",
                            row_index_key="archive_csv_row_index",
                        ),
                    )
                    continue
                payload = load_json_bytes(data)
                if payload is None:
                    continue
                parsed_entries += 1
                yield from collect_cloud_json_payload(
                    path,
                    payload,
                    source_hashes=source_hashes,
                    source_path=f"{path.resolve()}::{info.filename}",
                    source_index_base=(archive_index * CLOUD_ARCHIVE_JSON_ROW_LIMIT) + 1,
                    archive_context=cloud_archive_row_context(
                        info,
                        archive_index=archive_index,
                        row_index=0,
                        source_format="zip-json-entry",
                        row_index_key="archive_json_row_index",
                    ),
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return


def cloud_archive_row_context(
    info: zipfile.ZipInfo,
    *,
    archive_index: int,
    row_index: int,
    source_format: str,
    row_index_key: str,
) -> dict[str, object]:
    return {
        "source_format": source_format,
        "archive_entry_name": info.filename,
        "archive_entry_index": archive_index,
        "archive_entry_crc32": f"{info.CRC:08x}",
        "archive_entry_size": int(info.file_size),
        "archive_entry_modified_at": zip_datetime_iso(info),
        row_index_key: row_index,
    }


def with_cloud_archive_context(
    details: Mapping[str, object],
    *,
    archive_context: Mapping[str, object],
    row_index: int,
) -> dict[str, object]:
    detail_payload = dict(details)
    context = dict(archive_context)
    if "archive_json_row_index" in context:
        context["archive_json_row_index"] = row_index
    if "archive_csv_row_index" in context:
        context["archive_csv_row_index"] = row_index
    detail_payload.update(context)
    checks = dict(detail_payload.get("validation_checks") or {})
    checks.update(
        {
            "archive_embedded_row": True,
            "archive_entry_name_present": bool(context.get("archive_entry_name")),
            "archive_entry_crc32_present": bool(context.get("archive_entry_crc32")),
            "bounded_archive_entry_parse": True,
            "archive_json_row_index_present": "archive_json_row_index" in context,
            "archive_csv_row_index_present": "archive_csv_row_index" in context,
        }
    )
    detail_payload["validation_checks"] = checks
    risk_flags = list(detail_payload.get("risk_flags") or [])
    risk_flags.append("provider-archive-embedded-json")
    detail_payload["risk_flags"] = sorted(set(map(str, risk_flags)))
    return detail_payload


def with_cloud_row_context(
    details: Mapping[str, object],
    *,
    row_context: Mapping[str, object],
    row_index: int,
) -> dict[str, object]:
    if any(str(key).startswith("archive_") for key in row_context):
        return with_cloud_archive_context(details, archive_context=row_context, row_index=row_index)
    detail_payload = dict(details)
    context = dict(row_context)
    if "csv_row_index" in context:
        context["csv_row_index"] = row_index
    detail_payload.update(context)
    checks = dict(detail_payload.get("validation_checks") or {})
    checks.update(
        {
            "bounded_csv_row_parse": True,
            "csv_row_index_present": "csv_row_index" in context,
        }
    )
    detail_payload["validation_checks"] = checks
    risk_flags = list(detail_payload.get("risk_flags") or [])
    risk_flags.append("provider-csv-row")
    detail_payload["risk_flags"] = sorted(set(map(str, risk_flags)))
    return detail_payload


def collect_cloud_tabular_rows(
    path: Path,
    rows: Sequence[Mapping[str, object]],
    *,
    source_hashes: Mapping[str, str],
    source_path: str,
    source_index_base: int,
    row_context: Mapping[str, object],
) -> Iterable[ArtifactRecord]:
    if not rows:
        return
    detected = detect_row_export_type(source_path.lower(), rows[0])
    normalizers = {
        "cloud-mail": ("cloud-mail", normalize_cloud_mail),
        "cloud-file": ("cloud-file", normalize_cloud_file),
        "cloud-message": ("cloud-message", normalize_cloud_message),
        "cloud-audit": ("cloud-audit", normalize_cloud_audit),
        "cloud-iaas-audit": ("cloud-iaas-audit", normalize_cloud_iaas_audit),
    }
    if detected not in normalizers:
        return
    artifact_type, normalizer = normalizers[detected]
    for index, row in enumerate(rows):
        details = normalizer(row, source_path=source_path)
        details = with_cloud_row_context(details, row_context=row_context, row_index=index)
        yield build_record(
            path,
            artifact_type=artifact_type,
            source_index=source_index_base + index,
            source_hashes=source_hashes,
            details=details,
        )


def collect_cloud_json_payload(
    path: Path,
    payload: object,
    *,
    source_hashes: Mapping[str, str],
    source_path: str,
    source_index_base: int = 0,
    archive_context: Mapping[str, object] | None = None,
) -> Iterable[ArtifactRecord]:
    detected = detect_export_type(Path(source_path), payload)
    if detected == "google-location":
        rows = extract_google_location_rows(payload)[:CLOUD_ARCHIVE_JSON_ROW_LIMIT if archive_context else None]
        for index, row in enumerate(rows):
            details = normalize_google_location(row)
            if archive_context:
                details = with_cloud_archive_context(details, archive_context=archive_context, row_index=index)
            yield build_record(
                path,
                artifact_type="cloud-location",
                source_index=source_index_base + index,
                source_hashes=source_hashes,
                details=details,
            )
        return
    if detected == "google-activity":
        rows = extract_list_rows(payload)[:CLOUD_ARCHIVE_JSON_ROW_LIMIT if archive_context else None]
        for index, row in enumerate(rows):
            details = normalize_activity(row)
            if archive_context:
                details = with_cloud_archive_context(details, archive_context=archive_context, row_index=index)
            yield build_record(
                path,
                artifact_type="cloud-activity",
                source_index=source_index_base + index,
                source_hashes=source_hashes,
                details=details,
            )
        return
    if detected == "cloud-account":
        details = normalize_account(payload if isinstance(payload, Mapping) else {}, source_path=source_path)
        if archive_context:
            details = with_cloud_archive_context(details, archive_context=archive_context, row_index=0)
        yield build_record(
            path,
            artifact_type="cloud-account",
            source_index=source_index_base,
            source_hashes=source_hashes,
            details=details,
        )
        return
    normalizers = {
        "cloud-mail": ("cloud-mail", normalize_cloud_mail),
        "cloud-file": ("cloud-file", normalize_cloud_file),
        "cloud-message": ("cloud-message", normalize_cloud_message),
        "cloud-audit": ("cloud-audit", normalize_cloud_audit),
        "cloud-iaas-audit": ("cloud-iaas-audit", normalize_cloud_iaas_audit),
    }
    if detected not in normalizers:
        return
    artifact_type, normalizer = normalizers[detected]
    rows = extract_list_or_single_rows(payload)[:CLOUD_ARCHIVE_JSON_ROW_LIMIT if archive_context else None]
    for index, row in enumerate(rows):
        details = normalizer(row, source_path=source_path)
        if archive_context:
            details = with_cloud_archive_context(details, archive_context=archive_context, row_index=index)
        yield build_record(
            path,
            artifact_type=artifact_type,
            source_index=source_index_base + index,
            source_hashes=source_hashes,
            details=details,
        )
    return


def collect_cloud_json(path: Path) -> Iterable[ArtifactRecord]:
    payload = load_json(path)
    if payload is None:
        return
    source_hashes = compute_hashes(path)
    yield from collect_cloud_json_payload(path, payload, source_hashes=source_hashes, source_path=str(path.resolve()))


def collect_cloud_csv(path: Path) -> Iterable[ArtifactRecord]:
    rows = load_csv_rows(path, limit=CLOUD_CSV_ROW_LIMIT)
    if not rows:
        return
    source_hashes = compute_hashes(path)
    yield from collect_cloud_tabular_rows(
        path,
        rows,
        source_hashes=source_hashes,
        source_path=str(path.resolve()),
        source_index_base=0,
        row_context={"source_format": "csv", "csv_row_index": 0},
    )


def normalize_cloud_archive(path: Path, *, source_hashes: Mapping[str, str]) -> dict[str, object]:
    source_path = str(path.resolve())
    entry_manifest: list[dict[str, object]] = []
    product_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    suffix_counts: dict[str, int] = {}
    total_uncompressed = 0
    total_compressed = 0
    truncated = False
    archive_opened = False
    archive_error = ""

    try:
        with zipfile.ZipFile(path) as archive:
            archive_opened = True
            entries = [info for info in archive.infolist() if not info.is_dir()]
            for index, info in enumerate(sorted(entries, key=lambda item: item.filename.lower())):
                product = infer_cloud_archive_product(info.filename)
                provider = cloud_archive_provider_for_product(product, info.filename)
                suffix = Path(info.filename).suffix.lower() or "(none)"
                product_counts[product] = product_counts.get(product, 0) + 1
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
                suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
                total_uncompressed += int(info.file_size)
                total_compressed += int(info.compress_size)
                if len(entry_manifest) >= CLOUD_ARCHIVE_ENTRY_LIMIT:
                    truncated = True
                    continue
                entry_manifest.append(
                    {
                        "index": index,
                        "name": info.filename,
                        "suffix": suffix,
                        "product_family": product,
                        "provider_family": provider,
                        "uncompressed_size": int(info.file_size),
                        "compressed_size": int(info.compress_size),
                        "crc32": f"{info.CRC:08x}",
                        "modified_at": zip_datetime_iso(info),
                        "json_candidate": suffix == ".json",
                        "csv_candidate": suffix == ".csv",
                    }
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        archive_error = str(exc)

    service = cloud_archive_service_from_counts(provider_counts, source_path)
    entry_count = sum(product_counts.values())
    json_entry_count = suffix_counts.get(".json", 0)
    csv_entry_count = suffix_counts.get(".csv", 0)
    archive_manifest = build_cloud_archive_manifest(
        source_path=source_path,
        source_hashes=source_hashes,
        service=service,
        entry_count=entry_count,
        json_entry_count=json_entry_count,
        csv_entry_count=csv_entry_count,
        product_counts=product_counts,
        provider_counts=provider_counts,
        suffix_counts=suffix_counts,
        total_uncompressed=total_uncompressed,
        total_compressed=total_compressed,
        entry_manifest=entry_manifest,
        truncated=truncated,
        archive_opened=archive_opened,
        archive_error=archive_error,
    )
    risk_flags = ["provider-export-archive"]
    if total_uncompressed >= 10 * 1024 * 1024 * 1024:
        risk_flags.append("large-cloud-export-archive")
    if product_counts.get("gmail") or product_counts.get("icloud-mail") or product_counts.get("exchange"):
        risk_flags.append("contains-mail-export")
    if product_counts.get("location-history"):
        risk_flags.append("contains-location-export")
    if product_counts.get("teams"):
        risk_flags.append("contains-team-chat-export")

    return {
        "service": service,
        "event_type": "cloud-export-archive",
        "timestamp": "",
        "archive_entry_count": entry_count,
        "archive_json_entry_count": json_entry_count,
        "archive_csv_entry_count": csv_entry_count,
        "archive_total_uncompressed_size": total_uncompressed,
        "archive_total_compressed_size": total_compressed,
        "archive_manifest_truncated": truncated,
        "archive_error": archive_error,
        "product_counts": dict(sorted(product_counts.items())),
        "provider_counts": dict(sorted(provider_counts.items())),
        "suffix_counts": dict(sorted(suffix_counts.items())),
        "cloud_archive_manifest": archive_manifest,
        "cloud_archive_manifest_hash": archive_manifest["manifest_sha256"],
        "risk_flags": risk_flags,
        "validation_checks": {
            "archive_opened": archive_opened,
            "archive_entry_manifest_emitted": True,
            "has_required_field_candidate": archive_opened and entry_count > 0,
            "provider_export_schema_validated": False,
            "provider_scope_verified": False,
            "provider_known_answer_validated": False,
            "original_export_hash_verified": bool(source_hashes.get("sha256")),
            "timezone_semantics_verified": False,
            "json_entry_count": json_entry_count,
            "csv_entry_count": csv_entry_count,
            "product_family_count": len(product_counts),
        },
        "commercial_grade_blockers": cloud_blockers(service)
        + [
            "provider-selected-products-or-workload-scope-manifest-required",
            "split-archive-completeness-and-password-state-required",
            "provider-native-export-or-api-diff-required",
        ],
        "legal_warning": "Provider export archives may contain broad account, tenant, mail, file, and location data. Preserve the original archive hash and verify export scope before reporting.",
        "raw": {
            "archive_name": path.name,
            "entry_manifest_sample": entry_manifest,
            "entry_manifest_truncated": truncated,
        },
    }


def build_record(
    path: Path,
    *,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> ArtifactRecord:
    detail_payload = dict(details)
    service = str(detail_payload.get("service") or "")
    gap_ids, family = cloud_gap_ids(service, artifact_type)
    detail_payload.setdefault(
        "cloud_provider_strategy_profile",
        cloud_provider_strategy_profile(
            family=family,
            service=service,
            artifact_type=artifact_type,
            details=detail_payload,
        ),
    )
    google_review_profile = google_takeout_review_profile(
        family=family,
        service=service,
        artifact_type=artifact_type,
        source_path=str(path.resolve()),
        details=detail_payload,
    )
    if google_review_profile:
        detail_payload["google_takeout_review_profile"] = google_review_profile
        checks = dict(detail_payload.get("validation_checks") or {})
        checks.update(
            {
                "google_takeout_review_profile_emitted": True,
                "google_takeout_product_inferred": bool(google_review_profile.get("product_family")),
                "google_takeout_row_pivot_present": bool(google_review_profile.get("primary_pivot_present")),
            }
        )
        detail_payload["validation_checks"] = checks
    icloud_review_profile = icloud_export_review_profile(
        family=family,
        service=service,
        artifact_type=artifact_type,
        source_path=str(path.resolve()),
        details=detail_payload,
    )
    if icloud_review_profile:
        detail_payload["icloud_export_review_profile"] = icloud_review_profile
        checks = dict(detail_payload.get("validation_checks") or {})
        checks.update(
            {
                "icloud_export_review_profile_emitted": True,
                "icloud_product_inferred": bool(icloud_review_profile.get("product_family")),
                "icloud_row_pivot_present": bool(icloud_review_profile.get("primary_pivot_present")),
            }
        )
        detail_payload["validation_checks"] = checks
    m365_review_profile = m365_export_review_profile(
        family=family,
        service=service,
        artifact_type=artifact_type,
        source_path=str(path.resolve()),
        details=detail_payload,
    )
    if m365_review_profile:
        detail_payload["m365_export_review_profile"] = m365_review_profile
        checks = dict(detail_payload.get("validation_checks") or {})
        checks.update(
            {
                "m365_export_review_profile_emitted": True,
                "m365_workload_inferred": bool(m365_review_profile.get("workload_family")),
                "m365_row_pivot_present": bool(m365_review_profile.get("primary_pivot_present")),
            }
        )
        detail_payload["validation_checks"] = checks
    detail_payload["cloud_export_import_manifest"] = build_cloud_export_import_manifest(
        artifact_type=artifact_type,
        family=family,
        service=service,
        source_index=source_index,
        source_hashes=source_hashes,
        source_path=str(path.resolve()),
        details=detail_payload,
    )
    detail_payload["cloud_export_import_manifest_hash"] = detail_payload["cloud_export_import_manifest"]["manifest_sha256"]
    if family == "google":
        detail_payload["google_takeout_parser_manifest"] = build_google_takeout_parser_manifest(
            artifact_type=artifact_type,
            service=service,
            source_index=source_index,
            source_hashes=source_hashes,
            source_path=str(path.resolve()),
            details=detail_payload,
        )
        detail_payload["google_takeout_parser_manifest_hash"] = detail_payload["google_takeout_parser_manifest"][
            "manifest_sha256"
        ]
    if family == "apple-icloud":
        detail_payload["icloud_export_parser_manifest"] = build_icloud_export_parser_manifest(
            artifact_type=artifact_type,
            service=service,
            source_index=source_index,
            source_hashes=source_hashes,
            source_path=str(path.resolve()),
            details=detail_payload,
        )
        detail_payload["icloud_export_parser_manifest_hash"] = detail_payload["icloud_export_parser_manifest"][
            "manifest_sha256"
        ]
    if family == "microsoft-365":
        detail_payload["m365_export_parser_manifest"] = build_m365_export_parser_manifest(
            artifact_type=artifact_type,
            service=service,
            source_index=source_index,
            source_hashes=source_hashes,
            source_path=str(path.resolve()),
            details=detail_payload,
        )
        detail_payload["m365_export_parser_manifest_hash"] = detail_payload["m365_export_parser_manifest"][
            "manifest_sha256"
        ]
    validation_checks = detail_payload.get("validation_checks")
    if not isinstance(validation_checks, Mapping):
        validation_checks = {}
    report_grade = cloud_report_grade_assessment(gap_ids, family, service)
    return ArtifactRecord(
        provider=CloudExportProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "cloud-export",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": str(detail_payload.get("source_format") or ("zip" if artifact_type == "cloud-export-archive" else "json")),
            "source_index": source_index,
            "source_hashes": dict(source_hashes),
            "commercial_grade_ready": False,
            "commercial_gap_ids": gap_ids,
            "cloud_family": family,
            "cloud_validation_matrix": cloud_validation_matrix(validation_checks),
            "cloud_report_grade_assessment": report_grade,
            "commercial_uplift_evidence": cloud_commercial_uplift_evidence(
                gap_ids=gap_ids,
                family=family,
                service=service,
                artifact_type=artifact_type,
                source_index=source_index,
                source_hashes=source_hashes,
                validation_checks=validation_checks,
                issue_matrix=cloud_issue_matrix(family, artifact_type),
                report_grade=report_grade,
                details=detail_payload,
                source_path=str(path.resolve()),
            ),
            "cloud_native_capabilities": dict(CLOUD_NATIVE_CAPABILITIES),
            "cloud_provider_profile": cloud_provider_profile(family, service),
            "cloud_issue_matrix": cloud_issue_matrix(family, artifact_type),
            "core_accuracy_gates": cloud_core_accuracy_gates(
                gap_ids=gap_ids,
                family=family,
                service=service,
                artifact_type=artifact_type,
                source_hashes=source_hashes,
                details=detail_payload,
                source_index=source_index,
                source_path=str(path.resolve()),
            ),
            "forensic_review": cloud_forensic_review(
                gap_ids=gap_ids,
                family=family,
                service=service,
                artifact_type=artifact_type,
                report_grade=report_grade,
                details=detail_payload,
            ),
            "cloud_analyst_review_profile": cloud_analyst_review_profile(
                gap_ids=gap_ids,
                family=family,
                service=service,
                artifact_type=artifact_type,
                source_index=source_index,
                source_hashes=source_hashes,
                source_path=str(path.resolve()),
                report_grade=report_grade,
                details=detail_payload,
            ),
            **detail_payload,
        },
    )


def load_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def load_json_bytes(data: bytes) -> object | None:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def load_csv_rows(path: Path, *, limit: int) -> list[Mapping[str, object]]:
    rows: list[Mapping[str, object]] = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if index >= limit:
                    break
                rows.append({str(key): value for key, value in row.items() if key is not None})
    except (OSError, UnicodeDecodeError, csv.Error):
        return []
    return rows


def load_csv_rows_bytes(data: bytes, *, limit: int) -> list[Mapping[str, object]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    rows: list[Mapping[str, object]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for index, row in enumerate(reader):
            if index >= limit:
                break
            rows.append({str(key): value for key, value in row.items() if key is not None})
    except csv.Error:
        return []
    return rows


def detect_export_type(path: Path, payload: object) -> str:
    lowered = str(path).lower()
    if isinstance(payload, Mapping):
        if "locations" in payload and isinstance(payload["locations"], list):
            return "google-location"
        rows = extract_list_or_single_rows(payload)
        if rows:
            row_type = detect_row_export_type(lowered, rows[0])
            if row_type:
                return row_type
        account_keys = {"account", "apple id", "email", "phone", "full_name", "name", "created"}
        if account_keys.intersection({str(key).lower() for key in payload.keys()}):
            return "cloud-account"
    if isinstance(payload, list) and payload and all(isinstance(item, Mapping) for item in payload[:5]):
        row_type = detect_row_export_type(lowered, payload[0])
        if row_type:
            return row_type
        if "my activity" in lowered or "takeout" in lowered or any("time" in item or "timestamp" in item for item in payload[:5] if isinstance(item, Mapping)):
            return "google-activity"
    return ""


def detect_row_export_type(source_hint: str, row: Mapping[str, object]) -> str:
    keys = {normalize_key(key) for key in row}
    if is_iaas_audit_row(source_hint, keys, row):
        return "cloud-iaas-audit"
    if (
        "gmail" in source_hint
        or "/mail/" in source_hint
        or keys.intersection({"messageid", "internetmessageid"})
        or ("subject" in keys and keys.intersection({"to", "torecipients", "senderemailaddress"}))
    ):
        return "cloud-mail"
    if any(token in source_hint for token in ("teams", "chat", "messages")) or keys.intersection(
        {"chatid", "channelid", "teamid", "messagetext", "bodycontent"}
    ):
        return "cloud-message"
    if any(token in source_hint for token in ("drive", "onedrive", "icloud", "photos", "files")) or keys.intersection(
        {"filename", "fileid", "weburl", "downloadurl", "owner", "owners", "size", "mimeType".lower()}
    ):
        return "cloud-file"
    if any(token in source_hint for token in ("audit", "security", "signin", "sign-in")) or keys.intersection(
        {"operation", "activity", "actor", "useragent", "ipaddress", "clientip"}
    ):
        return "cloud-audit"
    return ""


def extract_google_location_rows(payload: object) -> list[Mapping[str, object]]:
    if isinstance(payload, Mapping) and isinstance(payload.get("locations"), list):
        return [item for item in payload["locations"] if isinstance(item, Mapping)]
    return []


def extract_list_rows(payload: object) -> list[Mapping[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    return []


def extract_list_or_single_rows(payload: object) -> list[Mapping[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        for key in ("messages", "mail", "files", "items", "events", "auditRecords", "records", "Records", "value"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
        return [payload]
    return []


def extract_mbox_message_rows(data: bytes) -> list[Mapping[str, object]]:
    rows: list[Mapping[str, object]] = []
    chunks = re.split(rb"\n(?=From [^\n]+\n)", data)
    for chunk in chunks[:CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT]:
        if chunk.startswith(b"From "):
            chunk = chunk.split(b"\n", 1)[1] if b"\n" in chunk else b""
        if not chunk.strip():
            continue
        message = email.message_from_bytes(chunk, policy=policy.default)
        rows.append(
            {
                "subject": optional_text(message.get("subject", "")),
                "from": optional_text(message.get("from", "")),
                "to": optional_text(message.get("to", "")),
                "date": optional_text(message.get("date", "")),
                "messageId": optional_text(message.get("message-id", "")),
                "body": extract_email_text_body(message),
                "attachmentCount": count_email_attachments(message),
            }
        )
    return rows


def extract_email_text_body(message: email.message.Message) -> str:
    if message.is_multipart():
        for part in message.walk():
            content_disposition = str(part.get("content-disposition", "")).lower()
            if "attachment" in content_disposition:
                continue
            if part.get_content_type() != "text/plain":
                continue
            try:
                return optional_text(part.get_content())
            except (LookupError, UnicodeDecodeError, AttributeError):
                payload = part.get_payload(decode=True)
                return decode_email_payload(payload)
        return ""
    try:
        return optional_text(message.get_content())
    except (LookupError, UnicodeDecodeError, AttributeError):
        payload = message.get_payload(decode=True)
        return decode_email_payload(payload)


def decode_email_payload(payload: object) -> str:
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        return payload
    return ""


def count_email_attachments(message: email.message.Message) -> int:
    count = 0
    for part in message.walk():
        content_disposition = str(part.get("content-disposition", "")).lower()
        filename = part.get_filename()
        if "attachment" in content_disposition or filename:
            count += 1
    return count


def normalize_google_location(row: Mapping[str, object]) -> dict[str, object]:
    latitude = e7_to_decimal(row.get("latitudeE7") or row.get("latitude_e7"))
    longitude = e7_to_decimal(row.get("longitudeE7") or row.get("longitude_e7"))
    timestamp = normalize_timestamp(row.get("timestamp") or row.get("timestampMs") or row.get("time"))
    accuracy = optional_text(row.get("accuracy") or row.get("accuracyMeters"))
    return {
        "service": "google-takeout",
        "event_type": "location",
        "timestamp": timestamp,
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_meters": accuracy,
        "source": optional_text(row.get("source") or row.get("deviceTag")),
        "risk_flags": ["precise-location"] if latitude is not None and longitude is not None else [],
        "validation_checks": cloud_validation_checks(row, required=("timestamp", "timestampMs", "latitudeE7", "longitudeE7")),
        "commercial_grade_blockers": cloud_blockers("google-location"),
        "raw": dict(row),
    }


def normalize_activity(row: Mapping[str, object]) -> dict[str, object]:
    title = optional_text(row.get("title"))
    products = normalize_products(row.get("products"))
    details = row.get("details") if isinstance(row.get("details"), list) else []
    timestamp = normalize_timestamp(row.get("time") or row.get("timestamp") or row.get("timestampMs"))
    risk_flags = []
    lowered = " ".join([title, " ".join(products)]).lower()
    if any(token in lowered for token in ("search", "chrome", "youtube", "maps")):
        risk_flags.append("user-activity")
    if any(token in lowered for token in ("login", "password", "security")):
        risk_flags.append("security-related")
    return {
        "service": "google-takeout",
        "event_type": "activity",
        "timestamp": timestamp,
        "title": title,
        "products": products,
        "details": details,
        "risk_flags": risk_flags,
        "validation_checks": cloud_validation_checks(row, required=("time", "timestamp", "title")),
        "commercial_grade_blockers": cloud_blockers("google-activity"),
        "raw": dict(row),
    }


def normalize_account(payload: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    email = optional_text(payload.get("email") or payload.get("Email") or payload.get("account"))
    name = optional_text(payload.get("name") or payload.get("full_name") or payload.get("Full Name"))
    created = normalize_timestamp(payload.get("created") or payload.get("creation_time") or payload.get("Created"))
    service = "apple-export" if "apple" in source_path.lower() else "cloud-export"
    return {
        "service": service,
        "event_type": "account",
        "timestamp": created,
        "account_email": email,
        "account_name": name,
        "field_count": len(payload),
        "risk_flags": ["account-profile"] if email or name else [],
        "validation_checks": cloud_validation_checks(payload, required=("email", "account", "name")),
        "commercial_grade_blockers": cloud_blockers(service),
        "legal_warning": "Cloud account exports may contain personal or privileged data. Verify authorization, export scope, and provider timestamp semantics.",
        "raw": dict(payload),
    }


def normalize_cloud_mail(row: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    subject = optional_text(first_value(row, ("subject", "Subject", "title")))
    body = optional_text(first_value(row, ("body", "snippet", "text", "plainText", "bodyPreview")))
    archive_fields = {
        key: row[key]
        for key in (
            "source_format",
            "archive_entry_name",
            "archive_entry_index",
            "archive_entry_crc32",
            "archive_entry_size",
            "archive_entry_modified_at",
            "archive_message_index",
        )
        if key in row
    }
    validation_checks = cloud_validation_checks(row, required=("subject", "from", "date", "receivedDateTime"))
    if archive_fields:
        validation_checks.update(
            {
                "archive_embedded_row": True,
                "archive_entry_name_present": bool(archive_fields.get("archive_entry_name")),
                "archive_entry_crc32_present": bool(archive_fields.get("archive_entry_crc32")),
                "bounded_archive_entry_parse": True,
            }
        )
    return {
        "service": service_from_path(source_path, default="gmail-takeout" if "takeout" in source_path.lower() else "cloud-mail"),
        "event_type": "mail",
        "timestamp": normalize_timestamp(first_value(row, ("date", "time", "timestamp", "createdDateTime", "receivedDateTime", "sentDateTime"))),
        "subject": subject,
        "from": optional_text(first_value(row, ("from", "sender", "senderEmailAddress"))),
        "to": optional_text(first_value(row, ("to", "recipients", "toRecipients"))),
        "message_id": optional_text(first_value(row, ("messageId", "messageid", "id", "internetMessageId"))),
        "body_preview": body[:1000],
        "body_sha256": sha256_text(body) if body else "",
        "attachment_count": optional_text(first_value(row, ("attachmentCount", "attachments", "hasAttachments"))),
        "risk_flags": cloud_text_risk_flags(subject, body) + (["provider-archive-embedded-mail"] if archive_fields else []),
        "validation_checks": validation_checks,
        "commercial_grade_blockers": cloud_blockers("cloud-mail"),
        **archive_fields,
        "raw": dict(row),
    }


def normalize_cloud_file(row: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    name = optional_text(first_value(row, ("name", "fileName", "filename", "title", "displayName")))
    url = optional_text(first_value(row, ("url", "webUrl", "downloadUrl", "alternateLink")))
    return {
        "service": service_from_path(source_path, default="cloud-files"),
        "event_type": "file",
        "timestamp": normalize_timestamp(first_value(row, ("modifiedTime", "createdTime", "lastModifiedDateTime", "dateCreated", "time"))),
        "file_id": optional_text(first_value(row, ("id", "fileId", "docId"))),
        "file_name": name,
        "mime_type": optional_text(first_value(row, ("mimeType", "mime", "contentType"))),
        "size": optional_text(first_value(row, ("size", "fileSize", "quotaBytesUsed"))),
        "owner": optional_text(first_value(row, ("owner", "owners", "createdBy", "lastModifiedBy"))),
        "url": url,
        "url_sha256": sha256_text(url) if url else "",
        "risk_flags": cloud_file_risk_flags(name, url),
        "validation_checks": cloud_validation_checks(row, required=("name", "fileName", "id", "webUrl")),
        "commercial_grade_blockers": cloud_blockers("cloud-file"),
        "raw": dict(row),
    }


def normalize_cloud_message(row: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    text = optional_text(first_value(row, ("messageText", "messagetext", "body", "bodyContent", "content", "text")))
    return {
        "service": service_from_path(source_path, default="microsoft-teams" if "teams" in source_path.lower() else "cloud-message"),
        "event_type": "message",
        "timestamp": normalize_timestamp(first_value(row, ("createdDateTime", "lastModifiedDateTime", "time", "timestamp", "date"))),
        "team_id": optional_text(first_value(row, ("teamId", "teamid"))),
        "channel_id": optional_text(first_value(row, ("channelId", "channelid"))),
        "chat_id": optional_text(first_value(row, ("chatId", "chatid", "conversationId"))),
        "message_id": optional_text(first_value(row, ("id", "messageId", "messageid"))),
        "sender": optional_text(first_value(row, ("from", "sender", "user", "actor"))),
        "message_text_preview": text[:1000],
        "message_text_sha256": sha256_text(text) if text else "",
        "risk_flags": ["cloud-message"] + cloud_text_risk_flags("", text),
        "validation_checks": cloud_validation_checks(row, required=("createdDateTime", "messageText", "body", "id")),
        "commercial_grade_blockers": cloud_blockers("cloud-message"),
        "raw": dict(row),
    }


def normalize_cloud_audit(row: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    operation = optional_text(first_value(row, ("operation", "activity", "eventName", "action", "Operation")))
    return {
        "service": service_from_path(source_path, default="microsoft-365-audit" if "microsoft" in source_path.lower() or "m365" in source_path.lower() else "cloud-audit"),
        "event_type": "audit",
        "timestamp": normalize_timestamp(first_value(row, ("creationTime", "createdDateTime", "time", "timestamp", "date"))),
        "operation": operation,
        "actor": optional_text(first_value(row, ("actor", "userId", "user", "userPrincipalName", "Actor"))),
        "ip_address": optional_text(first_value(row, ("ipAddress", "clientIP", "clientIp", "ClientIP"))),
        "user_agent": optional_text(first_value(row, ("userAgent", "UserAgent"))),
        "object_id": optional_text(first_value(row, ("objectId", "itemName", "target", "resource"))),
        "risk_flags": cloud_audit_risk_flags(operation, row),
        "validation_checks": cloud_validation_checks(row, required=("operation", "activity", "creationTime", "actor")),
        "commercial_grade_blockers": cloud_blockers("cloud-audit"),
        "raw": dict(row),
    }


def normalize_cloud_iaas_audit(row: Mapping[str, object], *, source_path: str) -> dict[str, object]:
    provider = infer_iaas_provider(source_path, row)
    operation = optional_text(
        first_value(row, ("eventName", "operationName", "methodName", "protoPayload.methodName", "action", "operation"))
        or nested_value(row, ("protoPayload", "methodName"))
    )
    principal = optional_text(
        nested_value(row, ("userIdentity", "arn"))
        or nested_value(row, ("userIdentity", "principalId"))
        or nested_value(row, ("protoPayload", "authenticationInfo", "principalEmail"))
        or first_value(row, ("caller", "callerIpAddress", "identity", "principal", "user", "actor"))
    )
    ip_address = optional_text(
        first_value(row, ("sourceIPAddress", "callerIpAddress", "ipAddress", "clientIP", "clientIp"))
        or nested_value(row, ("protoPayload", "requestMetadata", "callerIp"))
    )
    resource_id = optional_text(
        first_value(row, ("resourceId", "resourceName", "resource", "objectId"))
        or nested_value(row, ("resource", "labels", "project_id"))
        or nested_value(row, ("responseElements", "instancesSet"))
    )
    return {
        "service": provider,
        "event_type": "iaas-audit",
        "timestamp": normalize_timestamp(
            first_value(row, ("eventTime", "time", "timestamp", "creationTime", "eventTimestamp"))
            or nested_value(row, ("protoPayload", "metadata", "eventTimestamp"))
        ),
        "operation": operation,
        "principal": principal,
        "actor": principal,
        "ip_address": ip_address,
        "region": optional_text(first_value(row, ("awsRegion", "region", "location"))),
        "event_source": optional_text(first_value(row, ("eventSource", "category", "serviceName"))),
        "account_id": optional_text(
            first_value(row, ("recipientAccountId", "accountId", "subscriptionId"))
            or nested_value(row, ("userIdentity", "accountId"))
            or nested_value(row, ("resource", "labels", "project_id"))
        ),
        "resource_id": resource_id,
        "request_parameters_preview": preview_json(
            first_value(row, ("requestParameters", "authorization", "properties"))
            or nested_value(row, ("protoPayload", "request"))
        ),
        "response_preview": preview_json(
            first_value(row, ("responseElements", "status", "properties"))
            or nested_value(row, ("protoPayload", "response"))
        ),
        "risk_flags": cloud_iaas_risk_flags(provider, operation, row),
        "validation_checks": {
            **cloud_validation_checks(row, required=("eventName", "operationName", "methodName", "eventTime", "time")),
            "iaas_provider_inferred": bool(provider),
            "provider_scope_verified": False,
            "provider_known_answer_validated": False,
        },
        "commercial_grade_blockers": [
            "provider-audit-export-scope-not-verified",
            "organization-subscription-project-scope-not-attached",
            "provider-native-console-or-siem-diff-required",
            "retention-log-integrity-chain-not-validated",
        ],
        "raw": dict(row),
    }


def is_iaas_audit_row(source_hint: str, keys: set[str], row: Mapping[str, object]) -> bool:
    if any(token in source_hint for token in ("cloudtrail", "aws", "azure", "entra", "gcp", "googlecloud", "google cloud")):
        return True
    if keys.intersection({"eventsource", "eventname", "eventtime", "awsregion", "sourceipaddress", "recipientaccountid"}):
        return True
    if keys.intersection({"operationname", "calleripaddress", "subscriptionid", "resourceid"}):
        return True
    if "protopayload" in keys or nested_value(row, ("protoPayload", "methodName")):
        return True
    return False


def infer_iaas_provider(source_path: str, row: Mapping[str, object]) -> str:
    lowered = source_path.lower().replace("_", "-")
    if "cloudtrail" in lowered or "/aws" in lowered or "\\aws" in lowered or "aws-" in lowered:
        return "aws-cloudtrail"
    if "azure" in lowered or "entra" in lowered or "operationname" in {normalize_key(key) for key in row}:
        return "azure-activity-log"
    if (
        "gcp" in lowered
        or "googlecloud" in lowered
        or "google cloud" in lowered
        or "google-cloud" in lowered
        or nested_value(row, ("protoPayload", "methodName"))
    ):
        return "gcp-audit-log"
    keys = {normalize_key(key) for key in row}
    if keys.intersection({"eventsource", "awsregion", "recipientaccountid"}):
        return "aws-cloudtrail"
    return "iaas-cloud-audit"


def nested_value(row: Mapping[str, object], path: Sequence[str]) -> object:
    current: object = row
    for key in path:
        if not isinstance(current, Mapping):
            return ""
        if key in current:
            current = current[key]
            continue
        normalized_key = normalize_key(key)
        match = next((value for candidate, value in current.items() if normalize_key(candidate) == normalized_key), "")
        current = match
    return current


def preview_json(value: object, *, limit: int = 1000) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value[:limit]
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)[:limit]
    except TypeError:
        return str(value)[:limit]


def cloud_iaas_risk_flags(provider: str, operation: str, row: Mapping[str, object]) -> list[str]:
    lowered_operation = operation.lower()
    lowered_row = json.dumps(row, ensure_ascii=False, default=str).lower()
    flags = ["iaas-audit-row"]
    if any(term in lowered_operation for term in ("delete", "disable", "detach", "revoke", "remove")):
        flags.append("destructive-cloud-action")
    if any(term in lowered_operation for term in ("createaccesskey", "putuserpolicy", "assumerole", "setiampolicy")):
        flags.append("identity-privilege-action")
    if any(term in lowered_row for term in ("accessdenied", "unauthorized", "denied")):
        flags.append("failed-or-denied-cloud-action")
    if provider == "aws-cloudtrail" and "root" in lowered_row:
        flags.append("aws-root-identity-reference")
    return flags


def first_value(row: Mapping[str, object], keys: Iterable[str]) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for key in keys:
        for candidate in (key, normalize_key(key)):
            if candidate in row and row[candidate] not in (None, ""):
                return row[candidate]
            if candidate in normalized and normalized[candidate] not in (None, ""):
                return normalized[candidate]
    return ""


def infer_cloud_archive_product(name: str) -> str:
    lowered = name.lower().replace("\\", "/")
    if "gmail" in lowered or "/mail/" in lowered or lowered.endswith(".mbox"):
        return "gmail"
    if "location history" in lowered or "semantic location" in lowered or "records.json" in lowered:
        return "location-history"
    if "my activity" in lowered or "/activity/" in lowered:
        return "my-activity"
    if "google photos" in lowered or "/photos/" in lowered:
        return "photos"
    if "/drive/" in lowered or "my drive" in lowered or "google drive" in lowered:
        return "drive"
    if "teams" in lowered or "team chat" in lowered:
        return "teams"
    if "onedrive" in lowered:
        return "onedrive"
    if "sharepoint" in lowered:
        return "sharepoint"
    if "exchange" in lowered or "purview" in lowered or "ediscovery" in lowered:
        return "exchange"
    if "audit" in lowered or "unified audit" in lowered:
        return "m365-audit"
    if "icloud" in lowered and ("photo" in lowered or "album" in lowered):
        return "icloud-photos"
    if "icloud" in lowered and "mail" in lowered:
        return "icloud-mail"
    if "icloud" in lowered or "apple" in lowered:
        return "icloud-drive"
    if "account" in lowered or "profile" in lowered:
        return "account"
    return "unknown"


def cloud_archive_provider_for_product(product: str, name: str) -> str:
    lowered = name.lower()
    if product in {"gmail", "location-history", "my-activity", "photos", "drive"} or "takeout" in lowered:
        return "google"
    if product in {"teams", "onedrive", "sharepoint", "exchange", "m365-audit"} or any(
        token in lowered for token in ("m365", "microsoft", "office 365", "purview", "ediscovery")
    ):
        return "microsoft-365"
    if product in {"icloud-photos", "icloud-mail", "icloud-drive"} or any(token in lowered for token in ("icloud", "apple")):
        return "apple-icloud"
    return "unknown"


def cloud_archive_service_from_counts(provider_counts: Mapping[str, int], source_path: str) -> str:
    known = {provider: count for provider, count in provider_counts.items() if provider != "unknown"}
    if known:
        provider = max(sorted(known), key=lambda item: known[item])
        return {
            "google": "google-takeout",
            "microsoft-365": "microsoft-365",
            "apple-icloud": "apple-icloud-export",
        }.get(provider, "cloud-export")
    return service_from_path(source_path, default="cloud-export")


def zip_datetime_iso(info: zipfile.ZipInfo) -> str:
    try:
        return dt.datetime(*info.date_time, tzinfo=dt.timezone.utc).isoformat()
    except (TypeError, ValueError):
        return ""


def build_cloud_archive_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    service: str,
    entry_count: int,
    json_entry_count: int,
    csv_entry_count: int,
    product_counts: Mapping[str, int],
    provider_counts: Mapping[str, int],
    suffix_counts: Mapping[str, int],
    total_uncompressed: int,
    total_compressed: int,
    entry_manifest: Sequence[Mapping[str, object]],
    truncated: bool,
    archive_opened: bool,
    archive_error: str,
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "manifest_version": "cloud-export-archive-manifest-v1",
        "source_path": source_path,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": service,
        "archive_opened": archive_opened,
        "archive_error": archive_error,
        "entry_count": entry_count,
        "json_entry_count": json_entry_count,
        "csv_entry_count": csv_entry_count,
        "product_counts": dict(sorted(product_counts.items())),
        "provider_counts": dict(sorted(provider_counts.items())),
        "suffix_counts": dict(sorted(suffix_counts.items())),
        "total_uncompressed_size": total_uncompressed,
        "total_compressed_size": total_compressed,
        "entry_manifest_limit": CLOUD_ARCHIVE_ENTRY_LIMIT,
        "entry_manifest_truncated": truncated,
        "entry_manifest": [dict(item) for item in entry_manifest],
        "source_viewer_locator": {
            "viewer": "cloud-provider-archive-manifest",
            "source_path": source_path,
            "service": service,
            "entry_manifest_limit": CLOUD_ARCHIVE_ENTRY_LIMIT,
        },
        "validation_status": "archive-inventoried-scope-validation-required",
        "commercial_blockers": [
            "provider-selected-products-or-workload-scope-manifest-required",
            "split-archive-completeness-and-password-state-required",
            "provider-native-export-or-api-diff-required",
            "known-answer-cloud-export-corpus-required",
        ],
    }
    manifest["manifest_sha256"] = stable_cloud_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def normalize_key(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def service_from_path(source_path: str, *, default: str) -> str:
    lowered = source_path.lower()
    if "cloudtrail" in lowered or "/aws" in lowered or "\\aws" in lowered or "aws-" in lowered:
        return "aws-cloudtrail"
    if "azure" in lowered or "entra" in lowered:
        return "azure-activity-log"
    if "gcp" in lowered or "google cloud" in lowered or "googlecloud" in lowered:
        return "gcp-audit-log"
    if "gmail" in lowered or "/mail/" in lowered or "\\mail\\" in lowered:
        return "gmail-takeout"
    if "slack" in lowered:
        return "slack"
    if "dropbox" in lowered:
        return "dropbox"
    if "/box/" in lowered or "\\box\\" in lowered or "box export" in lowered:
        return "box"
    if "zoom" in lowered:
        return "zoom"
    if "icloud" in lowered or "apple" in lowered:
        return "apple-icloud-export"
    if "teams" in lowered:
        return "microsoft-teams"
    if "onedrive" in lowered:
        return "microsoft-onedrive"
    if "m365" in lowered or "microsoft" in lowered or "office" in lowered:
        return "microsoft-365"
    if "takeout" in lowered or "google" in lowered or "drive" in lowered:
        return "google-takeout"
    return default


def cloud_gap_ids(service: str, artifact_type: str) -> CloudGap:
    lowered = f"{service} {artifact_type}".lower()
    if any(token in lowered for token in ("iaas", "cloudtrail", "aws", "azure", "entra", "gcp-audit", "google cloud")):
        return ["#40"], "iaas-cloud"
    if any(token in lowered for token in ("slack", "dropbox", "box", "zoom", "notion", "atlassian", "github")):
        return ["#37", "#38", "#39"], "collaboration-saas"
    if any(token in lowered for token in ("microsoft", "m365", "office", "onedrive", "teams")):
        return ["#39"], "microsoft-365"
    if any(token in lowered for token in ("icloud", "apple")):
        return ["#38"], "apple-icloud"
    if any(token in lowered for token in ("gmail", "google", "takeout", "google-drive")):
        return ["#37"], "google"
    return ["#37", "#38", "#39"], "cloud-export"


def _gap_numbers(gap_ids: Iterable[str]) -> list[int]:
    numbers: list[int] = []
    for gap_id in gap_ids:
        text = str(gap_id).lstrip("#")
        if text.isdigit():
            numbers.append(int(text))
    return numbers


def cloud_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    return [
        {
            "id": "source-hash-present",
            "label": "Cloud export source is hashed",
            "passed": True,
            "severity": "critical",
        },
        {
            "id": "core-fields-normalized",
            "label": "Core timestamp/account/content fields are normalized",
            "passed": bool(checks.get("has_required_field_candidate", True)),
            "severity": "high",
        },
        {
            "id": "provider-scope-verified",
            "label": "Provider export scope, API scope, and tenant/account ownership are verified",
            "passed": bool(checks.get("provider_scope_verified")),
            "severity": "critical",
        },
        {
            "id": "deleted-and-sharing-state",
            "label": "Deleted object state, sharing/permission graph, and retention semantics are validated",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "known-answer-cloud-validation",
            "label": "Parser behavior is validated against provider known-answer exports",
            "passed": False,
            "severity": "critical",
        },
    ]


def cloud_report_grade_assessment(gap_ids: list[str], family: str, service: str) -> dict[str, object]:
    trusted_diff_blockers = [
        CLOUD_TRUSTED_DIFF_BLOCKERS[number]
        for number in _gap_numbers(gap_ids)
        if number in CLOUD_TRUSTED_DIFF_BLOCKERS
    ]
    return {
        "status": "validation-required",
        "commercial_gap_ids": list(gap_ids),
        "cloud_family": family,
        "service": service,
        "blockers": [*CLOUD_REPORT_GRADE_BLOCKERS, *trusted_diff_blockers],
        "ready_for_court_report": False,
        "recommended_validation": [
            "Preserve provider export/API scope, account ownership proof, timestamps/timezone notes, and original export hashes.",
            "Validate key mail/file/message/audit rows against provider-native views or known-answer exports before testimony.",
        ],
    }


def cloud_export_import_functional_profile(
    *,
    family: str,
    service: str,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    validation_checks: Mapping[str, object],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    export_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    google_manifest = (
        details.get("google_takeout_parser_manifest")
        if isinstance(details.get("google_takeout_parser_manifest"), Mapping)
        else {}
    )
    icloud_manifest = (
        details.get("icloud_export_parser_manifest")
        if isinstance(details.get("icloud_export_parser_manifest"), Mapping)
        else {}
    )
    m365_manifest = (
        details.get("m365_export_parser_manifest")
        if isinstance(details.get("m365_export_parser_manifest"), Mapping)
        else {}
    )
    archive_manifest = (
        details.get("cloud_archive_manifest")
        if isinstance(details.get("cloud_archive_manifest"), Mapping)
        else {}
    )
    failed_checks = [
        check
        for check, failed in {
            "provider-export-scope-not-verified": not validation_checks.get("provider_scope_verified"),
            "original-cloud-export-hash-not-verified": not validation_checks.get("original_export_hash_verified"),
            "provider-known-answer-corpus-required": not validation_checks.get("provider_known_answer_validated"),
            "cloud-export-import-manifest-not-emitted": not export_manifest,
            "google-takeout-parser-manifest-not-emitted": family == "google" and not google_manifest,
            "icloud-export-parser-manifest-not-emitted": family == "apple-icloud" and not icloud_manifest,
            "m365-export-parser-manifest-not-emitted": family == "microsoft-365" and not m365_manifest,
            "trusted-provider-export-diff-required": trusted_diff.get("status") != "pass",
        }.items()
        if failed
    ]
    return {
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "item_number": 55,
        "qc_prep_item_numbers": cloud_qc_prep_item_numbers(family),
        "qc_prep_contracts": cloud_qc_prep_contracts(family),
        "implementation_track": "cloud-export-import-provider-matrix",
        "status": "usable-internal-triage-not-provider-complete",
        "family": family,
        "service": service,
        "artifact_type": artifact_type,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "implemented_controls": {
            "google_takeout_gmail_drive_photos_location_inventory": family == "google",
            "icloud_photos_files_account_inventory": family == "apple-icloud",
            "m365_teams_onedrive_sharepoint_inventory": family == "microsoft-365",
            "provider_specific_schema_warning": True,
            "source_hash_preserved": bool(source_hashes.get("sha256")),
            "provider_export_scope_verified": bool(validation_checks.get("provider_scope_verified")),
            "deleted_cloud_object_recovery": False,
            "tenant_permission_graph_complete": False,
            "strategy_track": optional_text(
                details.get("cloud_provider_strategy_profile", {}).get("selected_track")
                if isinstance(details.get("cloud_provider_strategy_profile"), Mapping)
                else ""
            ),
            "cloud_export_import_manifest_hash": optional_text(export_manifest.get("manifest_sha256")),
            "cloud_export_import_manifest_emitted": bool(export_manifest),
            "source_viewer_locator_emitted": isinstance(export_manifest.get("source_viewer_locator"), Mapping),
            "google_takeout_parser_manifest_hash": optional_text(google_manifest.get("manifest_sha256")),
            "google_takeout_source_row_citation_present": bool(
                isinstance(google_manifest.get("row_citation"), Mapping)
                and google_manifest.get("row_citation", {}).get("row_hash")
            ),
            "icloud_export_parser_manifest_hash": optional_text(icloud_manifest.get("manifest_sha256")),
            "icloud_export_source_row_citation_present": bool(
                isinstance(icloud_manifest.get("row_citation"), Mapping)
                and icloud_manifest.get("row_citation", {}).get("row_hash")
            ),
            "m365_export_parser_manifest_hash": optional_text(m365_manifest.get("manifest_sha256")),
            "m365_export_source_row_citation_present": bool(
                isinstance(m365_manifest.get("row_citation"), Mapping)
                and m365_manifest.get("row_citation", {}).get("row_hash")
            ),
            "cloud_archive_manifest_hash": optional_text(archive_manifest.get("manifest_sha256")),
            "cloud_archive_manifest_emitted": bool(archive_manifest),
            "cloud_archive_entry_count": int(details.get("archive_entry_count") or 0),
            "cloud_archive_json_entry_count": int(details.get("archive_json_entry_count") or 0),
        },
        "source_subject_or_object": optional_text(
            details.get("subject") or details.get("file_name") or details.get("chat_id") or details.get("account_email")
        ),
        "trusted_diff_status": str(trusted_diff.get("status") or "not-attached"),
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "cloud-export-import-manifest-emitted": bool(export_manifest),
                "cloud-export-source-locator-emitted": isinstance(export_manifest.get("source_viewer_locator"), Mapping),
                "google-takeout-parser-manifest-emitted": family == "google" and bool(google_manifest),
                "google-takeout-source-locator-emitted": family == "google"
                and isinstance(google_manifest.get("row_citation"), Mapping)
                and isinstance(google_manifest.get("row_citation", {}).get("source_viewer_locator"), Mapping),
                "icloud-export-parser-manifest-emitted": family == "apple-icloud" and bool(icloud_manifest),
                "icloud-export-source-locator-emitted": family == "apple-icloud"
                and isinstance(icloud_manifest.get("row_citation"), Mapping)
                and isinstance(icloud_manifest.get("row_citation", {}).get("source_viewer_locator"), Mapping),
                "m365-export-parser-manifest-emitted": family == "microsoft-365" and bool(m365_manifest),
                "m365-export-source-locator-emitted": family == "microsoft-365"
                and isinstance(m365_manifest.get("row_citation"), Mapping)
                and isinstance(m365_manifest.get("row_citation", {}).get("source_viewer_locator"), Mapping),
                "cloud-provider-archive-manifest-emitted": bool(archive_manifest),
                "cloud-source-hash-preserved": bool(source_hashes.get("sha256")),
            }.items()
            if passed
        ],
        "failed_validation_check_ids": failed_checks,
        "ready_for_court_report": False,
        "next_internal_step": "Attach provider export manifest/scope proof and known-answer exports for each claimed provider family.",
    }


def cloud_commercial_uplift_evidence(
    *,
    gap_ids: list[str],
    family: str,
    service: str,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    validation_checks: Mapping[str, object],
    issue_matrix: list[dict[str, object]],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
    source_path: str,
) -> dict[str, object]:
    matrix = cloud_validation_matrix(validation_checks)
    trusted_diff = details.get("cloud_trusted_diff") if isinstance(details.get("cloud_trusted_diff"), Mapping) else {}
    item_numbers = sorted(
        int(gap_id.lstrip("#"))
        for gap_id in gap_ids
        if gap_id.startswith("#") and gap_id.lstrip("#").isdigit()
    )
    objectives = {
        37: "Expose Google Takeout/Gmail/Drive/Activity export evidence and selected-products/export-scope blockers.",
        38: "Expose iCloud account/file/photo export evidence and ADP/shared-album/container blockers.",
        39: "Expose Microsoft 365/Teams/OneDrive/SharePoint export evidence and eDiscovery/permissions/retention blockers.",
    }
    source_refs = [
        f"source_path:{source_path}",
        f"source_index:{source_index}",
        f"source_sha256:{source_hashes.get('sha256', '')}",
        f"family:{family}",
        f"service:{service}",
        f"artifact_type:{artifact_type}",
    ]
    export_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    if export_manifest.get("manifest_sha256"):
        source_refs.append(f"cloud_export_manifest_sha256:{export_manifest['manifest_sha256']}")
    google_manifest = (
        details.get("google_takeout_parser_manifest")
        if isinstance(details.get("google_takeout_parser_manifest"), Mapping)
        else {}
    )
    if google_manifest.get("manifest_sha256"):
        source_refs.append(f"google_takeout_parser_manifest_sha256:{google_manifest['manifest_sha256']}")
    icloud_manifest = (
        details.get("icloud_export_parser_manifest")
        if isinstance(details.get("icloud_export_parser_manifest"), Mapping)
        else {}
    )
    if icloud_manifest.get("manifest_sha256"):
        source_refs.append(f"icloud_export_parser_manifest_sha256:{icloud_manifest['manifest_sha256']}")
    m365_manifest = (
        details.get("m365_export_parser_manifest")
        if isinstance(details.get("m365_export_parser_manifest"), Mapping)
        else {}
    )
    if m365_manifest.get("manifest_sha256"):
        source_refs.append(f"m365_export_parser_manifest_sha256:{m365_manifest['manifest_sha256']}")
    archive_manifest = (
        details.get("cloud_archive_manifest")
        if isinstance(details.get("cloud_archive_manifest"), Mapping)
        else {}
    )
    if archive_manifest.get("manifest_sha256"):
        source_refs.append(f"cloud_archive_manifest_sha256:{archive_manifest['manifest_sha256']}")
    for key in ("subject", "file_name", "chat_id", "operation", "account_email", "message_id", "file_id"):
        value = optional_text(details.get(key))
        if value:
            source_refs.append(f"{key}:{value}")
    passed_validation_matrix_ids = [str(item.get("id")) for item in matrix if item.get("passed")]
    failed_validation_matrix_ids = [str(item.get("id")) for item in matrix if not item.get("passed")]
    passed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if item.get("passed")]
    failed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if not item.get("passed")]
    return {
        "batch_id": "commercial-uplift-036-040",
        "item_numbers": item_numbers,
        "qc_prep_item_numbers": cloud_qc_prep_item_numbers(family),
        "qc_prep_contracts": cloud_qc_prep_contracts(family),
        "implementation_track": "cloud-export-provider-validation",
        "objective": " ".join(objectives[number] for number in item_numbers if number in objectives),
        "reportability_decision": cloud_reportability_decision(
            item_numbers=item_numbers,
            family=family,
            service=service,
            validation_checks=validation_checks,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
            failed_issue_matrix_ids=failed_issue_matrix_ids,
            report_grade=report_grade,
            details=details,
            trusted_diff=trusted_diff,
        ),
        "source_refs": source_refs,
        "cloud_provider_strategy_profile": (
            dict(details["cloud_provider_strategy_profile"])
            if isinstance(details.get("cloud_provider_strategy_profile"), Mapping)
            else {}
        ),
        "functional_priority_profile": cloud_export_import_functional_profile(
            family=family,
            service=service,
            artifact_type=artifact_type,
            source_index=source_index,
            source_hashes=source_hashes,
            validation_checks=validation_checks,
            details=details,
            trusted_diff=trusted_diff,
        ),
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "passed_issue_matrix_ids": passed_issue_matrix_ids,
        "failed_issue_matrix_ids": failed_issue_matrix_ids,
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_ids": [
                CLOUD_TRUSTED_DIFF_BLOCKERS[number]
                for number in item_numbers
                if number in CLOUD_TRUSTED_DIFF_BLOCKERS
            ],
            "required_tools": {
                str(number): sorted(CLOUD_TRUSTED_DIFF_TOOLS[number])
                for number in item_numbers
                if number in CLOUD_TRUSTED_DIFF_TOOLS
            },
        },
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or CLOUD_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "provider_export_scope_verified": bool(validation_checks.get("provider_scope_verified")),
            "original_export_hash_verified": bool(validation_checks.get("original_export_hash_verified")),
            "google_takeout_review_profile_present": bool(details.get("google_takeout_review_profile")),
            "icloud_export_review_profile_present": bool(details.get("icloud_export_review_profile")),
            "m365_export_review_profile_present": bool(details.get("m365_export_review_profile")),
            "cloud_export_import_manifest_hash": optional_text(export_manifest.get("manifest_sha256")),
            "cloud_export_source_locator_present": isinstance(export_manifest.get("source_viewer_locator"), Mapping),
            "google_takeout_parser_manifest_hash": optional_text(google_manifest.get("manifest_sha256")),
            "google_takeout_source_row_citation_present": bool(
                isinstance(google_manifest.get("row_citation"), Mapping)
                and google_manifest.get("row_citation", {}).get("row_hash")
            ),
            "google_takeout_viewer_controls_present": bool(
                isinstance(google_manifest.get("large_data_controls"), Mapping)
                and google_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "icloud_export_parser_manifest_hash": optional_text(icloud_manifest.get("manifest_sha256")),
            "icloud_export_source_row_citation_present": bool(
                isinstance(icloud_manifest.get("row_citation"), Mapping)
                and icloud_manifest.get("row_citation", {}).get("row_hash")
            ),
            "icloud_export_viewer_controls_present": bool(
                isinstance(icloud_manifest.get("large_data_controls"), Mapping)
                and icloud_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "m365_export_parser_manifest_hash": optional_text(m365_manifest.get("manifest_sha256")),
            "m365_export_source_row_citation_present": bool(
                isinstance(m365_manifest.get("row_citation"), Mapping)
                and m365_manifest.get("row_citation", {}).get("row_hash")
            ),
            "m365_export_viewer_controls_present": bool(
                isinstance(m365_manifest.get("large_data_controls"), Mapping)
                and m365_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "deleted_cloud_object_recovery": False,
            "tenant_permission_graph_complete": False,
            "known_answer_cloud_corpus_required": True,
        },
        "next_internal_step": "Add provider-specific export manifests, sidecar merge validation, sharing/retention graph capture, and provider known-answer corpora.",
        "external_evidence_required": True,
    }


def build_cloud_export_import_manifest(
    *,
    artifact_type: str,
    family: str,
    service: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    strategy = (
        details.get("cloud_provider_strategy_profile")
        if isinstance(details.get("cloud_provider_strategy_profile"), Mapping)
        else {}
    )
    google_profile = (
        details.get("google_takeout_review_profile")
        if isinstance(details.get("google_takeout_review_profile"), Mapping)
        else {}
    )
    icloud_profile = (
        details.get("icloud_export_review_profile")
        if isinstance(details.get("icloud_export_review_profile"), Mapping)
        else {}
    )
    m365_profile = (
        details.get("m365_export_review_profile")
        if isinstance(details.get("m365_export_review_profile"), Mapping)
        else {}
    )
    primary_profile = google_profile or icloud_profile or m365_profile
    row_pivots = {
        key: optional_text(details.get(key))
        for key in (
            "message_id",
            "file_id",
            "subject",
            "file_name",
            "chat_id",
            "operation",
            "account_email",
            "timestamp",
            "archive_entry_name",
            "archive_message_index",
            "archive_json_row_index",
            "archive_csv_row_index",
            "csv_row_index",
        )
        if optional_text(details.get(key))
    }
    manifest: dict[str, object] = {
        "manifest_version": "cloud-export-import-manifest-v1",
        "item_number": 55,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "artifact_type": artifact_type,
        "family": family,
        "service": service,
        "source_path": source_path,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": str(source_index),
        "source_viewer_locator": {
            "viewer": "cloud-provider-export-row",
            "source_path": source_path,
            "source_index": source_index,
            "family": family,
            "service": service,
            "artifact_type": artifact_type,
            "row_pivots": row_pivots,
        },
        "provider_strategy": {
            "selected_track": optional_text(strategy.get("selected_track")),
            "provider_product_matrix": strategy.get("provider_product_matrix", []),
            "expected_source_pivots": strategy.get("expected_source_pivots", []),
            "source_scope_blockers": strategy.get("source_scope_blockers", []),
        },
        "provider_review": {
            "profile_version": optional_text(primary_profile.get("profile_version")),
            "product_or_workload_family": optional_text(
                primary_profile.get("product_family") or primary_profile.get("workload_family")
            ),
            "present_primary_pivots": primary_profile.get("present_primary_pivots", []),
            "primary_pivot_present": bool(primary_profile.get("primary_pivot_present")),
            "review_display_mode": optional_text(primary_profile.get("review_display_mode")),
        },
        "row_pivots": row_pivots,
        "large_data_controls": {
            "raw_values_redacted_by_default": True,
            "deleted_cloud_object_recovery": False,
            "tenant_permission_graph_complete": False,
        },
        "commercial_blockers": [
            "provider-export-scope-proof-required",
            "provider-known-answer-export-required",
            "deleted-state-and-share-permission-validation-required",
            "provider-native-export-or-api-diff-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_cloud_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_google_takeout_parser_manifest(
    *,
    artifact_type: str,
    service: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    """#37 Google Takeout/Gmail/Drive/Activity source manifest."""
    review_profile = (
        details.get("google_takeout_review_profile")
        if isinstance(details.get("google_takeout_review_profile"), Mapping)
        else {}
    )
    import_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    product_family = optional_text(review_profile.get("product_family")) or google_takeout_product_family(
        service=service,
        artifact_type=artifact_type,
        source_path=source_path,
    )
    row_pivots = {
        key: optional_text(details.get(key))
        for key in (
            "message_id",
            "subject",
            "file_id",
            "file_name",
            "timestamp",
            "latitude",
            "longitude",
            "title",
            "account_email",
            "archive_entry_name",
            "archive_message_index",
            "archive_json_row_index",
            "archive_csv_row_index",
            "csv_row_index",
        )
        if optional_text(details.get(key))
    }
    row_payload = {
        "artifact_type": artifact_type,
        "service": service,
        "product_family": product_family,
        "source_index": source_index,
        "source_path": source_path,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_pivots": row_pivots,
        "body_sha256": optional_text(details.get("body_sha256")),
        "url_sha256": optional_text(details.get("url_sha256")),
    }
    manifest: dict[str, object] = {
        "manifest_version": "google-takeout-parser-manifest-v1",
        "item_number": 37,
        "batch_id": "commercial-uplift-036-040",
        "gap_id": "#37",
        "qc_prep_item_number": 43,
        "qc_prep_item_goal": CLOUD_QC_PREP_GOALS[43],
        "qc_prep_contract": dict(CLOUD_QC_PREP_CONTRACTS[43]),
        "artifact_type": artifact_type,
        "service": service or "unknown",
        "product_family": product_family,
        "source_path": source_path,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_citation": {
            **row_payload,
            "row_hash": stable_cloud_json_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "google-takeout-product-row",
                "source_path": source_path,
                "source_index": source_index,
                "product_family": product_family,
                "row_pivots": row_pivots,
            },
        },
        "parser_tracks": [
            {
                "track": "gmail-drive-photos-activity-location-json-import",
                "status": "implemented",
                "reportable_as": "google-export-triage-pivot",
            },
            {
                "track": "takeout-archive-selected-products-scope-proof",
                "status": "operator-supplied-evidence-required",
                "reportable_as": "not-product-matrix-complete",
            },
            {
                "track": "sidecar-exif-sharing-retention-provider-diff",
                "status": "known-answer-and-provider-diff-required",
                "reportable_as": "not-provider-complete",
            },
        ],
        "product_review": {
            "profile_version": optional_text(review_profile.get("profile_version")),
            "expected_primary_pivots": list(review_profile.get("expected_primary_pivots") or []),
            "present_primary_pivots": list(review_profile.get("present_primary_pivots") or []),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "source_path_hints": dict(review_profile.get("source_path_hints") or {}),
            "sidecar_merge_status": optional_text(review_profile.get("sidecar_merge_status")),
            "timezone_semantics_status": optional_text(review_profile.get("timezone_semantics_status")),
            "provider_native_diff_status": optional_text(review_profile.get("provider_native_diff_status")),
        },
        "import_manifest_ref": {
            "manifest_sha256": optional_text(import_manifest.get("manifest_sha256")),
            "source_viewer_locator_present": isinstance(import_manifest.get("source_viewer_locator"), Mapping),
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "selected_products_manifest_attached": False,
            "original_takeout_archive_hash_verified": False,
            "provider_native_diff_attached": False,
            "sidecar_merge_validated": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "metadata_collapsed_by_default": True,
            "viewer_default": "google-product-matrix-virtualized-row-review",
            "raw_values_redacted_by_default": True,
            "row_pivot_count": len(row_pivots),
        },
        "commercial_blockers": [
            "google-takeout-selected-products-manifest-required",
            "original-takeout-archive-hash-required",
            "gmail-drive-photos-sidecar-timezone-validation-required",
            "google-provider-native-diff-required",
        ],
        "required_before_report": [
            "attach selected Takeout products, account owner, export timestamp, and original archive hash",
            "merge and validate Gmail/Drive/Photos sidecars and timezone semantics for the product family",
            "diff selected rows against Google native export/admin/API or known-answer provider output",
            "document deleted, retention, sharing, and export-scope limitations",
        ],
        "reporting_status": "google-takeout-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_cloud_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_icloud_export_parser_manifest(
    *,
    artifact_type: str,
    service: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    """#38 Apple/iCloud export source manifest."""
    review_profile = (
        details.get("icloud_export_review_profile")
        if isinstance(details.get("icloud_export_review_profile"), Mapping)
        else {}
    )
    import_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    product_family = optional_text(review_profile.get("product_family")) or icloud_product_family(
        service=service,
        artifact_type=artifact_type,
        source_path=source_path,
    )
    row_pivots = {
        key: optional_text(details.get(key))
        for key in (
            "account_email",
            "account_name",
            "file_id",
            "file_name",
            "message_id",
            "subject",
            "timestamp",
            "mime_type",
            "owner",
            "url_sha256",
            "archive_entry_name",
            "archive_json_row_index",
            "archive_csv_row_index",
            "csv_row_index",
        )
        if optional_text(details.get(key))
    }
    row_payload = {
        "artifact_type": artifact_type,
        "service": service,
        "product_family": product_family,
        "source_index": source_index,
        "source_path": source_path,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_pivots": row_pivots,
        "body_sha256": optional_text(details.get("body_sha256")),
        "url_sha256": optional_text(details.get("url_sha256")),
    }
    manifest: dict[str, object] = {
        "manifest_version": "icloud-export-parser-manifest-v1",
        "item_number": 38,
        "batch_id": "commercial-uplift-036-040",
        "gap_id": "#38",
        "qc_prep_item_number": 44,
        "qc_prep_item_goal": CLOUD_QC_PREP_GOALS[44],
        "qc_prep_contract": dict(CLOUD_QC_PREP_CONTRACTS[44]),
        "artifact_type": artifact_type,
        "service": service or "unknown",
        "product_family": product_family,
        "source_path": source_path,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_citation": {
            **row_payload,
            "row_hash": stable_cloud_json_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "icloud-export-product-row",
                "source_path": source_path,
                "source_index": source_index,
                "product_family": product_family,
                "row_pivots": row_pivots,
            },
        },
        "parser_tracks": [
            {
                "track": "apple-privacy-icloud-account-drive-photos-mail-json-import",
                "status": "implemented",
                "reportable_as": "icloud-export-triage-pivot",
            },
            {
                "track": "adp-shared-album-third-party-container-scope-proof",
                "status": "operator-supplied-evidence-required",
                "reportable_as": "not-icloud-scope-complete",
            },
            {
                "track": "photo-sidecar-exif-native-provider-diff",
                "status": "known-answer-and-provider-diff-required",
                "reportable_as": "not-provider-complete",
            },
        ],
        "product_review": {
            "profile_version": optional_text(review_profile.get("profile_version")),
            "expected_primary_pivots": list(review_profile.get("expected_primary_pivots") or []),
            "present_primary_pivots": list(review_profile.get("present_primary_pivots") or []),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "source_path_hints": dict(review_profile.get("source_path_hints") or {}),
            "advanced_data_protection_status": optional_text(review_profile.get("advanced_data_protection_status")),
            "shared_album_semantics_status": optional_text(review_profile.get("shared_album_semantics_status")),
            "photo_sidecar_exif_merge_status": optional_text(review_profile.get("photo_sidecar_exif_merge_status")),
            "third_party_container_visibility_status": optional_text(
                review_profile.get("third_party_container_visibility_status")
            ),
            "provider_native_diff_status": optional_text(review_profile.get("provider_native_diff_status")),
        },
        "import_manifest_ref": {
            "manifest_sha256": optional_text(import_manifest.get("manifest_sha256")),
            "source_viewer_locator_present": isinstance(import_manifest.get("source_viewer_locator"), Mapping),
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "apple_export_scope_attached": False,
            "original_apple_export_hash_verified": False,
            "adp_shared_album_scope_validated": False,
            "photo_sidecar_exif_merge_validated": False,
            "provider_native_diff_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "metadata_collapsed_by_default": True,
            "viewer_default": "icloud-product-matrix-virtualized-row-review",
            "raw_values_redacted_by_default": True,
            "row_pivot_count": len(row_pivots),
        },
        "commercial_blockers": [
            "apple-export-scope-and-account-proof-required",
            "original-apple-export-hash-required",
            "adp-shared-album-third-party-container-validation-required",
            "icloud-photo-sidecar-exif-merge-required",
            "icloud-provider-native-diff-required",
        ],
        "required_before_report": [
            "attach Apple privacy/iCloud export scope, account owner, export timestamp, and original archive hash",
            "validate Advanced Data Protection, shared albums, and third-party container visibility for the acquisition context",
            "merge and validate iCloud Photos sidecars/EXIF/album/share metadata where applicable",
            "diff selected rows against Apple/iCloud native export, iCloud web export, or provider known-answer output",
        ],
        "reporting_status": "icloud-export-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_cloud_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_m365_export_parser_manifest(
    *,
    artifact_type: str,
    service: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    """#39 Microsoft 365/Teams/OneDrive/SharePoint export source manifest."""
    review_profile = (
        details.get("m365_export_review_profile")
        if isinstance(details.get("m365_export_review_profile"), Mapping)
        else {}
    )
    import_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    workload_family = optional_text(review_profile.get("workload_family")) or m365_workload_family(
        service=service,
        artifact_type=artifact_type,
        source_path=source_path,
    )
    row_pivots = {
        key: optional_text(details.get(key))
        for key in (
            "message_id",
            "chat_id",
            "channel_id",
            "team_id",
            "sender",
            "file_id",
            "file_name",
            "owner",
            "operation",
            "actor",
            "ip_address",
            "object_id",
            "timestamp",
            "url_sha256",
            "message_text_sha256",
            "archive_entry_name",
            "archive_json_row_index",
            "archive_csv_row_index",
            "csv_row_index",
        )
        if optional_text(details.get(key))
    }
    row_payload = {
        "artifact_type": artifact_type,
        "service": service,
        "workload_family": workload_family,
        "source_index": source_index,
        "source_path": source_path,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_pivots": row_pivots,
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "url_sha256": optional_text(details.get("url_sha256")),
    }
    manifest: dict[str, object] = {
        "manifest_version": "m365-export-parser-manifest-v1",
        "item_number": 39,
        "batch_id": "commercial-uplift-036-040",
        "gap_id": "#39",
        "qc_prep_item_number": 45,
        "qc_prep_item_goal": CLOUD_QC_PREP_GOALS[45],
        "qc_prep_contract": dict(CLOUD_QC_PREP_CONTRACTS[45]),
        "artifact_type": artifact_type,
        "service": service or "unknown",
        "workload_family": workload_family,
        "source_path": source_path,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "row_citation": {
            **row_payload,
            "row_hash": stable_cloud_json_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "m365-export-workload-row",
                "source_path": source_path,
                "source_index": source_index,
                "workload_family": workload_family,
                "row_pivots": row_pivots,
            },
        },
        "parser_tracks": [
            {
                "track": "purview-graph-exchange-teams-onedrive-audit-json-import",
                "status": "implemented",
                "reportable_as": "m365-export-triage-pivot",
            },
            {
                "track": "tenant-custodian-query-scope-retention-proof",
                "status": "operator-supplied-evidence-required",
                "reportable_as": "not-tenant-or-scope-complete",
            },
            {
                "track": "teams-compliance-sharepoint-permission-provider-diff",
                "status": "known-answer-and-provider-diff-required",
                "reportable_as": "not-provider-complete",
            },
        ],
        "workload_review": {
            "profile_version": optional_text(review_profile.get("profile_version")),
            "expected_primary_pivots": list(review_profile.get("expected_primary_pivots") or []),
            "present_primary_pivots": list(review_profile.get("present_primary_pivots") or []),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "source_path_hints": dict(review_profile.get("source_path_hints") or {}),
            "graph_api_scope_status": optional_text(review_profile.get("graph_api_scope_status")),
            "teams_compliance_record_status": optional_text(review_profile.get("teams_compliance_record_status")),
            "sharepoint_permission_graph_status": optional_text(review_profile.get("sharepoint_permission_graph_status")),
            "retention_hold_policy_status": optional_text(review_profile.get("retention_hold_policy_status")),
            "deleted_or_version_history_status": optional_text(review_profile.get("deleted_or_version_history_status")),
            "provider_native_diff_status": optional_text(review_profile.get("provider_native_diff_status")),
        },
        "import_manifest_ref": {
            "manifest_sha256": optional_text(import_manifest.get("manifest_sha256")),
            "source_viewer_locator_present": isinstance(import_manifest.get("source_viewer_locator"), Mapping),
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "primary_pivot_present": bool(review_profile.get("primary_pivot_present")),
            "purview_export_manifest_attached": False,
            "tenant_scope_verified": False,
            "teams_compliance_record_reconciled": False,
            "sharepoint_permission_graph_built": False,
            "retention_deleted_version_state_validated": False,
            "provider_native_diff_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "metadata_collapsed_by_default": True,
            "viewer_default": "m365-workload-virtualized-row-review",
            "raw_values_redacted_by_default": True,
            "row_pivot_count": len(row_pivots),
        },
        "commercial_blockers": [
            "m365-purview-ediscovery-export-scope-required",
            "m365-tenant-custodian-query-original-package-hash-required",
            "teams-compliance-record-reconciliation-required",
            "sharepoint-onedrive-permission-graph-required",
            "retention-hold-deleted-version-history-validation-required",
            "m365-provider-native-diff-required",
        ],
        "required_before_report": [
            "attach Purview/eDiscovery export manifest, tenant/custodian scope, query, export timestamp, and original package hash",
            "validate Graph API scopes, pagination, throttling, and workload coverage when Graph/API collection is used",
            "reconcile Teams messages with Exchange compliance records, attachments, reactions, edits, and deletes",
            "validate OneDrive/SharePoint permissions, file versions, retention holds, deleted state, and audit retention",
            "diff selected rows against Purview, Graph, Exchange eDiscovery, Teams admin, or provider known-answer output",
        ],
        "reporting_status": "m365-export-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_cloud_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_cloud_json_sha256(value: Mapping[str, object] | list[object] | str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def cloud_reportability_decision(
    *,
    item_numbers: list[int],
    family: str,
    service: str,
    validation_checks: Mapping[str, object],
    failed_validation_matrix_ids: list[str],
    failed_issue_matrix_ids: list[str],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers") or CLOUD_REPORT_GRADE_BLOCKERS if str(item)}
    blockers.update(f"matrix:{item}" for item in failed_validation_matrix_ids)
    blockers.update(f"issue:{item}" for item in failed_issue_matrix_ids)
    if not validation_checks.get("provider_scope_verified"):
        blockers.add("provider-export-scope-not-verified")
    if not validation_checks.get("original_export_hash_verified"):
        blockers.add("original-cloud-export-hash-not-verified")
    if not validation_checks.get("provider_known_answer_validated"):
        blockers.add("provider-known-answer-corpus-not-attached")
    trusted_diff = trusted_diff or {}
    if trusted_diff.get("status") != "pass":
        for number in item_numbers:
            blocker = CLOUD_TRUSTED_DIFF_BLOCKERS.get(number)
            if blocker:
                blockers.add(blocker)
    primary = item_numbers[0] if item_numbers else 37
    decisions = {
        37: ("do-not-report-google-takeout-as-product-matrix-complete", "google-export-triage-pivot"),
        38: ("do-not-report-icloud-export-as-account-or-photo-complete", "icloud-export-triage-pivot"),
        39: ("do-not-report-m365-export-as-tenant-or-permission-complete", "m365-export-triage-pivot"),
    }
    decision, allowed_use = decisions.get(primary, ("do-not-report-cloud-export-as-commercial-grade", "cloud-export-triage-pivot"))
    return {
        "profile_version": "cloud-export-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}" for number in item_numbers],
        "qc_prep_item_numbers": cloud_qc_prep_item_numbers(family),
        "qc_prep_contracts": cloud_qc_prep_contracts(family),
        "decision": decision,
        "allowed_use": allowed_use,
        "family": family,
        "service": service,
        "blockers": sorted(blockers),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "failed_issue_matrix_ids": list(failed_issue_matrix_ids),
        "source_subject_or_object": optional_text(
            details.get("subject") or details.get("file_name") or details.get("chat_id") or details.get("account_email")
        ),
        "ready_for_court_report": False,
        "required_before_report": [
            "attach provider export/API scope, account ownership proof, timestamps/timezone notes, and original export hashes",
            "validate rows against provider-native views or known-answer exports",
            "attach a passing trusted provider/export diff for every claimed Google, iCloud, or Microsoft row family",
            "document retention/deleted-state, sharing/permission, sidecar, and product-scope limitations",
        ],
    }


def cloud_qc_prep_item_numbers(family: str) -> list[int]:
    item_number = CLOUD_QC_PREP_ITEMS.get(family)
    return [item_number] if item_number else []


def cloud_qc_prep_contracts(family: str) -> list[dict[str, object]]:
    return [dict(CLOUD_QC_PREP_CONTRACTS[number]) for number in cloud_qc_prep_item_numbers(family)]


def cloud_core_accuracy_gates(
    *,
    gap_ids: list[str],
    family: str,
    service: str,
    artifact_type: str,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
    source_index: int,
    source_path: str,
) -> list[dict[str, object]]:
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    evidence_refs = [
        f"source_path:{source_path}",
        f"source_index:{source_index}",
        f"service:{service}",
        f"artifact_type:{artifact_type}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")
    export_manifest = (
        details.get("cloud_export_import_manifest")
        if isinstance(details.get("cloud_export_import_manifest"), Mapping)
        else {}
    )
    if export_manifest.get("manifest_sha256"):
        evidence_refs.append(f"cloud_export_manifest_sha256:{export_manifest['manifest_sha256']}")
    google_manifest = (
        details.get("google_takeout_parser_manifest")
        if isinstance(details.get("google_takeout_parser_manifest"), Mapping)
        else {}
    )
    if google_manifest.get("manifest_sha256"):
        evidence_refs.append(f"google_takeout_parser_manifest_sha256:{google_manifest['manifest_sha256']}")
    icloud_manifest = (
        details.get("icloud_export_parser_manifest")
        if isinstance(details.get("icloud_export_parser_manifest"), Mapping)
        else {}
    )
    if icloud_manifest.get("manifest_sha256"):
        evidence_refs.append(f"icloud_export_parser_manifest_sha256:{icloud_manifest['manifest_sha256']}")
    m365_manifest = (
        details.get("m365_export_parser_manifest")
        if isinstance(details.get("m365_export_parser_manifest"), Mapping)
        else {}
    )
    if m365_manifest.get("manifest_sha256"):
        evidence_refs.append(f"m365_export_parser_manifest_sha256:{m365_manifest['manifest_sha256']}")
    archive_manifest = (
        details.get("cloud_archive_manifest")
        if isinstance(details.get("cloud_archive_manifest"), Mapping)
        else {}
    )
    if archive_manifest.get("manifest_sha256"):
        evidence_refs.append(f"cloud_archive_manifest_sha256:{archive_manifest['manifest_sha256']}")
    trusted_diff = details.get("cloud_trusted_diff") if isinstance(details.get("cloud_trusted_diff"), Mapping) else {}
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    gates: list[dict[str, object]] = []
    for gap_id in gap_ids:
        number = int(gap_id.strip("#"))
        satisfied: list[str] = []
        if number == 37:
            if family == "google" or "google" in service or "gmail" in service:
                satisfied.append("Google service/profile detection")
            if details.get("cloud_provider_strategy_profile"):
                satisfied.append("Google Takeout product matrix strategy")
            if details.get("google_takeout_review_profile"):
                satisfied.append("Google Takeout product review profile")
            if validation.get("google_takeout_row_pivot_present"):
                satisfied.append("Google Takeout row pivot inventory")
            if artifact_type in {"cloud-mail", "cloud-file", "cloud-activity", "cloud-location"}:
                satisfied.append("Gmail/Drive/Activity/Location normalization")
            if source_hashes.get("sha256") and not validation.get("provider_scope_verified"):
                satisfied.append("source hash and export-scope warning")
            if details.get("commercial_grade_blockers"):
                satisfied.append("sidecar/media/linkage limitation")
                satisfied.append("provider schema/timezone warning")
            if export_manifest:
                satisfied.append("cloud export import manifest")
                if isinstance(export_manifest.get("source_viewer_locator"), Mapping):
                    satisfied.append("cloud export source locator")
            if archive_manifest:
                satisfied.append("cloud provider archive manifest")
            if google_manifest:
                satisfied.append("Google Takeout parser manifest")
                if isinstance(google_manifest.get("row_citation"), Mapping) and google_manifest.get("row_citation", {}).get("row_hash"):
                    satisfied.append("Google Takeout source row citation")
                if isinstance(google_manifest.get("large_data_controls"), Mapping) and google_manifest.get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("Google Takeout review viewer controls")
            if trusted_diff.get("status") == "pass" and int(trusted_diff.get("gap_number") or 0) == 37:
                satisfied.append("trusted Google Takeout/provider diff pass")
        elif number == 38:
            if family == "apple-icloud" or "icloud" in service or "apple" in service:
                satisfied.append("Apple/iCloud service profile detection")
            if details.get("cloud_provider_strategy_profile"):
                satisfied.append("iCloud export scope strategy")
            if details.get("icloud_export_review_profile"):
                satisfied.append("iCloud account/file/photo review profile")
            if validation.get("icloud_row_pivot_present"):
                satisfied.append("iCloud row pivot inventory")
            if artifact_type in {"cloud-account", "cloud-file", "cloud-mail"}:
                satisfied.append("account/file/photo metadata normalization")
            if source_hashes.get("sha256") and not validation.get("provider_scope_verified"):
                satisfied.append("source hash and export-scope warning")
            if details.get("commercial_grade_blockers"):
                satisfied.append("ADP/shared-album limitation warning")
                satisfied.append("provider retention/schema warning")
            if export_manifest:
                satisfied.append("cloud export import manifest")
                if isinstance(export_manifest.get("source_viewer_locator"), Mapping):
                    satisfied.append("cloud export source locator")
            if archive_manifest:
                satisfied.append("cloud provider archive manifest")
            if icloud_manifest:
                satisfied.append("iCloud export parser manifest")
                if isinstance(icloud_manifest.get("row_citation"), Mapping) and icloud_manifest.get("row_citation", {}).get("row_hash"):
                    satisfied.append("iCloud export source row citation")
                if isinstance(icloud_manifest.get("large_data_controls"), Mapping) and icloud_manifest.get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("iCloud export review viewer controls")
            if trusted_diff.get("status") == "pass" and int(trusted_diff.get("gap_number") or 0) == 38:
                satisfied.append("trusted iCloud/provider export diff pass")
        elif number == 39:
            if family == "microsoft-365" or "microsoft" in service or "teams" in service or "onedrive" in service:
                satisfied.append("Microsoft 365 service profile detection")
            if details.get("cloud_provider_strategy_profile"):
                satisfied.append("M365/Teams eDiscovery strategy")
            if details.get("m365_export_review_profile"):
                satisfied.append("M365 workload review profile")
            if validation.get("m365_row_pivot_present"):
                satisfied.append("M365 row pivot inventory")
            if artifact_type in {"cloud-mail", "cloud-file", "cloud-message", "cloud-audit"}:
                satisfied.append("mail/file/message/audit normalization")
            if source_hashes.get("sha256") and not validation.get("provider_scope_verified"):
                satisfied.append("source hash and eDiscovery/export warning")
            if details.get("commercial_grade_blockers"):
                satisfied.append("permissions/retention/deleted limitation")
                satisfied.append("provider schema/timestamp warning")
            if export_manifest:
                satisfied.append("cloud export import manifest")
                if isinstance(export_manifest.get("source_viewer_locator"), Mapping):
                    satisfied.append("cloud export source locator")
            if archive_manifest:
                satisfied.append("cloud provider archive manifest")
            if m365_manifest:
                satisfied.append("M365 export parser manifest")
                if isinstance(m365_manifest.get("row_citation"), Mapping) and m365_manifest.get("row_citation", {}).get("row_hash"):
                    satisfied.append("M365 export source row citation")
                if isinstance(m365_manifest.get("large_data_controls"), Mapping) and m365_manifest.get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("M365 export review viewer controls")
            if trusted_diff.get("status") == "pass" and int(trusted_diff.get("gap_number") or 0) == 39:
                satisfied.append("trusted M365/eDiscovery export diff pass")
        gates.append(build_accuracy_gate(number, satisfied_checks=satisfied, evidence_refs=evidence_refs))
    return gates


def build_cloud_export_trusted_diff(
    gap_number: int,
    rapid_rows: Iterable[Mapping[str, object]],
    trusted_rows: Iterable[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "cloud-export-trusted-diff",
) -> dict[str, object]:
    accepted_tools = CLOUD_TRUSTED_DIFF_TOOLS.get(gap_number, set())
    rapid_index = {_cloud_diff_key(row): _cloud_diff_values(row) for row in rapid_rows}
    trusted_index = {_cloud_diff_key(row): _cloud_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index).intersection(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in (
            "service",
            "event_type",
            "timestamp",
            "subject",
            "message_id",
            "file_id",
            "file_name",
            "chat_id",
            "operation",
            "account_email",
            "body_sha256",
            "message_text_sha256",
            "url_sha256",
        ):
            left = rapid.get(field)
            right = trusted.get(field)
            if left not in (None, "") and right not in (None, "") and str(left) != str(right):
                mismatches.append({"row_key": key, "field": field, "rapid": str(left), "trusted": str(right)})
    tool_key = trusted_tool.strip().lower()
    tool_accepted = tool_key in accepted_tools
    status = (
        "pass"
        if tool_accepted
        and rapid_index
        and trusted_index
        and not missing_in_trusted
        and not unexpected_in_trusted
        and not mismatches
        else "fail"
    )
    return {
        "profile_version": "cloud-export-trusted-diff-v1",
        "comparison_id": comparison_id,
        "gap_number": gap_number,
        "status": status,
        "blocker_id": "" if status == "pass" else CLOUD_TRUSTED_DIFF_BLOCKERS.get(gap_number, "cloud-provider-diff-required"),
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(accepted_tools),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_row_count": len(set(rapid_index).intersection(trusted_index)),
        "missing_in_trusted": missing_in_trusted[:200],
        "unexpected_in_trusted": unexpected_in_trusted[:200],
        "mismatched_fields": mismatches[:200],
        "evidence_summary": "Rapid cloud rows match trusted provider/export rows" if status == "pass" else "Trusted provider/export diff is missing or mismatched",
    }


def _cloud_diff_key(row: Mapping[str, object]) -> str:
    values = _cloud_diff_values(row)
    for field in ("message_id", "file_id", "chat_id", "account_email"):
        if values.get(field):
            return f"{field}:{values[field]}"
    parts = [
        str(values.get("service") or ""),
        str(values.get("event_type") or ""),
        str(values.get("timestamp") or ""),
        str(values.get("subject") or values.get("file_name") or values.get("operation") or ""),
        str(values.get("source_index") or ""),
    ]
    return "cloud-fingerprint:" + sha256_text("|".join(parts))


def _cloud_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    source = row.get("details") if isinstance(row.get("details"), Mapping) else row
    return {
        "source_index": source.get("source_index"),
        "service": source.get("service"),
        "event_type": source.get("event_type"),
        "timestamp": source.get("timestamp"),
        "subject": source.get("subject"),
        "message_id": source.get("message_id"),
        "file_id": source.get("file_id"),
        "file_name": source.get("file_name"),
        "chat_id": source.get("chat_id"),
        "operation": source.get("operation"),
        "account_email": source.get("account_email"),
        "body_sha256": source.get("body_sha256"),
        "message_text_sha256": source.get("message_text_sha256"),
        "url_sha256": source.get("url_sha256"),
    }


def cloud_provider_profile(family: str, service: str) -> dict[str, object]:
    profile = CLOUD_PROVIDER_PROFILES.get(family, {})
    return {
        "family": family,
        "service": service or "unknown",
        "known_profile": bool(profile),
        "service_candidates": list(profile.get("services", ())),
        "collection_modes": list(profile.get("collection_modes", ("export", "api"))),
        "known_gaps": list(profile.get("known_gaps", ("provider-schema-version-validation",))),
        "reporting_boundary": "provider-export-scoped-until-source-scope-and-retention-validated",
    }


def cloud_provider_strategy_profile(
    *,
    family: str,
    service: str,
    artifact_type: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    tracks = {
        "google": "google-takeout-product-matrix-validation",
        "apple-icloud": "icloud-export-account-photo-file-scope-validation",
        "microsoft-365": "m365-purview-graph-ediscovery-validation",
        "collaboration-saas": "collaboration-saas-admin-export-scope-validation",
    }
    product_matrix = {
        "google": [
            "Gmail messages/MBOX or JSON exports",
            "Drive file metadata and file bytes",
            "Photos media plus JSON sidecars/EXIF",
            "My Activity products and browser/search history",
            "Location History timeline records",
        ],
        "apple-icloud": [
            "Apple ID account export",
            "iCloud Drive file inventory",
            "iCloud Photos EXIF/album/share metadata",
            "Mail/Contacts/Calendar client-export differences",
            "device/account association metadata",
        ],
        "microsoft-365": [
            "Purview/eDiscovery mail and Teams exports",
            "Graph API messages/files/audit rows",
            "OneDrive and SharePoint file metadata",
            "Teams reactions/attachments/compliance records",
            "tenant audit, retention, hold, and permission context",
        ],
        "collaboration-saas": [
            "workspace export scope",
            "threads/reactions/edits/deletes where available",
            "file sharing/version state",
            "admin audit and legal-hold scope",
        ],
    }
    expected_pivots = {
        "cloud-mail": ["message_id", "subject", "sender/recipient", "body hash", "attachment count"],
        "cloud-file": ["file_id", "file_name", "web/download URL hash", "owner", "size"],
        "cloud-message": ["chat/channel/team id", "message id", "sender", "message hash", "attachment/reaction fields"],
        "cloud-audit": ["operation", "actor", "IP address", "user agent", "object id"],
        "cloud-account": ["account email", "account name", "created timestamp", "device/account relation"],
        "cloud-location": ["timestamp", "latitude", "longitude", "accuracy", "source device"],
        "cloud-activity": ["timestamp", "title", "products", "detail rows", "source device"],
    }
    blockers = [
        "provider-export-scope-not-verified",
        "original-cloud-export-hash-not-verified",
        "provider-known-answer-corpus-not-attached",
    ]
    if family == "google":
        blockers.append("takeout-selected-products-and-sidecars-not-fully-merged")
    elif family == "apple-icloud":
        blockers.append("icloud-adp-shared-album-third-party-container-limits-not-validated")
    elif family == "microsoft-365":
        blockers.append("m365-retention-hold-permission-graph-not-validated")
    else:
        blockers.append("workspace-plan-admin-export-scope-not-validated")
    return {
        "profile_version": "cloud-provider-strategy-v1",
        "family": family,
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "selected_track": tracks.get(family, "generic-cloud-export-scope-validation"),
        "provider_product_matrix": product_matrix.get(family, ["provider export/API rows", "source hashes", "scope record"]),
        "expected_row_pivots": expected_pivots.get(artifact_type, ["timestamp", "source hash", "provider row id"]),
        "provider_scope_verified": bool(
            details.get("validation_checks", {}).get("provider_scope_verified")
            if isinstance(details.get("validation_checks"), Mapping)
            else False
        ),
        "message_or_object_reportable": False,
        "deleted_retention_permission_graph_complete": False,
        "trusted_provider_diff_required": True,
        "blockers": blockers,
        "required_before_report": [
            "attach original export/API manifest, selected products/scopes, account or tenant owner, and export timestamp",
            "hash and preserve the original provider archive or response set",
            "diff important rows against provider-native export/admin/eDiscovery views",
            "document deleted-state, retention/hold, sharing/permission, sidecar, and timezone semantics",
        ],
    }


def google_takeout_review_profile(
    *,
    family: str,
    service: str,
    artifact_type: str,
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    if family != "google":
        return {}
    product_family = google_takeout_product_family(service=service, artifact_type=artifact_type, source_path=source_path)
    primary_pivots = {
        "gmail": ["message_id", "subject", "from", "to", "body_sha256", "attachment_count"],
        "drive": ["file_id", "file_name", "mime_type", "owner", "url_sha256", "size"],
        "activity": ["timestamp", "title", "products"],
        "location": ["timestamp", "latitude", "longitude", "accuracy_meters", "source"],
        "photos": ["file_id", "file_name", "timestamp", "url_sha256"],
        "account": ["account_email", "account_name", "timestamp"],
    }
    expected = primary_pivots.get(product_family, ["timestamp", "source_hashes"])
    present = [pivot for pivot in expected if optional_text(details.get(pivot)) or details.get(pivot) not in (None, "", [])]
    source_lower = source_path.lower()
    return {
        "profile_version": "google-takeout-review-v1",
        "product_family": product_family,
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "source_track": "google-takeout-product-matrix-review",
        "source_path_hints": {
            "takeout_path": "takeout" in source_lower,
            "gmail_path": "mail" in source_lower or "gmail" in source_lower,
            "drive_path": "drive" in source_lower,
            "activity_path": "my activity" in source_lower,
            "location_path": "location history" in source_lower,
            "photos_path": "photos" in source_lower,
        },
        "expected_primary_pivots": expected,
        "present_primary_pivots": present,
        "primary_pivot_present": bool(present),
        "selected_products_manifest_attached": False,
        "original_takeout_archive_hash_verified": False,
        "sidecar_merge_status": "not-performed",
        "timezone_semantics_status": "not-validated",
        "deleted_or_retention_state_status": "not-validated",
        "provider_native_diff_status": "not-attached",
        "review_display_mode": "product-matrix-row-with-scope-sidecar-metadata-collapsed",
        "required_before_report": [
            "attach Google Takeout archive manifest, selected products, account owner, export time, and original archive hash",
            "merge product sidecars such as Drive/Photos metadata JSON before file/photo conclusions",
            "validate Gmail threading, Drive sharing, My Activity product semantics, and Location timezone/source fields with known-answer exports",
            "diff important rows against Google native export/admin/API evidence before report-grade claims",
        ],
    }


def google_takeout_product_family(*, service: str, artifact_type: str, source_path: str) -> str:
    lowered = f"{service} {artifact_type} {source_path}".lower()
    if "gmail" in lowered or "mail" in lowered:
        return "gmail"
    if "drive" in lowered or artifact_type == "cloud-file":
        return "drive"
    if "photos" in lowered or "photo" in lowered:
        return "photos"
    if "activity" in lowered or artifact_type == "cloud-activity":
        return "activity"
    if "location" in lowered or artifact_type == "cloud-location":
        return "location"
    if artifact_type == "cloud-account":
        return "account"
    return "google-export"


def icloud_export_review_profile(
    *,
    family: str,
    service: str,
    artifact_type: str,
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    if family != "apple-icloud":
        return {}
    product_family = icloud_product_family(service=service, artifact_type=artifact_type, source_path=source_path)
    primary_pivots = {
        "account": ["account_email", "account_name", "timestamp"],
        "icloud-drive": ["file_id", "file_name", "mime_type", "owner", "url_sha256", "size"],
        "icloud-photos": ["file_id", "file_name", "mime_type", "timestamp", "url_sha256"],
        "icloud-mail": ["message_id", "subject", "from", "to", "body_sha256"],
        "device-association": ["account_email", "timestamp"],
    }
    expected = primary_pivots.get(product_family, ["timestamp", "source_hashes"])
    present = [pivot for pivot in expected if optional_text(details.get(pivot)) or details.get(pivot) not in (None, "", [])]
    source_lower = source_path.lower()
    return {
        "profile_version": "icloud-export-review-v1",
        "product_family": product_family,
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "source_track": "icloud-export-account-photo-file-scope-review",
        "source_path_hints": {
            "apple_export_path": "apple" in source_lower,
            "icloud_path": "icloud" in source_lower,
            "photos_path": "photo" in source_lower,
            "drive_path": "drive" in source_lower,
            "mail_path": "mail" in source_lower,
        },
        "expected_primary_pivots": expected,
        "present_primary_pivots": present,
        "primary_pivot_present": bool(present),
        "advanced_data_protection_status": "not-validated",
        "shared_album_semantics_status": "not-validated",
        "photo_sidecar_exif_merge_status": "not-performed",
        "third_party_container_visibility_status": "not-validated",
        "original_export_hash_verified": False,
        "provider_native_diff_status": "not-attached",
        "review_display_mode": "icloud-product-row-with-scope-adp-sidecar-metadata-collapsed",
        "required_before_report": [
            "attach Apple privacy export/iCloud copy scope, account owner proof, export timestamp, and original archive hash",
            "validate Advanced Data Protection and third-party iCloud container visibility for the acquisition context",
            "merge photo sidecars, EXIF, album/share metadata, comments, and likes before photo timeline conclusions",
            "diff key account/file/photo/mail rows against Apple/iCloud native export or known-answer provider evidence",
        ],
    }


def icloud_product_family(*, service: str, artifact_type: str, source_path: str) -> str:
    lowered = f"{service} {artifact_type} {source_path}".lower()
    if "photo" in lowered:
        return "icloud-photos"
    if "drive" in lowered or artifact_type == "cloud-file":
        return "icloud-drive"
    if "mail" in lowered or artifact_type == "cloud-mail":
        return "icloud-mail"
    if "device" in lowered:
        return "device-association"
    if artifact_type == "cloud-account":
        return "account"
    return "icloud-export"


def m365_export_review_profile(
    *,
    family: str,
    service: str,
    artifact_type: str,
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    if family != "microsoft-365":
        return {}
    workload_family = m365_workload_family(service=service, artifact_type=artifact_type, source_path=source_path)
    primary_pivots = {
        "exchange": ["message_id", "subject", "from", "to", "body_sha256"],
        "teams": ["chat_id", "channel_id", "team_id", "message_id", "sender", "message_text_sha256"],
        "onedrive-sharepoint": ["file_id", "file_name", "owner", "url_sha256", "size"],
        "audit": ["operation", "actor", "ip_address", "user_agent", "object_id"],
        "tenant-account": ["account_email", "account_name", "timestamp"],
    }
    expected = primary_pivots.get(workload_family, ["timestamp", "source_hashes"])
    present = [pivot for pivot in expected if optional_text(details.get(pivot)) or details.get(pivot) not in (None, "", [])]
    source_lower = source_path.lower()
    return {
        "profile_version": "m365-export-review-v1",
        "workload_family": workload_family,
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "source_track": "m365-purview-graph-ediscovery-review",
        "source_path_hints": {
            "purview_or_ediscovery_path": "purview" in source_lower or "ediscovery" in source_lower,
            "teams_path": "teams" in source_lower,
            "onedrive_path": "onedrive" in source_lower,
            "sharepoint_path": "sharepoint" in source_lower,
            "exchange_path": "exchange" in source_lower or "mail" in source_lower,
            "audit_path": "audit" in source_lower,
        },
        "expected_primary_pivots": expected,
        "present_primary_pivots": present,
        "primary_pivot_present": bool(present),
        "purview_export_manifest_attached": False,
        "graph_api_scope_status": "not-validated",
        "teams_compliance_record_status": "not-validated",
        "sharepoint_permission_graph_status": "not-built",
        "retention_hold_policy_status": "not-validated",
        "deleted_or_version_history_status": "not-validated",
        "provider_native_diff_status": "not-attached",
        "review_display_mode": "m365-workload-row-with-ediscovery-retention-permission-metadata-collapsed",
        "required_before_report": [
            "attach Purview/eDiscovery export manifest, tenant/custodian scope, search query, export time, and original package hash",
            "validate Graph API scopes, pagination, throttling, and selected workload coverage when API collection is used",
            "reconcile Teams messages with Exchange compliance records, attachments, reactions, edits, and deletes",
            "validate OneDrive/SharePoint permissions, file versions, retention holds, deleted state, and audit retention before report-grade claims",
        ],
    }


def m365_workload_family(*, service: str, artifact_type: str, source_path: str) -> str:
    lowered = f"{service} {artifact_type} {source_path}".lower()
    if "teams" in lowered or artifact_type == "cloud-message":
        return "teams"
    if "onedrive" in lowered or "sharepoint" in lowered or artifact_type == "cloud-file":
        return "onedrive-sharepoint"
    if "audit" in lowered or artifact_type == "cloud-audit":
        return "audit"
    if "exchange" in lowered or "mail" in lowered or artifact_type == "cloud-mail":
        return "exchange"
    if artifact_type == "cloud-account":
        return "tenant-account"
    return "m365-export"


def cloud_issue_matrix(family: str, artifact_type: str) -> list[dict[str, object]]:
    is_microsoft = family == "microsoft-365"
    is_google = family == "google"
    is_apple = family == "apple-icloud"
    is_message = artifact_type in {"cloud-message", "cloud-mail"}
    is_file = artifact_type == "cloud-file"
    return [
        {
            "id": "export-scope-captured",
            "label": "Provider export/API scope, selected products, tenant/account owner, and request time are captured",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "retention-hold-and-deleted-state",
            "label": "Retention policy, hold state, deleted object state, and audit retention are validated",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "provider-storage-model",
            "label": "Provider-specific storage model is understood for this artifact type",
            "passed": False,
            "severity": "critical" if is_microsoft and is_message else "high",
        },
        {
            "id": "sidecar-and-metadata-merge",
            "label": "Sidecar JSON/CSV metadata is merged back to files/messages where needed",
            "passed": False,
            "severity": "high" if (is_google or is_file) else "medium",
        },
        {
            "id": "shared-item-permissions",
            "label": "Sharing, membership, permissions, reactions, edits, and comments are preserved",
            "passed": False,
            "severity": "high" if is_file or is_message else "medium",
        },
        {
            "id": "icloud-copy-limitations",
            "label": "iCloud copy/export limitations such as shared album fidelity and third-party containers are disclosed",
            "passed": not is_apple,
            "severity": "high" if is_apple else "low",
        },
        {
            "id": "known-answer-provider-corpus",
            "label": "Output is diffed against provider-native view and known-answer export corpus",
            "passed": False,
            "severity": "critical",
        },
    ]


def cloud_forensic_review(
    *,
    gap_ids: list[str],
    family: str,
    service: str,
    artifact_type: str,
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    primary = [
        f"artifact_type={artifact_type}",
        f"family={family}",
        f"service={service or optional_text(details.get('service'))}",
        f"event_type={optional_text(details.get('event_type'))}",
    ]
    for key in ("timestamp", "subject", "file_name", "chat_id", "operation", "account_email", "url"):
        value = optional_text(details.get(key))
        if value:
            primary.append(f"{key}={value}")
    return build_forensic_review(
        gap_id=gap_ids[0] if gap_ids else "#37",
        artifact_goal="Cloud provider export mail/file/message/audit/account normalization and validation",
        primary_evidence=primary,
        validation_required=True,
        report_grade_assessment=report_grade,
        blockers=CLOUD_REPORT_GRADE_BLOCKERS,
        caveats=[
            "Cloud export rows are provider-export scoped; preserve export/API scope, account ownership, and original hashes.",
            "Deleted state, retention/eDiscovery semantics, sharing graph, and provider-native completeness remain validation-gated.",
        ],
    )


def cloud_analyst_review_profile(
    *,
    gap_ids: list[str],
    family: str,
    service: str,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: str,
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    manifest = details.get("cloud_export_import_manifest") if isinstance(details.get("cloud_export_import_manifest"), Mapping) else {}
    viewer_locator = manifest.get("source_viewer_locator") if isinstance(manifest.get("source_viewer_locator"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    row_pivots = manifest.get("row_pivots") if isinstance(manifest.get("row_pivots"), list) else []
    profile_names = [
        key
        for key in ("google_takeout_review_profile", "icloud_export_review_profile", "m365_export_review_profile")
        if isinstance(details.get(key), Mapping)
    ]
    return {
        "profile_version": "cloud-analyst-review-profile-v1",
        "gap_ids": list(gap_ids),
        "artifact_type": artifact_type,
        "cloud_family": family,
        "service": service or optional_text(details.get("service")),
        "source_index": source_index,
        "severity": "high" if risk_flags else "medium",
        "summary": f"{artifact_type} / {family} / {service or optional_text(details.get('service')) or 'unknown-service'}",
        "evidence_interpretation": "Provider export/API row normalization and source-scoped cloud review pivot",
        "not_proof_of": [
            "complete provider account export",
            "deleted object recovery",
            "tenant-wide permission graph",
            "provider-native API equivalence",
            "retention/eDiscovery completeness",
        ],
        "analyst_questions": [
            "Does this row match the provider-native export or admin/eDiscovery view?",
            "Are export scope, account ownership, timezone, retention, and source hash preserved?",
            "Do attachments, shared permissions, reactions, or deleted/version history need a provider-specific diff?",
            "Should this row be correlated with email, browser, mobile, timeline, or entity views?",
        ],
        "primary_pivots": [
            value
            for value in (
                optional_text(details.get("message_id")),
                optional_text(details.get("file_id")),
                optional_text(details.get("file_name")),
                optional_text(details.get("chat_id")),
                optional_text(details.get("operation")),
                optional_text(details.get("account_email")),
                optional_text(details.get("url")),
            )
            if value
        ][:8],
        "source_field_values": {
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_index": source_index,
            "event_type": optional_text(details.get("event_type")),
            "timestamp": optional_text(details.get("timestamp")),
            "subject": optional_text(details.get("subject")),
            "file_name": optional_text(details.get("file_name")),
            "operation": optional_text(details.get("operation")),
            "manifest_sha256": optional_text(manifest.get("manifest_sha256")),
            "viewer": optional_text(viewer_locator.get("viewer")),
        },
        "provider_profiles_present": profile_names,
        "row_pivots": list(row_pivots),
        "correlation_targets": [
            "provider-native export/API diff",
            "account ownership and legal scope",
            "email/mobile/browser/timeline correlation",
            "sharing and permission review",
            "retention/deleted-state validation",
        ],
        "risk_tags": sorted(set(map(str, risk_flags)) | {"cloud-validation-required"}),
        "validation_required": True,
        "report_grade_ready": False,
        "validation_snapshot": dict(validation_checks),
        "commercial_blockers": list(report_grade.get("blockers", CLOUD_REPORT_GRADE_BLOCKERS)),
        "report_guidance": "Use as a provider-export review pivot until source scope, native provider diff, and known-answer corpus evidence are attached.",
    }


def cloud_validation_checks(row: Mapping[str, object], *, required: Iterable[str]) -> dict[str, object]:
    normalized_keys = {normalize_key(key) for key in row}
    return {
        "has_required_field_candidate": any(normalize_key(key) in normalized_keys for key in required),
        "normalized_key_count": len(normalized_keys),
        "provider_export_schema_validated": False,
        "original_export_hash_verified": False,
        "timezone_semantics_verified": False,
    }


def cloud_blockers(scope: str) -> list[str]:
    return [
        f"{scope} import is heuristic and fixture-backed; provider schema versions and export settings must be recorded.",
        "Deleted items, retention/eDiscovery semantics, timezone normalization, and provider-side audit completeness require independent validation.",
        "Use authorized provider exports/API collections only and preserve original export hashes before reporting.",
    ]


def cloud_text_risk_flags(subject: str, body: str) -> list[str]:
    lowered = f"{subject} {body}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("password", "otp", "credential", "wire", "invoice", "payment")):
        flags.append("sensitive-cloud-content")
    if any(token in lowered for token in ("incident", "malware", "phishing", "ransomware")):
        flags.append("incident-keyword")
    return flags


def cloud_file_risk_flags(name: str, url: str) -> list[str]:
    lowered = f"{name} {url}".lower()
    flags = ["cloud-file"]
    if any(token in lowered for token in ("share", "download", "public", "anonymous")):
        flags.append("sharing-or-download-context")
    if any(lowered.endswith(suffix) for suffix in (".pst", ".ost", ".zip", ".7z", ".docx", ".xlsx", ".pdf")):
        flags.append("reviewable-document-or-archive")
    return flags


def cloud_audit_risk_flags(operation: str, row: Mapping[str, object]) -> list[str]:
    lowered = f"{operation} {' '.join(optional_text(value) for value in row.values())}".lower()
    flags = ["cloud-audit"]
    if any(token in lowered for token in ("login", "loggedin", "signin", "sign-in", "failed", "mfa", "password")):
        flags.append("identity-security-event")
    if any(token in lowered for token in ("sharing", "download", "delete", "external")):
        flags.append("data-access-event")
    return flags


def sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def e7_to_decimal(value: object) -> float | None:
    try:
        return round(float(value) / 10_000_000, 7)
    except (TypeError, ValueError):
        return None


def normalize_timestamp(value: object) -> str:
    text = optional_text(value)
    if not text:
        return ""
    if text.isdigit():
        timestamp = int(text)
        if timestamp > 10_000_000_000:
            timestamp = timestamp // 1000
        return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def normalize_products(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return []


def optional_text(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(value)
