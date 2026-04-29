from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Iterable, Mapping

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "cloud-export-v3"
CLOUD_JSON_SUFFIXES = {".json"}
CloudGap = tuple[list[str], str]
CLOUD_NATIVE_CAPABILITIES = {
    "google_takeout_location_activity_import": True,
    "gmail_json_export_import": True,
    "icloud_account_file_export_import": True,
    "microsoft_365_onedrive_teams_audit_import": True,
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


def collect_cloud_json(path: Path) -> Iterable[ArtifactRecord]:
    payload = load_json(path)
    if payload is None:
        return
    source_hashes = compute_hashes(path)
    source_path = str(path.resolve())
    detected = detect_export_type(path, payload)
    if detected == "google-location":
        for index, row in enumerate(extract_google_location_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-location",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_google_location(row),
            )
        return
    if detected == "google-activity":
        for index, row in enumerate(extract_list_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-activity",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_activity(row),
            )
        return
    if detected == "cloud-account":
        yield build_record(
            path,
            artifact_type="cloud-account",
            source_index=0,
            source_hashes=source_hashes,
            details=normalize_account(payload if isinstance(payload, Mapping) else {}, source_path=source_path),
        )
        return
    if detected == "cloud-mail":
        for index, row in enumerate(extract_list_or_single_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-mail",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_cloud_mail(row, source_path=source_path),
            )
        return
    if detected == "cloud-file":
        for index, row in enumerate(extract_list_or_single_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-file",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_cloud_file(row, source_path=source_path),
            )
        return
    if detected == "cloud-message":
        for index, row in enumerate(extract_list_or_single_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-message",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_cloud_message(row, source_path=source_path),
            )
        return
    if detected == "cloud-audit":
        for index, row in enumerate(extract_list_or_single_rows(payload)):
            yield build_record(
                path,
                artifact_type="cloud-audit",
                source_index=index,
                source_hashes=source_hashes,
                details=normalize_cloud_audit(row, source_path=source_path),
            )


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
    validation_checks = detail_payload.get("validation_checks")
    if not isinstance(validation_checks, Mapping):
        validation_checks = {}
    return ArtifactRecord(
        provider=CloudExportProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "cloud-export",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": "json",
            "source_index": source_index,
            "source_hashes": dict(source_hashes),
            "commercial_grade_ready": False,
            "commercial_gap_ids": gap_ids,
            "cloud_family": family,
            "cloud_validation_matrix": cloud_validation_matrix(validation_checks),
            "cloud_report_grade_assessment": cloud_report_grade_assessment(gap_ids, family, service),
            "cloud_native_capabilities": dict(CLOUD_NATIVE_CAPABILITIES),
            **detail_payload,
        },
    )


def load_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


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
    if any(token in source_hint for token in ("teams", "chat", "messages")) or keys.intersection(
        {"chatid", "channelid", "teamid", "messagetext", "bodycontent"}
    ):
        return "cloud-message"
    if "gmail" in source_hint or "mail" in source_hint or keys.intersection({"subject", "from", "to", "messageid"}):
        return "cloud-mail"
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
        for key in ("messages", "mail", "files", "items", "events", "auditRecords", "records", "value"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
        return [payload]
    return []


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
        "risk_flags": cloud_text_risk_flags(subject, body),
        "validation_checks": cloud_validation_checks(row, required=("subject", "from", "date", "receivedDateTime")),
        "commercial_grade_blockers": cloud_blockers("cloud-mail"),
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


def first_value(row: Mapping[str, object], keys: Iterable[str]) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for key in keys:
        for candidate in (key, normalize_key(key)):
            if candidate in row and row[candidate] not in (None, ""):
                return row[candidate]
            if candidate in normalized and normalized[candidate] not in (None, ""):
                return normalized[candidate]
    return ""


def normalize_key(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def service_from_path(source_path: str, *, default: str) -> str:
    lowered = source_path.lower()
    if "gmail" in lowered:
        return "gmail-takeout"
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
    if any(token in lowered for token in ("microsoft", "m365", "office", "onedrive", "teams")):
        return ["#39"], "microsoft-365"
    if any(token in lowered for token in ("icloud", "apple")):
        return ["#38"], "apple-icloud"
    if any(token in lowered for token in ("gmail", "google", "takeout", "google-drive")):
        return ["#37"], "google"
    return ["#37", "#38", "#39"], "cloud-export"


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
    return {
        "status": "validation-required",
        "commercial_gap_ids": list(gap_ids),
        "cloud_family": family,
        "service": service,
        "blockers": list(CLOUD_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Preserve provider export/API scope, account ownership proof, timestamps/timezone notes, and original export hashes.",
            "Validate key mail/file/message/audit rows against provider-native views or known-answer exports before testimony.",
        ],
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
