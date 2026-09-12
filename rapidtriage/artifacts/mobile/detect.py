from __future__ import annotations
import contextlib
import csv
import datetime as dt
import hashlib
import json
import plistlib
import shlex
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from ...core.submission import compute_hashes
from ..review import build_forensic_review

from .constants import (
    ACCOUNT_KEYS,
    APP_KEYS,
    BROWSER_KEYS,
    CALL_KEYS,
    CHAT_APP_PROFILES,
    CHAT_KEYS,
    CONTACT_KEYS,
    FILE_KEYS,
    HEALTH_KEYS,
    LOCATION_KEYS,
    MEDIA_KEYS,
    MESSAGE_KEYS,
    MOBILE_REPORT_GRADE_BLOCKERS,
    SCREEN_TIME_KEYS,
    VENDOR_HINTS,
)
from .helpers import (
    mobile_artifact_goal,
    normalize_key,
    optional_text,
)


def first_mobile_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def detect_artifact_type(row: Mapping[str, object], path: Path) -> str:
    source_hint = str(path).lower()
    keys = set(row)
    if keys.intersection(MESSAGE_KEYS) and (
        keys.intersection({"sender", "from", "fromphone", "recipient", "to", "tophone", "direction"})
        or keys.intersection(CHAT_KEYS)
        or any(token in source_hint for token in ("sms", "message", "chat", "conversation", "imessage", "whatsapp"))
        or detect_chat_service(row, path)
    ):
        return "mobile-message"
    # Screen-time classification runs before the generic app branch: loose
    # path tokens such as "app" otherwise match user directories like
    # Windows AppData and swallow screen-time rows.
    if keys.intersection(SCREEN_TIME_KEYS) and any(
        token in source_hint for token in ("screentime", "screen_time", "digital", "wellbeing", "appusage", "app_usage")
    ):
        return "mobile-screen-time"
    if keys.intersection(APP_KEYS) and (
        keys.intersection({"package", "packagename", "bundleid", "bundleidentifier"})
        or any(token in source_hint for token in ("app", "application", "installed"))
    ):
        return "mobile-app"
    if keys.intersection(BROWSER_KEYS) and (
        any(key in keys for key in ("url", "uri", "downloadurl"))
        or any(token in source_hint for token in ("browser", "history", "safari", "chrome", "edge", "firefox"))
    ):
        return "mobile-browser"
    if keys.intersection(LOCATION_KEYS) and (
        keys.intersection({"latitude", "longitude", "latitudee7", "longitudee7", "lat", "lon", "lng"})
        or any(token in source_hint for token in ("location", "gps", "geofence", "map"))
    ):
        return "mobile-location"
    if keys.intersection(HEALTH_KEYS) and any(
        token in source_hint for token in ("health", "fitness", "steps", "workout", "activity", "sleep")
    ):
        return "mobile-health"
    if keys.intersection(CALL_KEYS):
        return "mobile-call"
    if keys.intersection(CONTACT_KEYS) and any(key in keys for key in ("phone", "phonenumber", "email", "displayname", "fullname")):
        return "mobile-contact"
    if "call" in source_hint and any(key in keys for key in ("phone", "phonenumber", "number", "date", "timestamp")):
        return "mobile-call"
    if keys.intersection(ACCOUNT_KEYS) and any(
        token in source_hint for token in ("account", "profile", "user", "owner", "identity")
    ):
        return "mobile-account"
    if keys.intersection(MEDIA_KEYS) and (
        any(key in keys for key in ("mediapath", "mediafilename", "attachment", "mime", "mimetype"))
        or any(token in source_hint for token in ("media", "photo", "image", "video", "camera", "dcim"))
    ):
        return "mobile-media"
    if keys.intersection(FILE_KEYS) and any(key in keys for key in ("filepath", "path", "originalpath", "logicalpath", "filename")):
        return "mobile-file"
    return ""


def mobile_decimal_location(value: object) -> float | None:
    text = optional_text(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    if abs(number) > 180 and number.is_integer():
        number = number / 10_000_000
    if -180 <= number <= 180:
        return number
    return None


def detect_chat_service(row: Mapping[str, object], path: Path) -> str:
    haystack_parts = [str(path).lower()]
    for value in row.values():
        if value in (None, ""):
            continue
        haystack_parts.append(optional_text(value).lower())
    haystack = " ".join(haystack_parts)
    for profile in CHAT_APP_PROFILES:
        aliases = profile.get("aliases", ())
        if any(str(alias).lower() in haystack for alias in aliases):
            return str(profile["service"])
    return ""


def service_family(service: str) -> str:
    text = service.lower().replace(" ", "-")
    if not text:
        return "unknown-chat"
    for profile in CHAT_APP_PROFILES:
        if str(profile["service"]).lower() == service.lower():
            return str(profile["service"]).lower().replace(" ", "-")
    return text


def chat_profile_message_tables(service: str) -> tuple[str, ...]:
    for profile in CHAT_APP_PROFILES:
        if str(profile["service"]).lower() == service.lower():
            return tuple(str(value).lower() for value in profile.get("message_tables", ()))
    return ("message", "messages", "chat", "chat_history")


def detect_source_tool(path: Path) -> str:
    lowered = str(path).lower()
    for vendor, hints in VENDOR_HINTS.items():
        if any(hint in lowered for hint in hints):
            return vendor
    return "mobile-export"


def message_risk_flags(text: str, service: str) -> list[str]:
    lowered = f"{service} {text}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("password", "otp", "2fa", "인증", "비밀번호")):
        flags.append("credential-or-otp")
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-conversation")
    if detect_chat_service({"service": service}, Path("")):
        flags.append("messenger-app-conversation")
    if text:
        flags.append("message-content")
    return flags


def build_mobile_analyst_review_profile(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    gap_ids: Sequence[str],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    manifest = details.get("mobile_vendor_import_manifest")
    if not isinstance(manifest, Mapping):
        manifest = details.get("ios_backup_parser_manifest")
    if not isinstance(manifest, Mapping):
        manifest = {}
    viewer_locator = manifest.get("source_viewer_locator") if isinstance(manifest.get("source_viewer_locator"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    failed_checks = report_grade.get("failed_check_ids") if isinstance(report_grade.get("failed_check_ids"), list) else []
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    summary_parts = [artifact_type, source_tool or "unknown-tool"]
    service = optional_text(details.get("service"))
    if service:
        summary_parts.append(service)
    domain = optional_text(details.get("domain"))
    if domain:
        summary_parts.append(domain)
    table = optional_text(details.get("table"))
    if table:
        summary_parts.append(table)
    package = optional_text(details.get("package"))
    if package:
        summary_parts.append(package)
    not_proof_of = [
        "complete device extraction",
        "vendor parser equivalence",
        "deleted record recovery",
        "protected or encrypted value decryption",
    ]
    if "#28" in gap_ids:
        not_proof_of.append("keychain secret values or access semantics")
    if "#27" in gap_ids:
        not_proof_of.append("decrypted iOS protected file contents")
    if "#26" in gap_ids:
        not_proof_of.append("source-complete vendor export coverage")
    return {
        "profile_version": "mobile-analyst-review-profile-v1",
        "gap_ids": list(gap_ids),
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "severity": "high" if {"credential-or-otp", "sensitive-artifact-redacted"} & set(map(str, risk_flags)) else "medium",
        "summary": " / ".join(part for part in summary_parts if part),
        "evidence_interpretation": mobile_artifact_goal(artifact_type),
        "not_proof_of": not_proof_of,
        "analyst_questions": [
            "Does this row match the original vendor/mobile tool view?",
            "Are acquisition hash, export settings, timezone, and parser version preserved?",
            "Is the source app/schema version covered by a known-answer fixture?",
            "Should this item be correlated with messages, contacts, calls, media, browser, or cloud records?",
        ],
        "primary_pivots": [
            key
            for key in (
                optional_text(details.get("source_record_id")),
                optional_text(details.get("message_id")),
                optional_text(details.get("conversation_id")),
                optional_text(details.get("file_id")),
                optional_text(details.get("domain")),
                optional_text(details.get("logical_path")),
                optional_text(details.get("table")),
                optional_text(details.get("package")),
            )
            if key
        ][:8],
        "source_field_values": {
            "source_path": optional_text(details.get("source_path")),
            "source_sha256": source_hashes.get("sha256", ""),
            "source_record_id": optional_text(details.get("source_record_id")),
            "event_type": optional_text(details.get("event_type")),
            "service": service,
            "domain": domain,
            "logical_path": optional_text(details.get("logical_path")),
            "file_id": optional_text(details.get("file_id")),
            "table": table,
            "row_count": int(details.get("row_count") or details.get("record_count") or 0),
            "manifest_sha256": optional_text(manifest.get("manifest_sha256")),
            "viewer": optional_text(viewer_locator.get("viewer")),
        },
        "correlation_targets": [
            "vendor/mobile tool row diff",
            "acquisition hash log",
            "mobile timeline",
            "contacts/calls/SMS/media correlation",
            "app schema version registry",
        ],
        "risk_tags": sorted(set(map(str, risk_flags)) | set(map(str, failed_checks)) | {"mobile-validation-required"}),
        "validation_required": True,
        "report_grade_ready": False,
        "validation_snapshot": dict(validation_checks),
        "commercial_blockers": list(report_grade.get("blockers", MOBILE_REPORT_GRADE_BLOCKERS)),
        "report_guidance": "Use as a triage/review pivot until source export settings, acquisition hashes, known-answer fixtures, and trusted tool diffs are attached.",
    }


def is_chat_app_database_candidate(path: Path) -> bool:
    if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        return False
    return bool(detect_chat_service({}, path))
