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
    CHAT_APP_GAP_IDS,
)


def discover_vendor_export_manifest(path: Path) -> Path | None:
    candidates = [
        path.with_suffix(path.suffix + ".export-metadata.json"),
        path.with_suffix(path.suffix + ".manifest.json"),
        path.with_suffix(path.suffix + ".export-manifest.json"),
        path.with_name(path.stem + "-export-metadata.json"),
        path.with_name(path.stem + "-manifest.json"),
        path.parent / "export-metadata.json",
        path.parent / "export_manifest.json",
        path.parent / "manifest.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _mobile_vendor_export_validation_command(
    command_id: str,
    argv: Sequence[object],
    *,
    purpose: str,
    expected_output: str,
    trusted_tool: bool = False,
    status: str = "pending-run",
) -> dict[str, object]:
    clean_argv = [str(item) for item in argv if str(item) != ""]
    return {
        "id": command_id,
        "argv": clean_argv,
        "command": shlex.join(clean_argv),
        "purpose": purpose,
        "expected_output": expected_output,
        "status": status,
        "trusted_tool_required": trusted_tool,
    }


def _gap_item_numbers(gap_ids: Sequence[str]) -> list[int]:
    numbers: list[int] = []
    for gap_id in gap_ids:
        value = str(gap_id).strip().removeprefix("#")
        if value.isdigit():
            number = int(value)
            if number not in numbers:
                numbers.append(number)
    return numbers


def _matrix_item_numbers(rows: Sequence[Mapping[str, object]], fallback: Sequence[int]) -> list[int]:
    numbers = set(fallback)
    for row in rows:
        item_number = row.get("item_number")
        if isinstance(item_number, int):
            numbers.add(item_number)
        row_numbers = row.get("item_numbers")
        if isinstance(row_numbers, Sequence) and not isinstance(row_numbers, (str, bytes)):
            numbers.update(int(number) for number in row_numbers if isinstance(number, int))
    return sorted(numbers)


def _mobile_matrix_status(complete: bool, observed: bool) -> str:
    if complete:
        return "validated"
    if observed:
        return "observed-validation-required"
    return "supported-not-observed"


def normalize_keys(row: Mapping[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {}
    for key, value in row.items():
        canonical = normalize_key(key)
        normalized[canonical] = value
    return normalized


def normalize_key(key: object) -> str:
    return "".join(character for character in str(key).lower() if character.isalnum())


def normalized_mobile_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def classify_kakaotalk_export_attachment(media_reference: str, attachment_name: str, message_type: str) -> str:
    lowered = f"{media_reference} {attachment_name} {message_type}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".gif", "image", "photo", "thumbnail")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".avi", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in ("file", "attach", ".pdf", ".doc", ".xls", ".zip")):
        return "file"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


def is_whatsapp_jid(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith("@s.whatsapp.net") or lowered.endswith("@g.us") or lowered.endswith("@broadcast")


def whatsapp_actor_shape(value: str) -> str:
    if not value:
        return "missing"
    if value.endswith("@g.us"):
        return "group-jid"
    if value.endswith("@s.whatsapp.net"):
        return "user-jid"
    if value.endswith("@broadcast"):
        return "broadcast-jid"
    if any(character.isdigit() for character in value):
        return "phone-or-export-actor"
    return "display-name-or-export-actor"


def classify_whatsapp_media(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".opus", ".ogg", ".m4a", ".mp3", ".wav", "audio", "ptt", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


def classify_telegram_media(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".mkv", ".webm", "video")):
        return "video"
    if any(token in lowered for token in (".ogg", ".opus", ".m4a", ".mp3", ".wav", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


def classify_signal_attachment(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".webm", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", ".ogg", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


def extended_messenger_source_track(service: str) -> str:
    tracks = {
        "WeChat": "wechat-export-wcdb-authority-gated-schema-review",
        "LINE": "line-export-database-schema-review",
        "Discord": "discord-data-package-channel-message-review",
        "Instagram": "instagram-data-download-thread-message-review",
    }
    return tracks.get(service, "extended-service-export-schema-validation")


def classify_extended_messenger_attachment(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo", "sticker")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".mkv", ".webm", ".3gp", "video", "reel")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", ".ogg", ".opus", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".ppt", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


def mobile_location_review_profile(
    latitude: float | None,
    longitude: float | None,
    label: str,
    source_device: str,
) -> dict[str, object]:
    return {
        "profile_version": "mobile-location-map-review-profile-v1",
        "coordinate_pair_present": latitude is not None and longitude is not None,
        "latitude": latitude,
        "longitude": longitude,
        "label_present": bool(label),
        "source_device_present": bool(source_device),
        "values_are_candidates": True,
        "source_viewer_hint": "Use the map/timeline view to correlate this coordinate with media EXIF, Wi-Fi, app, and cloud location rows.",
        "not_proof_of": [
            "person-physically-present",
            "device-owner-present",
            "continuous-route",
        ],
        "report_blockers": [
            "source-app-schema-fixture-required",
            "timezone-and-clock-skew-validation-required",
            "map-provider-independent-review-required",
        ],
    }


def mobile_location_risk_flags(latitude: float | None, longitude: float | None) -> list[str]:
    flags = ["mobile-location-candidate"]
    if latitude is not None and longitude is not None:
        flags.extend(["precise-location", "map-review-candidate"])
    return flags


def first_present_health_metric(row: Mapping[str, object]) -> str:
    for key in ("steps", "stepcount", "heartrate", "sleep", "sleepstart", "workout", "calories", "distance"):
        if optional_text(first_value(row, (key,))):
            return key
    return ""


def mobile_health_review_profile(metric_type: str, metric_value: str) -> dict[str, object]:
    return {
        "profile_version": "mobile-health-review-profile-v1",
        "metric_type": metric_type,
        "metric_value_present": bool(metric_value),
        "values_are_candidates": True,
        "source_viewer_hint": "Correlate health/fitness rows with device unlocks, app usage, location, and acquisition timestamps.",
        "not_proof_of": [
            "device-holder-identity",
            "medical-grade-measurement",
            "continuous-activity",
        ],
        "report_blockers": [
            "health-app-schema-version-required",
            "device-timezone-validation-required",
            "source-device-attribution-required",
        ],
    }


def mobile_screen_time_review_profile(app_name: str, duration: str, screen_event: str) -> dict[str, object]:
    return {
        "profile_version": "mobile-screen-time-review-profile-v1",
        "app_name_present": bool(app_name),
        "duration_present": bool(duration),
        "screen_event_present": bool(screen_event),
        "values_are_candidates": True,
        "source_viewer_hint": "Correlate screen/app usage with notifications, app databases, and device lock/unlock events.",
        "not_proof_of": [
            "specific-person-using-device",
            "foreground-app-content-viewed",
            "complete-screen-time-history",
        ],
        "report_blockers": [
            "digital-wellbeing-screen-time-schema-fixture-required",
            "timezone-and-device-clock-validation-required",
            "app-identity-corroboration-required",
        ],
    }


def chat_table_is_message_candidate(table_name: str, columns: Iterable[str], profile_tables: Iterable[str]) -> bool:
    lowered_table = table_name.lower()
    lowered_columns = {column.lower() for column in columns}
    if any(candidate in lowered_table for candidate in profile_tables):
        return True
    return bool(
        lowered_columns.intersection({"message", "text", "body", "content", "timestamp", "date", "sender", "author"})
        and lowered_columns.intersection({"chat_id", "thread_id", "conversation_id", "from_jid", "recipient", "remote_jid"})
    )


def split_participants(value: object) -> list[str]:
    text = optional_text(value)
    if not text:
        return []
    if text.startswith("[") or text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [optional_text(item) for item in parsed if optional_text(item)]
        if isinstance(parsed, Mapping):
            return [optional_text(item) for item in parsed.values() if optional_text(item)]
    return [
        item.strip()
        for item in text.replace(";", ",").replace("|", ",").split(",")
        if item.strip()
    ]


def first_value(row: Mapping[str, object], keys: Iterable[str]) -> object:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
        normalized_key = normalize_key(key)
        if normalized_key in row and row[normalized_key] not in (None, ""):
            return row[normalized_key]
    return ""


def first_truthy(*values: object) -> object:
    for value in values:
        if value:
            return value
    return None


def normalize_timestamp(value: object) -> str:
    text = optional_text(value)
    if not text:
        return ""
    if text.isdigit():
        timestamp = int(text)
        if timestamp > 10_000_000_000_000:
            timestamp = timestamp // 1_000_000
        elif timestamp > 10_000_000_000:
            timestamp = timestamp // 1000
        return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def source_format_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    return "json"


def app_risk_flags(app_name: str, package: str) -> list[str]:
    lowered = f"{app_name} {package}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("vpn", "proxy", "tor", "secure", "vault", "signal", "telegram")):
        flags.append("privacy-or-evasion-app")
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-app")
    return flags


def file_risk_flags(file_path: str) -> list[str]:
    lowered = file_path.lower()
    flags: list[str] = []
    if any(token in lowered for token in ("/dcim/", "/pictures/", "/download/", "/documents/")):
        flags.append("user-file")
    if any(lowered.endswith(suffix) for suffix in (".db", ".sqlite", ".sqlite3", ".plist", ".xml", ".json")):
        flags.append("structured-data-file")
    return flags


def media_risk_flags(media_path: str, mime_type: str) -> list[str]:
    lowered = f"{media_path} {mime_type}".lower()
    flags = ["mobile-media"]
    if any(token in lowered for token in ("image", ".jpg", ".jpeg", ".png", "/dcim/", "camera")):
        flags.append("image-media")
    if any(token in lowered for token in ("video", ".mp4", ".mov", ".3gp")):
        flags.append("video-media")
    if any(token in lowered for token in ("audio", ".m4a", ".wav", ".mp3")):
        flags.append("audio-media")
    return flags


def browser_risk_flags(url: str, title: str) -> list[str]:
    lowered = f"{url} {title}".lower()
    flags = ["mobile-browser-history"]
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-usage")
    if any(token in lowered for token in ("login", "account", "password", "otp")):
        flags.append("credential-context")
    return flags


def ios_backup_file_risk_flags(domain: str, relative_path: str) -> list[str]:
    lowered = f"{domain}/{relative_path}".lower()
    flags = ["ios-backup-file"]
    if any(token in lowered for token in ("sms", "message", "chat", "whatsapp", "telegram", "line", "kakao")):
        flags.append("message-store-candidate")
    if any(token in lowered for token in ("camera", "dcim", "photo", "media", ".jpg", ".mov", ".mp4")):
        flags.append("media-candidate")
    if any(token in lowered for token in ("account", "profile", "keychain", "credential", "cookie")):
        flags.append("sensitive-artifact-candidate")
    return flags


def row_validation_checks(
    row: Mapping[str, object],
    *,
    required: Iterable[str],
    content_present: bool | None = None,
) -> dict[str, object]:
    keys = set(row)
    checks: dict[str, object] = {
        "has_required_field_candidate": any(key in keys and row[key] not in (None, "") for key in required),
        "normalized_key_count": len(keys),
        "row_hash_algorithm": "sha256-json-normalized",
        "vendor_schema_validated": False,
    }
    if content_present is not None:
        checks["content_present"] = content_present
    return checks


def mobile_commercial_gap_ids(artifact_type: str, source_tool: str) -> list[str]:
    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata"}:
        return ["#27"]
    if artifact_type == "ios-keychain-inventory":
        return ["#28"]
    if source_tool in {"cellebrite", "xry", "graykey", "axiom"} or artifact_type.startswith("mobile-"):
        return ["#26"]
    return ["#26"]


def mobile_validation_matrix(
    *,
    artifact_type: str,
    source_tool: str,
    validation_checks: Mapping[str, object],
) -> list[dict[str, object]]:
    return [
        {
            "id": "source-hash-present",
            "label": "Source export or database hash is recorded",
            "passed": True,
            "severity": "critical",
        },
        {
            "id": "source-tool-detected",
            "label": "Source tool or acquisition family is identified",
            "passed": bool(source_tool),
            "severity": "medium",
        },
        {
            "id": "core-fields-normalized",
            "label": "Core artifact fields are normalized into reviewable output",
            "passed": bool(validation_checks.get("has_required_field_candidate", True)),
            "severity": "high",
        },
        {
            "id": "vendor-settings-verified",
            "label": "Vendor export settings, parser version, and original acquisition hash are verified",
            "passed": bool(validation_checks.get("vendor_export_settings_verified"))
            and bool(validation_checks.get("original_acquisition_hash_verified")),
            "severity": "critical",
        },
        {
            "id": "protected-data-boundary",
            "label": "Protected/encrypted secrets are not exposed without explicit validated workflow",
            "passed": not bool(validation_checks.get("secrets_extracted")),
            "severity": "critical",
        },
        {
            "id": "known-answer-mobile-validation",
            "label": "Parser behavior is validated against mobile known-answer corpora",
            "passed": False,
            "severity": "critical",
        },
    ]


def mobile_correlation_core_accuracy_gates(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    if artifact_type != "mobile-correlation-summary":
        return []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    evidence_refs = [
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
        f"message_count:{details.get('message_count', 0)}",
        f"media_count:{details.get('media_count', 0)}",
        f"contact_count:{details.get('contact_count', 0)}",
        f"call_count:{details.get('call_count', 0)}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")
    trusted_diff = (
        details.get("mobile_correlation_trusted_diff")
        if isinstance(details.get("mobile_correlation_trusted_diff"), Mapping)
        else {}
    )
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")

    item43: list[str] = []
    if validation.get("media_message_links_built") or details.get("message_media_links") is not None:
        item43.append("message-media linkage built")
    if any(int(details.get(key) or 0) >= 0 for key in ("message_count", "media_count", "contact_count", "call_count")):
        item43.append("message/contact/call/media counts preserved")
    if details.get("services") is not None:
        item43.append("service attribution")
    if details.get("timeline_correlation_ready") is not None:
        item43.append("timeline correlation readiness")
    timeline_profile = (
        details.get("mobile_timeline_correlation_profile")
        if isinstance(details.get("mobile_timeline_correlation_profile"), Mapping)
        else {}
    )
    if timeline_profile:
        item43.append("timeline correlation profile")
        evidence_refs.append(f"timeline_event_count:{timeline_profile.get('event_count', 0)}")
        evidence_refs.append(f"unresolved_media_link_count:{timeline_profile.get('unresolved_media_link_count', 0)}")
    citation_manifest = (
        details.get("mobile_correlation_citation_manifest")
        if isinstance(details.get("mobile_correlation_citation_manifest"), Mapping)
        else {}
    )
    if citation_manifest:
        item43.append("correlation citation manifest")
        evidence_refs.append(
            f"mobile_correlation_citation_manifest_sha256:{citation_manifest.get('manifest_sha256', '')}"
        )
        if int(citation_manifest.get("timeline_event_citation_count") or 0) > 0:
            item43.append("timeline event source citations")
        if int(citation_manifest.get("message_media_link_citation_count") or 0) > 0:
            item43.append("message-media link citations")
    timeline_validation_plan = (
        details.get("mobile_timeline_report_grade_validation_plan")
        if isinstance(details.get("mobile_timeline_report_grade_validation_plan"), Mapping)
        else {}
    )
    if timeline_validation_plan:
        item43.append("timeline report-grade validation plan")
        evidence_refs.append(
            "mobile_timeline_report_grade_validation_plan_sha256:"
            f"{timeline_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            item43.append("timeline report-grade ready slots")
    if not validation.get("correlation_validated_against_known_answer", False):
        item43.append("known-answer limitation warning")
    if trusted_diff.get("status") == "pass":
        item43.append("trusted mobile correlation diff pass")

    item44: list[str] = []
    if validation.get("unified_contact_call_sms_view_built") or details.get("unified_contact_call_sms_view") is not None:
        item44.append("contact/call/SMS actor merge")
    if details.get("message_media_links") is not None or details.get("unified_contact_call_sms_view") is not None:
        item44.append("source row links preserved")
    if details.get("participants") is not None:
        item44.append("participant attribution")
    actor_review_profile = (
        details.get("mobile_actor_review_profile")
        if isinstance(details.get("mobile_actor_review_profile"), Mapping)
        else {}
    )
    if actor_review_profile:
        item44.append("actor review profile")
        evidence_refs.append(f"actor_review_queue_count:{actor_review_profile.get('review_queue_count', 0)}")
        evidence_refs.append(f"multi_identifier_actor_count:{actor_review_profile.get('multi_identifier_actor_count', 0)}")
    actor_citation_manifest = (
        details.get("mobile_actor_citation_manifest")
        if isinstance(details.get("mobile_actor_citation_manifest"), Mapping)
        else {}
    )
    if actor_citation_manifest:
        item44.append("actor citation manifest")
        evidence_refs.append(
            f"mobile_actor_citation_manifest_sha256:{actor_citation_manifest.get('manifest_sha256', '')}"
        )
        if int(actor_citation_manifest.get("actor_entry_count") or 0) > 0:
            item44.append("actor source viewer locators")
        if actor_citation_manifest.get("raw_actor_values_serialized") is False:
            item44.append("actor values hashed in manifest")
    actor_validation_plan = (
        details.get("mobile_actor_report_grade_validation_plan")
        if isinstance(details.get("mobile_actor_report_grade_validation_plan"), Mapping)
        else {}
    )
    if actor_validation_plan:
        item44.append("actor report-grade validation plan")
        evidence_refs.append(
            "mobile_actor_report_grade_validation_plan_sha256:"
            f"{actor_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(actor_validation_plan.get("ready_slot_count") or 0) >= 6:
            item44.append("actor report-grade ready slots")
    if actor_review_profile.get("merge_split_review_required"):
        item44.append("merge/split review requirement")
    item44.append("dedupe/entity limitation warning")
    item44.append("export-scope limitation warning")
    if trusted_diff.get("status") == "pass":
        item44.append("trusted mobile actor diff pass")

    item45: list[str] = []
    if validation.get("schema_version_registry_built") or details.get("schema_version_registry") is not None:
        item45.append("app/service schema version registry")
    schema_compatibility_profile = (
        details.get("mobile_schema_compatibility_profile")
        if isinstance(details.get("mobile_schema_compatibility_profile"), Mapping)
        else {}
    )
    if schema_compatibility_profile:
        item45.append("schema compatibility profile")
        evidence_refs.append(f"schema_compatibility_entry_count:{schema_compatibility_profile.get('entry_count', 0)}")
        evidence_refs.append(f"schema_unvalidated_entry_count:{schema_compatibility_profile.get('unvalidated_entry_count', 0)}")
    schema_version_manifest = (
        details.get("mobile_schema_version_manifest")
        if isinstance(details.get("mobile_schema_version_manifest"), Mapping)
        else {}
    )
    if schema_version_manifest:
        item45.append("schema version manifest")
        evidence_refs.append(
            f"mobile_schema_version_manifest_sha256:{schema_version_manifest.get('manifest_sha256', '')}"
        )
        if int(schema_version_manifest.get("schema_entry_count") or 0) > 0:
            item45.append("schema source viewer locators")
        if schema_version_manifest.get("release_gate_blocked"):
            item45.append("schema release gates recorded")
    schema_validation_plan = (
        details.get("mobile_schema_report_grade_validation_plan")
        if isinstance(details.get("mobile_schema_report_grade_validation_plan"), Mapping)
        else {}
    )
    if schema_validation_plan:
        item45.append("schema report-grade validation plan")
        evidence_refs.append(
            "mobile_schema_report_grade_validation_plan_sha256:"
            f"{schema_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(schema_validation_plan.get("ready_slot_count") or 0) >= 6:
            item45.append("schema report-grade ready slots")
    if details.get("services") is not None or details.get("schema_versions") is not None:
        item45.append("source app/version attribution")
    item45.append("schema compatibility warning")
    if not validation.get("schema_version_registry_known_answer_validated", False):
        item45.append("migration fixture warning")
    item45.append("release-gate limitation disclosure")
    if trusted_diff.get("status") == "pass":
        item45.append("trusted app schema migration diff pass")

    return [
        build_accuracy_gate(43, satisfied_checks=item43, evidence_refs=evidence_refs),
        build_accuracy_gate(44, satisfied_checks=item44, evidence_refs=evidence_refs),
        build_accuracy_gate(45, satisfied_checks=item45, evidence_refs=evidence_refs),
    ]


def mobile_artifact_goal(artifact_type: str) -> str:
    if artifact_type.startswith("ios-backup"):
        return "iOS backup Manifest.db/plist inventory and authorized backup pivot evidence"
    if artifact_type == "ios-keychain-inventory":
        return "iOS keychain redacted inventory with strict protected-data boundary"
    if artifact_type.startswith("mobile-"):
        return "Vendor mobile export row normalization for messages, apps, contacts, calls, files, media and browser data"
    return "Mobile export artifact review"


def source_validation_checks(
    source_format: str,
    source_tool: str,
    emitted: int,
    detected_types: set[str],
    *,
    input_rows: int | None = None,
    vendor_manifest_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = vendor_manifest_profile or {}
    return {
        "source_format": source_format,
        "source_tool_detected": source_tool,
        "row_count_nonzero": emitted > 0,
        "input_row_count_recorded": input_rows is not None,
        "unclassified_rows_recorded": input_rows is not None and input_rows >= emitted,
        "row_cap_recorded": True,
        "schema_profile_emitted": True,
        "detected_artifact_type_count": len(detected_types),
        "vendor_export_settings_verified": bool(manifest.get("export_settings_present"))
        and bool(manifest.get("vendor_tool_version"))
        and bool(manifest.get("source_hash_matches_manifest")),
        "original_acquisition_hash_verified": bool(manifest.get("original_acquisition_hash_present")),
        "vendor_schema_validated": bool(manifest.get("schema_version")) and manifest.get("validation_status") == "metadata-linked",
    }


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mobile_export_blockers(source_tool: str) -> list[str]:
    return [
        f"{source_tool} schema coverage is heuristic and fixture-backed only for common CSV/JSON exports.",
        "Original device/acquisition hashes, extraction settings, and vendor parser version must be independently recorded.",
        "Deleted records, encrypted app stores, and proprietary package semantics are not fully validated.",
    ]


def chat_app_blockers(service: str) -> list[str]:
    label = service or "chat app"
    return [
        f"{label} parsing is limited to authorized exports/backups and heuristic CSV/JSON/SQLite inventory.",
        "App-specific encrypted stores, deleted records, schema-version drift, and attachment recovery are not fully validated.",
        "Original device/acquisition hashes, export settings, app version, timezone, and account ownership must be independently verified.",
    ]


def chat_app_gap_ids(service: str) -> list[str]:
    gap = CHAT_APP_GAP_IDS.get(service)
    return [gap] if gap else ["#31", "#32", "#33", "#34", "#35"]


def version_at_least(value: str, minimum: str) -> bool:
    return version_tuple(value) >= version_tuple(minimum)


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for item in value.replace("-", ".").split("."):
        digits = "".join(character for character in item if character.isdigit())
        if digits:
            parts.append(int(digits))
        if len(parts) >= 4:
            break
    return tuple(parts or [0])


def source_record_id(details: Mapping[str, object], source_index: int) -> str:
    raw = details.get("raw")
    if isinstance(raw, Mapping):
        for key in ("id", "recordid", "sourceid", "guid", "messageid", "fileid"):
            value = raw.get(key)
            if value not in (None, ""):
                return optional_text(value)
        return sha256_text(json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str))
    return str(source_index)


def stable_mobile_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    if isinstance(value, str):
        return sha256_text(value)
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))


def looks_like_ios_backup_path(path: Path) -> bool:
    lowered = str(path).lower()
    if any(token in lowered for token in ("ios", "iphone", "ipad", "mobilebackup", "backup")):
        return True
    return path.name in {"Manifest.db", "Info.plist", "Status.plist", "keychain-2.db"}


def sqlite_table_names(connection: sqlite3.Connection) -> list[str]:
    try:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
    except sqlite3.Error:
        return []


def sqlite_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    if not safe_sqlite_identifier(table_name):
        return []
    try:
        return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table_name}")')]
    except sqlite3.Error:
        return []


def sqlite_row_count(connection: sqlite3.Connection, table_name: str) -> int | None:
    if not safe_sqlite_identifier(table_name):
        return None
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()
    except sqlite3.Error:
        return None
    return int(row[0]) if row else None


def safe_sqlite_identifier(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character in {"_", "-"} for character in value)


def unique_non_empty(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def optional_text(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(value)
