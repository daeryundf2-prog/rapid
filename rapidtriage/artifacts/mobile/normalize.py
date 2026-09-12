from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .constants import (
    MEDIA_REFERENCE_KEYS,
    MESSAGE_ID_KEYS,
    REACTION_KEYS,
    TIMESTAMP_KEYS,
)
from .detect import (
    detect_chat_service,
    message_risk_flags,
    mobile_decimal_location,
    service_family,
)
from .helpers import (
    app_risk_flags,
    browser_risk_flags,
    chat_app_blockers,
    chat_app_gap_ids,
    file_risk_flags,
    first_present_health_metric,
    first_value,
    ios_backup_file_risk_flags,
    media_risk_flags,
    mobile_export_blockers,
    mobile_health_review_profile,
    mobile_location_review_profile,
    mobile_location_risk_flags,
    mobile_screen_time_review_profile,
    normalize_key,
    normalize_timestamp,
    optional_text,
    row_validation_checks,
    sha256_text,
    split_participants,
    unique_non_empty,
)
from .ios import (
    build_ios_backup_file_profile,
)
from .messengers import (
    chat_app_issue_matrix,
    chat_app_native_capabilities,
    chat_app_report_grade_assessment,
    chat_app_scope_profile,
    extended_messenger_message_review_profile,
    kakaotalk_compatibility_payload,
    kakaotalk_message_review_profile,
    signal_message_review_profile,
    telegram_message_review_profile,
    whatsapp_message_review_profile,
)


def normalize_mobile_row(artifact_type: str, row: Mapping[str, object], path: Path | None = None) -> dict[str, object]:
    if artifact_type == "mobile-message":
        return normalize_message(row, path or Path(""))
    if artifact_type == "mobile-call":
        return normalize_call(row)
    if artifact_type == "mobile-app":
        return normalize_app(row)
    if artifact_type == "mobile-contact":
        return normalize_contact(row)
    if artifact_type == "mobile-file":
        return normalize_file(row)
    if artifact_type == "mobile-account":
        return normalize_account(row)
    if artifact_type == "mobile-media":
        return normalize_media(row)
    if artifact_type == "mobile-browser":
        return normalize_browser(row)
    if artifact_type == "mobile-location":
        return normalize_location(row)
    if artifact_type == "mobile-health":
        return normalize_health(row)
    if artifact_type == "mobile-screen-time":
        return normalize_screen_time(row)
    return {"event_type": "mobile-row", "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)), "raw": dict(row)}


def normalize_message(row: Mapping[str, object], path: Path) -> dict[str, object]:
    text = optional_text(first_value(row, ("messagetext", "messagebody", "body", "message", "content", "text", "snippet", "chat")))
    participants = unique_non_empty(
        [
            optional_text(first_value(row, ("sender", "from", "fromphone", "author", "source"))),
            optional_text(first_value(row, ("recipient", "to", "tophone", "destination"))),
            *split_participants(first_value(row, ("participants", "members", "contacts", "users"))),
        ]
    )
    service = detect_chat_service(row, path) or optional_text(first_value(row, ("service", "platform", "app", "appname", "application", "source")))
    message_id = optional_text(first_value(row, MESSAGE_ID_KEYS))
    app_version = optional_text(first_value(row, ("appversion", "version", "clientversion", "kakaotalkversion")))
    media_reference = optional_text(first_value(row, MEDIA_REFERENCE_KEYS))
    reaction = optional_text(first_value(row, REACTION_KEYS))
    deleted_state = optional_text(first_value(row, ("deleted", "deletedstate", "isdeleted", "deletionstatus")))
    kakaotalk_profile = kakaotalk_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    whatsapp_profile = whatsapp_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    telegram_profile = telegram_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    signal_profile = signal_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    extended_messenger_profile = extended_messenger_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    return {
        "event_type": "message",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "service": service,
        "service_family": service_family(service),
        "schema_version": optional_text(first_value(row, ("schemaversion", "dbversion", "exportversion", "appversion"))),
        "app_version": app_version,
        "conversation_id": optional_text(first_value(row, ("conversationid", "chatid", "threadid", "groupid", "roomid"))),
        "conversation_title": optional_text(first_value(row, ("conversationname", "chatname", "chattitle", "roomname", "groupname"))),
        "message_id": message_id,
        "message_id_sha256": sha256_text(message_id) if message_id else "",
        "direction": optional_text(first_value(row, ("direction", "type", "messagetype", "status"))),
        "sender": participants[0] if participants else "",
        "recipient": participants[1] if len(participants) > 1 else "",
        "participants": participants,
        "participant_count": len(participants),
        "message_text": text,
        "message_text_preview": text[:240],
        "message_text_sha256": sha256_text(text) if text else "",
        "attachment_name": optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename"))),
        "media_reference": media_reference,
        "media_reference_sha256": sha256_text(media_reference) if media_reference else "",
        "reaction": reaction,
        "reply_to_message_id": optional_text(first_value(row, ("replyto", "replytomessageid", "quotedmessageid", "parentmessageid"))),
        "edited_at": normalize_timestamp(first_value(row, ("edited", "editedat", "lastedited", "updated"))),
        "deleted_state": deleted_state,
        "risk_flags": message_risk_flags(text, service),
        "validation_checks": {
            **row_validation_checks(row, required=("timestamp",), content_present=bool(text)),
            "service_detected": bool(service),
            "participants_detected": bool(participants),
            "message_id_present": bool(message_id),
            "media_reference_present": bool(media_reference),
            "reaction_present": bool(reaction),
            "app_schema_validated": False,
            "kakaotalk_review_profile_emitted": bool(kakaotalk_profile),
            "kakaotalk_message_hash_present": bool(kakaotalk_profile.get("message_text_sha256_present")) if kakaotalk_profile else False,
            "kakaotalk_attachment_metadata_present": bool(kakaotalk_profile.get("attachment_metadata_present")) if kakaotalk_profile else False,
            "kakaotalk_read_or_deleted_state_tracked": bool(kakaotalk_profile.get("read_state_present") or kakaotalk_profile.get("deleted_state_present")) if kakaotalk_profile else False,
            "whatsapp_review_profile_emitted": bool(whatsapp_profile),
            "whatsapp_message_hash_present": bool(whatsapp_profile.get("message_text_sha256_present")) if whatsapp_profile else False,
            "whatsapp_media_metadata_present": bool(whatsapp_profile.get("media_metadata_present")) if whatsapp_profile else False,
            "whatsapp_jid_attribution_present": bool(whatsapp_profile.get("jid_attribution_present")) if whatsapp_profile else False,
            "telegram_review_profile_emitted": bool(telegram_profile),
            "telegram_message_hash_present": bool(telegram_profile.get("message_text_sha256_present")) if telegram_profile else False,
            "telegram_account_or_dialog_attribution_present": bool(telegram_profile.get("account_or_dialog_attribution_present")) if telegram_profile else False,
            "telegram_media_cache_metadata_present": bool(telegram_profile.get("media_cache_metadata_present")) if telegram_profile else False,
            "signal_review_profile_emitted": bool(signal_profile),
            "signal_message_hash_present": bool(signal_profile.get("message_text_sha256_present")) if signal_profile else False,
            "signal_thread_or_recipient_attribution_present": bool(signal_profile.get("thread_or_recipient_attribution_present")) if signal_profile else False,
            "signal_attachment_metadata_present": bool(signal_profile.get("attachment_metadata_present")) if signal_profile else False,
            "extended_messenger_review_profile_emitted": bool(extended_messenger_profile),
            "extended_messenger_service_attribution_present": (
                bool(extended_messenger_profile.get("service_attribution_present")) if extended_messenger_profile else False
            ),
            "extended_messenger_thread_or_channel_present": (
                bool(extended_messenger_profile.get("thread_or_channel_attribution_present")) if extended_messenger_profile else False
            ),
            "extended_messenger_attachment_metadata_present": (
                bool(extended_messenger_profile.get("attachment_metadata_present")) if extended_messenger_profile else False
            ),
        },
        **({"kakaotalk_message_review_profile": kakaotalk_profile} if kakaotalk_profile else {}),
        **({"whatsapp_message_review_profile": whatsapp_profile} if whatsapp_profile else {}),
        **({"telegram_message_review_profile": telegram_profile} if telegram_profile else {}),
        **({"signal_message_review_profile": signal_profile} if signal_profile else {}),
        **({"extended_messenger_message_review_profile": extended_messenger_profile} if extended_messenger_profile else {}),
        "chat_app_gap_ids": chat_app_gap_ids(service),
        "chat_app_report_grade_assessment": chat_app_report_grade_assessment(service),
        "chat_app_native_capabilities": chat_app_native_capabilities(service),
        "chat_app_scope_profile": chat_app_scope_profile(service),
        "chat_app_issue_matrix": chat_app_issue_matrix(service, artifact_type="mobile-message", app_version=app_version),
        **kakaotalk_compatibility_payload(service, app_version),
        "commercial_grade_blockers": chat_app_blockers(service),
        "raw": dict(row),
    }


def normalize_call(row: Mapping[str, object]) -> dict[str, object]:
    phone = optional_text(first_value(row, ("phone", "phonenumber", "number", "remote", "remotephone", "address")))
    call_type = optional_text(first_value(row, ("calltype", "type", "direction", "status")))
    return {
        "event_type": "call",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "contact_name": optional_text(first_value(row, ("name", "contact", "contactname", "displayname"))),
        "phone_number": phone,
        "call_type": call_type,
        "duration_seconds": optional_text(first_value(row, ("durationseconds", "duration", "callduration"))),
        "risk_flags": ["missed-call"] if "miss" in call_type.lower() else [],
        "validation_checks": row_validation_checks(row, required=("timestamp", "phone", "phonenumber", "number")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-call-export"),
        "raw": dict(row),
    }


def normalize_contact(row: Mapping[str, object]) -> dict[str, object]:
    email = optional_text(first_value(row, ("email", "emailaddress", "mail")))
    phone = optional_text(first_value(row, ("phone", "phonenumber", "mobile", "number")))
    return {
        "event_type": "contact",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "contact_name": optional_text(first_value(row, ("displayname", "fullname", "name", "contact", "contactname"))),
        "phone_number": phone,
        "email": email,
        "organization": optional_text(first_value(row, ("organization", "company"))),
        "risk_flags": ["contact-identity"] if phone or email else [],
        "validation_checks": row_validation_checks(row, required=("phone", "phonenumber", "email", "displayname", "fullname")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-contact-export"),
        "raw": dict(row),
    }


def normalize_app(row: Mapping[str, object]) -> dict[str, object]:
    package = optional_text(first_value(row, ("packagename", "package", "bundleid", "bundleidentifier", "identifier")))
    app_name = optional_text(first_value(row, ("appname", "app", "application", "name", "displayname")))
    return {
        "event_type": "installed-app",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "app_name": app_name,
        "package": package,
        "version": optional_text(first_value(row, ("version", "versionname", "bundleversion", "appversion"))),
        "installed_at": normalize_timestamp(first_value(row, ("installed", "installedtime", "installdate"))),
        "risk_flags": app_risk_flags(app_name, package),
        "source_app_identifier": package or app_name,
        "validation_checks": row_validation_checks(row, required=("packagename", "package", "bundleid", "bundleidentifier")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-app-export"),
        "raw": dict(row),
    }


def normalize_file(row: Mapping[str, object]) -> dict[str, object]:
    file_path = optional_text(first_value(row, ("filepath", "originalpath", "logicalpath", "path", "filename")))
    return {
        "event_type": "file",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "file_path": file_path,
        "file_name": Path(file_path).name if file_path else optional_text(first_value(row, ("filename", "name"))),
        "size": optional_text(first_value(row, ("size", "filesize", "length"))),
        "mime_type": optional_text(first_value(row, ("mime", "mimetype", "contenttype"))),
        "md5": optional_text(first_value(row, ("md5", "hashmd5"))),
        "sha1": optional_text(first_value(row, ("sha1", "hashsha1"))),
        "sha256": optional_text(first_value(row, ("sha256", "hashsha256"))),
        "risk_flags": file_risk_flags(file_path),
        "validation_checks": row_validation_checks(row, required=("filepath", "originalpath", "logicalpath", "path", "filename")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-file-export"),
        "raw": dict(row),
    }


def normalize_account(row: Mapping[str, object]) -> dict[str, object]:
    identifier = optional_text(first_value(row, ("accountid", "userid", "profileid", "handle", "email", "username", "account")))
    account_name = optional_text(first_value(row, ("accountname", "username", "displayname", "fullname", "name", "email")))
    service = optional_text(first_value(row, ("service", "platform", "app", "appname", "application", "source")))
    return {
        "event_type": "account",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "service": service,
        "account_identifier": identifier,
        "account_identifier_sha256": sha256_text(identifier) if identifier else "",
        "account_name": account_name,
        "risk_flags": ["mobile-account"] + (["ai-service-account"] if "chatgpt" in f"{service} {account_name}".lower() else []),
        "validation_checks": row_validation_checks(row, required=("accountid", "userid", "profileid", "email", "username")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-account-export"),
        "raw": dict(row),
    }


def normalize_media(row: Mapping[str, object]) -> dict[str, object]:
    media_path = optional_text(first_value(row, ("mediapath", "filepath", "originalpath", "logicalpath", "path", "filename")))
    mime_type = optional_text(first_value(row, ("mime", "mimetype", "contenttype")))
    return {
        "event_type": "media",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "media_path": media_path,
        "file_name": Path(media_path).name if media_path else optional_text(first_value(row, ("mediafilename", "filename", "name"))),
        "mime_type": mime_type,
        "size": optional_text(first_value(row, ("size", "filesize", "length"))),
        "width": optional_text(first_value(row, ("width", "pixelwidth"))),
        "height": optional_text(first_value(row, ("height", "pixelheight"))),
        "duration": optional_text(first_value(row, ("duration", "durationseconds"))),
        "md5": optional_text(first_value(row, ("md5", "hashmd5"))),
        "sha1": optional_text(first_value(row, ("sha1", "hashsha1"))),
        "sha256": optional_text(first_value(row, ("sha256", "hashsha256"))),
        "risk_flags": media_risk_flags(media_path, mime_type),
        "validation_checks": row_validation_checks(row, required=("mediapath", "filepath", "mime", "mimetype", "sha256")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-media-export"),
        "raw": dict(row),
    }


def normalize_browser(row: Mapping[str, object]) -> dict[str, object]:
    url = optional_text(first_value(row, ("url", "uri", "downloadurl")))
    title = optional_text(first_value(row, ("title", "pagetitle", "name")))
    return {
        "event_type": "mobile-browser",
        "timestamp": normalize_timestamp(first_value(row, (*TIMESTAMP_KEYS, "lastvisited", "visittime"))),
        "browser": optional_text(first_value(row, ("browser", "app", "appname", "application"))),
        "url": url,
        "url_sha256": sha256_text(url) if url else "",
        "title": title,
        "visit_count": optional_text(first_value(row, ("visitcount", "visits", "typedcount"))),
        "risk_flags": browser_risk_flags(url, title),
        "validation_checks": row_validation_checks(row, required=("url", "uri", "timestamp", "lastvisited")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-browser-export"),
        "raw": dict(row),
    }


def normalize_location(row: Mapping[str, object]) -> dict[str, object]:
    latitude = mobile_decimal_location(first_value(row, ("latitude", "lat", "latitudee7")))
    longitude = mobile_decimal_location(first_value(row, ("longitude", "lon", "lng", "longitudee7")))
    label = optional_text(first_value(row, ("placename", "address", "location", "name", "label")))
    source_device = optional_text(first_value(row, ("sourcedevice", "device", "devicename", "account", "source")))
    return {
        "event_type": "mobile-location",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_meters": optional_text(first_value(row, ("accuracy", "horizontalaccuracy", "radius"))),
        "altitude": optional_text(first_value(row, ("altitude", "elevation"))),
        "location_label": label,
        "source_device": source_device,
        "map_review_profile": mobile_location_review_profile(latitude, longitude, label, source_device),
        "risk_flags": mobile_location_risk_flags(latitude, longitude),
        "validation_checks": {
            **row_validation_checks(row, required=("latitude", "longitude", "latitudee7", "longitudee7")),
            "coordinate_pair_present": latitude is not None and longitude is not None,
            "map_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-location-export"),
        "raw": dict(row),
    }


def normalize_health(row: Mapping[str, object]) -> dict[str, object]:
    metric_type = optional_text(first_value(row, ("metric", "type", "activitytype", "workout", "category")))
    metric_value = optional_text(first_value(row, ("value", "steps", "stepcount", "heartrate", "calories", "distance", "duration")))
    if not metric_type:
        metric_type = first_present_health_metric(row)
    return {
        "event_type": "mobile-health",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "metric_type": metric_type,
        "metric_value": metric_value,
        "unit": optional_text(first_value(row, ("unit", "units"))),
        "source_device": optional_text(first_value(row, ("sourcedevice", "device", "devicename", "source"))),
        "start_time": normalize_timestamp(first_value(row, ("start", "starttime", "sleepstart"))),
        "end_time": normalize_timestamp(first_value(row, ("end", "endtime", "sleepend"))),
        "health_review_profile": mobile_health_review_profile(metric_type, metric_value),
        "risk_flags": ["mobile-health-fitness-candidate"] + ([f"health-metric:{normalize_key(metric_type)}"] if metric_type else []),
        "validation_checks": {
            **row_validation_checks(row, required=("steps", "stepcount", "heartrate", "sleep", "workout")),
            "metric_present": bool(metric_type or metric_value),
            "health_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-health-export"),
        "raw": dict(row),
    }


def normalize_screen_time(row: Mapping[str, object]) -> dict[str, object]:
    app_name = optional_text(first_value(row, ("app", "appname", "application", "bundleid", "package", "name")))
    duration = optional_text(first_value(row, ("duration", "durationseconds", "foregroundtime", "screentime", "appusage")))
    screen_event = optional_text(first_value(row, ("event", "screenon", "screenoff", "unlockcount", "notificationcount")))
    return {
        "event_type": "mobile-screen-time",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "app_name": app_name,
        "duration_seconds": duration,
        "screen_event": screen_event,
        "source_device": optional_text(first_value(row, ("sourcedevice", "device", "devicename", "source"))),
        "screen_time_review_profile": mobile_screen_time_review_profile(app_name, duration, screen_event),
        "risk_flags": ["mobile-screen-time-candidate"] + (["app-usage-duration-candidate"] if duration else []),
        "validation_checks": {
            **row_validation_checks(row, required=("screentime", "digitalwellbeing", "appusage", "duration")),
            "app_or_event_present": bool(app_name or screen_event),
            "duration_present": bool(duration),
            "screen_time_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-screen-time-export"),
        "raw": dict(row),
    }


def normalize_ios_backup_file(row: Mapping[str, object], validation: Mapping[str, object]) -> dict[str, object]:
    domain = optional_text(row.get("domain"))
    relative_path = optional_text(row.get("relativePath"))
    file_id = optional_text(row.get("fileID"))
    return {
        "event_type": "ios-backup-file",
        "timestamp": "",
        "file_id": file_id,
        "file_id_sha256": sha256_text(file_id) if file_id else "",
        "domain": domain,
        "relative_path": relative_path,
        "logical_path": f"{domain}/{relative_path}".strip("/"),
        "flags": optional_text(row.get("flags")),
        "ios_backup_file_profile": build_ios_backup_file_profile(domain, relative_path, file_id, row.get("flags")),
        "risk_flags": ios_backup_file_risk_flags(domain, relative_path),
        "validation_checks": dict(validation),
        "commercial_grade_blockers": [
            "Manifest inventory only; file payload decoding and application schema parsing are not complete.",
            "Encrypted/protected backup handling and deleted-record recovery require external validation.",
        ],
        "raw": dict(row),
    }
