from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Iterable, Mapping

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "cloud-export-v1"
CLOUD_JSON_SUFFIXES = {".json"}


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


def build_record(
    path: Path,
    *,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> ArtifactRecord:
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
            **dict(details),
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
        account_keys = {"account", "apple id", "email", "phone", "full_name", "name", "created"}
        if account_keys.intersection({str(key).lower() for key in payload.keys()}):
            return "cloud-account"
    if isinstance(payload, list) and payload and all(isinstance(item, Mapping) for item in payload[:5]):
        if "my activity" in lowered or "takeout" in lowered or any("time" in item or "timestamp" in item for item in payload[:5] if isinstance(item, Mapping)):
            return "google-activity"
    return ""


def extract_google_location_rows(payload: object) -> list[Mapping[str, object]]:
    if isinstance(payload, Mapping) and isinstance(payload.get("locations"), list):
        return [item for item in payload["locations"] if isinstance(item, Mapping)]
    return []


def extract_list_rows(payload: object) -> list[Mapping[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
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
        "raw": dict(payload),
    }


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
