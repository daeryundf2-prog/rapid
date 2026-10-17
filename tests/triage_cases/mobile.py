"""Fixtures of ``rapidtriage.core.triage_rules.mobile`` (see ``tests.triage_cases``)."""

from __future__ import annotations

import datetime as dt

EXPORT = "mobile-export\\calllog.db"


def record(artifact_type: str, source: str = EXPORT, **details: object) -> dict[str, object]:
    return {"kind": "mobile-export", "row": {"artifact_type": artifact_type, "path": source, "details": {"source_path": source, **details}}}


def call(timestamp: str, number: str = "010-0000-1111", **details: object) -> dict[str, object]:
    return record("mobile-call", timestamp=timestamp, phone_number=number, **details)


def contact(number: str) -> dict[str, object]:
    return record("mobile-contact", "mobile-export\\contacts.db", contact_name="Contact A", phone_number=number)


def app(app_name: str, package: str, installed_at: str = "2024-03-01T10:00:00Z") -> dict[str, object]:
    return record("mobile-app", "mobile-export\\apps.json", app_name=app_name, package=package, installed_at=installed_at)


def location(lat: float, lon: float) -> dict[str, object]:
    return record("mobile-location", "mobile-export\\locations.db", latitude=lat, longitude=lon, timestamp="2024-03-01T10:00:00Z")


def calls_every(start: str, count: int, step_minutes: float) -> list[dict[str, object]]:
    first = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
    return [call((first + dt.timedelta(minutes=step_minutes * index)).isoformat().replace("+00:00", "Z")) for index in range(count)]


# 20 fixes around a city centre (±0.01°, about 1 km).
CITY = [location(37.5665 + 0.001 * (index % 10 - 5), 126.9780 + 0.001 * (index // 10 - 1)) for index in range(20)]

CASES = {
    "mobile.backup_encrypted_partial": {
        "positive": {"rows": [record("ios-backup-metadata", "ios-backup\\Manifest.plist", device_name="Test iPhone", is_encrypted=False)], "flagged": [0]},
        # Encrypted backup: Health/Keychain are included.
        "negative": {"rows": [record("ios-backup-metadata", "ios-backup\\Manifest.plist", device_name="Test iPhone", is_encrypted=True)], "flagged": []},
    },
    "mobile.deleted_calls_sms": {
        "positive": {
            "rows": [
                call("2024-03-01T10:00:00Z", deleted_state="freelist"),
                record("mobile-message", "mobile-export\\sms.db", timestamp="2024-03-01T10:01:00Z", sender="010-0000-1111", is_deleted=True),
            ],
            "flagged": [0, 1],
        },
        # Live rows of the same databases.
        "negative": {
            "rows": [
                call("2024-03-01T10:00:00Z", deleted_state="live"),
                record("mobile-message", "mobile-export\\sms.db", timestamp="2024-03-01T10:01:00Z", sender="010-0000-1111", is_deleted=False),
            ],
            "flagged": [],
        },
    },
    "mobile.call_to_unsaved_number": {
        "positive": {
            "rows": [contact("010-0000-2222"), *(call(f"2024-03-0{day}T10:00:00Z", "010-0000-1111") for day in range(1, 6))],
            "flagged": [1, 2, 3, 4, 5],
        },
        # The frequently called number is a saved contact (stored in +82 form).
        "negative": {
            "rows": [contact("+82 10-0000-1111"), *(call(f"2024-03-0{day}T10:00:00Z", "010-0000-1111") for day in range(1, 6))],
            "flagged": [],
        },
    },
    "mobile.call_burst_event": {
        # 20 calls within 19 minutes.
        "positive": {"rows": calls_every("2024-03-01T10:00:00Z", 20, 1), "flagged": list(range(20))},
        # The same burst falls outside the incident window under review.
        "negative": {
            "rows": calls_every("2024-03-01T10:00:00Z", 20, 1),
            "flagged": [],
            "incident": ("2024-03-05T00:00:00Z", "2024-03-06T00:00:00Z"),
        },
    },
    "mobile.app_installed_recent": {
        "positive": {"rows": [app("Telegram", "org.telegram.messenger"), app("NordVPN", "com.nordvpn.android")], "flagged": [0, 1]},
        # Stock system apps; "Wireless" merely starts with the keyword "wire".
        "negative": {
            "rows": [
                app("Wireless emergency alerts", "com.google.android.cellbroadcastreceiver"),
                app("Calendar", "com.example.calendar"),
            ],
            "flagged": [],
        },
    },
    "mobile.location_outlier": {
        "positive": {"rows": [*CITY, location(35.1796, 129.0756)], "flagged": [20]},
        # GPS jitter around the usual area only.
        "negative": {"rows": [*CITY, location(37.5765, 126.9880)], "flagged": []},
    },
    "mobile.time_epoch_mismatch": {
        "positive": {
            "rows": [
                call("2024-03-01T10:00:00Z", timestamp_raw="1709287200"),
                call("2024-03-01T10:05:00Z", timestamp_raw="1709287500"),
                call("2024-03-01T10:10:00Z", timestamp_raw="1709287800"),
                call("2024-03-01T10:15:00Z", timestamp_raw="1709288100000000000"),
            ],
            "flagged": [3],
        },
        # Two databases with different but internally consistent units.
        "negative": {
            "rows": [
                call("2024-03-01T10:00:00Z", timestamp_raw="1709287200"),
                call("2024-03-01T10:05:00Z", timestamp_raw="1709287500"),
                record("mobile-message", "mobile-export\\sms.db", timestamp="2024-03-01T10:10:00Z", timestamp_raw="1709287800000"),
                record("mobile-message", "mobile-export\\sms.db", timestamp="2024-03-01T10:15:00Z", timestamp_raw="1709288100000"),
            ],
            "flagged": [],
        },
    },
    "mobile.factory_reset_gap": {
        "positive": {
            "rows": [call("2023-01-01T10:00:00Z"), call("2023-01-02T10:00:00Z"), call("2023-09-01T10:00:00Z")],
            "flagged": [2],
        },
        # Continuous use with ordinary pauses.
        "negative": {
            "rows": [call("2023-01-01T10:00:00Z"), call("2023-03-15T10:00:00Z"), call("2023-06-20T10:00:00Z"), call("2023-09-01T10:00:00Z")],
            "flagged": [],
        },
    },
}
