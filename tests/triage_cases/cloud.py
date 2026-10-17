"""Fixtures of ``rapidtriage.core.triage_rules.cloud`` (see ``tests.triage_cases``)."""

from __future__ import annotations

import datetime as dt

START = dt.datetime(2024, 5, 1, 9, 0, tzinfo=dt.timezone.utc)


def audit(operation: str, at: dt.datetime | str, artifact_type: str = "cloud-audit", raw: dict[str, object] | None = None, **details: object) -> dict[str, object]:
    timestamp = at if isinstance(at, str) else at.isoformat().replace("+00:00", "Z")
    base: dict[str, object] = {
        "service": "microsoft-365-audit",
        "event_type": "audit",
        "timestamp": timestamp,
        "operation": operation,
        "actor": "alice@example.com",
        "raw": {"Operation": operation, "UserId": "alice@example.com", **(raw or {})},
    }
    base.update(details)
    return {"kind": "cloud", "row": {"artifact_type": artifact_type, "path": r"E:\export\m365\audit.json", "details": base}}


def downloads(count: int, step: dt.timedelta) -> list[dict[str, object]]:
    return [audit("FileDownloaded", START + step * index, object_id=f"https://example.sharepoint.com/sites/hr/doc{index}.xlsx") for index in range(count)]


def login(at: dt.datetime, ip: str) -> dict[str, object]:
    return audit("UserLoggedIn", at, ip_address=ip)


def photo(raw: dict[str, object]) -> dict[str, object]:
    return {
        "kind": "cloud",
        "row": {"artifact_type": "cloud-photo", "path": r"E:\export\Takeout\Google Photos\IMG_0001.jpg.json", "details": {"service": "google-photos", "file_name": "IMG_0001.jpg", "raw": {"title": "IMG_0001.jpg", **raw}}},
    }


def sync_upload(index: int, at: dt.datetime, *, size: int = 2_000_000, eligible: bool = True) -> dict[str, object]:
    """A desktop sync-client upload event (``cloud-sync-event``, R2 M4)."""
    return {
        "kind": "cloud-sync",
        "row": {
            "artifact_type": "cloud-sync-event",
            "path": r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2024-05-01.odl",
            "details": {
                "client": "onedrive",
                "operation": "upload",
                "timestamp": at.isoformat().replace("+00:00", "Z"),
                "actor": "alice@example.com",
                "item_path": rf"C:\Users\alice\OneDrive\설계\도면{index:03d}.dwg",
                "size": size,
                "bulk_rule_eligible": eligible,
            },
        },
    }


def sync_account(*roots: str) -> dict[str, object]:
    """A desktop sync-client account row with its sync root(s) (``cloud-sync-account``)."""
    return {
        "kind": "cloud-sync",
        "row": {
            "artifact_type": "cloud-sync-account",
            "path": r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\settings\Personal\global.ini",
            "details": {"client": "onedrive", "actor": "alice@example.com", "sync_root": roots[0], "sync_roots": list(roots)},
        },
    }


ITEM ="https://example.sharepoint.com/sites/finance/Shared Documents/budget.xlsx"
DAY = dt.timedelta(days=1)

CASES = {
    "cloud.bulk_download": {
        "positive": {"rows": downloads(100, dt.timedelta(seconds=5)), "flagged": list(range(100))},
        # The same number of downloads spread over a working day.
        "negative": {"rows": downloads(100, dt.timedelta(minutes=5)), "flagged": []},
    },
    "cloud.external_share": {
        "positive": {
            "rows": [
                audit("AnonymousLinkCreated", START, object_id=ITEM),
                audit("SharingInvitationCreated", START, object_id=ITEM, raw={"TargetUserOrGroupName": "partner@example.net", "TargetUserOrGroupType": "Guest"}),
            ],
            "flagged": [0, 1],
        },
        # Collaboration inside the organisation: an invitation to a colleague and an org-wide (company) link.
        "negative": {
            "rows": [
                audit("SharingInvitationCreated", START, object_id=ITEM, raw={"TargetUserOrGroupName": "bob@example.com", "TargetUserOrGroupType": "Member"}),
                audit("CompanyLinkCreated", START, object_id=ITEM),
            ],
            "flagged": [],
        },
    },
    "cloud.new_device_login": {
        "positive": {
            "rows": [login(START + DAY * index, "203.0.113.10") for index in range(5)] + [login(START + DAY * 5, "198.51.100.77")],
            "flagged": [5],
        },
        # Office and home (VPN) addresses both appear in the baseline and keep recurring.
        "negative": {
            "rows": [login(START + DAY * index, "203.0.113.10" if index % 2 else "203.0.113.20") for index in range(5)]
            + [login(START + DAY * 5, "203.0.113.20"), login(START + DAY * 6, "203.0.113.10")],
            "flagged": [],
        },
    },
    "cloud.delete_after_share": {
        "positive": {
            "rows": [
                audit("AnonymousLinkCreated", START, object_id=ITEM),
                audit("FileDeleted", START + dt.timedelta(minutes=25), object_id=ITEM),
            ],
            "flagged": [1],
        },
        # Clean-up of a file shared a week earlier.
        "negative": {
            "rows": [
                audit("AnonymousLinkCreated", START, object_id=ITEM),
                audit("FileDeleted", START + DAY * 7, object_id=ITEM),
            ],
            "flagged": [],
        },
    },
    "cloud.taken_vs_creation_gap": {
        "positive": {
            "rows": [photo({"photoTakenTime": {"timestamp": "1577869200"}, "creationTime": {"timestamp": "1714554000"}})],
            "flagged": [0],
        },
        # Phone auto-upload a few hours after the shot.
        "negative": {
            "rows": [photo({"photoTakenTime": {"timestamp": "1714543200"}, "creationTime": {"timestamp": "1714554000"}})],
            "flagged": [],
        },
    },
    "cloud.json_exif_gps_mismatch": {
        "positive": {
            "rows": [photo({"geoData": {"latitude": 37.5665, "longitude": 126.978}, "geoDataExif": {"latitude": 35.1796, "longitude": 129.0756}})],
            "flagged": [0],
        },
        # Takeout writes 0.0/0.0 into geoData when the photo has no edited location.
        "negative": {
            "rows": [photo({"geoData": {"latitude": 0.0, "longitude": 0.0}, "geoDataExif": {"latitude": 35.1796, "longitude": 129.0756}})],
            "flagged": [],
        },
    },
    "cloud.audit_retention_gap": {
        "positive": {
            "rows": [
                audit("FileAccessed", START + DAY, object_id=ITEM),
                audit("FileAccessed", START, object_id=ITEM),
                audit("FileModified", START + DAY * 2, object_id=ITEM),
            ],
            "flagged": [1],
        },
        # A sync client's activity rows are not a retention-bounded audit log.
        "negative": {
            "rows": [
                audit("FileAccessed", START, "cloud-activity", object_id=ITEM, service="onedrive-sync"),
                audit("FileModified", START + DAY, "cloud-activity", object_id=ITEM, service="onedrive-sync"),
            ],
            "flagged": [],
        },
    },
    "cloud.bulk_upload": {
        # 50 files uploaded by one account within 25 minutes.
        "positive": {"rows": [sync_upload(index, START + dt.timedelta(seconds=30 * index)) for index in range(50)], "flagged": list(range(50))},
        # The same 50 files trickled over a working day (one every 15 minutes), plus 60 log keyword
        # hits inside one minute that the parser marked ineligible (no item path).
        "negative": {
            "rows": [sync_upload(index, START + dt.timedelta(minutes=15 * index)) for index in range(50)]
            + [sync_upload(index, START + dt.timedelta(seconds=index), eligible=False) for index in range(60)],
            "flagged": [],
        },
    },
    "cloud.sync_folder_outside_user_profile": {
        # A removable/second drive and the shared Public profile.
        "positive": {"rows": [sync_account(r"E:\OneDrive"), sync_account(r"C:\Users\Public\Dropbox")], "flagged": [0, 1]},
        # Default and business locations under the user's own profile (and a volume-relative root).
        "negative": {
            "rows": [
                sync_account(r"C:\Users\alice\OneDrive - Contoso", r"C:\Users\alice\OneDrive"),
                sync_account("\\Users\\alice\\iCloudDrive"),
            ],
            "flagged": [],
        },
    },
}
