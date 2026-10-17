"""Cloud export / sync-client indicators: Google / iCloud / Microsoft 365 exports and desktop sync clients (catalogue: apps §4, R2 M4)."""

from __future__ import annotations

import datetime as dt
import math
import re
from collections import defaultdict
from collections.abc import Iterator, Mapping

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_list,
    as_number,
    email_domain,
    evidence,
    org_domain,
    parse_time,
    register,
    select,
    window_groups,
)

ACTIVITY = select(types={"cloud-audit", "cloud-activity", "cloud-iaas-audit", "cloud-file"})
PHOTOS = select(types={"cloud-file", "cloud-location", "cloud-photo", "cloud-media"})
DOWNLOAD_OPERATIONS = ("filedownloaded", "filesyncdownloadedfull", "filesyncdownloadedpartial", "download")
SHARE_OPERATIONS = ("anonymouslinkcreated", "sharinginvitationcreated", "sharingset", "addedtosecurelink", "companylinkcreated", "share")
DELETE_OPERATIONS = ("filedeleted", "filerecycled", "filedeletedfirststagerecyclebin", "delete", "trash")
LOGIN_OPERATIONS = ("userloggedin", "login", "signin", "sign-in")
# M365 audit FileUploaded / FileSyncUploaded* and sync-client ``upload`` events (R2 M4).
UPLOAD_OPERATIONS = ("fileuploaded", "filesyncuploadedfull", "filesyncuploadedpartial", "upload")
UPLOADS = select(types={"cloud-sync-event", "cloud-audit", "cloud-activity"})
# A user profile folder: X:\Users\<name> (not Public / Default / All Users) or the legacy
# X:\Documents and Settings\<name>; macOS /Users/<name>, Linux /home/<name>. Input is
# casefolded with "/" turned into "\" for drive-letter paths.
_WINDOWS_PROFILE = re.compile(
    r"^[a-z]:\\(?:users|documents and settings)\\(?!(?:public|default|default user|all users)(?:\\|$))[^\\]+(?:\\|$)"
)
_POSIX_PROFILE = re.compile(r"^/(?:users/(?!shared(?:/|$))[^/]+|home/[^/]+)(?:/|$)")


def operation(row: RowView) -> str:
    return row.text("operation", "activity", "action", "event_name", "event_type").lower().replace(" ", "")


def actor(row: RowView) -> str:
    return row.text("actor", "account", "user", "user_id", "account_email").lower()


def item_key(row: RowView) -> str:
    return row.text("object_id", "item_path", "file_path", "file_name", "file_id").lower()


def _matches(op: str, names: tuple[str, ...]) -> bool:
    return any(name in op for name in names)


def _coordinates(value: object) -> tuple[float, float] | None:
    if not isinstance(value, Mapping):
        return None
    lat = as_number(value.get("latitude"))
    lon = as_number(value.get("longitude"))
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None
    return lat, lon


def distance_km(left: tuple[float, float], right: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*left, *right))
    hav = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(hav)))


def takeout_time(row: RowView, name: str) -> dt.datetime | None:
    value = row.raw(f"{name}.timestamp", name)
    return parse_time(int(value)) if isinstance(value, str) and value.isdigit() else parse_time(value)


@register("cloud.bulk_download")
class BulkDownload(Rule):
    """≥ ``min_count`` download/sync-download operations by one account within ``window_minutes``."""

    selector = ACTIVITY

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.items: dict[str, list[tuple[dt.datetime, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if _matches(operation(row), DOWNLOAD_OPERATIONS):
            moment = row.time("timestamp", "event_time")
            if moment is not None:
                self.items[actor(row)].append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 10)))
        for account, items in self.items.items():
            for group in window_groups(items, window, int(self.param("min_count", 100))):
                for _moment, ref in group:
                    yield ref, RuleResult(evidence(account=account, burst_count=len(group), burst_start=group[0][0], burst_end=group[-1][0]))


def _internal_share(row: RowView, op: str, shared: str) -> bool:
    """Organisation-only sharing: an org-wide (company) link, an M365 ``Member`` target, or a target in the actor's own domain."""
    if "companylink" in op:
        return True
    target = shared or str(row.raw("TargetUserOrGroupName") or "").lower()
    if "#ext#" in target:
        return False
    if str(row.raw("TargetUserOrGroupType") or "").strip().lower() == "member":
        return True
    target_domain, actor_domain = email_domain(target), email_domain(actor(row))
    return bool(target_domain and actor_domain and org_domain(target_domain) == org_domain(actor_domain))


@register("cloud.external_share")
class ExternalShare(Rule):
    """Anonymous / external sharing link or invitation created."""

    selector = ACTIVITY

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        op = operation(row)
        shared = row.text("shared_with", "target_user", "recipient").lower()
        anyone = "anyone" in shared or "anonymous" in op
        if not _matches(op, SHARE_OPERATIONS) and not anyone and not row.number("sharing_link_count"):
            return None
        if not anyone and _internal_share(row, op, shared):
            return None
        return RuleResult(evidence(operation=op, item=item_key(row), shared_with=shared, account=actor(row)))


@register("cloud.new_device_login")
class NewDeviceLogin(Rule):
    """Sign-in from an IP/device first seen after the account's first ``baseline_logins`` sign-ins."""

    selector = ACTIVITY

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.logins: dict[str, list[tuple[dt.datetime, RowRef, str]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not _matches(operation(row), LOGIN_OPERATIONS):
            return None
        moment = row.time("timestamp", "event_time")
        origin = row.text("ip_address", "client_ip", "device", "user_agent")
        if moment is not None and origin:
            self.logins[actor(row)].append((moment, row.ref, origin))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        baseline = int(self.param("baseline_logins", 5))
        for account, items in self.logins.items():
            items.sort(key=lambda item: item[0])
            known = {origin for _moment, _ref, origin in items[:baseline]}
            for moment, ref, origin in items[baseline:]:
                if origin not in known:
                    known.add(origin)
                    yield ref, RuleResult(evidence(account=account, origin=origin, first_seen=moment))


@register("cloud.delete_after_share")
class DeleteAfterShare(Rule):
    """Delete of an item within ``window_minutes`` after it was shared or downloaded."""

    selector = ACTIVITY

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.touched: dict[str, list[dt.datetime]] = defaultdict(list)
        self.deletes: list[tuple[dt.datetime, RowRef, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        op, item, moment = operation(row), item_key(row), row.time("timestamp", "event_time")
        if not item or moment is None:
            return None
        if _matches(op, SHARE_OPERATIONS) or _matches(op, DOWNLOAD_OPERATIONS):
            self.touched[item].append(moment)
        elif _matches(op, DELETE_OPERATIONS):
            self.deletes.append((moment, row.ref, item))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 60)))
        for moment, ref, item in self.deletes:
            before = [at for at in self.touched.get(item, ()) if moment - window <= at <= moment]
            if before:
                yield ref, RuleResult(evidence(item=item, shared_or_downloaded_at=max(before), deleted_at=moment))


@register("cloud.taken_vs_creation_gap")
class TakenVsCreation(Rule):
    """Takeout photoTakenTime and creationTime more than ``max_gap_days`` apart (old photo uploaded later)."""

    selector = PHOTOS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        taken = takeout_time(row, "photoTakenTime") or row.time("photo_taken_time", "taken_time")
        created = takeout_time(row, "creationTime") or row.time("creation_time")
        if taken is None or created is None:
            return None
        gap = abs((created - taken).days)
        if gap <= int(self.param("max_gap_days", 30)):
            return None
        return RuleResult(evidence(photo_taken=taken, creation=created, gap_days=gap))


@register("cloud.json_exif_gps_mismatch")
class JsonExifGpsMismatch(Rule):
    """Takeout geoData and geoDataExif more than ``max_distance_km`` apart (location edited)."""

    selector = PHOTOS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        json_point = _coordinates(row.raw("geoData") or row.get("geo_data"))
        exif_point = _coordinates(row.raw("geoDataExif") or row.get("geo_data_exif"))
        if json_point is None or exif_point is None:
            return None
        distance = distance_km(json_point, exif_point)
        if distance <= float(self.param("max_distance_km", 1.0)):
            return None
        return RuleResult(evidence(geo_data=list(json_point), geo_data_exif=list(exif_point), distance_km=round(distance, 2)))


@register("cloud.audit_retention_gap")
class AuditRetentionGap(Rule):
    """Earliest audit record per service: activity older than the retention period (``retention_days``) cannot appear."""

    selector = select(types={"cloud-audit", "cloud-iaas-audit"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.earliest: dict[str, tuple[dt.datetime, RowRef]] = {}

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = row.time("timestamp", "event_time")
        service = row.text("service") or row.type
        if moment is not None and (service not in self.earliest or moment < self.earliest[service][0]):
            self.earliest[service] = (moment, row.ref)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        days = int(self.param("retention_days", 180))
        for service, (moment, ref) in self.earliest.items():
            yield ref, RuleResult(
                evidence(service=service, earliest_record=moment, retention_days=days),
                note=f"이 시각 이전 활동은 감사 보존기간(기본 {days}일) 밖일 수 있음: 부재 ≠ 미발생",
            )


@register("cloud.bulk_upload")
class BulkUpload(Rule):
    """One account's uploads within ``window_minutes``: ≥ ``min_count`` items or ≥ ``min_bytes`` bytes.

    Sync-client rows the parser marks ``bulk_rule_eligible = false`` (log keyword hits without an
    item path, folders) are not counted; the same item uploaded again within one second counts once
    (a client log restating one transfer).
    """

    selector = UPLOADS

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.items: dict[tuple[str, str], list[tuple[dt.datetime, RowRef, float, str]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not _matches(operation(row), UPLOAD_OPERATIONS) or row.flag("bulk_rule_eligible") is False:
            return None
        moment = row.time("timestamp", "event_time")
        if moment is None:
            return None
        size = max(row.number("size", "size_bytes") or 0.0, 0.0)
        item = item_key(row) or f"{row.ref[0]}#{row.ref[1]}"
        self.items[(row.text("client", "service").lower(), actor(row))].append((moment, row.ref, size, item))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 60)))
        min_count = int(self.param("min_count", 50))
        min_bytes = float(self.param("min_bytes", 500_000_000))
        for (client, account), raw in self.items.items():
            seen: set[tuple[str, dt.datetime]] = set()
            items: list[tuple[dt.datetime, RowRef, float, str]] = []
            for entry in sorted(raw, key=lambda item: (item[0], item[1])):
                key = (entry[3], entry[0].replace(microsecond=0))
                if key not in seen:
                    seen.add(key)
                    items.append(entry)
            left, total, flagged_upto = 0, 0.0, -1
            for right, (moment, _ref, size, _item) in enumerate(items):
                total += size
                while moment - items[left][0] > window:
                    total -= items[left][2]
                    left += 1
                count = right - left + 1
                if count < min_count and total < min_bytes:
                    continue
                result = RuleResult(
                    evidence(
                        client=client,
                        account=account,
                        upload_count=count,
                        upload_bytes=int(total),
                        window_start=items[left][0],
                        window_end=moment,
                    )
                )
                for index in range(max(left, flagged_upto + 1), right + 1):
                    yield items[index][1], result
                flagged_upto = right


def within_user_profile(path: str) -> bool | None:
    """``True`` under a user profile folder, ``False`` outside, ``None`` when ``path`` is not absolute."""
    text = path.strip().strip('"')
    text = text.removeprefix("\\\\?\\")
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return bool(_WINDOWS_PROFILE.match(text.lower().replace("/", "\\")))
    if text.startswith("\\\\"):
        return False  # UNC share
    if text.startswith("\\"):
        # Volume-relative (a sync root found by path signature in an evidence copy).
        return bool(_WINDOWS_PROFILE.match("c:" + text.lower()))
    if text.startswith("/"):
        return bool(_POSIX_PROFILE.match(text.lower()))
    return None


@register("cloud.sync_folder_outside_user_profile")
class SyncFolderOutsideProfile(Rule):
    """A sync client's sync root outside every user profile folder (other drive, removable disk, Public)."""

    selector = select(types={"cloud-sync-account"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        roots = [item for item in as_list(row.get("sync_roots")) if isinstance(item, str)] or [row.text("sync_root")]
        outside = [root for root in roots if root and within_user_profile(root) is False]
        if not outside:
            return None
        return RuleResult(evidence(client=row.text("client"), account=actor(row), sync_root=outside[0], other_roots=outside[1:]))
