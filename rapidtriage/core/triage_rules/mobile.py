"""Mobile export indicators: iOS backup / Android (catalogue: apps §8)."""

from __future__ import annotations

import datetime as dt
import math
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterator

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    evidence,
    register,
    select,
    window_groups,
)
from .cloud import distance_km

CALLS_MESSAGES = select(types={"mobile-call", "mobile-message"})
DELETED_STATES = frozenset({"deleted", "recovered", "freelist", "free-page", "journal", "wal", "unallocated", "carved"})


def phone_key(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if digits.startswith("82") and len(digits) > 9:
        digits = "0" + digits[2:]
    return digits[-10:] if len(digits) >= 7 else ""


def counterpart(row: RowView) -> str:
    return row.text("phone_number", "recipient", "sender", "counterpart", "address")


@register("mobile.backup_encrypted_partial")
class BackupUnencrypted(Rule):
    """Unencrypted iOS backup: Health/Keychain/Safari data are absent by design (collection limit, not absence of evidence)."""

    selector = select(types={"ios-backup-source", "ios-backup-metadata", "ios-backup"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        value = row.get("is_encrypted", "encrypted", "backup_encrypted", "encrypted_backup_hint")
        if as_bool(value) is not False:
            return None
        return RuleResult(evidence(backup=row.text("device_name", "source_path"), encrypted=False), note="비암호화 백업은 건강·키체인·Safari 일부를 담지 않음")


@register("mobile.deleted_calls_sms")
class DeletedCallsSms(Rule):
    """Call/SMS row recovered from free pages/journal or marked deleted."""

    selector = CALLS_MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        state = row.text("deleted_state", "recovery_source", "record_state", "deletion_state").lower()
        if state not in DELETED_STATES and "deleted" not in state and as_bool(row.get("deleted", "is_deleted")) is not True:
            return None
        return RuleResult(evidence(state=state or "deleted", counterpart=counterpart(row), timestamp=row.text("timestamp")))


@register("mobile.call_to_unsaved_number")
class CallToUnsavedNumber(Rule):
    """A number called/texted ≥ ``min_calls`` times that is not in the contacts."""

    selector = select(types={"mobile-call", "mobile-message", "mobile-contact"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.contacts: set[str] = set()
        self.calls: dict[str, list[RowRef]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        key = phone_key(counterpart(row))
        if not key:
            return None
        if row.type == "mobile-contact":
            self.contacts.add(key)
        else:
            self.calls[key].append(row.ref)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if not self.contacts:
            return  # no contact list collected: cannot tell saved from unsaved
        minimum = int(self.param("min_calls", 5))
        for number, refs in self.calls.items():
            if number not in self.contacts and len(refs) >= minimum:
                for ref in refs:
                    yield ref, RuleResult(evidence(number_suffix=number[-4:], occurrences=len(refs)))


@register("mobile.call_burst_event")
class CallBurst(Rule):
    """≥ ``min_count`` calls/messages within ``window_minutes`` (inside the incident window when one is set)."""

    selector = CALLS_MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.items: list[tuple[dt.datetime, RowRef]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = row.time("timestamp")
        if moment is not None and (not ctx.has_incident_window or ctx.in_incident(moment)):
            self.items.append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 30)))
        for group in window_groups(self.items, window, int(self.param("min_count", 20))):
            for _moment, ref in group:
                yield ref, RuleResult(evidence(burst_count=len(group), burst_start=group[0][0], burst_end=group[-1][0]))


@register("mobile.app_installed_recent")
class AppInstalledRecent(Rule):
    """Messenger/VPN/cleaner app (``app_keywords``) installed; restricted to the incident window when one is set."""

    selector = select(types={"mobile-app", "android-app-data", "android-apk"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        name = f"{row.text('app_name', 'name')} {row.text('package', 'bundle_id', 'package_name')}".lower()
        # A keyword must end a word ("nordvpn", "org.telegram.x" match; "wireless" does not match "wire").
        keyword = next(
            (str(item) for item in self.param("app_keywords", []) if str(item) and re.search(rf"{re.escape(str(item).lower())}(?![a-z])", name)),
            "",
        )
        if not keyword:
            return None
        installed = row.time("installed_at", "first_install_time", "timestamp")
        if ctx.has_incident_window and not ctx.in_incident(installed):
            return None
        return RuleResult(evidence(app=name.strip(), keyword=keyword, installed_at=installed))


@register("mobile.location_outlier")
class LocationOutlier(Rule):
    """Location more than ``radius_km`` from the median position of ≥ ``min_points`` points."""

    selector = select(types={"mobile-location", "cloud-location"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.points: list[tuple[float, float, RowRef]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        lat, lon = row.number("latitude"), row.number("longitude")
        if lat is not None and lon is not None and not (lat == 0 and lon == 0) and math.isfinite(lat) and math.isfinite(lon):
            self.points.append((lat, lon, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if len(self.points) < int(self.param("min_points", 20)):
            return
        center = (statistics.median(point[0] for point in self.points), statistics.median(point[1] for point in self.points))
        radius = float(self.param("radius_km", 50))
        for lat, lon, ref in self.points:
            distance = distance_km(center, (lat, lon))
            if distance > radius:
                yield ref, RuleResult(evidence(latitude=lat, longitude=lon, distance_from_median_km=round(distance, 1)))


@register("mobile.time_epoch_mismatch")
class TimeEpochMismatch(Rule):
    """Raw timestamp whose digit count differs from the majority of its database (seconds vs nanoseconds mixed)."""

    selector = select(kinds={"mobile-export"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.digits: dict[str, list[tuple[int, RowRef, str]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        raw = row.text("timestamp_raw", "raw_timestamp")
        if not raw:
            value = row.raw("date", "timestamp", "time")
            raw = str(value) if value is not None else ""
        text = raw.strip().split(".")[0]
        if text.isdigit() and len(text) >= 9:
            self.digits[row.text("source_path") or row.path()].append((len(text), row.ref, raw))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        for source, items in self.digits.items():
            majority, _count = Counter(length for length, _ref, _raw in items).most_common(1)[0]
            for length, ref, raw in items:
                if abs(length - majority) >= 3:
                    yield ref, RuleResult(evidence(raw_timestamp=raw, digits=length, majority_digits=majority, source=source))


@register("mobile.factory_reset_gap")
class FactoryResetGap(Rule):
    """Data of one export only after a gap longer than ``gap_days`` (reset/migration point)."""

    selector = select(kinds={"mobile-export"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.times: list[tuple[dt.datetime, RowRef]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = row.time("timestamp")
        if moment is not None:
            self.times.append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        gap = dt.timedelta(days=float(self.param("gap_days", 180)))
        self.times.sort(key=lambda item: item[0])
        for (previous, _), (moment, ref) in zip(self.times, self.times[1:]):
            if moment - previous > gap:
                yield ref, RuleResult(evidence(previous_record_at=previous, record_at=moment, gap_days=(moment - previous).days))
