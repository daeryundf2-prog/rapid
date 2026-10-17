"""Messenger indicators: KakaoTalk / Telegram / WhatsApp / Slack / Teams / SMS (catalogue: apps §1)."""

from __future__ import annotations

import datetime as dt
import re
import statistics
from collections import defaultdict
from collections.abc import Iterator

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    base_name,
    evidence,
    host_matches,
    hour_of,
    register,
    select,
    url_host,
    window_groups,
)

MESSAGES = select(types={"mobile-message", "cloud-message", "kakaotalk-message", "messenger-message", "chat-message"})
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DELETED_STATES = frozenset({"deleted", "recovered", "wal", "freelist", "free-page", "freepage", "journal", "unallocated", "carved"})
OUTGOING = frozenset({"out", "outgoing", "sent", "send", "from_me", "1", "true", "발신"})


def message_time(row: RowView) -> dt.datetime | None:
    return row.time("timestamp", "msg_time", "sent_at", "message_time", "date")


def conversation(row: RowView) -> str:
    return f"{row.text('source_path') or row.path()}|{row.text('conversation_id', 'chat_id', 'thread_id', 'chat_room', 'room_id')}"


def numeric_id(row: RowView) -> int | None:
    value = row.number("message_id", "msg_id", "log_id", "row_id", "id")
    return int(value) if value is not None else None


def is_outgoing(row: RowView) -> bool:
    flag = as_bool(row.get("from_me", "is_from_me", "key_from_me", "out"))
    if flag is not None:
        return flag
    return row.text("direction").lower() in OUTGOING


@register("messenger.time_regression")
class TimeRegression(Rule):
    """In one conversation a later message id carries an earlier time than its predecessor (beyond ``tolerance_seconds``)."""

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.rows: dict[str, list[tuple[int, dt.datetime, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        number, moment = numeric_id(row), message_time(row)
        if number is not None and moment is not None:
            self.rows[conversation(row)].append((number, moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        tolerance = dt.timedelta(seconds=float(self.param("tolerance_seconds", 60)))
        for items in self.rows.values():
            items.sort(key=lambda item: item[0])
            for (prev_id, prev_time, _), (number, moment, ref) in zip(items, items[1:]):
                if moment < prev_time - tolerance:
                    yield ref, RuleResult(evidence(message_id=number, time=moment, previous_id=prev_id, previous_time=prev_time))


@register("messenger.server_client_skew")
class ServerClientSkew(Rule):
    """Server time and device time of one message differ by more than ``max_skew_minutes``."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        server = row.time("server_timestamp", "receipt_server_timestamp", "server_time", "received_timestamp")
        client = message_time(row)
        if server is None or client is None:
            return None
        skew = abs((server - client).total_seconds())
        if skew <= float(self.param("max_skew_minutes", 5)) * 60:
            return None
        return RuleResult(evidence(client_time=client, server_time=server, skew_seconds=int(skew)))


@register("messenger.id_gap")
class IdGap(Rule):
    """Missing message ids inside a conversation whose ids are otherwise consecutive (median step 1)."""

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.ids: dict[str, list[tuple[int, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        number = numeric_id(row)
        if number is not None:
            self.ids[conversation(row)].append((number, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        min_missing = int(self.param("min_missing", 1))
        for items in self.ids.values():
            items.sort()
            steps = [current - previous for (previous, _), (current, _) in zip(items, items[1:])]
            if len(steps) < 3 or statistics.median(steps) != 1:
                continue  # globally increasing ids: gaps carry no meaning
            for (previous, _), (current, ref) in zip(items, items[1:]):
                if current - previous - 1 >= min_missing:
                    yield ref, RuleResult(evidence(previous_id=previous, message_id=current, missing=current - previous - 1))


@register("messenger.deleted_recovered")
class DeletedRecovered(Rule):
    """Message recovered from WAL / free pages / journal only, or marked deleted."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        state = row.text("deleted_state", "recovery_source", "record_state", "source_state", "deletion_state").lower()
        wal = as_bool(row.get("wal_origin", "is_deleted", "deleted")) is True
        if state not in DELETED_STATES and not any(item in state for item in ("deleted", "wal", "free")) and not wal:
            return None
        return RuleResult(evidence(state=state or "wal/deleted", message_id=row.text("message_id"), time=message_time(row)))


@register("messenger.disappearing_on")
class DisappearingOn(Rule):
    """Disappearing/ephemeral-message setting present (limits what can be preserved)."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        value = row.get("disappearing", "ephemeral_duration", "expire_timer", "expires_in", "ttl", "disappearing_timer")
        if value is None:
            value = row.raw("ephemeral_duration", "expiretimer", "expire_timer", "disappearing")
        number = None
        try:
            number = float(str(value)) if value is not None else None
        except ValueError:
            number = None
        if not (as_bool(value) is True or (number is not None and number > 0)):
            return None
        return RuleResult(evidence(setting=value, conversation=row.text("conversation_id", "conversation_title")))


@register("messenger.external_share_link")
class ExternalShareLink(Rule):
    """Message body with a file-sharing or URL-shortener link."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        text = row.text("message_text", "message_text_preview", "body", "text", "message")
        domains = list(self.param("share_domains", [])) + list(self.param("shortener_domains", []))
        for url in _URL.findall(text):
            matched = host_matches(url_host(url), domains)
            if matched:
                return RuleResult(evidence(url=url, domain=matched, time=message_time(row)))
        return None


@register("messenger.late_night_burst")
class LateNightBurst(Rule):
    """≥ ``min_count`` outgoing messages within ``window_minutes`` during local night hours."""

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.night: dict[str, list[tuple[dt.datetime, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = message_time(row)
        if moment is None or not is_outgoing(row):
            return None
        start, end = int(self.param("night_start_hour", 0)), int(self.param("night_end_hour", 5))
        hour = hour_of(moment, float(self.param("tz_offset_hours", 9)))
        if start <= hour < end:
            self.night[row.text("source_path") or row.path()].append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 30)))
        for items in self.night.values():
            for group in window_groups(items, window, int(self.param("min_count", 10))):
                for _moment, ref in group:
                    yield ref, RuleResult(evidence(burst_count=len(group), burst_start=group[0][0], burst_end=group[-1][0]))


@register("messenger.attachment_missing")
class AttachmentMissing(Rule):
    """Attachment metadata present but no file of that name in the run's file listing."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not ctx.file_paths_known:
            return None
        name = base_name(row.text("attachment_name", "attachment", "media_reference", "attachment_path"))
        if not name or name in ctx.file_names:
            return None
        return RuleResult(evidence(attachment=name, time=message_time(row)), note="미다운로드(썸네일만)일 수 있음")


@register("messenger.app_reinstall_gap")
class AppReinstallGap(Rule):
    """A gap longer than ``gap_days`` between consecutive messages of one database (reinstall/wipe/restore)."""

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.times: dict[str, list[tuple[dt.datetime, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = message_time(row)
        if moment is not None:
            self.times[row.text("source_path") or row.path()].append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        gap = dt.timedelta(days=float(self.param("gap_days", 90)))
        for items in self.times.values():
            items.sort(key=lambda item: item[0])
            for (previous, _), (moment, ref) in zip(items, items[1:]):
                if moment - previous > gap:
                    yield ref, RuleResult(evidence(previous_message_at=previous, message_at=moment, gap_days=(moment - previous).days))
