"""Web browser indicators: Chrome / Edge / Firefox (catalogue: apps §3)."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterator

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    as_list,
    as_number,
    evidence,
    extension,
    host_matches,
    register,
    select,
    url_host,
)

DOWNLOAD = select(types={"browser-download"})
EXTENSION = select(types={"browser-extension"})
HISTORY = select(types={"browser-history", "browser-visit"})
# Chromium ``download::DownloadDangerType`` (History ``downloads.danger_type``) -> name.
CHROMIUM_DANGER_NAMES = {
    0: "NOT_DANGEROUS",
    1: "DANGEROUS_FILE",
    2: "DANGEROUS_URL",
    3: "DANGEROUS_CONTENT",
    4: "MAYBE_DANGEROUS_CONTENT",
    5: "UNCOMMON_CONTENT",
    6: "USER_VALIDATED",
    7: "DANGEROUS_HOST",
    8: "POTENTIALLY_UNWANTED",
    9: "ALLOWLISTED_BY_POLICY",
    10: "ASYNC_SCANNING",
    11: "BLOCKED_PASSWORD_PROTECTED",
    12: "BLOCKED_TOO_LARGE",
    13: "SENSITIVE_CONTENT_WARNING",
    14: "SENSITIVE_CONTENT_BLOCK",
    15: "DEEP_SCANNED_SAFE",
    16: "DEEP_SCANNED_OPENED_DANGEROUS",
    17: "PROMPT_FOR_SCANNING",
    18: "BLOCKED_UNSUPPORTED_FILETYPE",
    19: "DANGEROUS_ACCOUNT_COMPROMISE",
}
STRONG_DANGER = (
    "DANGEROUS_FILE",
    "DANGEROUS_URL",
    "DANGEROUS_CONTENT",
    "USER_VALIDATED",
    "DANGEROUS_HOST",
    "POTENTIALLY_UNWANTED",
    "DEEP_SCANNED_OPENED_DANGEROUS",
    "DANGEROUS_ACCOUNT_COMPROMISE",
)
WEAK_DANGER = ("MAYBE_DANGEROUS_CONTENT", "UNCOMMON_CONTENT")
EXEC_EXTENSIONS = ("exe", "msi", "scr", "com", "pif", "cpl", "dll", "js", "jse", "vbs", "vbe", "wsf", "ps1", "bat", "cmd", "hta", "jar", "lnk", "iso", "img", "vhd", "vhdx", "apk")


def danger_name(row: RowView) -> str:
    """Upper-case Chromium danger name from ``danger_type_name`` or the numeric/text ``danger_type``."""
    for key in ("danger_type_name", "danger_type"):
        text = row.text(key)
        if not text:
            continue
        number = as_number(text)
        if number is not None and float(number).is_integer():
            return CHROMIUM_DANGER_NAMES.get(int(number), f"UNKNOWN_{int(number)}")
        return text.upper().replace(" ", "_").removeprefix("DANGER_TYPE_")
    return ""


BROAD_HOSTS = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})


def profile_key(row: RowView) -> str:
    return f"{row.text('browser')}|{row.text('profile')}|{row.text('source_path') or row.path()}"


def download_urls(row: RowView) -> list[str]:
    return [row.text(key) for key in ("source_url", "url", "tab_url", "referrer", "tab_referrer_url", "site_url") if row.text(key)]


def sensitive_term(text: str, keywords: list[object]) -> str:
    lowered = text.casefold()
    return next((str(word) for word in keywords if str(word).casefold() in lowered), "")


@register("browser.dl_from_filesharing")
class DownloadFromFileSharing(Rule):
    """Download whose URL, tab URL or referrer is a file-sharing / one-time transfer domain."""

    selector = DOWNLOAD

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        domains = list(self.param("share_domains", []))
        for url in download_urls(row):
            matched = host_matches(url_host(url), domains)
            if matched:
                return RuleResult(evidence(url=url, domain=matched, target_path=row.text("target_path", "current_path")))
        return None


@register("browser.dl_dangerous")
class DownloadDangerous(Rule):
    """Download with a strong ``danger_type`` verdict, or a weak one (``MAYBE_DANGEROUS_CONTENT``/``UNCOMMON_CONTENT``) on an executable/script target."""

    selector = DOWNLOAD

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        name = danger_name(row)
        if not name:
            return None
        strong = {str(item).upper() for item in self.param("strong_types", STRONG_DANGER)}
        weak = {str(item).upper() for item in self.param("weak_types", WEAK_DANGER)}
        target = row.text("target_path", "current_path")
        if name in weak:
            executables = {str(item).lower().lstrip(".") for item in self.param("exec_extensions", EXEC_EXTENSIONS)}
            if extension(target) not in executables:
                return None
        elif name not in strong:
            return None
        return RuleResult(evidence(danger_type=name, url=row.text("source_url", "url"), target_path=target))


@register("browser.dl_missing_file")
class DownloadMissingFile(Rule):
    """Download target absent from the file listing although its folder was listed (deleted/moved)."""

    selector = DOWNLOAD

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        target = row.text("target_path", "current_path")
        if not target or ctx.file_missing(target) is not True:
            return None
        return RuleResult(evidence(target_path=target, url=row.text("source_url", "url")))


@register("browser.incognito_gap")
class IncognitoGap(Rule):
    """≥ ``min_gap_days`` consecutive active days (event/Prefetch activity) without any browsing inside a profile's history span."""

    selector = HISTORY

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.visits: dict[str, dict[dt.date, RowRef]] = defaultdict(dict)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = row.time("timestamp", "visit_time")
        if moment is not None:
            self.visits[profile_key(row)].setdefault(moment.date(), row.ref)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        activity = ctx.shared.get("activity_days") or {}
        min_activity = int(self.param("min_activity_events", 50))
        min_gap = int(self.param("min_gap_days", 3))
        for days in self.visits.values():
            ordered = sorted(days)
            for previous, current in zip(ordered, ordered[1:]):
                gap = [previous + dt.timedelta(days=offset) for offset in range(1, (current - previous).days)]
                active = [day for day in gap if int(activity.get(day.isoformat(), 0)) >= min_activity]
                if len(gap) >= min_gap and len(active) >= min_gap:
                    yield days[current], RuleResult(
                        evidence(gap_start=gap[0].isoformat(), gap_end=gap[-1].isoformat(), active_days=len(active)),
                        note="다른 활동은 있는데 방문 기록이 비어 있는 기간 직후 첫 방문",
                    )


@register("browser.history_cleared")
class HistoryCleared(Rule):
    """The lowest surviving history row id of a profile is above ``min_first_id`` (older rows removed)."""

    selector = HISTORY

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.lowest: dict[str, tuple[int, RowRef]] = {}

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        value = row.number("url_id", "source_row_id", "id")
        if value is None:
            return None
        key = profile_key(row)
        if key not in self.lowest or value < self.lowest[key][0]:
            self.lowest[key] = (int(value), row.ref)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        threshold = int(self.param("min_first_id", 1000))
        for key, (lowest, ref) in self.lowest.items():
            if lowest > threshold:
                yield ref, RuleResult(evidence(profile=key.split("|", 2)[1], lowest_row_id=lowest), note="보관기간 자동 만료도 같은 모양")


@register("browser.ext_broad_perm")
class ExtensionBroadPermissions(Rule):
    """Extension with ``<all_urls>``-style host access together with ``webRequest``."""

    selector = EXTENSION

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        permissions = {str(item) for item in as_list(row.get("permissions")) + as_list(row.get("host_permissions")) + as_list(row.get("active_api_permissions"))}
        hosts = sorted(permissions & BROAD_HOSTS)
        if not hosts or not any(item.startswith("webRequest") for item in permissions):
            return None
        return RuleResult(evidence(name=row.text("name"), extension_id=row.text("extension_id"), host_permissions=hosts))


@register("browser.ext_sideloaded")
class ExtensionSideloaded(Rule):
    """Extension not installed from the web store and not a browser default/component."""

    selector = EXTENSION

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if as_bool(row.get("from_webstore")) is not False or as_bool(row.get("was_installed_by_default")) is True:
            return None
        location = row.text("location_name", "location").lower()
        if location in {"component", "external_component", "5", "10"}:
            return None
        return RuleResult(evidence(name=row.text("name"), extension_id=row.text("extension_id"), location=location))


@register("browser.search_sensitive")
class SearchSensitive(Rule):
    """Search term containing an incident keyword (``keywords``: wiping, evidence destruction, overseas transfer …)."""

    selector = select(types={"browser-search"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        term = row.text("term", "normalized_term")
        matched = sensitive_term(term, list(self.param("keywords", [])))
        return RuleResult(evidence(term=term, keyword=matched, timestamp=row.text("timestamp"))) if matched else None


@register("browser.cred_first_use_new_site")
class CredentialNewSite(Rule):
    """Saved login created inside the incident window (needs ``incident_start``/``incident_end``)."""

    selector = select(types={"browser-login"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = row.time("date_created", "timestamp")
        if not ctx.in_incident(moment):
            return None
        return RuleResult(evidence(site=row.text("origin", "action_url", "signon_realm"), date_created=moment))


@register("browser.typed_url_direct")
class TypedUrlDirect(Rule):
    """URL typed into the address bar that is a file-sharing site or contains an incident keyword."""

    selector = select(types={"browser-visit"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        transition = row.get("transition_core", "transition")
        text = str(transition or "").lower()
        typed = text in {"typed", "1"} or (text.isdigit() and int(text) & 0xFF == 1)
        if not typed:
            return None
        url = row.text("url")
        domain = host_matches(url_host(url), list(self.param("share_domains", [])))
        keyword = sensitive_term(url, list(self.param("keywords", [])))
        if not domain and not keyword:
            return None
        return RuleResult(evidence(url=url, domain=domain, keyword=keyword, timestamp=row.text("timestamp", "visit_time")))


UPLOAD = select(types={"web-upload-candidate"})
UPLOAD_STRENGTHS = ("weak", "medium", "strong")


def upload_strength_ok(row: RowView, minimum: object) -> bool:
    """The candidate's ``strength`` (weak < medium < strong) is at least ``minimum``."""
    strength = row.text("strength").lower()
    floor = str(minimum or "medium").lower()
    if strength not in UPLOAD_STRENGTHS or floor not in UPLOAD_STRENGTHS:
        return False
    return UPLOAD_STRENGTHS.index(strength) >= UPLOAD_STRENGTHS.index(floor)


def upload_evidence(row: RowView) -> dict[str, object]:
    return evidence(
        url=row.text("url"),
        service=row.text("service"),
        strength=row.text("strength"),
        method=row.text("method"),
        file_name_candidate=row.text("file_name_candidate"),
        source_artifact_type=row.text("source_artifact_type"),
        timestamp=row.text("timestamp"),
    )


@register("browser.webmail_upload")
class WebmailUpload(Rule):
    """Webmail attachment-upload candidate (Naver/Daum/Gmail/Outlook web) at or above ``min_strength``."""

    selector = UPLOAD

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.text("category") != "webmail" or not upload_strength_ok(row, self.param("min_strength", "medium")):
            return None
        return RuleResult(upload_evidence(row))


@register("browser.filesharing_upload")
class FileSharingUpload(Rule):
    """Upload candidate to a file-sharing / web-hard / personal cloud service at or above ``min_strength``."""

    selector = UPLOAD

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        categories = {str(item) for item in self.param("categories", ["filesharing", "cloud"])}
        if row.text("category") not in categories or not upload_strength_ok(row, self.param("min_strength", "medium")):
            return None
        return RuleResult(upload_evidence(row))
