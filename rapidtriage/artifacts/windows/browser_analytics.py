"""Google Analytics cookies -> visit history (R5 L3; 재감사 §3 item 28, plan r5 §2 decision).

Only the allow-listed cookie names ``__utma``, ``__utmz`` and ``_ga`` are read, and only these
fields of their values go into a row (the R5 decision: GA cookies are not credentials, but the
client ID is never stored):

* ``__utma`` = ``<domain hash>.<visitor id>.<first>.<previous>.<current>.<sessions>`` ->
  first / previous / current visit times (Unix seconds) and the session count;
* ``__utmz`` = ``<domain hash>.<time>.<session>.<campaign>.utmcsr=…|utmccn=…|utmcmd=…|utmctr=…``
  -> campaign time, session and campaign numbers, source (``utmcsr``), campaign (``utmccn``),
  medium (``utmcmd``), search term (``utmctr``) and referral path (``utmcct``);
  ``utmgclid`` / ``utmdclid`` (ad click ids) are dropped;
* ``_ga`` = ``GA1.<level>.<random>.<first visit>`` -> the first-visit time only.

The visitor id / random part (the client ID) and the domain hash are never copied. A value
the browser keeps encrypted (Chromium ``encrypted_value``) is not decrypted: the row says the
cookie exists and why its fields are empty.
"""

from __future__ import annotations

import datetime as dt
import re
from urllib.parse import unquote

ANALYTICS_COOKIE_NAMES = ("__utma", "__utmz", "_ga")
ANALYTICS_PARSER = "browser-analytics-cookie"
ANALYTICS_PARSER_VERSION = "browser-analytics-cookie-v1"
CLIENT_ID_POLICY = "클라이언트 ID(방문자 ID)와 도메인 해시 값은 저장하지 않음(방문 시각·세션 수·유입 출처·검색어만)"
MAX_VALUE_CHARS = 2048
MAX_FIELD_CHARS = 300
# Plausible GA cookie times: GA (urchin) launched 2005; anything far in the future is noise.
MIN_UNIX = 946_684_800  # 2000-01-01
MAX_UNIX = 4_102_444_800  # 2100-01-01
UTMZ_KEYS = {
    "utmcsr": "source",
    "utmccn": "campaign",
    "utmcmd": "medium",
    "utmctr": "search_term",
    "utmcct": "referral_path",
}
DIGITS = re.compile(r"^\d{1,12}$")


def _unix(text: str) -> str | None:
    if not DIGITS.fullmatch(text or ""):
        return None
    value = int(text)
    if not MIN_UNIX <= value <= MAX_UNIX:
        return None
    return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _count(text: str) -> int | None:
    return int(text) if DIGITS.fullmatch(text or "") else None


def parse_analytics_cookie(name: str, value: str) -> dict[str, object]:
    """Allowed fields of one GA cookie value (``value_status`` = ``parsed`` / ``unparsed-format``)."""
    text = unquote(str(value or "")[:MAX_VALUE_CHARS]).strip()
    fields: dict[str, object] = {"value_status": "unparsed-format"}
    if name == "__utma":
        parts = text.split(".")
        if len(parts) == 6:
            first, previous, current = _unix(parts[2]), _unix(parts[3]), _unix(parts[4])
            sessions = _count(parts[5])
            if first or current:
                fields.update(
                    {
                        "value_status": "parsed",
                        "first_visit_at": first,
                        "previous_visit_at": previous,
                        "current_visit_at": current,
                        "session_count": sessions,
                    }
                )
    elif name == "__utmz":
        parts = text.split(".", 4)
        if len(parts) == 5:
            campaign_time = _unix(parts[1])
            parsed: dict[str, object] = {
                "value_status": "parsed" if campaign_time else "unparsed-format",
                "campaign_set_at": campaign_time,
                "session_number": _count(parts[2]),
                "campaign_number": _count(parts[3]),
            }
            for item in parts[4].split("|"):
                key, _, raw = item.partition("=")
                target = UTMZ_KEYS.get(key.strip())
                if target and raw:
                    parsed[target] = " ".join(raw.split())[:MAX_FIELD_CHARS]
            if campaign_time:
                fields.update(parsed)
    elif name == "_ga":
        parts = text.split(".")
        if len(parts) >= 4 and parts[0].upper().startswith("GA"):
            first = _unix(parts[-1])
            if first:
                fields.update({"value_status": "parsed", "first_visit_at": first})
    return fields


def analytics_row_time(fields: dict[str, object]) -> tuple[str | None, str]:
    """``(timestamp, timestamp_kind)`` of a parsed GA row: current visit, campaign time, first visit."""
    for key, kind in (
        ("current_visit_at", "ga-current-visit"),
        ("campaign_set_at", "ga-campaign-set"),
        ("first_visit_at", "ga-first-visit"),
    ):
        value = fields.get(key)
        if isinstance(value, str) and value:
            return value, kind
    return None, ""
