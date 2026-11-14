"""Entity patterns of the search index (R7 lane B, Nuix "named entities").

Korean personal-data numbers and network identifiers are found in a row's text at
index build time. **No raw value is ever stored**: the index keeps, per distinct
value, ``sha256("rapidtriage-entity-v1\\0<kind>\\0<normalized>")`` and a mask, and the
row text itself is stored with every *sensitive* value replaced by its mask (so
the trigram index, snippets and ``fields`` never carry the number either).

Kinds (``KINDS``; Korean names in ``KIND_LABELS``):

* ``rrn`` 주민등록번호 / 외국인등록번호 -- ``YYMMDD-GNNNNNN``: a real birth date for
  the century digit ``G`` (1-8). ``verified`` when the check digit holds (weights
  2..9,2..5; foreigners ``(13 - s % 11) % 10``). Numbers issued since 2020-10 have
  no check digit, so a hyphenated value with a valid date/sex digit and a failing
  check is kept as a ``candidate``; a 13-digit run without the hyphen must verify.
* ``corpno`` 법인등록번호 -- ``NNNNNN-NNNNNNN`` with the 1/2-weight check digit
  (only when it is not a valid ``rrn``).
* ``card`` 카드번호 -- 13-19 digits (groups of 4, Amex 4-6-5, or one run) passing
  Luhn. ``verified`` when the issuer prefix (BIN) allows that length (Visa, Master,
  Amex, JCB, Diners, Discover, UnionPay, 국내 전용 9xxx); a grouped Luhn-valid number
  of an unknown prefix is a ``candidate``, an ungrouped one must verify. A Luhn
  failure is not a card.
* ``bizno`` 사업자등록번호 -- ``NNN-NN-NNNNN`` (hyphens required: bare 10-digit runs
  are mostly Unix times) with the 1,3,7,1,3,7,1,3,5 weights (``verified``); a
  failing check is a ``candidate``.
* ``phone`` 전화번호 -- mobile ``01[016789]`` (separators optional) and landline
  (02, 0[3-6][1-5], 070; separators required), also ``+82``; normalized to E.164
  (``+821012345678``). ``verified`` = valid Korean numbering plan.
* ``account`` 계좌번호 -- hyphenated bank layouts only (국민 6-2-6, 신한 3-3-6, 우리
  4-3-6, 하나 3-6-5, 농협 3-4-4-2, 기업 3-6-2-3, 카카오뱅크 3333-2-7, 토스뱅크 1000-4-4,
  새마을 4-2-6-1 …): **low confidence** (never ``verified``).
* ``passport`` 여권번호 -- ``[MSRGD]`` + 8 digits or the 2021 format ``M123A4567``
  (format only: never ``verified``).
* ``email`` 이메일 -- masked ``k***@naver.com`` (the domain stays searchable).
* ``ip`` IPv4/IPv6 (+ CIDR suffix) and ``host`` (URL hosts, bare domains of common
  TLDs): network identifiers, not personal numbers -- their "mask" is the
  canonical value (``ip:10.0.0.0/8`` ranges need it) and the row text keeps them.

Every scan starts with a literal or a character set (SRE's fast prefix/charset search)
and checks word boundaries in Python on the few candidates -- a leading lookbehind
would run at every position of ~300 MB of text. Repeats are bounded and the
separators disjoint (no nested variable quantifiers); ``tests/test_r7_b_patterns.py``
runs each pattern through :func:`.regex_guard.analyze_regex` and times adversarial rows.
"""

from __future__ import annotations

import bisect
import datetime as dt
import hashlib
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

HASH_PREFIX = "rapidtriage-entity-v1"
ENTITY_RULE = "entities-v1"
ROW_CAP = 64
TOTAL_CAP = 5_000_000
# Candidates scanned per text. Every indexed piece is at most ~520K characters (document body
# cap), i.e. fewer candidates than this, so the cap never leaves an indexed value unmasked; it
# only bounds a call on unbounded text.
SCAN_CAP = 600_000

KINDS = ("rrn", "corpno", "card", "bizno", "phone", "account", "passport", "email", "ip", "host")
KIND_LABELS = {
    "rrn": "주민등록번호",
    "corpno": "법인등록번호",
    "card": "카드번호",
    "bizno": "사업자등록번호",
    "phone": "전화번호",
    "account": "계좌번호",
    "passport": "여권번호",
    "email": "이메일",
    "ip": "IP 주소",
    "host": "호스트",
}
# Personal numbers: masked in the stored row text, never kept raw anywhere in the index.
SENSITIVE_KINDS = frozenset({"rrn", "corpno", "card", "bizno", "phone", "account", "passport", "email"})
# Bit of each kind in ``search_doc.entity_mask`` (facets read it from the result rows).
KIND_BITS = {kind: 1 << position for position, kind in enumerate(KINDS)}
LOW_CONFIDENCE_KINDS = frozenset({"account", "passport"})


@dataclass(frozen=True)
class Entity:
    kind: str
    normalized: str  # transient: hashed, never stored
    masked: str
    verified: bool
    start: int
    end: int
    net: str = ""  # ip only: fixed-width hex key (CIDR ranges)

    @property
    def sensitive(self) -> bool:
        return self.kind in SENSITIVE_KINDS


def entity_sha256(kind: str, normalized: str) -> bytes:
    return hashlib.sha256(f"{HASH_PREFIX}\x00{kind}\x00{normalized}".encode()).digest()


# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------

_RRN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
_CENTURY = {"1": 1900, "2": 1900, "3": 2000, "4": 2000, "5": 1900, "6": 1900, "7": 2000, "8": 2000}
_TODAY_YEAR = dt.datetime.now(dt.timezone.utc).year


def rrn_date_ok(digits: str) -> bool:
    century = _CENTURY.get(digits[6])
    if century is None:
        return False
    year = century + int(digits[0:2])
    if year > _TODAY_YEAR:
        return False
    try:
        dt.date(year, int(digits[2:4]), int(digits[4:6]))
    except ValueError:
        return False
    return True


def rrn_check_ok(digits: str) -> bool:
    total = sum(int(d) * w for d, w in zip(digits[:12], _RRN_WEIGHTS))
    if digits[6] in "5678":
        expected = (13 - total % 11) % 10
    else:
        expected = (11 - total % 11) % 10
    return expected == int(digits[12])


def corpno_check_ok(digits: str) -> bool:
    total = sum(int(d) * (1 if index % 2 == 0 else 2) for index, d in enumerate(digits[:12]))
    return (10 - total % 10) % 10 == int(digits[12])


_BIZ_WEIGHTS = (1, 3, 7, 1, 3, 7, 1, 3, 5)


def bizno_check_ok(digits: str) -> bool:
    total = sum(int(d) * w for d, w in zip(digits[:9], _BIZ_WEIGHTS))
    total += int(digits[8]) * 5 // 10
    return (10 - total % 10) % 10 == int(digits[9])


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_brand_ok(digits: str) -> bool:
    """The issuer prefix (BIN) allows this length."""
    length = len(digits)
    two, three, four = int(digits[:2]), int(digits[:3]), int(digits[:4])
    if digits[0] == "4":
        return length in (13, 16, 19)
    if 51 <= two <= 55 or 2221 <= four <= 2720:
        return length == 16
    if two in (34, 37):
        return length == 15
    if 3528 <= four <= 3589:
        return 16 <= length <= 19
    if 300 <= three <= 305 or two in (36, 38, 39):
        return 14 <= length <= 19
    if four == 6011 or two == 65 or 644 <= three <= 649:
        return 16 <= length <= 19
    if two == 62:
        return 16 <= length <= 19
    if digits[0] == "9":  # 국내 전용 카드(BC·지역 카드 등)
        return length == 16
    return False


_MOBILE_PREFIXES = frozenset({"010", "011", "016", "017", "018", "019"})
_LANDLINE_AREA = frozenset({"02", "070"} | {f"0{a}{b}" for a in "3456" for b in "12345"})
_E164_AREA = frozenset({"70"} | {f"{a}{b}" for a in "3456" for b in "12345"})


def _phone(groups: list[str], separated: bool) -> str | None:
    """E.164 of a Korean phone number written as ``groups`` (``None``: not a phone)."""
    digits = "".join(groups)
    if digits[:3] in _MOBILE_PREFIXES:
        if len(groups) == 1:
            ok = len(digits) == 11 or (len(digits) == 10 and digits[:3] != "010")
        else:
            ok = len(groups) == 3 and groups[0] in _MOBILE_PREFIXES and len(groups[1]) in (3, 4) and len(groups[2]) == 4
            ok = ok and not (groups[0] == "010" and len(groups[1]) != 4)
        return "+82" + digits[1:] if ok else None
    if not separated or len(groups) != 3:
        return None
    area, middle, last = groups
    if area not in _LANDLINE_AREA or len(last) != 4:
        return None
    if area == "070":
        if len(middle) != 4:
            return None
    elif len(middle) not in (3, 4) or middle[0] == "0":
        return None
    return "+82" + digits[1:]


def _phone_from_e164_parts(groups: list[str]) -> str | None:
    """``+82`` followed by the number without its leading 0 (``+82 10-1234-5678``)."""
    rest = "".join(groups)
    rest = rest.removeprefix("0")
    if rest[:2] in {"10", "11", "16", "17", "18", "19"}:
        return "+82" + rest if len(rest) in (9, 10) and (rest[:2] != "10" or len(rest) == 10) else None
    if rest.startswith("2") and len(rest) in (8, 9):
        return "+82" + rest
    if rest[:2] in _E164_AREA and len(rest) in (9, 10):
        return "+82" + rest
    return None


# Bank layouts (hyphenated group lengths) -- low confidence, never ``verified``.
_ACCOUNT_LAYOUTS = frozenset(
    {
        (6, 2, 6),  # 국민·농협·우체국
        (3, 3, 6),  # 신한·케이뱅크
        (3, 2, 6),  # 신한(구)·SC제일·수협
        (4, 3, 6),  # 우리
        (3, 6, 5),  # 하나
        (3, 4, 4, 2),  # 농협
        (3, 6, 2, 3),  # 기업
        (3, 6, 3),  # 씨티
        (4, 2, 6, 1),  # 새마을금고
        (3, 2, 4, 3),  # 국민(구)
    }
)
_PREFIXED_ACCOUNT_LAYOUTS = {(4, 2, 7): ("3333", "3355", "7979"), (4, 4, 4): ("1000", "1001", "1002", "1100")}


def _account(groups: list[str], separator: str) -> bool:
    if separator != "-":
        return False
    shape = tuple(len(group) for group in groups)
    if shape in _ACCOUNT_LAYOUTS:
        return True
    prefixes = _PREFIXED_ACCOUNT_LAYOUTS.get(shape)
    return prefixes is not None and groups[0] in prefixes


# ---------------------------------------------------------------------------
# masks
# ---------------------------------------------------------------------------


def mask_rrn(digits: str) -> str:
    return f"{digits[:6]}-{digits[6]}******"


def mask_corpno(digits: str) -> str:
    return f"{digits[:6]}-*******"


def mask_card(digits: str) -> str:
    return f"**** **** **** {digits[-4:]}"


def mask_bizno(digits: str) -> str:
    return f"{digits[:3]}-{digits[3:5]}-*****"


def mask_phone(e164: str) -> str:
    national = "0" + e164[3:]
    if national.startswith("02"):
        area, rest = "02", national[2:]
    else:
        area, rest = national[:3], national[3:]
    return f"{area}-****-{rest[-4:]}"


def mask_account(text: str) -> str:
    """Same layout, every digit but the last four starred (``***-***-**9012``)."""
    total = sum(char.isdigit() for char in text)
    seen = 0
    out: list[str] = []
    for char in text:
        if char.isdigit():
            seen += 1
            out.append(char if seen > total - 4 else "*")
        else:
            out.append(char)
    return "".join(out)


def mask_passport(value: str) -> str:
    return f"{value[0]}****{value[-4:]}"


def mask_email(value: str) -> str:
    local, _sep, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------

# A run of digits with ``-``/space separators (9+ characters, starts and ends with a digit).
NUMBER_RUN_RE = re.compile(r"[0-9][0-9 -]{7,}(?<=[0-9])")
PASSPORT_RE = re.compile(r"[MSRGD][0-9]{3}(?:[0-9]{5}|[A-Z][0-9]{4})")
EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24})(?![A-Za-z0-9\-])")
IPV4_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/[0-9]{1,2})?")
IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]{1,38}(?:%[0-9A-Za-z]{1,15})?(?:/[0-9]{1,3})?")
URL_RE = re.compile(r"://(?:[^\s/@:]{1,128}(?::[^\s/@]{0,128})?@)?(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,15})")
_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|io|kr|jp|cn|ru|uk|de|fr|eu|ca|au|br|tw|hk|sg|vn|onion|xyz|top|site|online|cloud|club|shop|live"
)
TLD_RE = re.compile(r"\.(?:" + _TLDS + r")(?![A-Za-z0-9\-_])", re.IGNORECASE)
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?")
_URL_SCHEMES = ("http", "https", "ftp", "ftps", "ws", "wss", "smb", "file")

# Every scanning pattern (the ReDoS test checks each).
ALL_PATTERNS = {
    "number": NUMBER_RUN_RE,
    "passport": PASSPORT_RE,
    "email": EMAIL_DOMAIN_RE,
    "ipv4": IPV4_RE,
    "ipv6": IPV6_RE,
    "url": URL_RE,
    "tld": TLD_RE,
    "label": _LABEL_RE,
}
# Anything a masked kind could start with: 9+ digit/separator characters, an "@", a passport.
# A full (uncompressed) IPv6 address has three colon-separated hex groups in a row (a time does not).
_IPV6_PROBE = re.compile(r":[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:")
_SENSITIVE_PROBE = re.compile(r"[0-9][0-9 \-]{7}[0-9]|@|[MSRGD][0-9]{3}")
_ALNUM = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_EMAIL_LOCAL = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._%+-")
_HOST_CHARS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-")


def classify_number(prefix: str, body: str) -> tuple[str, str, str, bool] | None:
    """``(kind, normalized, masked, verified)`` of a digit-group run, ``None`` when it is none of ours."""
    separators = {char for char in body if char in " -"}
    if len(separators) > 1:
        return None
    separator = next(iter(separators), "")
    groups = body.split(separator) if separator else [body]
    if any(not group for group in groups) or len(groups) > 5:
        return None
    digits = "".join(groups)
    if prefix:
        e164 = _phone_from_e164_parts(groups)
        return ("phone", e164, mask_phone(e164), True) if e164 else None
    shape = tuple(len(group) for group in groups)
    length = len(digits)
    if length == 13 and (shape == (13,) or (shape == (6, 7) and separator == "-")):
        resident = _resident_or_corp(digits, hyphen=separator == "-")
        if resident is not None:
            return resident
    if not separator and digits.startswith("01"):
        phone = _phone(groups, False)
        if phone is not None:
            return "phone", phone, mask_phone(phone), True
    grouped = shape in ((4, 6, 5), (4, 6, 4)) or (len(shape) > 1 and all(size == 4 for size in shape[:-1]) and 1 <= shape[-1] <= 4)
    if 13 <= length <= 19 and (grouped or shape == (length,)) and luhn_ok(digits):
        brand = card_brand_ok(digits)
        if brand or grouped:
            return "card", digits, mask_card(digits), brand
    if shape == (3, 2, 5) and separator == "-":
        return "bizno", digits, mask_bizno(digits), bizno_check_ok(digits)
    phone = _phone(groups, bool(separator))
    if phone is not None:
        return "phone", phone, mask_phone(phone), True
    if _account(groups, separator):
        return "account", digits, mask_account(body), False
    return None


def _resident_or_corp(digits: str, *, hyphen: bool) -> tuple[str, str, str, bool] | None:
    """주민등록번호 or 법인등록번호 of 13 digits: a verified 주민등록번호, else (hyphenated) a verified
    법인등록번호 (``110111-0…`` style numbers often read as a date too), else a hyphenated
    주민등록번호 candidate (numbers issued since 2020-10 carry no check digit)."""
    date_ok = rrn_date_ok(digits)
    if date_ok and rrn_check_ok(digits):
        return "rrn", digits, mask_rrn(digits), True
    if hyphen and corpno_check_ok(digits):
        return "corpno", digits, mask_corpno(digits), True
    if date_ok and hyphen:
        return "rrn", digits, mask_rrn(digits), False
    return None


class _Spans:
    """Taken ``[start, end)`` spans of one text (sorted; overlap test by bisection)."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def overlaps(self, start: int, end: int) -> bool:
        index = bisect.bisect_right(self.starts, start)
        if index > 0 and self.ends[index - 1] > start:
            return True
        return index < len(self.starts) and self.starts[index] < end

    def add(self, start: int, end: int) -> None:
        index = bisect.bisect_right(self.starts, start)
        self.starts.insert(index, start)
        self.ends.insert(index, end)


def _ip_key(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return f"4:{int(address):08x}" if address.version == 4 else f"6:{int(address):032x}"


def ip_net_range(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[str, str]:
    return _ip_key(network.network_address), _ip_key(network.broadcast_address)


def canonical_host(text: str) -> str:
    return text.strip().strip(".").lower()


def _char(text: str, index: int) -> str:
    """``text[index]``, a space outside the text (``"" in "abc"`` would be true)."""
    return text[index] if 0 <= index < len(text) else " "


def _number_entities(text: str, start: int, end: int, budget: int) -> tuple[list[Entity], int]:
    """``(entities, pieces examined)`` of one digit run ``text[start:end]`` (its boundaries already
    checked; a run right after ``+`` is a ``+82`` phone number or nothing). At most ``budget``
    space-separated pieces are examined."""
    run = text[start:end]
    if _char(text, start - 1) == "+":
        body = run[2:].lstrip(" -") if run.startswith("82") else ""
        classified = classify_number("+82", body) if body and body[0].isdigit() else None
        if classified is None:
            return [], 1
        kind, normalized, masked, verified = classified
        return [Entity(kind, normalized, masked, verified, start - 1, end)], 1
    if len(run) <= 24:
        if len(run) - run.count("-") - run.count(" ") < 9:
            return [], 1  # dates, short numbers: no kind has fewer than 9 digits
        if run.isdigit() and not (len(run) >= 13 or (len(run) in (10, 11) and run.startswith("01"))):
            return [], 1  # an ungrouped run is only a mobile number (01…), 주민/법인 (13) or a card (13-19)
        classified = classify_number("", run)
        if classified is not None:
            kind, normalized, masked, verified = classified
            return [Entity(kind, normalized, masked, verified, start, end)], 1
        if " " not in run:
            return [], 1
    # Space-separated pieces ("010-1234-5678 010-2345-6789", "1234567 4111 1111 1111 1111"):
    # a window of 4..2 digit-only pieces (cards, phones written with spaces), else one piece.
    pieces: list[tuple[int, str]] = []
    offset = start
    for piece in run.split(" "):
        if piece:
            pieces.append((offset, piece))
            if len(pieces) >= budget:
                break
        offset += len(piece) + 1
    found: list[Entity] = []
    index = 0
    while index < len(pieces):
        taken = 0
        for width in (4, 3, 2):
            window = pieces[index : index + width]
            if len(window) < width or not 9 <= sum(len(piece) for _offset, piece in window) <= 22:
                continue
            if not all(piece.isdigit() and 2 <= len(piece) <= 6 for _offset, piece in window):
                continue
            window_start = window[0][0]
            window_end = window[-1][0] + len(window[-1][1])
            # The window must be single-spaced: its text is exactly the pieces joined by one space.
            body = text[window_start:window_end]
            if body.count(" ") != width - 1:
                continue
            classified = classify_number("", body)
            # A space-joined window is a card only with a known issuer prefix (numeric tables of
            # 4-digit values pass Luhn one time in ten).
            if classified is not None and not (classified[0] == "card" and not classified[3]):
                kind, normalized, masked, verified = classified
                found.append(Entity(kind, normalized, masked, verified, window_start, window_end))
                taken = width
                break
        if taken:
            index += taken
            continue
        piece_start, piece = pieces[index]
        if len(piece) >= 9 and piece[0].isdigit() and piece[-1].isdigit():
            classified = classify_number("", piece)
            if classified is not None:
                kind, normalized, masked, verified = classified
                found.append(Entity(kind, normalized, masked, verified, piece_start, piece_start + len(piece)))
        index += 1
    return found, max(1, len(pieces))


def find_entities(text: str, *, scan_cap: int = SCAN_CAP, sensitive_only: bool = False) -> list[Entity]:
    """Every entity of ``text`` (non-overlapping, in text order). ``sensitive_only``: skip the
    network passes (URL hosts, IPs, bare hosts) -- for pieces that only need masking."""
    if not text or (sensitive_only and _SENSITIVE_PROBE.search(text) is None):
        return []
    found: list[Entity] = []
    spans = _Spans()
    budget = scan_cap

    def add(entity: Entity) -> None:
        found.append(entity)
        spans.add(entity.start, entity.end)

    if "@" in text:
        for match in EMAIL_DOMAIN_RE.finditer(text):
            budget -= 1
            if budget <= 0:
                break
            at = match.start()
            local_start = at
            while local_start > 0 and at - local_start < 64 and text[local_start - 1] in _EMAIL_LOCAL:
                local_start -= 1
            while local_start < at and text[local_start] in ".-+":
                local_start += 1
            if local_start == at or _char(text, local_start - 1) in _EMAIL_LOCAL or text[max(0, local_start - 3) : local_start] == "://":
                continue  # not an address / URL user info (the URL pass takes the host)
            normalized = text[local_start : match.end(1)].lower()
            add(Entity("email", normalized, mask_email(normalized), True, local_start, match.end(1)))
    if "://" in text and not sensitive_only:
        for match in URL_RE.finditer(text):
            budget -= 1
            if budget <= 0:
                break
            scheme_end = match.start()
            head = text[max(0, scheme_end - 6) : scheme_end].lower()
            scheme = next((name for name in _URL_SCHEMES if head.endswith(name) and _char(text, scheme_end - len(name) - 1) not in _ALNUM), None)
            if scheme is None:
                continue
            raw = match.group(1)
            if raw.startswith("[") or spans.overlaps(match.start(1), match.end(1)):
                continue  # an IPv6 literal (the IPv6 pass) / inside an e-mail address
            host = canonical_host(raw)
            if "." not in host:
                continue
            try:
                ipaddress.ip_address(host)
                continue  # an IPv4 literal: the IPv4 pass takes it
            except ValueError:
                pass
            add(Entity("host", host, host, True, match.start(1), match.end(1)))
    for match in NUMBER_RUN_RE.finditer(text):
        budget -= 1
        if budget <= 0:
            break
        start, end = match.start(), match.end()
        before, after = _char(text, start - 1), _char(text, end)
        if before in _ALNUM or before in ".-" or (before == "+" and _char(text, start - 2) in _ALNUM):
            continue
        if after in _ALNUM or (after in ".-" and _char(text, end + 1).isdigit()):
            continue
        entities, examined = _number_entities(text, start, end, budget)
        budget -= examined
        for entity in entities:
            if not spans.overlaps(entity.start, entity.end):
                add(entity)
    for match in PASSPORT_RE.finditer(text):
        budget -= 1
        if budget <= 0:
            break
        start, end = match.start(), match.end()
        if _char(text, start - 1) in _ALNUM or _char(text, end) in _ALNUM or spans.overlaps(start, end):
            continue
        value = match.group()
        add(Entity("passport", value, mask_passport(value), False, start, end))
    if not sensitive_only and text.count(".") >= 3:
        for match in IPV4_RE.finditer(text):
            budget -= 1
            if budget <= 0:
                break
            start, end = match.start(), match.end()
            before, after = _char(text, start - 1), _char(text, end)
            if before in _ALNUM or before == "." or after in _ALNUM or (after == "." and _char(text, end + 1).isdigit()):
                continue
            if spans.overlaps(start, end):
                continue
            address_text, _slash, prefix = match.group().partition("/")
            try:
                address = ipaddress.IPv4Address(address_text)
            except ValueError:
                continue
            canonical = str(address)
            if prefix:
                if int(prefix) > 32:
                    continue
                canonical = f"{canonical}/{prefix}"
            add(Entity("ip", canonical, canonical, True, start, end, _ip_key(address)))
    if not sensitive_only and ("::" in text or (text.count(":") >= 7 and _IPV6_PROBE.search(text) is not None)):
        for match in IPV6_RE.finditer(text):
            budget -= 1
            if budget <= 0:
                break
            start, end = match.start(), match.end()
            before, after = _char(text, start - 1), _char(text, end)
            if before in _ALNUM or before in ":." or after in _ALNUM or after == ":":
                continue
            raw, _slash, prefix = match.group().partition("/")
            if "::" not in raw and raw.count(":") != 7:
                continue
            if spans.overlaps(start, end):
                continue
            try:
                address = ipaddress.IPv6Address(raw.split("%", 1)[0])
            except ValueError:
                continue
            canonical = address.compressed
            if prefix:
                if int(prefix) > 128:
                    continue
                canonical = f"{canonical}/{prefix}"
            add(Entity("ip", canonical, canonical, True, start, end, _ip_key(address)))
    if not sensitive_only and "." in text:
        for match in TLD_RE.finditer(text):
            budget -= 1
            if budget <= 0:
                break
            end = match.end()
            if _char(text, end) == "." and _char(text, end + 1) in _ALNUM:
                continue  # "example.com.au": the ".au" hit takes it
            dot = match.start()
            start = dot
            floor = max(0, dot - 253)
            while start > floor and text[start - 1] in _HOST_CHARS:
                start -= 1
            while start < dot and text[start] in ".-":
                start += 1
            if start == dot or _char(text, start - 1) in "@_/\\" or _char(text, start - 1) in _HOST_CHARS:
                continue
            labels = text[start:dot].split(".")
            if len(labels) > 8 or not all(_LABEL_RE.fullmatch(label) for label in labels):
                continue
            if spans.overlaps(start, end):
                continue
            host = canonical_host(text[start:end])
            add(Entity("host", host, host, True, start, end))
    found.sort(key=lambda entity: entity.start)
    return found


def mask_text(text: str, entities: Iterable[Entity]) -> str:
    """``text`` with every sensitive entity replaced by its mask."""
    pieces: list[str] = []
    position = 0
    for entity in entities:
        if not entity.sensitive or entity.start < position:
            continue
        pieces.append(text[position : entity.start])
        pieces.append(entity.masked)
        position = entity.end
    if not pieces:
        return text
    pieces.append(text[position:])
    return "".join(pieces)


def mask_sensitive(text: str) -> str:
    """``text`` with its sensitive entities masked (query echoes, history)."""
    if not text:
        return text
    return mask_text(text, find_entities(text))


# ---------------------------------------------------------------------------
# query values
# ---------------------------------------------------------------------------


def whole_entity(text: str) -> Entity | None:
    """``text`` is exactly one entity (a keyword typed as a whole number/address)."""
    value = text.strip()
    if len(value) < 7:
        return None
    entities = find_entities(value)
    if len(entities) == 1 and entities[0].start == 0 and entities[0].end == len(value):
        return entities[0]
    return None


def parse_entity_value(kind: str, text: str) -> str | None:
    """The normalized value of a typed exact ``kind`` value (``None``: not a value of that kind)."""
    value = text.strip()
    if not value:
        return None
    if kind == "host":
        host = canonical_host(value)
        return host if host and all(_LABEL_RE.fullmatch(label) for label in host.split(".")) else None
    if kind == "ip":
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return None
    if kind == "passport":
        upper = value.upper()
        return upper if PASSPORT_RE.fullmatch(upper) else None
    entity = whole_entity(value)
    if entity is not None and entity.kind == kind:
        return entity.normalized
    if kind == "email":
        return None
    digits = re.sub(r"[ \-]", "", value)
    if kind == "phone":
        digits = re.sub(r"[.()]", "", digits)
        if digits.startswith("+82"):
            return _phone_from_e164_parts([digits[3:]])
        if digits.isdigit() and digits.startswith("0") and 9 <= len(digits) <= 11:
            return "+82" + digits[1:]
        return None
    if not digits.isdigit():
        return None
    expected = {"rrn": 13, "corpno": 13, "bizno": 10}.get(kind)
    if expected is not None and len(digits) != expected:
        return None
    if kind == "card" and not 13 <= len(digits) <= 19:
        return None
    return digits if kind in {"rrn", "corpno", "card", "bizno", "account"} else None
