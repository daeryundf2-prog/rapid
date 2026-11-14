"""Generate the entity-pattern known-answer set (R7 lane B): 300 SYNTHETIC values.

Every value is made up by this script from a fixed seed -- no real number is copied from
anywhere. The check digits are computed so the sets mean what they say:

* ``true`` (100): 주민등록번호 30 (valid birth date + sex digit + check digit), 카드번호 30
  (issuer prefix/length + Luhn), 사업자등록번호 20 (1,3,7,1,3,7,1,3,5 weights), 법인등록번호 20
  (1/2 weights; 7th digit 0 so it is never a birth-date number).
* ``check-fail`` (100): the same shapes with a wrong check digit. A 13-digit value is
  regenerated until it fails *every* check of its shape (주민 and 법인), so a failure never
  passes as the other kind by chance; cards fail Luhn.
* ``look-alike`` (100): digit strings that resemble the kinds but are none of them -- dates,
  times, Unix/epoch-ms times, version strings, grouped non-Luhn 16 digits, ISBN-13, order
  numbers, 대표번호(1588-xxxx), invalid mobile prefixes, out-of-range IPs, amounts, zip codes.

Run ``python tests/fixtures/entity_known_answer/generate_known_answer.py`` to rewrite
``known_answer.json``; the test regenerates it in memory and checks the file is identical.
"""

from __future__ import annotations

import datetime as dt
import json
import random
from pathlib import Path

SEED = 20261027
OUTPUT = Path(__file__).with_name("known_answer.json")
RRN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
BIZ_WEIGHTS = (1, 3, 7, 1, 3, 7, 1, 3, 5)


def rrn_check(first12: str) -> int:
    total = sum(int(d) * w for d, w in zip(first12, RRN_WEIGHTS))
    return (11 - total % 11) % 10


def corp_check(first12: str) -> int:
    total = sum(int(d) * (1 if index % 2 == 0 else 2) for index, d in enumerate(first12))
    return (10 - total % 10) % 10


def biz_check(first9: str) -> int:
    total = sum(int(d) * w for d, w in zip(first9, BIZ_WEIGHTS)) + int(first9[8]) * 5 // 10
    return (10 - total % 10) % 10


def luhn_check(body: str) -> int:
    total = 0
    for index, char in enumerate(reversed(body)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return (10 - total % 10) % 10


def luhn_ok(digits: str) -> bool:
    return luhn_check(digits[:-1]) == int(digits[-1])


def _digits(rng: random.Random, count: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(count))


def _birth(rng: random.Random) -> tuple[str, str]:
    day = dt.date(1950, 1, 1) + dt.timedelta(days=rng.randrange(0, 365 * 58))
    sex = rng.choice("12") if day.year < 2000 else rng.choice("34")
    return day.strftime("%y%m%d"), sex


def rrn(rng: random.Random, *, valid: bool) -> str:
    while True:
        birth, sex = _birth(rng)
        first12 = birth + sex + _digits(rng, 5)
        check = rrn_check(first12)
        if valid:
            return f"{first12[:6]}-{first12[6:]}{check}"
        wrong = (check + rng.randint(1, 9)) % 10
        if wrong != corp_check(first12):  # fails every 13-digit check
            return f"{first12[:6]}-{first12[6:]}{wrong}"


def corpno(rng: random.Random, *, valid: bool) -> str:
    while True:
        first12 = rng.choice(["1101", "1301", "1601", "2001", "1749", "1811"]) + rng.choice(["11", "71", "81", "14"]) + "0" + _digits(rng, 5)
        check = corp_check(first12)
        if valid:
            return f"{first12[:6]}-{first12[6:]}{check}"
        wrong = (check + rng.randint(1, 9)) % 10
        if wrong != rrn_check(first12):
            return f"{first12[:6]}-{first12[6:]}{wrong}"


CARD_PREFIXES = (("4", 16), ("51", 16), ("53", 16), ("2221", 16), ("34", 15), ("37", 15), ("3530", 16), ("6011", 16), ("62", 16), ("9410", 16))


def card(rng: random.Random, *, valid: bool) -> str:
    prefix, length = rng.choice(CARD_PREFIXES)
    body = prefix + _digits(rng, length - len(prefix) - 1)
    check = luhn_check(body)
    if not valid:
        check = (check + rng.randint(1, 9)) % 10
    digits = body + str(check)
    if length == 15:
        return f"{digits[:4]} {digits[4:10]} {digits[10:]}"
    separator = rng.choice([" ", "-", ""])
    return separator.join(digits[i : i + 4] for i in range(0, 16, 4))


def bizno(rng: random.Random, *, valid: bool) -> str:
    first9 = f"{rng.randint(101, 899)}{rng.choice(['81', '86', '87', '01', '05', '11', '23'])}{_digits(rng, 4)}"
    check = biz_check(first9)
    if not valid:
        check = (check + rng.randint(1, 9)) % 10
    return f"{first9[:3]}-{first9[3:5]}-{first9[5:]}{check}"


def look_alikes(rng: random.Random) -> list[str]:
    values: list[str] = []
    for _ in range(10):  # dates and date-times
        day = dt.date(2000, 1, 1) + dt.timedelta(days=rng.randrange(0, 9000))
        values.append(day.isoformat())
    for _ in range(8):
        values.append(f"{dt.date(2001, 1, 1) + dt.timedelta(days=rng.randrange(0, 8000))} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}")
    for _ in range(8):  # Unix seconds (10 digits)
        values.append(str(rng.randint(1_400_000_000, 1_800_000_000)))
    for _ in range(8):  # epoch milliseconds (13 digits; regenerated until no 13-digit check holds)
        while True:
            value = str(rng.randint(1_400_000_000_000, 1_800_000_000_000))
            if rrn_check(value[:12]) != int(value[12]) and corp_check(value[:12]) != int(value[12]):
                values.append(value)
                break
    for _ in range(8):  # version strings
        values.append(f"{rng.randint(1, 12)}.{rng.randint(0, 9)}.{rng.randint(1000, 30000)}.{rng.randint(1, 9999)}")
    for _ in range(10):  # 16 digits in groups of 4 failing Luhn
        while True:
            digits = _digits(rng, 16)
            if not luhn_ok(digits):
                values.append("-".join(digits[i : i + 4] for i in range(0, 16, 4)))
                break
    for _ in range(6):  # ISBN-13
        values.append(f"978-89-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}-{rng.randint(0, 9)}")
    for _ in range(8):  # order / document numbers
        values.append(f"{rng.randint(2015, 2026)}-{rng.randint(1000, 9999)}-{rng.randint(100000, 999999)}")
    for _ in range(6):  # 전국대표번호 and invalid mobile prefixes
        values.append(rng.choice([f"1588-{rng.randint(1000, 9999)}", f"1577-{rng.randint(1000, 9999)}", f"012-{rng.randint(100, 999)}-{rng.randint(1000, 9999)}", f"013-{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}"]))
    for _ in range(6):  # out-of-range IPv4-like
        values.append(f"{rng.randint(256, 999)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}")
    for _ in range(6):  # amounts with thousands separators
        values.append(f"{rng.randint(1, 999)},{rng.randint(100, 999)},{rng.randint(100, 999)},{rng.randint(100, 999)}")
    for _ in range(6):  # zip codes + short numbers
        values.append(f"{rng.randint(10000, 63999):05d}")
    for _ in range(10):  # 13 digits hyphenated 6-7 with an impossible date (month 13+)
        while True:
            value = f"{rng.randint(0, 99):02d}{rng.randint(13, 99):02d}{rng.randint(1, 28):02d}-{rng.choice('1234')}{_digits(rng, 6)}"
            digits = value.replace("-", "")
            if corp_check(digits[:12]) != int(digits[12]):
                values.append(value)
                break
    assert len(values) == 100, len(values)
    return values


def generate() -> list[dict[str, str]]:
    rng = random.Random(SEED)
    items: list[dict[str, str]] = []
    for kind, maker, count in (("rrn", rrn, 30), ("card", card, 30), ("bizno", bizno, 20), ("corpno", corpno, 20)):
        items.extend({"set": "true", "kind": kind, "value": maker(rng, valid=True)} for _ in range(count))
    for kind, maker, count in (("rrn", rrn, 30), ("card", card, 30), ("bizno", bizno, 20), ("corpno", corpno, 20)):
        items.extend({"set": "check-fail", "kind": kind, "value": maker(rng, valid=False)} for _ in range(count))
    items.extend({"set": "look-alike", "kind": "", "value": value} for value in look_alikes(rng))
    return items


def render() -> str:
    return json.dumps({"seed": SEED, "synthetic": True, "items": generate()}, ensure_ascii=False, indent=1) + "\n"


if __name__ == "__main__":
    OUTPUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT}")
