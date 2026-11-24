"""Python vs Rust per-row kernels of the opt-in EVTX engine (``evtx_engine=rust``).

Redaction: ``rapidcore_native.redact_recovery_passwords_in`` walks a row in Rust
and hands every string that could hold a BitLocker recovery password to the
Python ``redact_recovery_passwords``. It must return what the Python walk
returns, including returning the same object when nothing changed.

Without the native module these tests skip unless
``RAPIDTRIAGE_REQUIRE_NATIVE_EVTX=1``.
"""

from __future__ import annotations

import os
import random
import string
import unittest

from rapidtriage.artifacts.windows import evtx_engine
from rapidtriage.artifacts.windows.antiforensics import (
    redact_recovery_passwords,
    redact_recovery_passwords_in,
)

NATIVE, NATIVE_REASON = evtx_engine.load_native_evtx_decoder()
REQUIRE_NATIVE = os.environ.get("RAPIDTRIAGE_REQUIRE_NATIVE_EVTX") == "1"

# Synthetic checksum-valid groups (each a multiple of 11, at most 720885).
VALID = "123453-000011-720885-654324-100001-111111-222222-333333"
INVALID = "123456-000011-720885-654324-100001-111111-222222-333333"
FULLWIDTH = VALID.translate(str.maketrans("0123456789", "０１２３４５６７８９"))


class _Str(str):
    pass


class _Dict(dict):
    pass


class _List(list):
    pass


def native_redact(value: object) -> object:
    return NATIVE.redact_recovery_passwords_in(value, redact_recovery_passwords, redact_recovery_passwords_in)


def nested(depth: int, leaf: object) -> object:
    value = leaf
    for level in range(depth):
        value = {"level": level, "child": [value, "x"]}
    return value


def random_tree(rng: random.Random, depth: int = 0) -> object:
    kind = rng.random()
    if depth > 4 or kind < 0.45:
        pieces = [
            rng.choice((VALID, INVALID, FULLWIDTH, VALID.replace("-", " "), VALID.replace("-", "‐"), VALID.replace("-", ""))),
            "".join(rng.choice(string.digits + "- ") for _ in range(rng.randint(0, 80))),
            "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(0, 60))),
        ]
        rng.shuffle(pieces)
        return "".join(pieces[: rng.randint(1, 3)])
    if kind < 0.55:
        return rng.choice((None, 0, 1.5, True, b"123453", 10**20))
    if kind < 0.8:
        return {f"k{index}": random_tree(rng, depth + 1) for index in range(rng.randint(0, 5))}
    items = [random_tree(rng, depth + 1) for _ in range(rng.randint(0, 5))]
    return tuple(items) if rng.random() < 0.3 else items


class RedactionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        if NATIVE is None:
            if REQUIRE_NATIVE:
                self.fail(f"rapidcore_native EVTX engine required: {NATIVE_REASON}")
            self.skipTest(f"rapidcore_native EVTX engine not built: {NATIVE_REASON}")

    def assert_same(self, value: object) -> None:
        expected = redact_recovery_passwords_in(value)
        actual = native_redact(value)
        self.assertEqual(repr(actual), repr(expected))
        self.assertEqual(type(actual), type(expected))
        self.assertEqual(actual is value, expected is value)

    def test_edge_cases(self) -> None:
        cases = [
            f"cmd /c manage-bde -unlock C: -rp {VALID}",
            f"-rp {INVALID} (checksum fails, kept)",
            f"fullwidth {FULLWIDTH}",
            VALID.replace("-", " "),
            VALID.replace("-", "−"),
            VALID[:47],
            "1" * 47,
            "9" * 48,
            _Str(f"subclass {VALID}"),
            f"\ud800 lone surrogate {VALID}",
            f"\ud800{'0' * 50}",
            {"a": f"x {VALID}", "b": ("t", VALID, 3), "c": [VALID, {"d": VALID}]},
            {"unchanged": ["plain", ("tuple", 1)], "n": 1},
            _Dict(a="plain", b=VALID),
            _Dict(a="plain"),
            _List(["plain", VALID]),
            (VALID,),
            [],
            {},
            # 240 container levels: past the native walker's 200-level hand-off to Python.
            nested(120, VALID),
            nested(120, "plain"),
            12345,
            None,
        ]
        for case in cases:
            with self.subTest(case=repr(case)[:60]):
                self.assert_same(case)

    def test_random_trees(self) -> None:
        rng = random.Random(1102)
        for _ in range(3000):
            self.assert_same(random_tree(rng))


if __name__ == "__main__":
    unittest.main()
