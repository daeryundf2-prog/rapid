"""Python vs Rust per-row kernels of the opt-in EVTX engine (``evtx_engine=rust``).

Redaction: ``rapidcore_native.redact_recovery_passwords_in`` walks a row in Rust
and hands every string that could hold a BitLocker recovery password to the
Python ``redact_recovery_passwords``. It must return what the Python walk
returns, including returning the same object when nothing changed.

Compaction: ``profile_observe_details``/``profile_common`` (template folding),
``profile_strip_level`` (residues) and ``profile_merge`` (profile expansion)
must give the templates, residues and rows of ``artifact_profiles`` with the
same types (``True`` != ``1`` != ``1.0``), key order and object identity, and
decline (Python runs) whatever they cannot reproduce.

Without the native module these tests skip unless
``RAPIDTRIAGE_REQUIRE_NATIVE_EVTX=1``.
"""

from __future__ import annotations

import copy
import json
import os
import random
import string
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from evtx_engine_corpus import build_edge_corpus

from rapidtriage.artifacts.windows import evtx_engine
from rapidtriage.artifacts.windows.antiforensics import (
    redact_recovery_passwords,
    redact_recovery_passwords_in,
)
from rapidtriage.core import artifact_profiles as profiles
from rapidtriage.core import artifacts

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


NAN = float("nan")


def shape(value: object) -> object:
    """Type-strict, key-order-keeping view of a tree (``repr`` leaves, NaN-safe)."""
    if value is profiles._MISSING:
        return ("<missing>",)
    if isinstance(value, dict):
        return (type(value).__name__, tuple((shape(key), shape(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return (type(value).__name__, tuple(shape(item) for item in value))
    return (type(value).__name__, repr(value))


def aliases(result: object, *sources: object) -> list[object]:
    """Which source node (by path) each container of ``result`` is, in walk order."""
    paths: dict[int, str] = {}

    def index(node: object, path: str) -> None:
        if isinstance(node, (dict, list, tuple)):
            paths.setdefault(id(node), path)
            items = node.items() if isinstance(node, dict) else enumerate(node)
            for key, item in items:
                index(item, f"{path}/{key!r}")

    for number, source in enumerate(sources):
        index(source, f"s{number}")
    out: list[object] = []

    def walk(node: object) -> None:
        if isinstance(node, (dict, list, tuple)):
            out.append(paths.get(id(node), "new"))
            for item in node.values() if isinstance(node, dict) else node:
                walk(item)

    walk(result)
    return out


COMPACTION_SCALARS = (None, True, False, 0, 1, 1.0, 0.0, -0.0, 2**70, "a", "b", "", _Str("a"), NAN, "\ud800")
COMPACTION_KEYS = ("k1", "k2", "k3", "k4")


def compaction_tree(rng: random.Random, depth: int = 0) -> object:
    roll = rng.random()
    if depth > 3 or roll < 0.35:
        return rng.choice(COMPACTION_SCALARS)
    if roll < 0.65:
        return {rng.choice(COMPACTION_KEYS): compaction_tree(rng, depth + 1) for _ in range(rng.randint(0, 4))}
    if roll < 0.9:
        return [
            {rng.choice(COMPACTION_KEYS): compaction_tree(rng, depth + 1) for _ in range(rng.randint(0, 3))}
            for _ in range(rng.randint(0, 3))
        ]
    return rng.choice(
        (
            ("t", 1),
            _Dict(k1="a"),
            _List([{"k1": "a"}]),
            b"bytes",
            {1: "a"},
            {True: "a"},
            [compaction_tree(rng, depth + 1), "x"],
            float("nan"),
        )
    )


def mutate(rng: random.Random, value: object, depth: int = 0) -> object:
    """A variant of ``value``: mostly equal (often the same sub-objects), some leaves changed."""
    roll = rng.random()
    if roll < 0.35:
        return value
    if roll < 0.45 or depth > 4:
        return compaction_tree(rng, depth)
    if type(value) is dict:
        out = {key: mutate(rng, item, depth + 1) for key, item in value.items() if rng.random() > 0.1}
        if rng.random() < 0.2:
            out[rng.choice(COMPACTION_KEYS)] = compaction_tree(rng, depth + 1)
        return out
    if type(value) is list:
        return [mutate(rng, item, depth + 1) for item in value]
    if roll < 0.6:
        # Equal value, different object/type (1 vs 1.0 vs True, "a" vs _Str("a")).
        return copy.copy(rng.choice(COMPACTION_SCALARS))
    return value


def nested_dicts(depth: int, leaf: object) -> object:
    value = leaf
    for _ in range(depth):
        value = {"k1": value}
    return value


def compaction_edge_pairs() -> list[tuple[object, object]]:
    shared = {"k1": [NAN, {"k2": 1}]}
    return [
        (1, True),
        (1, 1.0),
        (0.0, -0.0),
        (NAN, NAN),
        ({"k1": NAN}, {"k1": NAN}),
        (shared, shared),
        ({"k1": shared}, {"k1": copy.copy(shared)}),
        ({"k1": 1}, {"k1": True}),
        ({"k1": 1}, {"k1": 1.0}),
        ({"k1": [1, 2]}, {"k1": [1, 2.0]}),
        ({"k1": 2**70}, {"k1": 2**70}),
        ({"k1": "a", "k2": "b"}, {"k2": "b", "k1": "a"}),
        ({"k1": "a"}, _Dict(k1="a")),
        ({"k1": "a"}, {"k1": _Str("a")}),
        ("a", _Str("a")),
        ({1: "a"}, {True: "a"}),
        ({"k1": {True: "a"}}, {"k1": {1: "a"}}),
        ({"k1": ("t",)}, {"k1": ["t"]}),
        ({"k1": b"x"}, {"k1": b"x"}),
        ([{"k1": 1}, {"k2": 2}], [{"k1": 1}, {"k2": 3}]),
        ([{"k1": 1}], [{"k1": 1}, {"k1": 1}]),
        ([{}], [{}]),
        ([{"k1": 1}, {}], [{"k1": 2}, {}]),
        ([], []),
        ([1], [1]),
        ({"k1": "\ud800"}, {"k1": "\ud800"}),
        (nested_dicts(250, "a"), nested_dicts(250, "a")),
        (nested_dicts(250, "a"), nested_dicts(250, "b")),
    ]


def native_common(left: object, right: object) -> tuple[bool, object]:
    folded = NATIVE.profile_common(left, right)
    return folded if folded is not None else profiles._common(left, right)


def python_strip(row: dict[str, object], level: dict[str, object]) -> None:
    profiles._strip_level(row, level)


def native_strip(row: dict[str, object], level: dict[str, object]) -> None:
    if not NATIVE.profile_strip_level(row, level):
        profiles._strip_level(row, level)


def copy_row(row: dict[str, object]) -> dict[str, object]:
    out = dict(row)
    for key in ("details", profiles.ENVELOPE_KEY):
        if type(out.get(key)) is dict:
            out[key] = dict(out[key])
    return out


def compaction_rows(rng: random.Random, count: int) -> list[dict[str, object]]:
    base = {
        "validation_matrix": compaction_tree(rng),
        "parser": "p",
        "note": [{"k1": "a", "k2": compaction_tree(rng)}],
        "record_id": 1,
        "forensic_review": {"k1": compaction_tree(rng), "k2": "b"},
    }
    envelope = {"schema": "v1", "fields": {"k1": compaction_tree(rng)}}
    rows = []
    for index in range(count):
        details = {key: mutate(rng, value) for key, value in base.items()}
        details["record_id"] = index
        if rng.random() < 0.1:
            details.pop("parser")
        rows.append(
            {
                "artifact_type": rng.choice(("t1", "t2")),
                "path": rng.choice(("a.evtx", "b.evtx")),
                "details": details,
                profiles.ENVELOPE_KEY: mutate(rng, envelope) if rng.random() > 0.05 else "not-a-dict",
            }
        )
    return rows


def run_builder(rows: list[dict[str, object]], native: object) -> tuple[object, list[str]]:
    """``stream_artifact_collection``'s three passes over ``rows`` (in memory)."""
    builder = profiles.StreamingProfileBuilder(native=native, context_min_rows=4)
    lines = []
    for row in rows:
        builder.observe(row)
        lines.append(json.dumps(row, default=repr))
    builder.finish_types()
    for line in lines:
        row = json.loads(line)
        builder.strip_type(row)
        builder.observe_context(row)
    builder.finish_contexts()
    out = []
    for line in lines:
        row = json.loads(line)
        builder.strip_type(row)
        out.append(json.dumps(builder.strip_context(row), default=repr))
    return shape(builder.profiles), out


class CompactionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        if NATIVE is None:
            if REQUIRE_NATIVE:
                self.fail(f"rapidcore_native EVTX engine required: {NATIVE_REASON}")
            self.skipTest(f"rapidcore_native EVTX engine not built: {NATIVE_REASON}")

    def assert_common(self, left: object, right: object) -> None:
        expected_hoisted, expected = profiles._common(left, right)
        hoisted, actual = native_common(left, right)
        self.assertEqual(hoisted, expected_hoisted)
        self.assertEqual(shape(actual), shape(expected))
        self.assertEqual(aliases(actual, left, right), aliases(expected, left, right))

    def assert_strip(self, value: object, template: object) -> None:
        row = {"details": {"k0": "kept", "key": value}, profiles.ENVELOPE_KEY: {"key": value}}
        level = {"details": {"key": template}, profiles.ENVELOPE_KEY: {"key": template}}
        expected, actual = copy_row(row), copy_row(row)
        python_strip(expected, level)
        native_strip(actual, level)
        self.assertEqual(shape(actual), shape(expected))
        self.assertEqual(aliases(actual, value, template), aliases(expected, value, template))

    def assert_merge(self, template: object, residue: object) -> None:
        expected = profiles._merge(template, residue, copy_template=False)
        actual = NATIVE.profile_merge(template, residue, profiles._MISSING, profiles._merge_shared)
        self.assertEqual(shape(actual), shape(expected))
        self.assertEqual(aliases(actual, template, residue), aliases(expected, template, residue))

    def test_edge_cases(self) -> None:
        for left, right in compaction_edge_pairs():
            for a, b in ((left, right), (right, left)):
                with self.subTest(left=repr(a)[:50], right=repr(b)[:50]):
                    self.assert_common(a, b)
                    self.assert_strip(a, b)
                    self.assert_merge(a, b)
                    self.assert_merge(a, profiles._MISSING)

    def test_random_folds_residues_and_merges(self) -> None:
        rng = random.Random(2511)
        for _ in range(2000):
            column = [compaction_tree(rng)]
            column.extend(mutate(rng, column[0]) for _ in range(4))
            template = column[0]
            for value in column[1:]:
                self.assert_common(template, value)
                hoisted, folded = profiles._common(template, value)
                if not hoisted:
                    break
                template = folded
            for value in column:
                self.assert_strip(value, template)
                residue = profiles._residue(value, template)
                self.assert_merge(template, residue)

    def test_tracker_observe_matches(self) -> None:
        rng = random.Random(77)
        for _ in range(200):
            rows = compaction_rows(rng, 12)
            python = profiles._TemplateTracker(rows[0]["details"], profiles._any_key)
            native = profiles._TemplateTracker(rows[0]["details"], profiles._any_key, NATIVE)
            for row in rows:
                python.observe(row["details"], row[profiles.ENVELOPE_KEY])
                native.observe(row["details"], row[profiles.ENVELOPE_KEY])
                self.assertEqual(shape(native.templates), shape(python.templates))
                self.assertEqual(aliases(native.templates, *rows), aliases(python.templates, *rows))
                self.assertEqual(shape(native.envelope), shape(python.envelope))
                self.assertEqual(native.envelope_ok, python.envelope_ok)
            self.assertEqual(shape(native.profile()), shape(python.profile()))

    def test_streaming_builder_profiles_and_rows(self) -> None:
        rng = random.Random(4242)
        for _ in range(60):
            rows = compaction_rows(rng, rng.randint(2, 90))
            expected = run_builder(copy.deepcopy(rows), None)
            actual = run_builder(copy.deepcopy(rows), NATIVE)
            self.assertEqual(actual[0], expected[0])
            self.assertEqual(actual[1], expected[1])

    def test_eventlog_collection_jsonl_bytes_and_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tree"
            logs = root / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            for name, blob in build_edge_corpus().items():
                # Its lone-surrogate rows cannot be written as UTF-8: the whole
                # collection is failed-isolated with either engine.
                if name != "python-fallback-chunks.evtx":
                    (logs / name).write_bytes(blob)
            for detail in ("full", "triage"):
                outputs = {}
                for label, native in (("python", None), ("rust", NATIVE)):
                    records = Path(tmp) / f"{label}-{detail}.jsonl"
                    with unittest.mock.patch.object(artifacts, "_native_row_kernels", return_value=native):
                        payload = artifacts.run_artifact_collection(
                            root,
                            kind="eventlog",
                            records_path=records,
                            collector_options={"record_detail": detail, "evtx_engine": "python"},
                        )
                    outputs[label] = (payload, records.read_bytes())
                (python_payload, python_bytes), (rust_payload, rust_bytes) = outputs["python"], outputs["rust"]
                with self.subTest(detail=detail):
                    self.assertGreater(python_payload["record_count"], 2000)
                    self.assertEqual(rust_bytes, python_bytes)
                    self.assertEqual(
                        shape(rust_payload[profiles.PROFILES_PAYLOAD_KEY]),
                        shape(python_payload[profiles.PROFILES_PAYLOAD_KEY]),
                    )
                    hoisted = python_payload[profiles.PROFILES_PAYLOAD_KEY]
                    for line in python_bytes.splitlines():
                        row = json.loads(line)
                        for kwargs in ({}, {"include_type_templates": False}):
                            expected = profiles.expand_profile(row, hoisted, copy_templates=False, **kwargs)
                            actual = profiles.expand_profile(row, hoisted, copy_templates=False, native=NATIVE, **kwargs)
                            self.assertEqual(shape(actual), shape(expected))
                            self.assertEqual(aliases(actual, row, hoisted), aliases(expected, row, hoisted))

    def test_payload_readers_select_kernels_by_engine(self) -> None:
        payload = {"kind": "eventlog", "collector_options": {"evtx_engine": "rust"}}
        self.assertIs(profiles.payload_row_kernels(payload), NATIVE)
        self.assertIsNone(profiles.payload_row_kernels({**payload, "collector_options": {"evtx_engine": "python"}}))
        self.assertIsNone(profiles.payload_row_kernels({**payload, "kind": "registry"}))
        with unittest.mock.patch.dict(os.environ, {evtx_engine.EVTX_ENGINE_ENV: "rust"}):
            self.assertIs(profiles.payload_row_kernels({"kind": "eventlog"}), NATIVE)


if __name__ == "__main__":
    unittest.main()
