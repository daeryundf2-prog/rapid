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

JSON rows: ``dump_json_row`` must write the text ``artifacts._dump_row`` writes
(or decline, and Python then writes it or raises the same exception).

Triage: ``EventlogTriageProjector.project`` must return the dict
``triage_eventlog_details`` returns (or decline).

Without the native module these tests skip unless
``RAPIDTRIAGE_REQUIRE_NATIVE_EVTX=1``.
"""

from __future__ import annotations

import copy
import datetime as dt
import enum
import json
import os
import random
import string
import struct
import tempfile
import unittest
import unittest.mock
from collections import OrderedDict
from decimal import Decimal
from pathlib import Path, PurePosixPath

from evtx_engine_corpus import build_edge_corpus

from rapidtriage.artifacts.windows import evtx_engine
from rapidtriage.artifacts.windows.antiforensics import (
    redact_recovery_passwords,
    redact_recovery_passwords_in,
)
from rapidtriage.artifacts.windows.eventlog import (
    EVENTLOG_TRIAGE_PAYLOAD_MAX_CHARS,
    EVENTLOG_TRIAGE_TEXT_MAX_CHARS,
    WindowsEventLogProvider,
    native_triage_projector,
    triage_eventlog_details,
)
from rapidtriage.core import artifact_profiles as profiles
from rapidtriage.core import artifacts
from rapidtriage.core.json_safe import json_default

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


def without_file_rows(jsonl: bytes) -> list[bytes]:
    """JSONL lines except eventlog-file rows (where the Rust engine records itself)."""
    return [line for line in jsonl.splitlines() if json.loads(line).get("artifact_type") != "eventlog-file"]


def without_file_profile(hoisted: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in hoisted.items() if key != "eventlog-file"}


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
                (logs / name).write_bytes(blob)
            for detail in ("full", "triage"):
                outputs = {}
                # Python vs Rust row kernels on the same (Python-engine) rows, then the whole
                # Rust engine (decoder + kernels); the corpus includes the lone-surrogate chunks.
                for label, native, engine in (
                    ("python", None, "python"),
                    ("rust", NATIVE, "python"),
                    ("rust-engine", NATIVE, "rust"),
                ):
                    records = Path(tmp) / f"{label}-{detail}.jsonl"
                    with unittest.mock.patch.object(artifacts, "_native_row_kernels", return_value=native):
                        payload = artifacts.run_artifact_collection(
                            root,
                            kind="eventlog",
                            records_path=records,
                            collector_options={"record_detail": detail, "evtx_engine": engine},
                        )
                    outputs[label] = (payload, records.read_bytes())
                (python_payload, python_bytes), (rust_payload, rust_bytes) = outputs["python"], outputs["rust"]
                engine_payload, engine_bytes = outputs["rust-engine"]
                with self.subTest(detail=detail):
                    for payload in (python_payload, rust_payload, engine_payload):
                        self.assertEqual(payload["summary"]["collection_status"], "completed", payload["parser_errors"])
                    self.assertGreater(python_payload["record_count"], 2000)
                    self.assertEqual(rust_bytes, python_bytes)
                    self.assertEqual(
                        shape(rust_payload[profiles.PROFILES_PAYLOAD_KEY]),
                        shape(python_payload[profiles.PROFILES_PAYLOAD_KEY]),
                    )
                    # The Rust engine adds its provenance to eventlog-file rows only.
                    self.assertEqual(without_file_rows(engine_bytes), without_file_rows(python_bytes))
                    self.assertEqual(
                        shape(without_file_profile(engine_payload[profiles.PROFILES_PAYLOAD_KEY])),
                        shape(without_file_profile(python_payload[profiles.PROFILES_PAYLOAD_KEY])),
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


class _Int(enum.IntEnum):
    ONE = 1


class _Float(float):
    pass


class _Unknown:
    pass


def json_edge_values() -> list[object]:
    circular: list[object] = []
    circular.append(circular)
    return [
        0.0,
        -0.0,
        1e16,
        1e15,
        123456789012345678.0,
        1e-4,
        1e-5,
        1e22,
        1.5e300,
        5e-324,
        0.1 + 0.2,
        1 / 3,
        float("nan"),
        float("inf"),
        float("-inf"),
        0,
        -1,
        2**63 - 1,
        2**63,
        -(2**63),
        -(2**63) - 1,
        10**100,
        10**5000,
        True,
        False,
        None,
        "",
        '"\\\n\r\t\b\f\x00\x1f\x7f',
        "é한글😀\u2028\u2029",
        "\ud800 lone",
        _Str("subclass"),
        _Int.ONE,
        _Float(1.5),
        [],
        {},
        (),
        ("t", 1, [2.5]),
        _List([1]),
        _Dict(a=1),
        OrderedDict(a=1),
        {1: "int key"},
        {None: "none key"},
        {1.5: "float key"},
        {True: "bool key"},
        {_Str("k"): "str subclass key"},
        {"b": 1, "a": [{"c": None}]},
        nested_dicts(250, "deep"),
        circular,
        b"\x00bytes",
        bytearray(b"ba"),
        memoryview(b"mv"),
        dt.datetime(2025, 5, 27, 1, 51, 29, 123456, tzinfo=dt.timezone.utc),
        dt.date(2025, 5, 27),
        PurePosixPath("/var/log/x"),
        {"b", "a", 3},
        frozenset({"z"}),
        Decimal("1.10"),
        _Unknown(),
        {"nested": [b"x", {"when": dt.date(2020, 1, 1)}, {_Unknown()}]},
    ]


def random_float(rng: random.Random) -> float:
    roll = rng.random()
    if roll < 0.4:
        return struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]
    if roll < 0.7:
        return rng.uniform(-1e6, 1e6)
    return round(rng.uniform(-100, 100), rng.randint(0, 6))


def random_text(rng: random.Random) -> str:
    pool = string.printable + "\x00\x01\x1b\x7f\x85é한글\u2028😀\"\\"
    return "".join(rng.choice(pool) for _ in range(rng.randint(0, 24)))


def json_tree(rng: random.Random, depth: int = 0) -> object:
    roll = rng.random()
    if depth > 4 or roll < 0.5:
        return rng.choice(
            (
                None,
                True,
                False,
                rng.randint(-(2**70), 2**70),
                rng.randint(-1000, 1000),
                random_float(rng),
                random_text(rng),
                random_text(rng),
                b"\x01",
                dt.date(2024, 2, 29),
            )
        )
    if roll < 0.75:
        return {random_text(rng): json_tree(rng, depth + 1) for _ in range(rng.randint(0, 5))}
    items = [json_tree(rng, depth + 1) for _ in range(rng.randint(0, 5))]
    return tuple(items) if rng.random() < 0.2 else items


class JsonRowKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        if NATIVE is None:
            if REQUIRE_NATIVE:
                self.fail(f"rapidcore_native EVTX engine required: {NATIVE_REASON}")
            self.skipTest(f"rapidcore_native EVTX engine not built: {NATIVE_REASON}")
        self.dump = artifacts._row_dumper(NATIVE)

    def assert_same_text(self, value: object) -> None:
        try:
            expected: object = artifacts._dump_row(value)
        except (TypeError, ValueError, RecursionError) as exc:
            expected = (type(exc), str(exc))
        try:
            actual: object = self.dump(value)
        except (TypeError, ValueError, RecursionError) as exc:
            actual = (type(exc), str(exc))
        self.assertEqual(actual, expected)

    def test_edge_cases(self) -> None:
        for index, value in enumerate(json_edge_values()):
            with self.subTest(index=index, type=type(value).__name__):
                self.assert_same_text(value)
                self.assert_same_text({"details": {"value": value}, "list": [value, value]})

    def test_plain_rows_are_encoded_in_rust(self) -> None:
        for value in (1.5, -0.0, float("nan"), 2**80, "é\x01", ("t",), b"x", dt.date(2020, 1, 1), {"a": [None]}):
            self.assertIsNotNone(NATIVE.dump_json_row({"v": value}, json_default), repr(value))
        for value in ("\ud800", _Str("s"), _Dict(), {1: 2}, _Unknown()):
            self.assertIsNone(NATIVE.dump_json_row({"v": value}, json_default), repr(value))

    def test_random_trees(self) -> None:
        rng = random.Random(3110)
        for _ in range(5000):
            self.assert_same_text(json_tree(rng))

    def test_corpus_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            for name, blob in build_edge_corpus().items():
                (logs / name).write_bytes(blob)
            compared = 0
            for detail in ("full", "triage"):
                provider = WindowsEventLogProvider().with_options(record_detail=detail, evtx_engine="python")
                for item in provider.collect(Path(tmp)):
                    self.assert_same_text(artifacts._shallow_row(item))
                    compared += 1
            self.assertGreater(compared, 4000)


ENGINE_FIELDS = (
    "native_evtx_engine",
    "native_evtx_engine_requested",
    "native_evtx_engine_python_fallback_chunk_count",
    "native_evtx_engine_notice_ko",
)


def corpus_tree(tmp: str) -> Path:
    logs = Path(tmp) / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    for name, blob in build_edge_corpus().items():
        (logs / name).write_bytes(blob)
    return Path(tmp)


def triage_text(rng: random.Random) -> object:
    pieces = ("a", "é", "한", "😀", "\x00", "\x01", "\x1f", "\x7f", "\t", "\n", "\r", "e\u0301", "\u2028")
    size = rng.choice((0, 3, EVENTLOG_TRIAGE_TEXT_MAX_CHARS - 1, EVENTLOG_TRIAGE_TEXT_MAX_CHARS + 2))
    if rng.random() < 0.05:
        size = EVENTLOG_TRIAGE_PAYLOAD_MAX_CHARS + 3
    return "".join(rng.choice(pieces) for _ in range(size))


def triage_value(rng: random.Random) -> object:
    return rng.choice(
        (
            None,
            "",
            [],
            {},
            (),
            0,
            False,
            True,
            0.0,
            float("nan"),
            7,
            2**70,
            "x",
            triage_text(rng),
            triage_text(rng),
            ["a", 1],
            {"k": "v"},
            b"\x01",
            _Str("s"),
            "\ud800",
        )
    )


def mutate_triage_details(rng: random.Random, details: dict[str, object]) -> dict[str, object]:
    out = copy.deepcopy(details)
    keys = list(out) + ["command_line", "raw_preview", "rule", "event_message", "user_name", "logon_id", "script_block_text"]
    for key in rng.sample(keys, k=min(len(keys), rng.randint(1, 6))):
        out[key] = triage_value(rng)
    roll = rng.random()
    if roll < 0.2:
        out["event_data_items"] = [
            rng.choice(({"name": triage_value(rng), "value": triage_value(rng)}, "not-a-mapping", {}))
            for _ in range(rng.choice((0, 2, 70)))
        ]
    elif roll < 0.4:
        data_key = "binxml_event_data_fields" if out.get("parser") == "windows-eventlog-evtx-native" else "data"
        out[data_key] = {
            rng.choice(("CommandLine", "ScriptBlockText", "İmagePath", "\u212aey", "Name", "x" * 3, 5)): rng.choice(
                (triage_text(rng), {"b": [1, b"x"], "a": None}, ["z", 2.5], 3, None, ("t",))
            )
            for _ in range(rng.choice((1, 3, 70)))
        }
    elif roll < 0.55:
        out["binxml_event_data_fields"] = {}
        out["evtx_binxml"] = {
            "value_fields": rng.choice(
                (
                    [
                        {"element_path": rng.choice(("Event/System/Provider", "Event/EventData", None)), "text": triage_value(rng)}
                        for _ in range(rng.choice((0, 3, 70)))
                    ],
                    (),
                    None,
                    "text",
                )
            )
        }
        out["extracted_strings"] = rng.choice(([triage_text(rng) for _ in range(20)], [1, "", "x"], (), None, "abc"))
    elif roll < 0.7:
        context = dict(out["evtx_chunk_context"]) if isinstance(out.get("evtx_chunk_context"), dict) else {}
        context["chunk_offset"] = rng.choice((0, 4095, 4096, 4096 + 65536 * 3, "  8192 ", "1_0000", "٤٠٩٦", 5000.0, True, 2**70, -5, None, "x"))
        context["chunk_boundary_status"] = triage_value(rng)
        out["evtx_chunk_context"] = context
        out["evtx_record_integrity"] = rng.choice(({"trailing_size_valid": rng.choice((1, 0, "", "yes"))}, [], None))
    elif roll < 0.8:
        out["rule"] = rng.choice(({"title": "", "id": 0}, {"title": "", "id": "R1"}, {"title": "T"}, _Dict(title="T"), []))
    elif roll < 0.9:
        out["parser"] = rng.choice(("windows-eventlog-evtx-native", _Str("windows-eventlog-evtx-native"), "other", None))
    return out


class TriageProjectionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        if NATIVE is None:
            if REQUIRE_NATIVE:
                self.fail(f"rapidcore_native EVTX engine required: {NATIVE_REASON}")
            self.skipTest(f"rapidcore_native EVTX engine not built: {NATIVE_REASON}")
        self.projector = native_triage_projector(NATIVE)

    def full_event_details(self) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            provider = WindowsEventLogProvider().with_options(record_detail="full", evtx_engine="python")
            return [
                item.details for item in provider.collect(corpus_tree(tmp)) if item.artifact_type == "eventlog-event"
            ]

    def assert_same_projection(self, details: object) -> bool:
        try:
            expected: object = shape(triage_eventlog_details(details))
        except Exception as exc:  # the native path must raise the same
            expected = (type(exc), str(exc))
        projected = self.projector.project(details)
        try:
            actual: object = shape(projected if projected is not None else triage_eventlog_details(details))
        except Exception as exc:
            actual = (type(exc), str(exc))
        self.assertEqual(actual, expected)
        return projected is not None

    def test_corpus_details(self) -> None:
        rows = self.full_event_details()
        native = sum(self.assert_same_projection(details) for details in rows)
        self.assertGreater(len(rows), 1000)
        # Lone-surrogate references are now plain text, so no corpus row needs the Python projection.
        self.assertEqual(native, len(rows))

    def test_mutated_details(self) -> None:
        rng = random.Random(8655)
        rows = self.full_event_details()
        native = 0
        for _ in range(4000):
            native += self.assert_same_projection(mutate_triage_details(rng, rng.choice(rows)))
        self.assertGreater(native, 1000)

    def test_non_dict_details(self) -> None:
        for details in ({}, _Dict(parser="x"), {"parser": "windows-eventlog-evtx-native"}):
            self.assert_same_projection(details)

    def test_provider_triage_rows_identical_across_engines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = corpus_tree(tmp)
            rows = {}
            for engine in ("python", "rust"):
                provider = WindowsEventLogProvider().with_options(record_detail="triage", evtx_engine=engine)
                rows[engine] = [artifacts._dump_row(artifacts._shallow_row(item)) for item in provider.collect(root)]
        python_rows, rust_rows = rows["python"], rows["rust"]
        self.assertEqual(len(rust_rows), len(python_rows))
        for index, (left, right) in enumerate(zip(python_rows, rust_rows)):
            left_row, right_row = json.loads(left), json.loads(right)
            if right_row["artifact_type"] == "eventlog-file":
                self.assertEqual(right_row["details"]["native_evtx_engine"], "rust")
                for key in ENGINE_FIELDS:
                    right_row["details"].pop(key, None)
                right = artifacts._dump_row(right_row)
                left = artifacts._dump_row(left_row)
            self.assertEqual(right, left, f"row {index}")


if __name__ == "__main__":
    unittest.main()
