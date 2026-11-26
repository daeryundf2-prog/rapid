"""Python vs Rust EVTX decoder differential (opt-in ``evtx_engine=rust``).

Every row produced with the native ``rapidcore_native.EvtxChunkDecoder`` must
equal the Python decoder's row field by field: event rows, chunk and
record-candidate structure rows, the eventlog-file row (apart from the engine
provenance fields it adds), detections, logon sessions and the summary. The
corpus is synthetic (``tests/evtx_engine_corpus.py``) plus the existing EVTX
fixture builders and seeded byte-level fuzzing of the decoder input.

The native module is built by ``scripts/build-native-accel.py``; without it
the differential tests skip unless ``RAPIDTRIAGE_REQUIRE_NATIVE_EVTX=1`` (the
CI native job sets it so a broken build cannot pass as a skip).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import random
import struct
import sys
import tempfile
import types
import unittest
import unittest.mock
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from carving_r3_fixtures import evtx as carving_evtx
from evtx_engine_corpus import (
    CHUNK_SIZE,
    Chunk,
    Event,
    add_event,
    build_edge_corpus,
    file_bytes,
    iter_mixed_chunks,
    mutate_chunks,
    real64,
)
from windows_artifact_fixtures import (
    build_chunk_template_evtx,
    build_corrupt_evtx_record_candidate,
    build_evtx_with_checked_chunk,
    build_evtx_with_slack_record,
    build_minimal_evtx,
    build_template_evtx,
)

from rapidtriage.artifacts.windows import evtx_engine
from rapidtriage.artifacts.windows.eventlog import (
    EvtxChunkDecoder,
    EvtxDecodeError,
    WindowsEventLogProvider,
    collect_native_evtx_events,
    iter_evtx_chunk_record_slots,
    render_evtx_element_xml,
)
from rapidtriage.cli.helpers import eventlog_collector_options
from rapidtriage.core.artifacts import _dump_row, _row_dumper
from rapidtriage.core.json_safe import json_default

NATIVE, NATIVE_REASON = evtx_engine.load_native_evtx_decoder()
REQUIRE_NATIVE = os.environ.get("RAPIDTRIAGE_REQUIRE_NATIVE_EVTX") == "1"
DECODE_ERRORS = (EvtxDecodeError, IndexError, struct.error, ValueError, RecursionError, UnicodeError)
ENGINE_FIELDS = (
    "native_evtx_engine",
    "native_evtx_engine_requested",
    "native_evtx_engine_python_fallback_chunk_count",
    "native_evtx_engine_notice_ko",
)
WHEN = datetime(2025, 5, 27, 1, 51, 29, tzinfo=timezone.utc)


def fixture_corpus() -> dict[str, bytes]:
    corpus = build_edge_corpus()
    corpus.update(
        {
            "fixture-minimal.evtx": build_minimal_evtx(7, WHEN, ["Security", "4624", "관리자", "192.0.2.10"]),
            "fixture-template.evtx": build_template_evtx(8, WHEN, "powershell.exe -enc AAAA"),
            "fixture-slack.evtx": build_evtx_with_slack_record(9, WHEN, ["System", "7045", "evil.sys"]),
            "fixture-checked-chunk.evtx": build_evtx_with_checked_chunk(10, WHEN, ["Security", "4625", "admin"]),
            "fixture-chunk-template.evtx": build_chunk_template_evtx(11, WHEN, "cmd.exe /c whoami"),
            "fixture-corrupt-candidate.evtx": build_corrupt_evtx_record_candidate(12, WHEN, ["Security", "1102"]),
            "fixture-carving-empty-chunks.evtx": carving_evtx(2),
        }
    )
    return corpus


def row_json(row: object) -> str:
    """The row as written to disk (key order kept; NaN-safe equality as text)."""
    return json.dumps(dataclasses.asdict(row), ensure_ascii=False, default=json_default)


def row_payload(row: object) -> dict[str, object]:
    return json.loads(row_json(row))


def field_differences(expected: Mapping[str, object], actual: Mapping[str, object], prefix: str = "") -> list[str]:
    differences = []
    for key in list(expected) + [key for key in actual if key not in expected]:
        left, right = expected.get(key, "<missing>"), actual.get(key, "<missing>")
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            differences.extend(field_differences(left, right, f"{prefix}{key}."))
        elif left != right or (key in expected) != (key in actual):
            differences.append(f"{prefix}{key}: {str(left)[:160]!r} != {str(right)[:160]!r}")
    if list(expected) != list(actual) and not differences:
        differences.append(f"{prefix}<key order>")
    return differences


def compare_row_streams(expected_rows: Iterable[object], actual_rows: Iterable[object]) -> tuple[int, list[str]]:
    expected = [row_json(row) for row in expected_rows]
    actual = [row_json(row) for row in actual_rows]
    problems = [] if len(expected) == len(actual) else [f"row count {len(expected)} != {len(actual)}"]
    for index, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            left_row, right_row = json.loads(left), json.loads(right)
            differences = field_differences(left_row, right_row) or ["<serialization>"]
            problems.extend(f"row {index} ({left_row.get('artifact_type')}): {item}" for item in differences[:10])
    return len(expected), problems


def normalized_decoded(decoded: Mapping[str, object]) -> dict[str, object]:
    out = dict(decoded)
    root = out.pop("root", None)
    if root is not None:
        out["rendered_xml"] = render_evtx_element_xml(root)
    out["system_raw"] = {
        key: None if isinstance(value, tuple) else value for key, value in dict(out.get("system_raw") or {}).items()
    }
    return out


def decode_outcomes(chunk: bytes, decoder: object) -> list[object]:
    outcomes: list[object] = []
    for slot in iter_evtx_chunk_record_slots(chunk, active=True):
        if not slot.parseable:
            continue
        try:
            outcomes.append(("ok", normalized_decoded(decoder.decode_record(slot.relative_offset, slot.declared_size))))
        except DECODE_ERRORS as exc:
            outcomes.append((type(exc).__name__, str(exc)))
    outcomes.append(("template_parse_count", decoder.template_parse_count))
    return outcomes


def iter_chunks(blob: bytes) -> Iterable[bytes]:
    for offset in range(4096, len(blob) - 8, CHUNK_SIZE):
        if blob[offset : offset + 8] == b"ElfChnk\x00":
            yield bytes(blob[offset : offset + CHUNK_SIZE])


class NativeEvtxTestCase(unittest.TestCase):
    def setUp(self) -> None:
        if NATIVE is None:
            if REQUIRE_NATIVE:
                self.fail(f"rapidcore_native EVTX decoder required: {NATIVE_REASON}")
            self.skipTest(f"rapidcore_native EVTX decoder not built: {NATIVE_REASON}")
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, blob: bytes) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        return path

    def assert_same_rows(self, path: Path, **kwargs: object) -> int:
        python_stats: dict[str, int] = {}
        native_stats: dict[str, int] = {}
        count, problems = compare_row_streams(
            collect_native_evtx_events(path, stats=python_stats, **kwargs),
            collect_native_evtx_events(path, stats=native_stats, native_decoder=NATIVE, **kwargs),
        )
        self.assertEqual(problems, [], f"{path.name} {kwargs}")
        native_stats.pop("native_decoder_python_fallback_chunk_count", None)
        self.assertEqual(python_stats, native_stats, path.name)
        return count


class CorpusRowDiffTests(NativeEvtxTestCase):
    def test_corpus_rows_identical_in_full_and_triage_detail(self) -> None:
        compared = 0
        for name, blob in fixture_corpus().items():
            path = self.write(name, blob)
            for detail in ("full", "triage"):
                with self.subTest(file=name, detail=detail):
                    compared += self.assert_same_rows(path, record_detail=detail, structure_rows=True)
        self.assertGreater(compared, 2500)

    def test_rust_decodes_corpus_without_python_except_marked_chunks(self) -> None:
        stats: dict[str, int] = {}
        path = self.write("fallback.evtx", build_edge_corpus()["python-fallback-chunks.evtx"])
        rows = list(collect_native_evtx_events(path, stats=stats, native_decoder=NATIVE, record_detail="triage"))
        self.assertEqual(stats["native_decoder_python_fallback_chunk_count"], 3)
        self.assertEqual(stats["decoded_record_count"] + stats.get("fallback_record_count", 0), 15)
        self.assertTrue(rows)
        stats = {}
        path = self.write("mixed.evtx", file_bytes(list(iter_mixed_chunks(300, seed=9))))
        list(collect_native_evtx_events(path, stats=stats, native_decoder=NATIVE, record_detail="triage"))
        self.assertNotIn("native_decoder_python_fallback_chunk_count", stats)
        self.assertEqual(stats["live_record_count"], 300)

    def test_fuzzed_inputs_decode_identically(self) -> None:
        rng = random.Random(20261124)
        seeds = [blob for name, blob in build_edge_corpus().items() if name in {"multi-chunk-slack.evtx", "value-types-and-tokens.evtx", "inline-names.evtx"}]
        decoded_records = 0
        for variant in range(120):
            blob = mutate_chunks(rng.choice(seeds), rng, mutations=rng.randint(1, 12))
            for chunk in iter_chunks(blob):
                expected = decode_outcomes(chunk, EvtxChunkDecoder(chunk))
                actual = decode_outcomes(chunk, evtx_engine.NativeEvtxChunkDecoder(NATIVE, chunk, render_xml=True))
                decoded_records += len(expected)
                if expected != actual:
                    mismatch = next(index for index, (left, right) in enumerate(zip(expected, actual)) if left != right)
                    self.fail(f"variant {variant} slot {mismatch}: {str(expected[mismatch])[:400]} != {str(actual[mismatch])[:400]}")
            if variant % 20 == 0:
                path = self.write(f"fuzz-{variant}.evtx", blob)
                self.assert_same_rows(path, record_detail="full", structure_rows=True)
        self.assertGreater(decoded_records, 10_000)


class ProviderEngineSwitchTests(NativeEvtxTestCase):
    def collect_rows(self, root: Path, **options: object) -> list[dict[str, object]]:
        provider = WindowsEventLogProvider().with_options(structure_rows=True, record_detail="full", **options)
        return [row_payload(row) for row in provider.collect(root)]

    def test_provider_rows_identical_and_file_row_records_engine(self) -> None:
        logs = self.tmp / "Windows" / "System32" / "winevt" / "Logs"
        for name, blob in build_edge_corpus().items():
            self.write(f"Windows/System32/winevt/Logs/{name}", blob)
        python_rows = self.collect_rows(self.tmp, evtx_engine="python")
        native_rows = self.collect_rows(self.tmp, evtx_engine="rust")
        self.assertTrue(logs.is_dir())
        file_rows = [row for row in native_rows if row["artifact_type"] == "eventlog-file"]
        self.assertTrue(file_rows)
        for row in file_rows:
            self.assertEqual(row["details"]["native_evtx_engine"], "rust")
            self.assertEqual(row["details"]["native_evtx_engine_requested"], "rust")
            self.assertNotIn("native_evtx_engine_notice_ko", row["details"])
            for key in ENGINE_FIELDS:
                row["details"].pop(key, None)
        fallback_row = next(row for row in file_rows if row["path"].endswith("python-fallback-chunks.evtx"))
        self.assertTrue(fallback_row)
        for row in python_rows:
            self.assertFalse(set(ENGINE_FIELDS) & set(row["details"]))
        self.assertEqual(len(python_rows), len(native_rows))
        problems = [
            f"row {index}: {item}"
            for index, (left, right) in enumerate(zip(python_rows, native_rows))
            for item in field_differences(left, right)
        ]
        self.assertEqual(problems, [])

    def test_environment_variable_selects_engine(self) -> None:
        self.write("Windows/System32/winevt/Logs/Security.evtx", build_edge_corpus()["inline-names.evtx"])
        with unittest.mock.patch.dict(os.environ, {evtx_engine.EVTX_ENGINE_ENV: "rust"}):
            provider = WindowsEventLogProvider()
            self.assertIn("evtx_engine=rust", provider.options_key)
            rows = [row_payload(row) for row in provider.collect(self.tmp)]
        file_row = next(row for row in rows if row["artifact_type"] == "eventlog-file")
        self.assertEqual(file_row["details"]["native_evtx_engine"], "rust")
        self.assertEqual(file_row["details"]["native_evtx_engine_python_fallback_chunk_count"], 0)

    def test_real64_ties_spell_like_python_repr(self) -> None:
        # 2**50 + 0.25 lies exactly between the shortest spellings ...624.2 and ...624.3;
        # CPython's repr keeps the even digit. Numeric equality would hide the defect.
        value = float.fromhex("0x1.0000000000001p+50")
        cases = {
            value: "1125899906842624.2",
            -value: "-1125899906842624.2",
            math.nextafter(value, 0.0): "1125899906842624",
            math.nextafter(value, math.inf): "1125899906842624.5",
        }
        dump_native = _row_dumper(NATIVE)
        for number, text in cases.items():
            with self.subTest(number=number.hex()):
                literal = text if "." in text else f"{text}.0"
                self.assertEqual(_dump_row({"v": number}), f'{{"v":{literal}}}')
                self.assertEqual(dump_native({"v": number}), f'{{"v":{literal}}}')
                chunk = Chunk()
                event = Event(1, 133801632000000009, provider="fixture", computer="test.invalid", event_id=17, data=[("Counter", real64(number))])
                self.assertTrue(add_event(chunk, event))
                root = self.tmp / number.hex()
                path = root / "Windows/System32/winevt/Logs/Application.evtx"
                path.parent.mkdir(parents=True)
                path.write_bytes(file_bytes([chunk.finish()], next_record_id=2))
                rows = {}
                for engine in ("python", "rust"):
                    (row,) = (row for row in self.collect_rows(root, evtx_engine=engine) if row["artifact_type"] == "eventlog-event")
                    self.assertEqual(row["details"]["data"]["Counter"], text, engine)
                    self.assertIn(f'<Data Name="Counter">{text}</Data>', row["details"]["event_message"], engine)
                    rows[engine] = row
                self.assertEqual(json.dumps(rows["rust"], ensure_ascii=False), json.dumps(rows["python"], ensure_ascii=False))


class EngineSelectionTests(unittest.TestCase):
    def test_default_is_python_without_provenance_fields(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(evtx_engine.EVTX_ENGINE_ENV, None)
            selection = evtx_engine.resolve_evtx_engine(None)
            self.assertEqual(WindowsEventLogProvider().options_key, "")
        self.assertEqual((selection.requested, selection.active), ("python", "python"))
        self.assertIsNone(selection.native_module)
        self.assertEqual(selection.file_row_fields({}), {})

    def test_rust_without_module_falls_back_with_notice(self) -> None:
        with unittest.mock.patch("rapidtriage.core.native_accel.extension", return_value=None):
            selection = evtx_engine.resolve_evtx_engine("rust")
        self.assertEqual((selection.requested, selection.active), ("rust", "python"))
        fields = selection.file_row_fields({})
        self.assertEqual(fields["native_evtx_engine"], "python")
        self.assertIn("빌드되지 않았습니다", fields["native_evtx_engine_notice_ko"])

    def test_stale_module_falls_back_with_notice(self) -> None:
        stale = types.SimpleNamespace(
            EvtxChunkDecoder=object,
            evtx_decoder_version=lambda: "evtx-chunk-binxml-decoder-v1",
            **dict.fromkeys(evtx_engine.NATIVE_ENGINE_FUNCTIONS),
        )
        with unittest.mock.patch("rapidtriage.core.native_accel.extension", return_value=stale):
            selection = evtx_engine.resolve_evtx_engine("rust")
        self.assertEqual(selection.active, "python")
        self.assertIn("다시 빌드", selection.notice_ko)
        old = types.SimpleNamespace(scan_evtx=None)
        with unittest.mock.patch("rapidtriage.core.native_accel.extension", return_value=old):
            self.assertIn("이전 빌드", evtx_engine.resolve_evtx_engine("rust").notice_ko)

    def test_unknown_environment_value_falls_back_with_notice(self) -> None:
        with unittest.mock.patch.dict(os.environ, {evtx_engine.EVTX_ENGINE_ENV: "Cython"}):
            selection = evtx_engine.resolve_evtx_engine(None)
        self.assertEqual((selection.requested, selection.active), ("cython", "python"))
        self.assertIn("알 수 없는", selection.file_row_fields({})["native_evtx_engine_notice_ko"])

    def test_option_validation_and_cli_flag(self) -> None:
        with self.assertRaises(ValueError):
            WindowsEventLogProvider(evtx_engine="java")
        provider = WindowsEventLogProvider().with_options(evtx_engine="RUST")
        self.assertEqual(provider.evtx_engine, "rust")
        self.assertEqual(provider.with_options(record_detail="triage").evtx_engine, "rust")
        namespace = argparse.Namespace(eventlog_structure_rows=False, eventlog_record_detail=None, eventlog_evtx_engine="rust")
        self.assertEqual(eventlog_collector_options(namespace), {"evtx_engine": "rust"})

    def test_requested_rust_without_module_keeps_python_rows(self) -> None:
        corpus = build_edge_corpus()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
            path.parent.mkdir(parents=True)
            path.write_bytes(corpus["inline-names.evtx"])
            with unittest.mock.patch("rapidtriage.core.native_accel.extension", return_value=None):
                rows = [row_payload(row) for row in WindowsEventLogProvider(evtx_engine="rust").collect(Path(tmp))]
            baseline = [row_payload(row) for row in WindowsEventLogProvider(evtx_engine="python").collect(Path(tmp))]
        file_row = next(row for row in rows if row["artifact_type"] == "eventlog-file")
        self.assertEqual(file_row["details"].pop("native_evtx_engine"), "python")
        self.assertEqual(file_row["details"].pop("native_evtx_engine_requested"), "rust")
        self.assertTrue(file_row["details"].pop("native_evtx_engine_notice_ko"))
        self.assertEqual(rows, baseline)


if __name__ == "__main__":
    unittest.main()
