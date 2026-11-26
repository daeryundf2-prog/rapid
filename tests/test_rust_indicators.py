"""Differential checks for the optional Rust candidate matcher."""

from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import indicator_kernel
from rapidtriage.core.indicators import (
    HASH_RE,
    IP_RE,
    MAX_SCALAR_LENGTH,
    URL_RE,
    build_indicator_summary,
)
from rapidtriage.core.rules import Rule, RuleSet
from rapidtriage.core.run.summary import build_run_disclosures
from tests.schema_validation import validate

_SWITCH = "RAPIDTRIAGE_RUST_INDICATORS"
_SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "rapidtriage-output-samples"
_DIGEST = "0123456789abcdef" * 4


def generated_rows():
    """Exercise candidate overlap, policy rejection, traversal limits and citations."""
    url = "https://case.example/overlap"
    values = [
        f"HTTPS://192.0.2.17/{_DIGEST} {url} HTTPS://CASE.EXAMPLE/OVERLAP.;",
        f"{url}\x00tail {url}\x1ctrail {url}\x1ftrail",
        f"hash={_DIGEST[:32]} sha1={_DIGEST[:40]} sha256={_DIGEST}",
        "host 192.0.2.17 192.00.2.17 999.0.0.1 build 2.4.5.6",
        f"한192.0.2.17 192.0.2.17글 e\u0301192.0.2.17 {url}",
        bytes.fromhex("c7d1b1db").decode("cp949") + " http://한글.example/경로",
        f"\ud800 {url} \udfff",
        f"httpſ://fold.example/a\u00a0{url} １９２.０.２.１７",
    ]
    for length in (MAX_SCALAR_LENGTH - 1, MAX_SCALAR_LENGTH, MAX_SCALAR_LENGTH + 1, 65536):
        prefix = f"https://size{length}.example/ "
        values.append(prefix.ljust(length, "x"))
    return [
        {
            "path": f"/fixture/{index}",
            "kind": "text",
            "body/~": text,
            "details": {"sha256": _DIGEST, "address": "ip 192.0.2.17"},
            "source_hashes": {"ignored": "https://ignored.example/"},
            # Rows with imported scanner hits are scanned by Python in JSONL mode.
            **({"ioc_hits": [{"rule_id": "fixture", "type": "keyword", "value": "Fixture", "count": 2}]}
               if index % 2 == 0 else {}),
        }
        for index, text in enumerate(values)
    ]


def summary(outputs, enabled, **options):
    with mock.patch.dict(os.environ, {_SWITCH: "1" if enabled else "0"}):
        result = build_indicator_summary({"outputs": outputs}, **options)
    schema = Path(__file__).resolve().parents[1] / "rapidtriage" / "schemas" / "indicators.schema.json"
    validate(result, json.loads(schema.read_text(encoding="utf-8")))
    # Invocation time is the only per-call value in the reference summary.
    result.pop("generated_at")
    return result


class RustIndicatorDifferentialTests(unittest.TestCase):
    def setUp(self):
        worker = indicator_kernel.worker_path()
        if not worker or not Path(worker).is_file():
            message = "build the rapid-indicators release worker to run the native differential"
            if os.environ.get(_SWITCH) == "1":
                self.fail(message)
            self.skipTest(message)

    def compare(self, outputs, **options):
        reference = summary(outputs, False, **options)
        native = summary(outputs, True, **options)
        metadata = native.pop("indicator_kernel")
        self.assertIsNone(metadata["fallback_reason"])
        self.assertGreater(metadata["native_rows"], 0)
        self.assertEqual(reference, native)
        return native, metadata

    def test_existing_synthetic_output_samples_match(self):
        outputs = {
            "docs": _SAMPLES / "docs-keyword-search.json",
            "files": _SAMPLES / "files-default-scan.json",
            "artifacts_manifest": _SAMPLES / "manifest-windows-artifacts.json",
        }
        result, _ = self.compare(outputs, max_indicators=None)
        self.assertTrue(result["indicators"])

    def test_rule_and_feed_enriched_rows_match(self):
        rules = RuleSet("fixture", "json", (Rule("fixture-domain", "", domains=("pivot.example",)),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs.json"
            path.write_text('{"url": "https://pivot.example/Item"}', encoding="utf-8")
            feed = Path(directory) / "feed.json"
            feed.write_text('[{"type": "domain", "value": "pivot.example", "severity": "high"}]', encoding="utf-8")
            result, _ = self.compare({"docs": path}, rule_set=rules, ti_feeds=[feed])
        domain = next(row for row in result["indicators"] if row["type"] == "domain")
        self.assertEqual(domain["matched_rules"], ["fixture-domain"])
        self.assertEqual(domain["ti_enrichment"]["matched_on"], "exact")

    def test_ascii_candidate_spans_match_python_in_family_order(self):
        rows = [
            f"{char}192.0.2.17{char}{_DIGEST}{char}hTtp://a.example{char}https://b.example/"
            for char in map(chr, range(128))
        ]
        rows += [f"x.{_DIGEST[:length]}-{'a' * length}." for length in range(30, 67)]
        rows += [
            "1.2.3.4.5 1000.2.3.4 1.2.3.4444.5.6.7 1.2.3..4 1..2.3.4",
            "http:// https://() http://https://x.example/ httpthttp://a",
            f"https://192.0.2.17/{_DIGEST}?next=https://192.0.2.18",
            "",
        ]
        expected = {}
        for index, text in enumerate(rows):
            spans = [
                (family, match.start(), match.end())
                for family, pattern in enumerate((URL_RE, IP_RE, HASH_RE))
                for match in pattern.finditer(text)
            ]
            if spans:
                expected[index] = spans
        self.assertEqual(indicator_kernel.scan_batch(rows), expected)

    def test_late_worker_error_preserves_completed_batch_and_replays_the_rest(self):
        rows = [{"url": f"https://row{index}.example/"} for index in range(10)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs.json"
            path.write_text(json.dumps({"results": rows}), encoding="utf-8")
            outputs = {"docs": path}
            reference = summary(outputs, False)
            scan = indicator_kernel.scan_batch
            batches = []

            def fail_second_batch(texts):
                batches.append(texts)
                if len(batches) == 1:
                    return scan(texts)
                raise OSError("worker exited")

            with mock.patch.object(indicator_kernel, "_MAX_ROWS", 3):
                with mock.patch.object(indicator_kernel, "scan_batch", side_effect=fail_second_batch):
                    actual = summary(outputs, True)
        metadata = actual.pop("indicator_kernel")
        self.assertEqual(len(batches), 2)
        self.assertEqual(metadata["native_rows"], 3)
        self.assertEqual(metadata["python_rows"], 7)
        self.assertTrue(metadata["fallback_reason"])
        self.assertEqual(reference, actual)

    def test_mixed_rows_match_in_each_traversal(self):
        rows = generated_rows()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.json"
            records_path = path.with_suffix(".jsonl")
            records_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            for mode in ("inline", "stream", "jsonl"):
                with self.subTest(mode=mode):
                    head = {"artifacts": rows}
                    if mode == "jsonl":
                        head = {"artifacts": [], "records_file": records_path.name}
                    path.write_text(json.dumps(head), encoding="utf-8")
                    name = "artifacts_fixture"
                    result, metadata = self.compare(
                        {name: path},
                        streamed_outputs={name} if mode == "stream" else set(),
                        max_sources_per_indicator=2,
                        max_indicators=None,
                    )
                    self.assertGreater(metadata["python_rows"], 0)
                    self.assertTrue(result["ioc_scanner_hits"])
                    self.assertGreater(result["summary"]["sources_truncated_indicator_count"], 0)
                    values = {row["value"] for row in result["indicators"]}
                    self.assertIn(f"https://size{MAX_SCALAR_LENGTH}.example/", values)
                    self.assertNotIn(f"https://size{MAX_SCALAR_LENGTH + 1}.example/", values)


class RustIndicatorFallbackTests(unittest.TestCase):
    def test_failed_native_batch_replays_every_row_through_python(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs.json"
            path.write_text(json.dumps({"results": generated_rows()}), encoding="utf-8")
            outputs = {"docs": path}
            reference = summary(outputs, False, max_indicators=4)
            for error in (FileNotFoundError("missing worker"), ValueError("invalid reply")):
                with self.subTest(error=type(error).__name__):
                    with mock.patch.object(indicator_kernel, "scan_batch", side_effect=error):
                        actual = summary(outputs, True, max_indicators=4)
                    metadata = actual.pop("indicator_kernel")
                    self.assertTrue(metadata["fallback_reason"])
                    self.assertEqual(metadata["native_rows"], 0)
                    self.assertGreater(metadata["python_rows"], 0)
                    self.assertEqual(reference, actual)

    def test_truncated_worker_reply_never_commits_its_valid_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs.json"
            path.write_text('{"url": "https://prefix.example/"}', encoding="utf-8")
            outputs = {"docs": path}
            reference = summary(outputs, False)
            partial = b"RIND1\n" + struct.pack("<IIII", 0, 0, 0, len("https://prefix.example/"))
            with mock.patch.object(indicator_kernel, "worker_path", return_value=path):
                with mock.patch.object(indicator_kernel.subprocess, "run", return_value=mock.Mock(stdout=partial)):
                    actual = summary(outputs, True)
            metadata = actual.pop("indicator_kernel")
            self.assertEqual(metadata["fallback_reason"], "invalid-worker-response")
            self.assertEqual(metadata["native_rows"], 0)
            disclosures = build_run_disclosures(
                files_payload={}, docs_payload={}, timeline_payload={}, artifact_payloads={}, steps=[],
                indicators_payload={**actual, "indicator_kernel": metadata},
            )
            self.assertEqual(disclosures["indicators"]["kernel"], metadata)
            self.assertEqual(reference, actual)

    def test_default_path_never_invokes_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs.json"
            path.write_text('{"body": "https://default.example/"}', encoding="utf-8")
            with mock.patch.dict(os.environ):
                os.environ.pop(_SWITCH, None)
                with mock.patch.object(indicator_kernel, "scan_batch") as scan:
                    result = build_indicator_summary({"outputs": {"docs": path}})
            scan.assert_not_called()
            self.assertNotIn("indicator_kernel", result)
            self.assertTrue(result["indicators"])


_IP = "192.0.2.17"
_URL = "https://case.example/a"
_TERMINATORS = ("\n", "\r\n", "\r")


def adversarial_jsonl_lines():
    """Raw JSONL lines, each inside the worker's exact subset or returned to Python."""
    hit = f"see {_IP} {_URL} sha256={_DIGEST}"
    deep = '{"a":' * 150 + f'"{_IP}"' + "}" * 150
    lines = [
        json.dumps({"path": "p", "source_path": 5, "artifact_type": "t", "kind": True, "event_type": False,
                    "source": "", "parser": None, "m": hit}),
        json.dumps({"path": {"a": 1}, "m": _URL}),
        json.dumps({"source": [], "m": _URL}),
        json.dumps({"kind": {}, "event_type": [1], "m": _IP}),
        json.dumps({"path": 0, "kind": -1, "m": _IP}),
        '{"path": -0, "m": "10.1.2.3"}',
    ]
    for artifact_type in ('"registry-hive-cell"', '"registry-key-tree-node"', "0", "-0", "false", "true", "[]",
                          "{}", '["x"]', '{"a":1}', "5", '""', "null"):
        lines.append(f'{{"artifact_type": {artifact_type}, "m": "{hit}"}}')
    lines += [
        '{"n": 12345678901234567890123456789012, "o": -12345678901234567890123456789012, "z": -0}',
        '{"n": ' + "1" * 640 + ', "m": "' + _IP + '"}',
        '{"n": ' + "1" * 700 + ', "m": "' + _IP + '"}',
        f'{{"f": 1.5, "g": 1e400, "h": NaN, "m": "{hit}"}}',
        '{"m": "a\\/b http:\\/\\/x.example\\/y \\"q\\" tab\\t1.2.3.4\\b \\f\\r\\n 8.8.8.8"}',
        '{"m": "\\u0041 1.2.3.4", "n": "\\u00e9 5.6.7.8", "s": "\\ud800 9.9.9.9", "z": "\\u0000 1.1.1.1"}',
        json.dumps({"a/~b": _URL, "x_sha256": _URL, "output": _URL, "sha256": _DIGEST, "md5": _DIGEST[:32]}),
        '{"x_sha256\\n": "' + _URL + '", "y_sha256\\n\\n": "' + _IP + '", "z_md5\\r": "' + _IP + '"}',
        json.dumps({"foo_manifest": {"m": _URL}, "source_hashes_by_file": {"m": _URL}, "hashes": {"m": _IP},
                    "options": [{"m": _IP}], "keep": {"m": _URL}}),
        f'{{"m": "{_IP}", "m": "5.6.7.8"}}',
        json.dumps({"d": {"ioc_hits": [{"rule_id": "r", "type": "ip", "value": _IP}]}, "m": _IP}),
        json.dumps({"ioc_hits": "not a list", "m": _URL}),
        deep,
        json.dumps({"l": [_IP, [_IP, {"m": _IP}], [[{"m": _URL, "path": "inner"}]], {}, []], "path": "outer"}),
        json.dumps({"m": "https://size.example/ ".ljust(MAX_SCALAR_LENGTH, "x"),
                    "n": "https://over.example/ ".ljust(MAX_SCALAR_LENGTH + 1, "x")}),
        "",
        "   ",
        "\t",
        "\x0c",
        "\x1c\x1f",
        "\u3000",
        "\u00a0 ",
        "[1, 2]",
        f'"text {_IP}"',
        "1.5",
        "null",
        '["\u00e9"]',
        f'   {{"m": "{_IP}"}}',
        f'\t{{"m": "{_URL}"}}  ',
        f'{{ "m" : "{_IP}" , "n" : [ 1 , 2 ] , "o" : {{ }} }}',
        json.dumps({"m": f"한글 {_IP}", "u": "httpſ://fold.example/x", "v": _URL}, ensure_ascii=False),
        json.dumps({"m": f"e\u0301{_IP} {_URL}"}),
        json.dumps({f"k{i}": f"10.0.{i}.1 {_URL}/{i % 3}" for i in range(40)}),
        json.dumps({"hash": _DIGEST, "name": _DIGEST.upper(), "data": "a" * 32, "sig": "0" * 64}),
        json.dumps({"u": "HTTPS://CASE.EXAMPLE/A.;", "v": "http://", "w": "xhttp://inner.example/"}),
        "{}",
        json.dumps({"m": _URL}),  # last line: written without a terminator
    ]
    return lines


def write_jsonl(directory, lines, *, terminators=_TERMINATORS, head=None):
    output = Path(directory) / "artifacts.json"
    records = output.with_suffix(".jsonl")
    text = "".join(line + terminators[index % len(terminators)] for index, line in enumerate(lines[:-1]))
    records.write_bytes((text + lines[-1]).encode("utf-8", "surrogatepass"))
    output.write_text(json.dumps({**(head or {}), "records_file": records.name}), encoding="utf-8")
    return {"artifacts_fixture": output}


def random_jsonl_lines(seed, count):
    """Seeded rows mixing native-subset and Python-only shapes."""
    import random

    rng = random.Random(seed)
    keys = ["path", "source_path", "artifact_type", "kind", "source", "m", "n", "a/~b", "x_sha256", "sha1",
            "output", "hashes", "foo_manifest", "ioc_hits", "value", "remote_address", "Version", "name"]
    texts = [_IP, _URL, _DIGEST, _DIGEST[:40], "1.0.0.1", "10.0.0.1", "127.0.0.1", "version 1.2.3.4",
             "host 8.8.8.8", f"sha256={_DIGEST}", "http://a.example/(x)", "plain", "", "registry-hive-cell",
             "C:\\Windows\\x.exe", "한 1.2.3.4", "0.0.0.0", "https://t.example/{{x}}",
             # Unicode classes, case folding and offsets that only Python's regexes decide.
             "httpſ://fold.example/x", "１.２.３.４ 1.2.3.4", "é1.2.3.4", "1.2.3.4é", f"{_DIGEST}é",
             "\U0001f600 https://e.example/\U0001f600", "١.٢.٣.٤", "\u00a0https://nb.example/\u00a0x",
             "e\u03011.2.3.4", "\u2028http://ls.example/", "경로 확인"]

    def value(depth):
        roll = rng.random()
        if depth < 3 and roll < 0.15:
            return {rng.choice(keys): value(depth + 1) for _ in range(rng.randint(0, 4))}
        if depth < 3 and roll < 0.25:
            return [value(depth + 1) for _ in range(rng.randint(0, 3))]
        if roll < 0.32:
            return rng.choice([0, -1, 7, 2**70, True, False, None])
        if roll < 0.35:
            return rng.choice([1.5, -0.0, 1e20])
        return " ".join(rng.choice(texts) for _ in range(rng.randint(1, 3)))

    lines = []
    for _ in range(count):
        row = {rng.choice(keys): value(0) for _ in range(rng.randint(1, 6))}
        lines.append(json.dumps(row, ensure_ascii=rng.random() < 0.5))
        if rng.random() < 0.03:
            lines.append(rng.choice(["", "  ", "[1]", '"s"']))
    return lines


class RustJsonlDifferentialTests(unittest.TestCase):
    setUp = RustIndicatorDifferentialTests.setUp
    compare = RustIndicatorDifferentialTests.compare

    def test_adversarial_lines_match_with_every_line_terminator(self):
        lines = adversarial_jsonl_lines()
        for terminators in (("\n",), ("\r\n",), ("\r",), _TERMINATORS):
            with self.subTest(terminators=terminators), tempfile.TemporaryDirectory() as directory:
                outputs = write_jsonl(directory, lines, terminators=terminators,
                                      head={"note": f"head {_URL}", "artifacts": []})
                result, metadata = self.compare(outputs, max_sources_per_indicator=2, max_indicators=None)
                self.assertGreater(metadata["python_rows"], 0)
                self.assertTrue(result["indicators"])
                self.assertTrue(result["ioc_scanner_hits"])

    def test_seeded_random_rows_match(self):
        for seed in (44, 4404):
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as directory:
                outputs = write_jsonl(directory, random_jsonl_lines(seed, 1500))
                self.compare(outputs, max_sources_per_indicator=3, max_indicators=None)

    def test_rows_spanning_many_frames_match(self):
        lines = [json.dumps({"path": f"/r/{i}", "m": f"10.{i % 250}.0.1 {_URL}/{i % 7}"}) for i in range(9000)]
        with tempfile.TemporaryDirectory() as directory:
            outputs = write_jsonl(directory, lines)
            _, metadata = self.compare(outputs, max_indicators=None)
        self.assertEqual(metadata["native_rows"], 18000)
        self.assertEqual(metadata["python_rows"], 0)

    def test_python_decode_errors_are_identical(self):
        cases = {
            "invalid-json": ("{}\n" * 5000 + '{"m": "1.2.3.4",}\n{}\n').encode(),
            "invalid-utf8": b'{"m": "1.2.3.4"}\n{"m": "\xff"}\n',
            "bom": '\ufeff{"m": "1.2.3.4"}\n'.encode(),
            "raw-control": b'{"m": "a\tb 1.2.3.4"}\n',
        }
        for name, data in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                outputs = write_jsonl(directory, ["{}"])
                outputs["artifacts_fixture"].with_suffix(".jsonl").write_bytes(data)
                errors = []
                for enabled in (False, True):
                    with self.assertRaises(ValueError) as caught:
                        summary(outputs, enabled)
                    errors.append((type(caught.exception), str(caught.exception)))
                self.assertEqual(errors[0], errors[1])


class RustJsonlFallbackTests(unittest.TestCase):
    setUp = RustIndicatorDifferentialTests.setUp

    def run_failing(self, error, *, after_frames):
        lines = [json.dumps({"m": f"10.{i % 250}.0.1 {_URL}/{i % 5}", "n": "\u00e9" * (i % 2)})
                 for i in range(10000)]
        frame = indicator_kernel._Reader.frame
        calls = []

        def failing_frame(reader):
            calls.append(None)
            if len(calls) > after_frames:
                raise error
            return frame(reader)

        with tempfile.TemporaryDirectory() as directory:
            outputs = write_jsonl(directory, lines)
            reference = summary(outputs, False, max_sources_per_indicator=2)
            with mock.patch.object(indicator_kernel._Reader, "frame", failing_frame):
                actual = summary(outputs, True, max_sources_per_indicator=2)
        metadata = actual.pop("indicator_kernel")
        self.assertEqual(reference, actual)
        return metadata

    def test_failure_after_applied_frames_resumes_from_the_checkpoint(self):
        metadata = self.run_failing(OSError("worker exited"), after_frames=1)
        self.assertEqual(metadata["fallback_reason"], "worker-io-error")
        self.assertEqual(metadata["native_rows"] + metadata["python_rows"], 15000)
        self.assertEqual(metadata["native_rows"], 6144)

    def test_timeout_and_invalid_reply_before_any_frame(self):
        for error, reason in (
            (indicator_kernel.subprocess.TimeoutExpired("rapid-indicators", 30), "worker-timeout"),
            (ValueError("truncated indicator frame"), "invalid-worker-response"),
            (indicator_kernel.subprocess.CalledProcessError(1, "rapid-indicators"), "worker-exit-error"),
        ):
            with self.subTest(reason=reason):
                metadata = self.run_failing(error, after_frames=0)
                self.assertEqual(metadata["fallback_reason"], reason)
                self.assertEqual(metadata["native_rows"], 0)

    def test_worker_that_never_speaks_the_protocol(self):
        import sys

        lines = [json.dumps({"m": _URL}), json.dumps({"m": _IP})]
        with tempfile.TemporaryDirectory() as directory:
            outputs = write_jsonl(directory, lines)
            reference = summary(outputs, False)
            # The interpreter exits on the unknown script name "jsonl".
            with mock.patch.object(indicator_kernel, "worker_path", return_value=Path(sys.executable)):
                actual = summary(outputs, True)
        metadata = actual.pop("indicator_kernel")
        self.assertIn(metadata["fallback_reason"], {"invalid-worker-response", "worker-io-error",
                                                    "worker-exit-error"})
        self.assertEqual(reference, actual)


def _frame(*records):
    return b"".join(records)


def _hit(index, pointer, text, spans, context=()):
    """A native hit, or with ``spans=None`` a scalar Python must match."""
    pointer, text = pointer.encode(), text.encode()
    data = [bytes([0 if spans is not None else 4]), struct.pack("<QI", index, len(pointer)), pointer,
            struct.pack("<I", len(text)), text, struct.pack("<I", len(context))]
    for slot, value in context:
        data += [struct.pack("<II", slot, len(value.encode())), value.encode()]
    if spans is not None:
        data.append(struct.pack("<I", len(spans)))
        data += [struct.pack("<III", *span) for span in spans]
    return b"".join(data)


def _line(line_number, index, raw, terminated=1):
    return bytes([1]) + struct.pack("<QQII", line_number, 0 if index is None else index + 1, terminated,
                                    len(raw)) + raw


def _checkpoint(offset, line_number, index, scalars=0):
    return bytes([2]) + struct.pack("<QQQQ", offset, line_number, index, scalars)


class RustJsonlProtocolTests(unittest.TestCase):
    def decode(self, frame, file_size=1000):
        from rapidtriage.core.indicators import NATIVE_FIELD_POLICY

        start = indicator_kernel._Checkpoint(0, 0, 0)
        return indicator_kernel._decode_frame(frame, start, NATIVE_FIELD_POLICY, file_size)

    def test_valid_frame_decodes_in_order(self):
        events, checkpoint = self.decode(_frame(
            _hit(0, "/artifacts/0/m", "x 1.2.3.4", [(1, 2, 9)], [(0, "p"), (3, "k")]),
            _hit(0, "/artifacts/0/\u00e9", "\u00e9 1.2.3.4", None, [(0, "\u00e9")]),
            _line(2, 1, b'{"m": "\xc3\xa9"}'),
            _line(3, None, b"[1]", terminated=0),
            _checkpoint(40, 3, 2, 5),
        ))
        self.assertEqual(events, [
            ("x 1.2.3.4", "/artifacts/0/m", {"path": "p", "kind": "k"}, [(1, 2, 9)]),
            ("\u00e9 1.2.3.4", "/artifacts/0/\u00e9", {"path": "\u00e9"}, None),
            (2, 1, '{"m": "\u00e9"}\n'),
            (3, None, "[1]"),
        ])
        self.assertEqual(checkpoint, indicator_kernel._Checkpoint(40, 3, 2, 5))

    def test_malformed_frames_are_rejected_before_use(self):
        valid_hit = _hit(0, "/artifacts/0/m", "x 1.2.3.4", [(1, 2, 9)])
        cases = {
            "empty": b"",
            "no checkpoint": valid_hit,
            "truncated": (valid_hit + _checkpoint(9, 1, 1))[:-3],
            "unknown tag": bytes([9]) + _checkpoint(9, 1, 1),
            "trailing": valid_hit + _checkpoint(9, 1, 1) + b"x",
            "span past text": _hit(0, "/artifacts/0/m", "abc", [(1, 0, 4)]) + _checkpoint(9, 1, 1),
            "empty span": _hit(0, "/artifacts/0/m", "abc", [(1, 1, 1)]) + _checkpoint(9, 1, 1),
            "bad family": _hit(0, "/artifacts/0/m", "abc", [(3, 0, 1)]) + _checkpoint(9, 1, 1),
            "family order": _hit(0, "/artifacts/0/m", "abc", [(2, 0, 1), (1, 0, 1)]) + _checkpoint(9, 1, 1),
            "overlap": _hit(0, "/artifacts/0/m", "abcd", [(1, 0, 3), (1, 2, 4)]) + _checkpoint(9, 1, 1),
            "no spans": _hit(0, "/artifacts/0/m", "abc", []) + _checkpoint(9, 1, 1),
            "pointer row": _hit(1, "/artifacts/0/m", "abc", [(1, 0, 1)]) + _checkpoint(9, 1, 2),
            "context slot": _hit(0, "/artifacts/0/m", "abc", [(1, 0, 1)], [(7, "x")]) + _checkpoint(9, 1, 1),
            "context order": _hit(0, "/artifacts/0/m", "abc", [(1, 0, 1)], [(1, "x"), (0, "y")])
            + _checkpoint(9, 1, 1),
            "oversized scalar": _hit(0, "/artifacts/0/m", "a" * (MAX_SCALAR_LENGTH + 1), [(1, 0, 1)])
            + _checkpoint(9, 1, 1),
            "oversized python scalar": _hit(0, "/artifacts/0/m", "\u00e9" * (MAX_SCALAR_LENGTH + 1), None)
            + _checkpoint(9, 1, 1),
            "non-ASCII hit": _hit(0, "/artifacts/0/m", "\u00e9 1.2.3.4", [(1, 2, 9)]) + _checkpoint(9, 1, 1),
            "ASCII python scalar": _hit(0, "/artifacts/0/m", "1.2.3.4", None) + _checkpoint(9, 1, 1),
            "row after hit": valid_hit + _line(2, 0, b"{}") + _checkpoint(9, 2, 1),
            "row order": _line(1, 3, b"{}") + _line(2, 1, b"{}") + _checkpoint(9, 2, 4),
            "line order": _line(2, None, b"[]") + _line(2, None, b"[]") + _checkpoint(9, 2, 0),
            "checkpoint rows": _line(1, 3, b"{}") + _checkpoint(9, 1, 3),
            "checkpoint lines": _line(5, None, b"[]") + _checkpoint(9, 4, 0),
            "checkpoint size": _checkpoint(1001, 1, 0),
            "not utf-8": _line(1, None, b"\xff") + _checkpoint(9, 1, 0),
        }
        for name, frame in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                self.decode(frame)

    def test_policy_and_leaf_pattern_are_unchanged(self):
        from rapidtriage.core.indicators import NATIVE_FIELD_POLICY, PROVENANCE_LEAF_RE

        self.assertEqual(
            PROVENANCE_LEAF_RE.pattern, r"(_sha256|_sha1|_md5|_hash|_hashes|_fingerprint|_digest|_row_hash|_id_hash)$",
        )
        self.assertTrue(NATIVE_FIELD_POLICY.encode().startswith(b"RINDJ1\n"))


class RustCandidateFuzzTests(unittest.TestCase):
    setUp = RustIndicatorDifferentialTests.setUp

    def test_seeded_ascii_spans_match_python_regexes(self):
        import random

        rng = random.Random(44043)
        pieces = ["http", "HTTP", "hTtPs", "://", ":/", "s", ".", "..", "1", "12", "123", "1234", "0", "a", "F",
                  "g", "_", "-", " ", "\t", "\x1c", "\x1f", "\x0b", "\x00", "\x7f", "[", ")", "{", '"', "'", "<",
                  "/", "\\", "=", _DIGEST[:32], _DIGEST.upper()[:40], _DIGEST, "a1" * 16]
        rows = ["".join(rng.choice(pieces) for _ in range(rng.randint(0, 40))) for _ in range(20000)]
        rows += ["".join(chr(rng.randint(0, 127)) for _ in range(rng.randint(0, 200))) for _ in range(2000)]
        for start in range(0, len(rows), 8000):
            chunk = rows[start:start + 8000]
            expected = {}
            for index, text in enumerate(chunk):
                spans = [(family, match.start(), match.end())
                         for family, pattern in enumerate((URL_RE, IP_RE, HASH_RE)) for match in pattern.finditer(text)]
                if spans:
                    expected[index] = spans
            self.assertEqual(indicator_kernel.scan_batch(chunk), expected)
