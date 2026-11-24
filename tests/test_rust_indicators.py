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
            "ioc_hits": [{"rule_id": "fixture", "type": "keyword", "value": "Fixture", "count": 2}],
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
