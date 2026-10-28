"""R8: recovery mode lifts the EVTX/registry parse caps; other modes keep them and disclose via coverage."""

from __future__ import annotations

import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.windows import eventlog
from rapidtriage.artifacts.windows.eventlog import (
    MAX_NATIVE_EVTX_BINXML_TOKENS,
    MAX_NATIVE_EVTX_RECORD_SIZE,
    MAX_NATIVE_EVTX_STRINGS,
    WindowsEventLogProvider,
    collect_native_evtx_events,
    iter_evtx_record_candidates,
)
from rapidtriage.artifacts.windows.registry import (
    MAX_HIVE_STRING_SCAN_BYTES,
    MAX_HIVE_STRINGS,
    WindowsRegistryProvider,
    collect_registry_hive,
)
from rapidtriage.core.coverage import coverage_entries, reset_coverage
from tests.test_parser_quality_registry import HiveWriter, Key, sz, write_hive

REG_SZ = 1
REG_BINARY = 3
STRING_COUNT = MAX_NATIVE_EVTX_STRINGS + 100


def synthetic_evtx(directory: Path) -> Path:
    """File header + one unchunked region holding a record with STRING_COUNT distinct UTF-16 strings."""
    payload = b"".join(f"evtx-string-{index:05d}".encode("utf-16-le") + b"\x00\x00" for index in range(STRING_COUNT))
    size = 24 + len(payload) + 4
    record = b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", size, 1, 0) + payload + struct.pack("<I", size)
    header = b"ElfFile\x00" + b"\x00" * (4096 - 8)
    path = directory / "Security.evtx"
    path.write_bytes(header + record + b"\x00" * (65536 - len(record)))
    return path


def string_counts(records: list) -> list[int]:
    return [len(record.details["extracted_strings"]) for record in records if "extracted_strings" in record.details]


class EvtxCapTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_coverage()
        self.addCleanup(reset_coverage)

    def collect(self, recovery: bool) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            return list(collect_native_evtx_events(synthetic_evtx(Path(tmp)), recovery=recovery))

    def test_triage_caps_strings_and_discloses(self) -> None:
        counts = string_counts(self.collect(recovery=False))
        self.assertTrue(counts)
        self.assertEqual(max(counts), MAX_NATIVE_EVTX_STRINGS)
        entries = [entry for entry in coverage_entries() if entry["area"] == "eventlog"]
        self.assertEqual(
            [(entry["reason_code"], entry["limit"], entry["observed"], entry["unit"]) for entry in entries],
            [("evtx-string-cap", MAX_NATIVE_EVTX_STRINGS, 1, "records")],
        )

    def test_recovery_keeps_every_string_without_coverage(self) -> None:
        counts = string_counts(self.collect(recovery=True))
        self.assertTrue(counts)
        self.assertGreaterEqual(max(counts), STRING_COUNT)
        self.assertEqual(coverage_entries(), [])

    def test_declared_record_size_cap_only_outside_recovery(self) -> None:
        size = MAX_NATIVE_EVTX_RECORD_SIZE + 1024
        blob = b"\x2a\x2a\x00\x00" + struct.pack("<I", size) + b"\x00" * (size + 64)
        capped = list(iter_evtx_record_candidates(blob))
        self.assertEqual([(item.parseable, item.reason) for item in capped], [(False, "declared-size-too-large")])
        lifted = list(iter_evtx_record_candidates(blob, recovery=True))
        self.assertEqual([(item.parseable, item.reason) for item in lifted], [(True, "record-size-plausible")])

    def test_binxml_token_budget_only_outside_recovery(self) -> None:
        used, size = MAX_NATIVE_EVTX_BINXML_TOKENS, MAX_NATIVE_EVTX_BINXML_TOKENS * 4
        for recovery in (False, True):
            hits: Counter[str] = Counter()
            with eventlog._evtx_caps_scope(recovery, hits):
                still_open = eventlog._evtx_tokens_open(0, size, used)
            self.assertEqual(still_open, recovery)
            self.assertEqual(dict(hits), {} if recovery else {"binxml-tokens": 1})

    def test_provider_receives_recovery_from_run_mode(self) -> None:
        self.assertFalse(WindowsEventLogProvider().with_options(run_mode="triage").recovery)
        self.assertTrue(WindowsEventLogProvider().with_options(run_mode="recovery").recovery)
        self.assertIn("recovery=1", WindowsEventLogProvider().with_options(run_mode="recovery").options_key)


class RegistryCapTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_coverage()
        self.addCleanup(reset_coverage)

    def hive_records(self, recovery: bool, big_blob: bool = True) -> list:
        root = Key("ROOT")
        values = root.path("Software\\Strings")
        for index in range(MAX_HIVE_STRINGS + 50):
            values.value(f"V{index:04d}", REG_SZ, sz(f"registry-string-{index:05d}"))
        if big_blob:
            root.path("Big").value("Blob", REG_BINARY, b"\x00" * (MAX_HIVE_STRING_SCAN_BYTES + 1024 * 1024))
        blob = HiveWriter().build(root)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Windows/System32/config/SOFTWARE", blob)
            return list(collect_registry_hive(path, recovery=recovery))

    def strings_row(self, records: list):
        return next(record for record in records if record.artifact_type == "registry-hive-strings")

    def test_triage_scan_byte_cap_truncates_and_discloses(self) -> None:
        # The hive is larger than the scan cap, so triage stops early and says so.
        details = self.strings_row(self.hive_records(recovery=False)).details
        self.assertTrue(details["scan_truncated"])
        reasons = {entry["reason_code"]: entry for entry in coverage_entries() if entry["area"] == "registry-hive-strings"}
        self.assertEqual(reasons["scan-bytes-cap"]["limit"], MAX_HIVE_STRING_SCAN_BYTES)
        self.assertGreater(reasons["scan-bytes-cap"]["observed"], MAX_HIVE_STRING_SCAN_BYTES)
        reset_coverage()
        whole = self.strings_row(self.hive_records(recovery=True)).details
        self.assertLess(len(details["extracted_strings"]), len(whole["extracted_strings"]))

    def test_triage_string_count_cap_discloses(self) -> None:
        # A small hive with more strings than the cap: exactly the cap is kept, and disclosed.
        details = self.strings_row(self.hive_records(recovery=False, big_blob=False)).details
        self.assertEqual(len(details["extracted_strings"]), MAX_HIVE_STRINGS)
        reasons = {entry["reason_code"]: entry for entry in coverage_entries() if entry["area"] == "registry-hive-strings"}
        self.assertEqual(reasons["string-count-cap"]["limit"], MAX_HIVE_STRINGS)
        self.assertNotIn("scan-bytes-cap", reasons)

    def test_recovery_scans_whole_hive_without_coverage(self) -> None:
        details = self.strings_row(self.hive_records(recovery=True)).details
        self.assertGreaterEqual(len(details["extracted_strings"]), MAX_HIVE_STRINGS + 50)
        self.assertEqual(details["extracted_string_count"], len(details["extracted_strings"]))
        self.assertFalse(details["scan_truncated"])
        self.assertEqual(coverage_entries(), [])

    def test_provider_receives_recovery_from_run_mode(self) -> None:
        self.assertFalse(WindowsRegistryProvider().with_options(run_mode="fraud").recovery)
        self.assertTrue(WindowsRegistryProvider().with_options(run_mode="recovery").recovery)


if __name__ == "__main__":
    unittest.main()
