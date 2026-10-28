"""R8 review fixes: every parser cap is lifted in recovery mode and disclosed (honestly) otherwise.

Covers f2 M3 / MINOR 1 / MINOR 10 and f1 B1 / N1 (EVTX chunk-decoder token cap, cap units,
registry options_key and string-count disclosure, SAM cell caps, USN journal caps).
"""

from __future__ import annotations

import shutil
import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows import eventlog, filesystem, os_account, registry
from rapidtriage.artifacts.windows.eventlog import (
    EVTX_BINXML_MAX_TOKENS,
    MAX_NATIVE_EVTX_STRINGS,
    collect_native_evtx_events,
)
from rapidtriage.artifacts.windows.filesystem import (
    USN_RECORD_SCAN_LIMIT,
    WindowsFilesystemProvider,
    native_usn_journal_records,
)
from rapidtriage.artifacts.windows.os_account import (
    WindowsOsAccountProvider,
    collect_sam_hive_candidates,
)
from rapidtriage.artifacts.windows.registry import (
    WindowsRegistryProvider,
    collect_registry_hive,
    iter_registry_cell_candidates,
)
from rapidtriage.core.coverage import coverage_entries, reset_coverage
from rapidtriage.core.input_root import resolve_input_root
from rapidtriage.core.run import collect_artifact_stages
from tests.test_parser_quality_eventlog import EvtxWriter, logon_event, write_evtx
from tests.test_parser_quality_registry import HiveWriter, Key, sz, write_hive
from tests.test_r8_caps import STRING_COUNT, synthetic_evtx

REG_SZ = 1


def entries(area: str) -> list[tuple[object, ...]]:
    return [
        (entry["reason_code"], entry["limit"], entry["observed"], entry["unit"])
        for entry in coverage_entries()
        if entry["area"] == area
    ]


class CoverageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        reset_coverage()
        self.addCleanup(reset_coverage)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)


class EvtxChunkDecoderTokenCapTests(CoverageTestCase):
    """f2 M3: the chunk decoder runs inside the cap scope; its token budget is lifted or disclosed."""

    def collect(self, recovery: bool) -> list:
        writer = EvtxWriter()
        writer.build_chunk([logon_event(1, 133000000000000000, user="alice", logon_id=7)])
        path = write_evtx(self.tmp / "Security.evtx", writer)
        # One normal record is far below 200k tokens; a 5-token budget makes it exceed the cap.
        with mock.patch.object(eventlog, "EVTX_BINXML_MAX_TOKENS", 5):
            return [row for row in collect_native_evtx_events(path, recovery=recovery) if row.artifact_type == "eventlog-event"]

    def test_triage_discloses_decoder_token_cap(self) -> None:
        events = self.collect(recovery=False)
        self.assertEqual(events[0].details["evtx_decode_error"], "EvtxDecodeError: token budget exhausted")
        self.assertEqual(entries("eventlog"), [("evtx-binxml-token-cap", EVTX_BINXML_MAX_TOKENS, None, "tokens")])

    def test_recovery_lifts_decoder_token_cap(self) -> None:
        events = self.collect(recovery=True)
        self.assertEqual(events[0].details["evtx_decode_error"], "")
        self.assertEqual(events[0].details["evtx_decoder_version"], "evtx-chunk-binxml-decoder-v2")
        self.assertEqual(coverage_entries(), [])


class EvtxCapUnitTests(CoverageTestCase):
    """f1 N1: limit and observed share the cap's unit; MINOR 10 analogue: no entry at exactly the cap."""

    def test_string_cap_reports_strings_with_real_total(self) -> None:
        list(collect_native_evtx_events(synthetic_evtx(self.tmp), recovery=False))
        self.assertEqual(entries("eventlog"), [("evtx-string-cap", MAX_NATIVE_EVTX_STRINGS, STRING_COUNT, "strings")])

    def test_exactly_cap_strings_is_not_disclosed(self) -> None:
        with mock.patch("tests.test_r8_caps.STRING_COUNT", MAX_NATIVE_EVTX_STRINGS):
            path = synthetic_evtx(self.tmp)
        list(collect_native_evtx_events(path, recovery=False))
        self.assertEqual(entries("eventlog"), [])

    def test_nested_binxml_size_cap_reports_bytes(self) -> None:
        hits: dict[str, int | None] = {}
        with eventlog._evtx_caps_scope(False, Counter(), hits):
            eventlog.parse_nested_binxml_value(b"\x0f" + b"\x00" * eventlog.MAX_NATIVE_EVTX_NESTED_BINXML_BYTES)
        eventlog._evtx_flush_cap_coverage({"nested-binxml-bytes": 1}, hits)
        size = eventlog.MAX_NATIVE_EVTX_NESTED_BINXML_BYTES
        self.assertEqual(entries("eventlog"), [("evtx-nested-binxml-size-cap", size, size + 1, "bytes")])

    def test_every_cap_has_a_non_record_unit(self) -> None:
        units = {name: unit for name, (_, _, unit) in eventlog._EVTX_CAP_DISCLOSURE.items()}
        self.assertEqual(
            units,
            {
                "strings": "strings",
                "binxml-tokens": "tokens",
                "chunk-decoder-tokens": "tokens",
                "nested-binxml-bytes": "bytes",
                "record-size": "bytes",
            },
        )


class RegistryReviewTests(CoverageTestCase):
    def hive(self, count: int) -> Path:
        root = Key("ROOT")
        values = root.path("Software\\Strings")
        for index in range(count):
            values.value(f"V{index:04d}", REG_SZ, sz(f"registry-string-{index:05d}"))
        return write_hive(self.tmp, "Windows/System32/config/SOFTWARE", HiveWriter().build(root))

    def strings_row(self, path: Path, recovery: bool):
        records = list(collect_registry_hive(path, recovery=recovery))
        return next(record for record in records if record.artifact_type == "registry-hive-strings").details

    def test_options_key_separates_recovery_cache_slot(self) -> None:
        """f2 MINOR 1."""
        self.assertEqual(WindowsRegistryProvider().options_key, "")
        self.assertEqual(WindowsRegistryProvider().with_options(run_mode="recovery").options_key, "recovery=1")

    def test_string_count_cap_only_when_strings_dropped(self) -> None:
        """f2 MINOR 10: no entry at exactly the cap; above it the entry carries the real total."""
        path = self.hive(40)
        total = len(self.strings_row(path, recovery=True)["extracted_strings"])
        reset_coverage()
        with mock.patch.object(registry, "MAX_HIVE_STRINGS", total):
            details = self.strings_row(path, recovery=False)
        self.assertEqual(len(details["extracted_strings"]), total)
        self.assertFalse(details["string_limit_reached"])
        self.assertEqual(entries("registry-hive-strings"), [])
        with mock.patch.object(registry, "MAX_HIVE_STRINGS", total - 1):
            details = self.strings_row(path, recovery=False)
        self.assertEqual(len(details["extracted_strings"]), total - 1)
        self.assertTrue(details["string_limit_reached"])
        self.assertEqual(entries("registry-hive-strings"), [("string-count-cap", total - 1, total, "strings")])

    def test_regex_string_extractor_matches_code_unit_scan(self) -> None:
        blob = (
            "abcd".encode("utf-16le")
            + b"\x00\xd8"  # lone high surrogate breaks the run
            + "efgh\tij".encode("utf-16le")
            + b"\x3d\xd8\x00\xde"  # valid surrogate pair is not printable either
            + "  klmn  ".encode("utf-16le")
            + b"\x00\x00x"
        )
        self.assertEqual(registry.extract_utf16le_strings(blob, limit=None)[:3], ["abcd", "efgh\tij", "klmn"])

    def test_cell_scan_reports_truncation_only_past_the_limit(self) -> None:
        blob = (self.hive(6)).read_bytes()
        stats: dict[str, object] = {}
        every = iter_registry_cell_candidates(blob, record_limit=None, scan_bytes=None, stats=stats)
        self.assertFalse(stats["record_limit_reached"])
        exact = iter_registry_cell_candidates(blob, record_limit=len(every), stats=stats)
        self.assertEqual(len(exact), len(every))
        self.assertFalse(stats["record_limit_reached"])
        fewer = iter_registry_cell_candidates(blob, record_limit=len(every) - 1, stats=stats)
        self.assertEqual(len(fewer), len(every) - 1)
        self.assertTrue(stats["record_limit_reached"])


class SamCellCapTests(CoverageTestCase):
    """f1 B1: os_account SAM cell caps are lifted in recovery and disclosed otherwise."""

    def sam(self) -> Path:
        root = Key("ROOT")
        users = root.path("Accounts\\Names")
        for index in range(8):
            users.path(f"user{index:02d}").value("x", REG_SZ, sz("y"))
        return write_hive(self.tmp, "Windows/System32/config/SAM", HiveWriter().build(root))

    def accounts(self, recovery: bool) -> list[str]:
        rows = collect_sam_hive_candidates(self.tmp, recovery=recovery)
        return [row.details.get("account_name") or "" for row in rows if row.artifact_type == "windows-sam-account-candidate"]

    def test_candidate_cap_disclosed_and_lifted(self) -> None:
        self.sam()
        whole = self.accounts(recovery=True)
        self.assertGreaterEqual(len(whole), 8)
        self.assertEqual(coverage_entries(), [])
        with mock.patch.object(os_account, "MAX_HIVE_CELL_RECORDS", 3):
            capped = self.accounts(recovery=False)
            self.assertLess(len(capped), len(whole))
            self.assertEqual(entries("registry"), [("candidate-cap", 3, None, "candidates")])
            reset_coverage()
            self.assertEqual(len(self.accounts(recovery=True)), len(whole))
            self.assertEqual(coverage_entries(), [])

    def test_scan_bytes_cap_disclosed_and_lifted(self) -> None:
        size = self.sam().stat().st_size
        with mock.patch.object(os_account, "MAX_HIVE_CELL_SCAN_BYTES", 4096):
            self.assertEqual(self.accounts(recovery=False), [])
            self.assertEqual(entries("registry"), [("scan-bytes-cap", 4096, size, "bytes")])
            reset_coverage()
            self.assertGreaterEqual(len(self.accounts(recovery=True)), 8)
            self.assertEqual(coverage_entries(), [])

    def test_run_mode_recovery_reaches_os_account_collector(self) -> None:
        """The artifact stage threads run_mode=recovery to windows-os-account (run/__init__ options_by_kind)."""
        self.sam()
        with mock.patch.object(os_account, "MAX_HIVE_CELL_RECORDS", 3):
            for run_mode, expected in ((None, [("candidate-cap", 3, None, "candidates")]), ("recovery", [])):
                reset_coverage()
                collect_artifact_stages(
                    resolve_input_root(self.tmp),
                    ["windows-os-account"],
                    artifacts_dir=self.tmp.parent / f"{self.tmp.name}-artifacts-{run_mode}",
                    resume=False,
                    rule_set=None,
                    run_mode=run_mode,
                )
                self.addCleanup(shutil.rmtree, self.tmp.parent / f"{self.tmp.name}-artifacts-{run_mode}", True)
                self.assertEqual(entries("registry"), expected, run_mode)

    def test_provider_receives_recovery_from_run_mode(self) -> None:
        self.assertFalse(WindowsOsAccountProvider().with_options(run_mode="triage").recovery)
        provider = WindowsOsAccountProvider().with_options(run_mode="recovery")
        self.assertTrue(provider.recovery)
        self.assertEqual(provider.options_key, "recovery=1")


def usn_record(index: int) -> bytes:
    name = f"file{index:05d}.txt".encode("utf-16le")
    length = (60 + len(name) + 7) // 8 * 8
    head = struct.pack(
        "<IHHQQQQIIIIHH",
        length, 2, 0, (index + 100) | (1 << 48), 5 | (1 << 48), index * 8,
        133000000000000000 + index, 0x100, 0, 0, 0x20, len(name), 60,
    )
    return (head + name).ljust(length, b"\x00")


class UsnJournalCapTests(CoverageTestCase):
    """f1 B1: USN_RECORD_SCAN_LIMIT and the 16 MiB prefix are lifted in recovery and disclosed otherwise."""

    def journal(self, count: int, *, lead_zeros: int = 0) -> Path:
        path = self.tmp / "$Extend" / "$J"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00" * lead_zeros + b"".join(usn_record(index) for index in range(count)))
        return path

    def test_record_cap_disclosed_only_when_records_dropped(self) -> None:
        exact = self.journal(USN_RECORD_SCAN_LIMIT)
        self.assertEqual(len(native_usn_journal_records(exact)), USN_RECORD_SCAN_LIMIT)
        self.assertEqual(coverage_entries(), [])
        more = self.journal(USN_RECORD_SCAN_LIMIT + 7)
        self.assertEqual(len(native_usn_journal_records(more)), USN_RECORD_SCAN_LIMIT)
        self.assertEqual(entries("windows-filesystem.usn"), [("candidate-cap", USN_RECORD_SCAN_LIMIT, None, "records")])
        reset_coverage()
        self.assertEqual(len(native_usn_journal_records(more, recovery=True)), USN_RECORD_SCAN_LIMIT + 7)
        self.assertEqual(coverage_entries(), [])

    def test_prefix_cap_disclosed_and_lifted(self) -> None:
        path = self.journal(10, lead_zeros=8192)
        with mock.patch.object(filesystem, "NATIVE_SCAN_LIMIT", 4096):
            self.assertEqual(native_usn_journal_records(path), [])
            self.assertEqual(entries("windows-filesystem.usn"), [("scan-bytes-cap", 4096, path.stat().st_size, "bytes")])
            reset_coverage()
            self.assertEqual(len(native_usn_journal_records(path, recovery=True)), 10)
            self.assertEqual(coverage_entries(), [])

    def test_provider_threads_recovery_into_usn_rows(self) -> None:
        self.journal(USN_RECORD_SCAN_LIMIT + 3)
        self.assertFalse(WindowsFilesystemProvider().with_options(run_mode="fraud").recovery)
        provider = WindowsFilesystemProvider().with_options(run_mode="recovery")
        self.assertEqual(provider.options_key, "recovery=1")
        rows = [row for row in provider.collect(self.tmp) if row.artifact_type == "usn-record"]
        self.assertEqual(len(rows), USN_RECORD_SCAN_LIMIT + 3)
        self.assertEqual(coverage_entries(), [])


if __name__ == "__main__":
    unittest.main()
