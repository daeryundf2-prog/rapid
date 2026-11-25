"""rapid-ntfs (Rust) vs filesystem.py (Python): zero field differences.

Both parsers run on the same synthetic $MFT and $UsnJrnl:$J blobs (clean,
windowed and byte-fuzzed); every field the Rust port emits must equal the
Python value with the same type. The Rust-only ``timestamps_filetime``
siblings are checked against the generator's 100 ns ticks instead.

Skipped when the extension is not built, unless
``RAPIDTRIAGE_REQUIRE_RAPID_NTFS=1`` (CI) turns a missing build into a failure.
"""

from __future__ import annotations

import datetime as dt
import os
import random
import struct
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

from rapidtriage.api.app import analysis_kinds
from rapidtriage.artifacts.windows import filesystem
from rapidtriage.core import ntfs_native
from tests import ntfs_synthetic as synth

EXTENSION, EXTENSION_REASON = ntfs_native.load_native_ntfs_parser()
REQUIRED = os.environ.get("RAPIDTRIAGE_REQUIRE_RAPID_NTFS") == "1"

# Python-only fields the Rust port leaves out (docs/architecture/rapid-ntfs.md).
PYTHON_ONLY_MFT_KEYS = {"attribute_list_resolution"}
PYTHON_ONLY_CHECKS = {
    "attribute_list_entries_present",
    "attribute_list_bounded_resolution_attempted",
    "attribute_list_bounded_resolution_complete",
    "attribute_list_unresolved_extension_records",
}
PYTHON_ONLY_HASH_KEYS = {"record_sha256_before", "record_sha256_after", "sha256", "resident_data_hashes", "preview_sha256"}
RUST_ONLY_KEYS = {"timestamps_filetime"}


def _without(value: object, keys: set[str]) -> object:
    if isinstance(value, dict):
        return {key: _without(item, keys) for key, item in value.items() if key not in keys}
    if isinstance(value, list):
        return [_without(item, keys) for item in value]
    return value


def python_mft_projection(record: dict[str, object]) -> object:
    trimmed = {key: value for key, value in record.items() if key not in PYTHON_ONLY_MFT_KEYS}
    checks = trimmed.get("validation_checks")
    if isinstance(checks, dict):
        trimmed["validation_checks"] = {key: value for key, value in checks.items() if key not in PYTHON_ONLY_CHECKS}
    return _without(trimmed, PYTHON_ONLY_HASH_KEYS)


def differences(left: object, right: object, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [f"{path}: {type(left).__name__} {left!r} != {type(right).__name__} {right!r}"]
    if isinstance(left, dict):
        found = [f"{path}.{key}: missing on one side" for key in sorted(set(left) ^ set(right))]
        if not found and list(left) != list(right):
            # Key order too: JSON written from either record must be byte-identical.
            return [f"{path}: key order {list(left)} != {list(right)}"]
        for key in sorted(set(left) & set(right)):
            found.extend(differences(left[key], right[key], f"{path}.{key}"))
        return found
    if isinstance(left, list):
        if len(left) != len(right):
            return [f"{path}: length {len(left)} != {len(right)}"]
        found = []
        for index, (a, b) in enumerate(zip(left, right)):
            found.extend(differences(a, b, f"{path}[{index}]"))
        return found
    return [] if left == right else [f"{path}: {left!r} != {right!r}"]


@unittest.skipIf(EXTENSION is None and not REQUIRED, "rapid_ntfs_native not built (scripts/build-rapid-ntfs.py)")
class RapidNtfsParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(EXTENSION, f"RAPIDTRIAGE_REQUIRE_RAPID_NTFS=1 but rapid_ntfs_native is unusable: {EXTENSION_REASON}")

    def assert_mft_parity(self, blob: bytes) -> list[dict[str, object]]:
        python = filesystem.parse_mft_record_headers(blob)
        rust = EXTENSION.parse_mft_record_headers(blob)
        self.assertEqual(len(rust), len(python))
        diff = differences([python_mft_projection(item) for item in python], _without(rust, RUST_ONLY_KEYS))
        self.assertEqual(diff, [], "\n".join(diff[:20]))
        return rust

    def assert_usn_parity(self, blob: bytes, **window: object) -> dict[str, object]:
        python = filesystem.parse_usn_record_scan(blob, **window)
        rust = EXTENSION.parse_usn_record_scan(blob, **window)
        python.pop("cursor_window_profile")
        diff = differences(python, rust)
        self.assertEqual(diff, [], "\n".join(diff[:20]))
        return rust

    def test_mft_corner_cases_have_zero_differences(self) -> None:
        specs = synth.parity_mft_specs()
        blob = synth.build_mft(specs)
        rust = self.assert_mft_parity(blob)
        by_offset = {record["record_offset"]: record for record in rust}
        # Coverage of the named corner cases, so the zero-diff result cannot be vacuous.
        self.assertEqual(by_offset[65 * 1024]["sequence_number"], 7)
        self.assertEqual(by_offset[65 * 1024]["record_number_candidate"], 65)
        parents = [entry["parent_reference"] for entry in by_offset[65 * 1024]["file_name_entries"]]
        self.assertEqual(parents, [{"record_number": 64, "sequence_number": 2}] * 2)
        self.assertEqual(by_offset[67 * 1024]["usa_fixup_application"]["status"], "not-applied-trailer-mismatch")
        self.assertEqual(by_offset[68 * 1024]["sequence_validation"]["status"], "missing")
        self.assertTrue(by_offset[69 * 1024]["record_number_header_mismatch"])
        self.assertEqual(by_offset[70 * 1024]["record_geometry_status"], "damaged")
        self.assertTrue(by_offset[70 * 1024]["record_number_trusted"])
        self.assertTrue(by_offset[66 * 1024]["validation_checks"]["has_nonresident_data_attribute"])
        self.assertTrue(by_offset[65 * 1024]["data_attributes"][0]["resident"])
        self.assertTrue(any(offset % 1024 for offset in by_offset))
        self.assertIn("timestamps_out_of_range", by_offset[72 * 1024]["standard_information"])
        self.assertEqual(by_offset[79 * 1024]["path_candidates"], ["C:\\Windows\\System32\\cmd.exe), \\\\server\\share\\x.txt"])

    def test_mft_filetimes_keep_100ns_ticks(self) -> None:
        specs = {spec.number: spec for spec in synth.parity_mft_specs()}
        rust = EXTENSION.parse_mft_record_headers(synth.build_mft(list(specs.values())))
        checked = 0
        for record in rust:
            offset = record["record_offset"]
            spec = specs.get(offset // 1024)
            if offset % 1024 or spec is None:
                continue
            fields = ("created_at", "modified_at", "mft_modified_at", "accessed_at")
            si = record["standard_information"]["timestamps_filetime"]
            expected_si = spec.si_times or tuple(synth.ticks(spec.number, salt) for salt in (1, 2, 3, 4))
            self.assertEqual(tuple(si[name] for name in fields), expected_si)
            for entry in record["file_name_entries"]:
                expected_fn = spec.fn_times or tuple(synth.ticks(spec.number, salt) for salt in (5, 6, 7, 8))
                self.assertEqual(tuple(entry["timestamps_filetime"][name] for name in fields), expected_fn)
            checked += 1
        self.assertGreaterEqual(checked, 15)
        self.assertNotEqual(synth.ticks(65, 1) % 10, 0)

    def test_mft_4k_volume_and_no_stride_blob(self) -> None:
        specs = synth.parity_mft_specs()[:6]
        self.assert_mft_parity(synth.build_mft(specs, size=4096))
        lone = synth.mft_record(synth.MftSpec(3, names=[("third.txt", synth.WIN32, synth.reference(5, 1))]), size=4096)
        previous = synth.mft_record(synth.MftSpec(2, names=[("previous", synth.WIN32, synth.reference(5, 1))]), size=4096)
        stranger = synth.mft_record(synth.MftSpec(9, names=[("third.txt", synth.WIN32, synth.reference(5, 1))]), size=4096)
        blobs = {
            "intact-alone": bytes(3 * 4096) + lone,
            "clipped-alone": bytes(3 * 4096) + lone[:-1],
            "clipped-with-neighbour": bytes(2 * 4096) + previous + lone[:-1],
            "header-disagrees": bytes(2 * 4096) + previous + stranger,
            "short": lone[:700],
        }
        results = {label: self.assert_mft_parity(blob) for label, blob in blobs.items()}
        slot3 = {label: next((r for r in rows if r["record_offset"] == 3 * 4096), None) for label, rows in results.items()}
        # PR #33: a clipped record without an intact neighbour keeps slot 3 but is not trusted.
        self.assertEqual(slot3["clipped-alone"]["record_number_candidate"], 3)
        self.assertFalse(slot3["clipped-alone"]["record_number_trusted"])
        self.assertTrue(slot3["intact-alone"]["record_number_trusted"])
        self.assertFalse(slot3["header-disagrees"]["record_number_trusted"])

    def test_mft_fuzzed_blobs(self) -> None:
        blob = synth.build_mft(synth.parity_mft_specs())
        for seed in range(60):
            with self.subTest(seed=seed):
                self.assert_mft_parity(synth.fuzz(blob, seed=seed, flips=40 + seed * 10))

    def test_usn_journal_has_zero_differences(self) -> None:
        blob, filetimes = synth.parity_usn_journal()
        scan = self.assert_usn_parity(blob)
        records = scan["records"]
        self.assertEqual([record["timestamp_filetime"] for record in records if record["major_version"] != 4], filetimes)
        hints = [record["rename_hint"] for record in records[:5]]
        self.assertEqual(hints, ["", "rename-old-name", "rename-new-name", "rename-new-name", "rename-old-and-new"])
        self.assertEqual([record["file_name"] for record in records[1:3]], ["draft.txt", "alice report.txt"])
        self.assertEqual(records[0]["parent_file_reference_number_decoded"]["sequence_number"], 2)
        self.assertGreater(scan["trailing_unparsed_bytes"], 0)
        self.assertEqual({record["major_version"] for record in records}, {2, 3, 4})
        self.assertIn("invalid-utf16", {record["file_name_decode_status"] for record in records})

    def test_usn_windows_and_limits(self) -> None:
        blob, _ = synth.parity_usn_journal()
        for window in (
            {"record_limit": 1},
            {"record_limit": 3, "start_offset": 40},
            {"start_offset": 41},
            {"start_offset": -5, "max_scan_bytes": 300},
            {"max_scan_bytes": 0},
            {"record_limit": 0},
            {"start_offset": len(blob) + 10},
        ):
            with self.subTest(window=window):
                self.assert_usn_parity(blob, **window)

    def test_usn_fuzzed_blobs(self) -> None:
        blob, _ = synth.parity_usn_journal()
        for seed in range(80):
            with self.subTest(seed=seed):
                self.assert_usn_parity(synth.fuzz(blob, seed=seed, flips=5 + seed))

    def test_usn_mft_correlation_identical_on_rust_records(self) -> None:
        # Post-#33 linking (trusted slots, rename-before-current-name, parent generation) fed with
        # Rust-parsed records must give exactly what Python-parsed records give.
        mft_blob, journal = synth.rename_volume()
        corner_blob = synth.build_mft(synth.parity_mft_specs())
        corner_journal, _ = synth.parity_usn_journal()
        for label, (table, usn) in {"rename": (mft_blob, journal), "corners": (corner_blob, corner_journal)}.items():
            with self.subTest(volume=label):
                outcome = {}
                for engine, mft_parser, usn_parser in (
                    ("python", filesystem.parse_mft_record_headers, filesystem.parse_usn_record_scan),
                    ("rust", EXTENSION.parse_mft_record_headers, EXTENSION.parse_usn_record_scan),
                ):
                    cache = filesystem.build_mft_bounded_path_cache(mft_parser(table))
                    outcome[engine] = [
                        filesystem.usn_bounded_mft_path_correlation(record, cache) for record in usn_parser(usn)["records"]
                    ]
                diff = differences(outcome["python"], outcome["rust"])
                self.assertEqual(diff, [], "\n".join(diff[:20]))
                if label == "rename":
                    old, new, _other, stale = outcome["rust"]
                    self.assertEqual(old["path_candidate"], "\\records\\old.txt")
                    self.assertFalse(old["file_reference_link"]["current_mft_name_match"])
                    self.assertTrue(old["file_reference_link"]["current_mft_parent_match"])
                    self.assertEqual(new["status"], "matched-file-reference-cache")
                    self.assertTrue(new["file_reference_link"]["current_mft_name_match"])
                    self.assertEqual(stale["status"], "unresolved-mft-parent-sequence-mismatch")

    def test_adversarial_mft_records(self) -> None:
        # Hostile headers, update-sequence arrays, attribute chains, runlists, ADS names,
        # $SI/$FN times, slack and torn sectors: several hundred corrupted records.
        records = 0
        for seed in range(400):
            with self.subTest(seed=seed):
                records += len(self.assert_mft_parity(synth.adversarial_mft(seed)))
        self.assertGreater(records, 1500)

    def test_adversarial_usn_records(self) -> None:
        records = 0
        for seed in range(1500):
            blob, window = synth.adversarial_usn(seed)
            with self.subTest(seed=seed, window=window):
                records += len(self.assert_usn_parity(blob, **window)["records"])
        self.assertGreater(records, 1500)

    def test_output_caps_match_python(self) -> None:
        users = synth.reference(64, 2)
        # 5,000-record scan limit (and the volume-size vote over more FILE hits).
        spam = synth.build_mft(synth.parity_mft_specs()) + (b"FILE" + bytes(44)) * 5_200
        self.assertEqual(len(self.assert_mft_parity(spam)), 5_000)
        # 64-run runlist preview, 250 UTF-16 strings, 10 path candidates.
        runs = synth.MftSpec(1, names=[("runs", synth.WIN32, users)], nonresident_runlist=bytes([0x01, 0x05]) * 100 + b"\x00")
        record = self.assert_mft_parity(synth.build_mft([runs], size=4096))[0]
        self.assertEqual(len(record["data_attributes"][0]["runlist_preview"]), 64)
        words = b"".join(f"S{index:03d}".encode("utf-16le") + b"\x01\x00" for index in range(300))
        self.assert_mft_parity(synth.build_mft([synth.MftSpec(1, names=[("w", synth.WIN32, users)], resident_data=words)], size=4096))
        paths = b"".join(f"C:\\p{index:02d}\\f.txt".encode("utf-16le") + b"\x01\x00" for index in range(30))
        record = self.assert_mft_parity(synth.build_mft([synth.MftSpec(1, names=[("p", synth.WIN32, users)], resident_data=paths)], size=4096))[0]
        self.assertEqual(len(record["path_candidates"]), 10)
        # 64-extent USN v4 preview, a 65,536-byte record, the 5,000-record USN limit.
        extents = [(index * 4096, 4096) for index in range(100)]
        scan = self.assert_usn_parity(synth.usn_v4(1, 2, 3, 0x100, extents))
        self.assertEqual(len(scan["records"][0]["v4_extents"]), 64)
        largest = bytearray(65_536)
        head = synth.usn_v2("big.txt", 0x100, 1, 2, 3, synth.ticks(1))
        largest[: len(head)] = head
        struct.pack_into("<I", largest, 0, 65_536)
        scan = self.assert_usn_parity(bytes(largest) + synth.bench_usn(5_100))
        self.assertEqual((len(scan["records"]), scan["largest_record_length"]), (5_000, 65_536))
        self.assertTrue(scan["record_limit_reached"])

    def test_filetime_text_and_ticks_over_the_whole_range(self) -> None:
        rng = random.Random(1601)
        values = [rng.randrange(1, 2_650_467_743_999_999_992) for _ in range(5_000)]
        values += [1, 9, 10, 11, 116_444_736_000_000_000, 2_650_467_743_999_999_990, 2_650_467_743_999_999_991, 2**63, 2**64 - 1]
        journal = b"".join(synth.usn_v2("t", 0x100, 1, 2, index, value) for index, value in enumerate(values))
        scan = self.assert_usn_parity(journal, record_limit=10**6)
        self.assertEqual([record["timestamp_filetime"] for record in scan["records"]], values)

    def test_ntfs_meta_rows_identical_under_both_engines(self) -> None:
        mft_blob = synth.build_mft(synth.parity_mft_specs())
        journal, _ = synth.parity_usn_journal()
        python_summary, python_rows = run_ntfs_meta(mft_blob, journal, "python")
        rust_summary, rust_rows = run_ntfs_meta(mft_blob, journal, "rust")
        provenance = {key: rust_summary.pop(key) for key in list(rust_summary) if key.startswith("native_")}
        self.assertEqual(
            provenance,
            {
                "native_mft_engine": "rust",
                "native_mft_engine_requested": "rust",
                "native_mft_engine_version": ntfs_native.RAPID_NTFS_VERSION,
                "native_mft_engine_python_fallback_count": 0,
                "native_usn_engine": "rust",
                "native_usn_engine_requested": "rust",
                "native_usn_engine_version": ntfs_native.RAPID_NTFS_VERSION,
                "native_usn_engine_python_fallback_count": 0,
            },
        )
        diff = differences([python_summary, python_rows], [rust_summary, rust_rows])
        self.assertEqual(diff, [], "\n".join(diff[:20]))
        self.assertGreater(len(rust_rows), 30)

    def test_extension_version_matches_the_bridge(self) -> None:
        self.assertEqual(EXTENSION.engine_version(), ntfs_native.RAPID_NTFS_VERSION)
        cargo = (Path(__file__).resolve().parents[1] / "engines/rust/crates/rapid-ntfs/Cargo.toml").read_text(encoding="utf-8")
        self.assertIn(f'\nversion = "{ntfs_native.RAPID_NTFS_VERSION}"\n', cargo)


def run_ntfs_meta(mft_blob: bytes, journal: bytes, engine: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    """The NTFS-meta analysis' $MFT and $UsnJrnl steps on synthetic files under ``engine``."""
    with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: engine}):
        root = Path(tmp)
        (root / "MFT.bin").write_bytes(mft_blob)
        (root / "J.bin").write_bytes(journal)
        ctx = _RowSink(root)
        nodes = analysis_kinds._NodeView()
        reference = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        summary = analysis_kinds.parse_mft_file(ctx, root / "MFT.bin", nodes, 1024, mismatch_reference=reference)  # type: ignore[arg-type]
        summary.update(analysis_kinds.parse_usn_file(ctx, root / "J.bin", nodes))  # type: ignore[arg-type]
        return summary, ctx.rows


class _RowSink:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.rows: list[dict[str, object]] = []

    @property
    def rows_written(self) -> int:
        return len(self.rows)

    def check_cancel(self) -> None:
        return None

    def advance(self, *_args: object, **_kwargs: object) -> None:
        return None

    def extend(self, *_args: object, **_kwargs: object) -> None:
        return None

    def set_message(self, *_args: object) -> None:
        return None

    def row(self, details: dict[str, object], *, path: str, artifact_type: str = "ntfs") -> dict[str, object]:
        return {"details": details, "path": path, "artifact_type": artifact_type}

    def write_row(self, row: dict[str, object]) -> None:
        self.rows.append(row)


# Keys a consumer of Rust records must never read: Python-only (absent there) or Rust-only.
UNREADABLE_KEYS = PYTHON_ONLY_MFT_KEYS | PYTHON_ONLY_CHECKS | PYTHON_ONLY_HASH_KEYS | RUST_ONLY_KEYS | {"cursor_window_profile"}


class _ReadTracker(dict):  # type: ignore[type-arg]
    reads: ClassVar[set[str]] = set()

    def __getitem__(self, key: object) -> object:
        self.reads.add(str(key))
        return super().__getitem__(key)

    def get(self, key: object, default: object = None) -> object:
        self.reads.add(str(key))
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        self.reads.add(str(key))
        return super().__contains__(key)


def _tracked(value: object) -> object:
    if isinstance(value, dict):
        return _ReadTracker({key: _tracked(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_tracked(item) for item in value]
    return value


def _module(**parsers: object) -> SimpleNamespace:
    return SimpleNamespace(engine_version=lambda: ntfs_native.RAPID_NTFS_VERSION, **parsers)


class NtfsEngineSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mft_blob = synth.build_mft(synth.parity_mft_specs())
        self.journal, _ = synth.parity_usn_journal()

    def rust_with(self, module: object, reason: str = "") -> unittest.mock._patch:  # type: ignore[type-arg]
        return unittest.mock.patch.object(ntfs_native, "load_native_ntfs_parser", return_value=(module, reason))

    def test_default_engine_is_python_and_leaves_the_summary_unchanged(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ntfs_native.ENGINE_ENV, None)
            engine = ntfs_native.resolve_ntfs_engine()
            self.assertEqual((engine.active, engine.provenance("mft")), ("python", {}))
        summary, _rows = run_ntfs_meta(self.mft_blob, self.journal, "python")
        self.assertFalse([key for key in summary if key.startswith("native_")])

    def test_missing_extension_falls_back_and_records_why(self) -> None:
        with self.rust_with(None, "rapid_ntfs_native 확장 모듈이 빌드되지 않았습니다"):
            summary, rows = run_ntfs_meta(self.mft_blob, self.journal, "rust")
        self.assertEqual(summary["native_mft_engine"], "python")
        self.assertEqual(summary["native_mft_engine_requested"], "rust")
        self.assertIn("빌드되지 않았습니다", str(summary["native_mft_engine_notice_ko"]))
        self.assertIn("빌드되지 않았습니다", str(summary["native_usn_engine_notice_ko"]))
        self.assertEqual(rows, run_ntfs_meta(self.mft_blob, self.journal, "python")[1])

    def test_stale_build_is_refused(self) -> None:
        stale = SimpleNamespace(engine_version=lambda: "0.0.0")
        with unittest.mock.patch.dict(sys.modules, {"rapid_ntfs_native": stale}):
            module, reason = ntfs_native.load_native_ntfs_parser.__wrapped__()
        self.assertIsNone(module)
        self.assertIn("0.0.0", reason)

    def test_rust_error_falls_back_for_the_rest_of_the_input_and_is_recorded(self) -> None:
        broken = unittest.mock.Mock(side_effect=RuntimeError("rapid-ntfs panicked: synthetic"))
        module = _module(parse_mft_record_headers=broken, parse_usn_record_scan=filesystem.parse_usn_record_scan)
        with self.rust_with(module):
            summary, rows = run_ntfs_meta(self.mft_blob, self.journal, "rust")
            with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "rust"}):
                engine = ntfs_native.resolve_ntfs_engine()
            engine.parse_mft_record_headers(self.mft_blob)
            engine.parse_mft_record_headers(self.mft_blob)
        self.assertEqual(broken.call_count, 2)  # once per input, never again after the failure
        self.assertEqual(engine.python_fallback_count, 2)
        self.assertEqual(summary["native_mft_engine"], "python")
        self.assertEqual(summary["native_mft_engine_python_fallback_count"], 1)
        self.assertIn("panicked: synthetic", str(summary["native_mft_engine_notice_ko"]))
        self.assertEqual((summary["native_usn_engine"], summary["native_usn_engine_python_fallback_count"]), ("rust", 0))
        self.assertEqual(rows, run_ntfs_meta(self.mft_blob, self.journal, "python")[1])

    def test_unknown_engine_value_keeps_python_and_is_recorded(self) -> None:
        with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "fortran"}):
            engine = ntfs_native.resolve_ntfs_engine()
        self.assertEqual(engine.active, "python")
        self.assertIn("fortran", str(engine.provenance("usn")["native_usn_engine_notice_ko"]))

    def test_consumer_reading_python_only_fields_keeps_python(self) -> None:
        loader = unittest.mock.Mock()
        with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "rust"}), unittest.mock.patch.object(
            ntfs_native, "load_native_ntfs_parser", loader
        ):
            engine = ntfs_native.resolve_ntfs_engine(reads_python_only=["hashes", "cursor_window_profile"])
            with self.assertRaises(ValueError):
                ntfs_native.resolve_ntfs_engine(reads_python_only=["sha1"])
        loader.assert_not_called()
        fields = engine.provenance("mft")
        self.assertEqual(fields["native_mft_engine"], "python")
        self.assertIn("cursor_window_profile, hashes", str(fields["native_mft_engine_notice_ko"]))

    def test_filesystem_collector_stays_python_and_records_why(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "$MFT").write_bytes(self.mft_blob)
            (Path(tmp) / "$J").write_bytes(self.journal)
            outputs = {}
            for engine in ("python", "rust"):
                with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: engine}):
                    outputs[engine] = list(filesystem.collect_native_ntfs_artifacts(Path(tmp)))
        inventories = {record.artifact_type: record.details for record in outputs["rust"] if record.artifact_type in {"mft-file", "usn-journal-file"}}
        self.assertEqual(set(inventories), {"mft-file", "usn-journal-file"})
        self.assertEqual(inventories["mft-file"]["native_mft_engine"], "python")
        self.assertIn("hashes", str(inventories["usn-journal-file"]["native_usn_engine_notice_ko"]))
        for record in outputs["python"]:
            self.assertFalse([key for key in record.details if key.startswith("native_mft_engine") or key.startswith("native_usn_engine")])
        self.assertEqual(len(outputs["python"]), len(outputs["rust"]))

    def test_ntfs_meta_analysis_reads_no_python_only_or_rust_only_field(self) -> None:
        # Every key the NTFS-meta analysis reads from a parser record or scan, on records that
        # carry all Python fields: none may be one the Rust records lack (or only Rust has).
        _ReadTracker.reads = set()
        module = _module(
            parse_mft_record_headers=lambda blob: _tracked(filesystem.parse_mft_record_headers(blob)),
            parse_usn_record_scan=lambda blob, **window: _tracked(filesystem.parse_usn_record_scan(blob, **window)),
        )
        with self.rust_with(module):
            run_ntfs_meta(self.mft_blob, self.journal, "rust")
        reads = set(_ReadTracker.reads)
        self.assertGreaterEqual(reads, {"records", "file_name_entries", "standard_information", "data_attributes", "file_reference_number_decoded"})
        self.assertEqual(reads & UNREADABLE_KEYS, set())

    def test_only_audited_consumers_use_the_engine_bridge(self) -> None:
        # A new consumer must declare reads_python_only (or extend the read audit above).
        package = Path(ntfs_native.__file__).resolve().parents[1]
        users = sorted(
            str(path.relative_to(package)).replace(os.sep, "/")
            for path in package.rglob("*.py")
            if "resolve_ntfs_engine" in path.read_text(encoding="utf-8") and path.name != "ntfs_native.py"
        )
        self.assertEqual(users, ["api/app/analysis_kinds.py", "artifacts/windows/filesystem.py"])

    def test_generator_produces_odd_tick_journal(self) -> None:
        journal, filetimes = synth.parity_usn_journal()
        first = synth.usn_v2("x", 0x100, 1, 2, 3, synth.ticks(1))
        self.assertEqual(struct.unpack_from("<Q", first, 32)[0] % 10, synth.ticks(1) % 10)
        self.assertGreater(len(journal), 4096)
        self.assertIn(synth.OUT_OF_RANGE_FILETIME, filetimes)


if __name__ == "__main__":
    unittest.main()
