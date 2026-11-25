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
import struct
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from rapidtriage.api.app import analysis_kinds
from rapidtriage.artifacts.windows import filesystem
from rapidtriage.core import ntfs_native
from tests import ntfs_synthetic as synth

EXTENSION = ntfs_native.load_extension()
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
        self.assertIsNotNone(EXTENSION, "RAPIDTRIAGE_REQUIRE_RAPID_NTFS=1 but rapid_ntfs_native is not importable")

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

    def test_ntfs_meta_rows_identical_under_both_engines(self) -> None:
        mft_blob = synth.build_mft(synth.parity_mft_specs())
        journal, _ = synth.parity_usn_journal()
        engines = {}
        for engine in ("python", "rust"):
            with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: engine}):
                root = Path(tmp)
                (root / "MFT.bin").write_bytes(mft_blob)
                (root / "J.bin").write_bytes(journal)
                ctx = _RowSink(root)
                nodes = analysis_kinds._NodeView()
                reference = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
                summary = analysis_kinds.parse_mft_file(ctx, root / "MFT.bin", nodes, 1024, mismatch_reference=reference)
                summary.update(analysis_kinds.parse_usn_file(ctx, root / "J.bin", nodes))
                engines[engine] = (summary, ctx.rows, ntfs_native.active_engine())
        self.assertEqual(engines["rust"][2], "rust")
        diff = differences(list(engines["python"][:2]), list(engines["rust"][:2]))
        self.assertEqual(diff, [], "\n".join(diff[:20]))
        self.assertGreater(len(engines["rust"][1]), 30)


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


class NtfsEngineSwitchTests(unittest.TestCase):
    def test_default_engine_is_python(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ntfs_native.ENGINE_ENV, None)
            self.assertEqual(ntfs_native.active_engine(), "python")

    def test_rust_request_without_extension_falls_back(self) -> None:
        blob = synth.build_mft(synth.parity_mft_specs()[:3])
        with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "rust"}), unittest.mock.patch.object(
            ntfs_native, "load_extension", return_value=None
        ):
            self.assertEqual(ntfs_native.active_engine(), "python")
            self.assertEqual(ntfs_native.parse_mft_record_headers(blob), filesystem.parse_mft_record_headers(blob))

    def test_rust_error_falls_back_to_python(self) -> None:
        journal, _ = synth.parity_usn_journal()
        broken = SimpleNamespace(parse_usn_record_scan=unittest.mock.Mock(side_effect=ValueError("boom")))
        with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "rust"}), unittest.mock.patch.object(
            ntfs_native, "load_extension", return_value=broken
        ):
            scan = ntfs_native.parse_usn_record_scan(journal)
        broken.parse_usn_record_scan.assert_called_once()
        self.assertEqual(scan, filesystem.parse_usn_record_scan(journal))

    def test_unknown_engine_value_keeps_python(self) -> None:
        with unittest.mock.patch.dict(os.environ, {ntfs_native.ENGINE_ENV: "fortran"}):
            self.assertEqual(ntfs_native.active_engine(), "python")

    def test_generator_produces_odd_tick_journal(self) -> None:
        journal, filetimes = synth.parity_usn_journal()
        first = synth.usn_v2("x", 0x100, 1, 2, 3, synth.ticks(1))
        self.assertEqual(struct.unpack_from("<Q", first, 32)[0] % 10, synth.ticks(1) % 10)
        self.assertGreater(len(journal), 4096)
        self.assertIn(synth.OUT_OF_RANGE_FILETIME, filetimes)


if __name__ == "__main__":
    unittest.main()
