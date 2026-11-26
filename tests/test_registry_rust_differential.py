"""Differential tests: the Rust registry engine against the Python hive reader.

The Rust engine (``rapid_registry_native``, ``engines/rust/crates/rapid-registry``) must be
indistinguishable from ``NativeRegistryHive``: identical reader-level traces (keys, values, data,
allocation state, lookups, raw offset probes, free-cell candidates, string pivot, error Counter
order) and identical collector rows (registry, ShellBags, execution/Amcache/UserAssist/BAM, SAM
accounts, media players) over fixture hives, generated hives (large trees, free cells, big data,
non-ASCII names, many hbins) and structurally damaged hives.

Skipped when the extension is not built unless ``RAPIDTRIAGE_REQUIRE_RUST_REGISTRY=1`` (CI sets
it after ``python scripts/build-native-accel.py --crate rapid-registry``).
"""

from __future__ import annotations

import os
import random
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from rapidtriage.artifacts.windows import registry_engine as engine_module
from rapidtriage.artifacts.windows.registry import (
    NativeRegistryHive,
    RegistryCollectionContext,
    RustRegistryHive,
    collect_registry_hive,
    filetime_to_iso_ticks,
)
from tests.r5_l1_fixtures import ntuser_media_hive
from tests.r5_l2_fixtures import ntuser_hive as putty_ntuser_hive
from tests.r5_l2_fixtures import software_hive as putty_software_hive
from tests.registry_depth_fixtures import cyclic_office_hive
from tests.registry_depth_fixtures import ntuser_hive as depth_ntuser_hive
from tests.registry_depth_fixtures import software_hive as depth_software_hive
from tests.registry_depth_fixtures import system_hive as depth_system_hive
from tests.registry_engine_diff import (
    api_trace,
    canonical,
    collect_rows,
    count_fields,
    diff_paths,
    open_engine,
    registry_engine,
    rust_module,
)
from tests.registry_hive_gen import corrupted_variants, generate_hive
from tests.test_d12_registry import amcache_hive as d12_amcache_hive
from tests.test_d12_registry import bagmru_hive, small_hive
from tests.test_d12_registry import system_hive as d12_system_hive
from tests.test_parser_quality_r2_artifacts import amcache_hive as r2_amcache_hive
from tests.test_parser_quality_r2_artifacts import usb_system_hive
from tests.test_parser_quality_registry import (
    build_sam_hive,
    build_system_hive,
    build_usrclass_shellbags,
)

REQUIRE_RUST = os.environ.get("RAPIDTRIAGE_REQUIRE_RUST_REGISTRY") == "1"


def fixture_hives() -> list[tuple[str, bytes]]:
    return [
        ("d12-system-current", d12_system_hive("CURRENT")),
        ("d12-system-current-lower", d12_system_hive("current")),
        ("d12-amcache", d12_amcache_hive()),
        ("d12-small", small_hive()),
        ("d12-bagmru", bagmru_hive(extra_child_without_value=True)),
        ("pq-system", build_system_hive()),
        ("pq-sam", build_sam_hive()),
        ("pq-usrclass", build_usrclass_shellbags()),
        ("depth-software", depth_software_hive()),
        ("depth-system", depth_system_hive()),
        ("depth-ntuser", depth_ntuser_hive()),
        ("depth-cyclic-office", cyclic_office_hive("User MRU", 300)),
        ("r5-ntuser-media", ntuser_media_hive()),
        ("r5-putty-ntuser", putty_ntuser_hive()),
        ("r5-putty-software", putty_software_hive()),
        ("r2-usb-system", usb_system_hive()),
        ("r2-amcache", r2_amcache_hive()),
    ]


def write(root: Path, relative: str, blob: bytes) -> None:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def build_evidence_tree(root: Path, variant: int) -> None:
    """A Windows-like tree whose hives exercise every collector that reads hives."""
    config = "Windows/System32/config"
    damaged = dict(corrupted_variants(500 + variant))
    if variant == 0:
        write(root, f"{config}/SYSTEM", build_system_hive())
        write(root, f"{config}/SOFTWARE", depth_software_hive())
        write(root, "Users/alice/NTUSER.DAT", depth_ntuser_hive())
        write(root, "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", build_usrclass_shellbags())
        write(root, "Users/bob/NTUSER.DAT", putty_ntuser_hive())
        write(root, "Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat", bagmru_hive())
        write(root, "Windows/AppCompat/Programs/Amcache.hve", d12_amcache_hive())
        write(root, f"{config}/DRIVERS", damaged["truncated-hbin-data"])
        write(root, f"{config}/ELAM", damaged["random-byte-damage-0"])
    else:
        write(root, f"{config}/SYSTEM", usb_system_hive())
        write(root, f"{config}/SOFTWARE", putty_software_hive())
        write(root, "Users/carol/NTUSER.DAT", ntuser_media_hive())
        write(root, "Windows/AppCompat/Programs/Amcache.hve", r2_amcache_hive())
        write(root, f"{config}/DRIVERS", damaged["hbin-signature-gap"])
        write(root, f"{config}/BBI", damaged["subkey-cycle-to-root"])
    write(root, f"{config}/SAM", build_sam_hive())
    write(root, f"{config}/SECURITY", generate_hive(900 + variant, key_count=400))
    write(root, f"{config}/COMPONENTS", generate_hive(950 + variant, key_count=1500, big_ratio=0.05))
    write(root, f"{config}/USERDIFF", damaged["ri-depth-exceeded"])
    write(root, f"{config}/DEFAULT", damaged["big-data-segment-missing"])


@unittest.skipUnless(rust_module() is not None or REQUIRE_RUST, "rapid_registry_native not built")
class RegistryRustDifferentialTests(unittest.TestCase):
    compared_fields = 0

    @classmethod
    def setUpClass(cls) -> None:
        if rust_module() is None:
            raise AssertionError(f"RAPIDTRIAGE_REQUIRE_RUST_REGISTRY=1 but the extension did not load: {engine_module.load_registry_extension()[1]}")

    def assert_identical(self, label: str, python_side: object, rust_side: object) -> None:
        if python_side != rust_side or canonical(python_side) != canonical(rust_side):
            self.fail(f"{label}: engines differ: {diff_paths(python_side, rust_side)}")
        type(self).compared_fields += count_fields(python_side)

    def assert_api_parity(self, label: str, blob: bytes, *, seed: int = 0) -> None:
        traces = []
        for engine in ("python", "rust"):
            hive = open_engine(blob, engine)
            try:
                traces.append(api_trace(hive, seed=seed))
            finally:
                hive.close()
        self.assert_identical(label, *traces)

    def test_engine_objects(self) -> None:
        hive = open_engine(build_system_hive(), "rust")
        try:
            self.assertIsInstance(hive, RustRegistryHive)
            self.assertEqual(type(hive.root).__module__, "rapid_registry_native")
        finally:
            hive.close()

    def test_fixture_hives_reader_parity(self) -> None:
        for label, blob in fixture_hives():
            with self.subTest(label):
                self.assert_api_parity(label, blob)

    def test_generated_hives_reader_parity(self) -> None:
        cases = [(seed, 150 + seed * 40) for seed in range(12)] + [(77, 6000)]
        for seed, key_count in cases:
            with self.subTest(seed=seed, keys=key_count):
                self.assert_api_parity(f"generated-{seed}", generate_hive(seed, key_count=key_count), seed=seed)

    def test_damaged_hives_reader_parity(self) -> None:
        for seed in (1, 2, 3):
            for label, blob in corrupted_variants(seed):
                with self.subTest(seed=seed, variant=label):
                    self.assert_api_parity(f"{seed}-{label}", blob, seed=seed)

    def test_text_and_time_decoding_parity(self) -> None:
        module = rust_module()
        rng = random.Random(7)
        alphabet = [0x00, 0x41, 0xD8, 0xDC, 0xDB, 0xDF, 0xFF, 0x20, 0xAC, 0xD5]
        for _ in range(20000):
            raw = bytes(rng.choice(alphabet) if rng.random() < 0.8 else rng.randrange(256) for _ in range(rng.randrange(0, 13)))
            self.assertEqual(
                module.decode_utf16le_replace(raw),  # type: ignore[attr-defined]
                raw.decode("utf-16-le", errors="replace"),
                raw.hex(),
            )
        ticks = [0, 1, 9_999_999, 10_000_000, 116_444_736_000_000_000, 2**63, 2**64 - 1]
        ticks += [rng.randrange(0, 2**64) for _ in range(20000)] + [rng.randrange(0, 2_650_467_743_990_000_000) for _ in range(20000)]
        for value in ticks:
            self.assertEqual(module.filetime_to_iso_ticks(value), filetime_to_iso_ticks(value), value)  # type: ignore[attr-defined]

    def test_collector_rows_parity(self) -> None:
        for variant in (0, 1):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                build_evidence_tree(root, variant)
                with registry_engine("python"):
                    python_rows = collect_rows(root)
                with registry_engine("rust"):
                    rust_rows = collect_rows(root)
                self.assertGreater(sum(len(rows) for rows in python_rows.values()), 1000)
                self.assert_identical(f"collector-rows-{variant}", python_rows, rust_rows)

    def test_registry_hive_row_names_the_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SYSTEM"
            path.write_bytes(build_system_hive())
            with registry_engine("rust"):
                hive_rows = [r for r in collect_registry_hive(path, context=RegistryCollectionContext(None)) if r.artifact_type == "registry-hive"]
            with registry_engine("python"):
                default_rows = [r for r in collect_registry_hive(path, context=RegistryCollectionContext(None)) if r.artifact_type == "registry-hive"]
        self.assertEqual(hive_rows[0].details["native_registry_engine"], "rust")
        self.assertEqual(hive_rows[0].details["native_registry_engine_requested"], "rust")
        self.assertEqual(hive_rows[0].details["native_registry_engine_notice_ko"], "")
        self.assertNotIn("native_registry_engine", default_rows[0].details)


class RegistryEngineSwitchTests(unittest.TestCase):
    """Default and fallback behaviour; runs whether or not the extension is built."""

    def hive_row(self, path: Path) -> dict[str, object]:
        return next(r.details for r in collect_registry_hive(path, context=RegistryCollectionContext(None)) if r.artifact_type == "registry-hive")

    def test_default_is_python_without_provenance_fields(self) -> None:
        with registry_engine(""):
            hive = NativeRegistryHive.from_bytes(build_system_hive())
        self.assertIs(type(hive), NativeRegistryHive)
        self.assertEqual(hive.engine_status, {"requested": "python", "active": "python", "notice_ko": ""})

    def test_missing_extension_falls_back_with_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SYSTEM"
            path.write_bytes(build_system_hive())
            with registry_engine("rust"), unittest.mock.patch.object(
                engine_module, "load_registry_extension", return_value=(None, "import-failed: test")
            ), self.assertLogs("rapidtriage.artifacts.windows.registry_engine", "WARNING"):
                engine_module._logged_notices.clear()
                hive = NativeRegistryHive.open(path)
                self.assertIs(type(hive), NativeRegistryHive)
                hive.close()
                details = self.hive_row(path)
        self.assertEqual(details["native_registry_engine"], "python")
        self.assertEqual(details["native_registry_engine_requested"], "rust")
        self.assertIn("import-failed: test", str(details["native_registry_engine_notice_ko"]))

    def test_unknown_engine_value_falls_back_with_notice(self) -> None:
        with registry_engine("gpu"), self.assertLogs("rapidtriage.artifacts.windows.registry_engine", "WARNING"):
            engine_module._logged_notices.clear()
            status = engine_module.registry_engine_status()
        self.assertEqual(status["active"], "python")
        self.assertEqual(status["requested"], "gpu")
        self.assertIn("gpu", status["notice_ko"])


if __name__ == "__main__":
    unittest.main()
