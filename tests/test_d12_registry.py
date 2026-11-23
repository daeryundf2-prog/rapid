"""D12 adversarial review: registry name case, Amcache cell allocation, hive completeness, BagMRU slots.

Every hive is synthesized in-test with the minimal regf writer from ``test_parser_quality_registry``.
The core assertions use only Rapid's native reader; python-registry is an optional cross-check.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.execution import build_native_amcache_records
from rapidtriage.artifacts.windows.registry import (
    NativeRegistryHive,
    RegistryValueMap,
    collect_registry_hive,
    registry_native_summary_facts,
)
from rapidtriage.artifacts.windows.shellbags import collect_native_shellbag_hive
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    dword,
    mru_list_ex,
    shell_volume,
    sz,
    write_hive,
)

HIVE_BIN_BASE = 4096


def python_registry(blob: bytes):
    try:
        from Registry import Registry
    except ImportError as exc:
        raise unittest.SkipTest("python-registry comparison reader unavailable") from exc
    return Registry.Registry(io.BytesIO(blob))


def details(records, artifact_type: str) -> dict:
    return next(record.details for record in records if record.artifact_type == artifact_type)


def system_hive(select_name: str) -> bytes:
    root = Key("ROOT")
    root.path("Select").value(select_name, REG_DWORD, dword(2))
    for index, bias in [(1, 0), (2, -540)]:
        root.path(rf"ControlSet{index:03d}\Control\TimeZoneInformation").value("Bias", REG_DWORD, dword(bias))
    return HiveWriter().build(root)


class SelectCurrentCaseTests(unittest.TestCase):
    """Item 5: Select\\Current is matched case-insensitively (Windows semantics)."""

    def test_every_spelling_resolves_controlset002_and_kst(self) -> None:
        for spelling in ("Current", "current", "CURRENT"):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as tmp:
                path = write_hive(Path(tmp), "SYSTEM", system_hive(spelling))
                records = list(collect_registry_hive(path))
                control = details(records, "windows-control-set")
                zone = details(records, "windows-timezone")
                self.assertEqual(control["current_control_set"], "ControlSet002")
                self.assertEqual(control["resolution_source"], "Select\\Current")
                self.assertEqual(zone["utc_offset"], "+09:00")
                self.assertEqual(control["select_values"], {spelling: 2})  # stored spelling kept for display
                self.assertIn("ControlSet002", zone["key_path"])

    def test_value_map_lookup_is_case_insensitive_and_keeps_spelling(self) -> None:
        hive = NativeRegistryHive.from_bytes(system_hive("CURRENT"))
        values = hive.values_dict(hive.open_key("select"))
        self.assertIsInstance(values, RegistryValueMap)
        self.assertEqual(list(values), ["CURRENT"])
        self.assertEqual(values.get("Current"), 2)
        self.assertEqual(values["current"], 2)
        self.assertIn("cUrReNt", values)
        self.assertIsNone(values.get("Missing"))
        self.assertNotIn("Missing", values)

    def test_reg_export_values_are_case_insensitive_too(self) -> None:
        from rapidtriage.artifacts.windows.registry_depth import ExportKeySource

        source = ExportKeySource("system", "HKEY_LOCAL_MACHINE\\SYSTEM", "")
        source.add("Select", {"CURRENT": 2}, 1)
        view = source.key("select")
        self.assertEqual(view.values.get("Current"), 2)
        # A later section with another spelling updates the same value, not a twin.
        source.add("SELECT", {"current": 3}, 5)
        self.assertEqual(dict(source.key("Select").values), {"CURRENT": 3})

    def test_python_registry_agrees_on_active_set(self) -> None:
        reference = python_registry(system_hive("CURRENT"))
        current = reference.open("Select").value("Current").value()
        bias = reference.open(rf"ControlSet{current:03d}\Control\TimeZoneInformation").value("Bias").value()
        self.assertEqual((current, bias - (1 << 32)), (2, -540))


def amcache_hive() -> bytes:
    root = Key("ROOT")
    item = root.path(r"Root\InventoryApplicationFile\Item")
    item.value("LowerCaseLongPath", REG_SZ, sz(r"c:\sample\demo.exe"))
    item.value("FileId", REG_SZ, sz("0000" + "f" * 40))
    return HiveWriter().build(root)


def free_cell(blob: bytes, file_offset: int) -> bytes:
    """Flip one allocated (negative-size) cell to free (positive size)."""
    size = int.from_bytes(blob[file_offset : file_offset + 4], "little", signed=True)
    assert size < 0, size
    patched = bytearray(blob)
    patched[file_offset : file_offset + 4] = (-size).to_bytes(4, "little", signed=True)
    return bytes(patched)


def item_cells(blob: bytes) -> tuple[int, int]:
    """(nk file offset, LowerCaseLongPath vk file offset) of the Amcache Item key."""
    hive = NativeRegistryHive.from_bytes(blob)
    key = hive.open_key(r"Root\InventoryApplicationFile\Item")
    value = hive.value(key, "LowerCaseLongPath")
    return HIVE_BIN_BASE + int(key.offset), HIVE_BIN_BASE + int(value.offset)


class AmcacheCellAllocationTests(unittest.TestCase):
    """Item 2: allocation_status comes from the cell-size sign, free cells are not current rows."""

    def collect(self, blob: bytes) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Amcache.hve", blob)
            return list(build_native_amcache_records(path))

    def test_allocated_control_stays_current_inventory(self) -> None:
        blob = amcache_hive()
        nk_offset, _ = item_cells(blob)
        records = self.collect(blob)
        rows = [record.details for record in records if record.artifact_type == "amcache-schema-row"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["allocation_status"], "allocated")
        self.assertEqual(rows[0]["cell_offset"], nk_offset)
        self.assertTrue(rows[0]["cell_allocation"]["key_cell_allocated"])
        self.assertEqual(rows[0]["executable_path"], r"c:\sample\demo.exe")
        self.assertEqual(details(records, "amcache-hive")["free_cell_recovery_candidate_count"], 0)

    def test_free_key_cell_is_recovery_candidate_not_allocated_row(self) -> None:
        blob = amcache_hive()
        nk_offset, _ = item_cells(blob)
        records = self.collect(free_cell(blob, nk_offset))
        self.assertEqual([record for record in records if record.artifact_type == "amcache-schema-row"], [])
        self.assertEqual([record for record in records if record.artifact_type == "amcache-string-candidate"], [])
        hive = details(records, "amcache-hive")
        self.assertEqual(hive["schema_row_count"], 0)
        self.assertEqual(hive["free_cell_recovery_candidate_count"], 1)
        candidate = hive["amcache_free_cell_recovery_candidates"][0]
        self.assertEqual(candidate["cell_offset"], nk_offset)
        self.assertEqual(candidate["allocation_status"], "free-or-deleted-candidate")
        self.assertFalse(candidate["cell_allocation"]["key_cell_allocated"])
        self.assertEqual(candidate["section"], "InventoryApplicationFile")
        self.assertEqual(candidate["decoded_values"]["LowerCaseLongPath"], r"c:\sample\demo.exe")
        self.assertTrue(candidate["source_path"].endswith("Amcache.hve"))
        self.assertEqual(hive["amcache_schema_decode"]["free_cell_candidate_row_count"], 1)

    def test_free_value_cell_also_demotes_the_row(self) -> None:
        blob = amcache_hive()
        _, vk_offset = item_cells(blob)
        records = self.collect(free_cell(blob, vk_offset))
        self.assertEqual([record for record in records if record.artifact_type == "amcache-schema-row"], [])
        candidate = details(records, "amcache-hive")["amcache_free_cell_recovery_candidates"][0]
        self.assertTrue(candidate["cell_allocation"]["key_cell_allocated"])
        self.assertEqual(
            candidate["cell_allocation"]["free_value_cells"],
            [{"value_name": "LowerCaseLongPath", "cell_offset": vk_offset}],
        )

    def test_python_registry_locates_the_same_nk_cell(self) -> None:
        blob = amcache_hive()
        nk_offset, _ = item_cells(blob)
        key = python_registry(blob).open(r"Root\InventoryApplicationFile\Item")
        self.assertEqual(key._nkrecord.offset() - 4, nk_offset)


def small_hive() -> bytes:
    root = Key("ROOT")
    root.path("Review").value("Data", REG_DWORD, dword(5))
    return HiveWriter().build(root)


class HiveCompletenessTests(unittest.TestCase):
    """Item 7: declared vs actual hbin range, root resolution and walk errors reach the coverage."""

    def inventory(self, blob: bytes, **kwargs: object) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "SOFTWARE", blob)
            return details(list(collect_registry_hive(path, **kwargs)), "registry-hive")

    def test_intact_control_is_a_full_walk(self) -> None:
        row = self.inventory(small_hive())
        self.assertEqual(row["coverage_status"], "native-hive-full-walk")
        self.assertEqual(row["parser_confidence"], 0.9)
        self.assertEqual((row["key_count"], row["value_count"]), (2, 1))
        self.assertEqual(row["key_tree_status"], "walked")
        self.assertEqual(row["hive_completeness_status"], "complete")
        self.assertEqual(row["hive_completeness"]["loss_locations"], [])

    def test_base_block_only_is_unreadable_with_loss_location(self) -> None:
        blob = small_hive()
        declared = int.from_bytes(blob[40:44], "little")
        row = self.inventory(blob[:HIVE_BIN_BASE])
        self.assertEqual(row["coverage_status"], "native-hive-unreadable")
        self.assertLess(row["parser_confidence"], 0.9)
        self.assertEqual(row["hive_completeness_status"], "unreadable")
        self.assertIsNone(row["key_count"])  # not examined, not "0 keys"
        self.assertIsNone(row["value_count"])
        self.assertEqual(row["key_tree_status"], "root-unresolved")
        losses = {loss["kind"]: loss for loss in row["hive_completeness"]["loss_locations"]}
        self.assertEqual(
            losses["hbin-data-truncated"],
            {
                "kind": "hbin-data-truncated",
                "declared_end": HIVE_BIN_BASE + declared,
                "actual_end": HIVE_BIN_BASE,
                "missing_bytes": declared,
            },
        )
        self.assertIn("root-cell-unresolved", losses)
        self.assertIn("registry-hive-unreadable", row["risk_flags"])
        hives = registry_native_summary_facts([_record("registry-hive", row)])["hives"]
        self.assertEqual(hives[0]["key_tree_status"], "root-unresolved")

    def test_walk_errors_make_the_walk_partial(self) -> None:
        root = Key("ROOT")
        root.path("Review").value("Data", REG_DWORD, dword(5))
        root.path("Other").value("Data", REG_DWORD, dword(6))
        blob = HiveWriter().build(root)
        hive = NativeRegistryHive.from_bytes(blob)
        other = hive.open_key("Other")
        offset = HIVE_BIN_BASE + int(other.offset)
        broken = bytearray(blob)
        broken[offset + 4 : offset + 6] = b"xx"  # child nk signature destroyed
        row = self.inventory(bytes(broken))
        self.assertEqual(row["coverage_status"], "native-hive-partial-walk")
        self.assertEqual(row["hive_completeness_status"], "incomplete")
        self.assertEqual(row["key_tree_status"], "partial")
        self.assertEqual(row["key_count"], 2)
        kinds = [loss["kind"] for loss in row["hive_completeness"]["loss_locations"]]
        self.assertEqual(kinds, ["key-tree-walk-errors"])

    def test_inventory_only_call_does_not_claim_a_walk(self) -> None:
        row = self.inventory(small_hive(), include_key_tree=False)
        self.assertNotEqual(row["coverage_status"], "native-hive-full-walk")
        self.assertEqual(row["coverage_status"], "native-hive-inventory")
        self.assertEqual(row["key_tree_status"], "not-run")
        self.assertIsNone(row["key_count"])
        self.assertIsNone(row["native_walk"]["key_count"])

    def test_python_registry_reads_the_intact_control(self) -> None:
        self.assertEqual(python_registry(small_hive()).open("Review").value("Data").value(), 5)


def _record(artifact_type: str, row: dict):
    from rapidtriage.core.models import ArtifactRecord

    return ArtifactRecord(provider="windows-registry", artifact_type=artifact_type, path="", supported=True, details=row)


def bagmru_hive(*, extra_child_without_value: bool = False) -> bytes:
    root = Key("ROOT")
    bagmru = root.path(r"Software\Microsoft\Windows\Shell\BagMRU")
    bagmru.value("0", REG_BINARY, shell_volume("F") + b"\x00\x00").key("0")
    bagmru.value("1", REG_BINARY, shell_volume("G") + b"\x00\x00")
    order = [1, 0]
    if extra_child_without_value:
        bagmru.key("2")
        order += [2, 5]
    bagmru.value("MRUListEx", REG_BINARY, mru_list_ex(order))
    return HiveWriter().build(root)


class BagMruSlotReconciliationTests(unittest.TestCase):
    """Item 13: numbered values and child keys are reconciled; a value without a child key is kept."""

    def collect(self, blob: bytes) -> tuple[dict, dict]:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "NTUSER.DAT", blob)
            records = list(collect_native_shellbag_hive(path))
        entries = {
            record.details["slot_name"]: record.details
            for record in records
            if record.artifact_type == "shellbag-entry" and not record.details["bagmru_root"]
        }
        return entries, details(records, "shellbag-hive-summary")

    def test_value_without_child_key_is_emitted_with_mru_rank(self) -> None:
        entries, summary = self.collect(bagmru_hive())
        self.assertEqual(sorted(entries), ["0", "1"])
        self.assertEqual((entries["0"]["item_name"], entries["0"]["mru_position"]), ("F:\\", 1))
        self.assertEqual((entries["1"]["item_name"], entries["1"]["mru_position"]), ("G:\\", 0))
        self.assertEqual(entries["0"]["slot_reconciliation"], "value-and-child-key")
        orphan = entries["1"]
        self.assertEqual(orphan["slot_reconciliation"], "value-without-child-key")
        self.assertFalse(orphan["slot_child_key_present"])
        self.assertEqual(orphan["key_last_written_at"], "")  # child last-write unknown
        self.assertEqual(orphan["timestamp"], "")
        self.assertEqual(orphan["key_cell_offset"], 0)
        self.assertTrue(orphan["key_path"].endswith("Shell\\BagMRU"))
        self.assertGreater(orphan["shellitem_value_cell_offset"], 0)
        self.assertEqual(summary["shellbag_entry_count"], 2)
        reconciliation = summary["bagmru_slot_reconciliation"]
        self.assertEqual(reconciliation["numbered_value_count"], 2)
        self.assertEqual(reconciliation["child_key_count"], 1)
        self.assertEqual(reconciliation["value_and_child_key_count"], 1)
        self.assertEqual(reconciliation["value_without_child_key_count"], 1)
        self.assertEqual(reconciliation["child_key_without_value_count"], 0)

    def test_child_without_value_and_dangling_mru_slot_are_counted(self) -> None:
        entries, summary = self.collect(bagmru_hive(extra_child_without_value=True))
        self.assertEqual(sorted(entries), ["0", "1", "2"])
        self.assertEqual(entries["2"]["slot_reconciliation"], "child-key-without-value")
        self.assertEqual(entries["2"]["mru_position"], 2)
        reconciliation = summary["bagmru_slot_reconciliation"]
        self.assertEqual(reconciliation["child_key_without_value_count"], 1)
        self.assertEqual(reconciliation["mru_slot_without_value_or_key_count"], 1)

    def test_python_registry_sees_both_numbered_values(self) -> None:
        key = python_registry(bagmru_hive()).open(r"Software\Microsoft\Windows\Shell\BagMRU")
        names = sorted(value.name() for value in key.values() if value.name().isdecimal())
        entries, _ = self.collect(bagmru_hive())
        self.assertEqual(names, sorted(entries))


if __name__ == "__main__":
    unittest.main()
