"""Compare complete registry rows with the pre-index allocator and parent searches."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.windows import registry
from tests.test_parser_quality_registry import REG_DWORD, HiveWriter, Key


# Frozen per-row searches from before the optimization. They scan the original
# candidate sequence the index was built from, never the index itself.
def scan_neighbor_context(
    candidate: Mapping[str, object],
    candidates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    candidate_offset = int(candidate.get("cell_offset") or 0)
    ordered = sorted(
        (item for item in candidates if int(item.get("cell_offset") or 0) > 0),
        key=lambda item: int(item.get("cell_offset") or 0),
    )
    index = next(
        (idx for idx, item in enumerate(ordered) if int(item.get("cell_offset") or 0) == candidate_offset),
        -1,
    )
    previous_cell = ordered[index - 1] if index > 0 else None
    next_cell = ordered[index + 1] if index >= 0 and index + 1 < len(ordered) else None
    current_end = candidate_offset + int(candidate.get("cell_size") or 0)
    next_offset = int(next_cell.get("cell_offset") or 0) if next_cell is not None else 0
    gap_to_next = next_offset - current_end if next_offset else 0
    previous_offset = int(previous_cell.get("cell_offset") or 0) if previous_cell is not None else 0
    return {
        "profile_version": "registry-allocator-neighbor-context-v1",
        "candidate_cell_offset": candidate_offset,
        "candidate_hbin_offset": int(candidate.get("hbin_offset") or 0),
        "ordered_cell_index": index,
        "previous_cell": registry.registry_neighbor_cell_summary(previous_cell),
        "next_cell": registry.registry_neighbor_cell_summary(next_cell),
        "same_hbin_previous": bool(
            previous_cell is not None
            and int(previous_cell.get("hbin_offset") or 0) == int(candidate.get("hbin_offset") or 0)
        ),
        "same_hbin_next": bool(
            next_cell is not None
            and int(next_cell.get("hbin_offset") or 0) == int(candidate.get("hbin_offset") or 0)
        ),
        "gap_to_next_cell": gap_to_next,
        "previous_gap_to_candidate": candidate_offset
        - (previous_offset + int(previous_cell.get("cell_size") or 0))
        if previous_cell is not None
        else 0,
        "context_quality": "bounded-neighbor-cells-recorded" if previous_cell or next_cell else "no-neighbor-cells-in-scan-window",
        "validation_guidance": (
            "Use neighbor context to detect overwritten/slack false positives; it is not sufficient alone "
            "to prove deletion without known-answer or second-parser offset validation."
        ),
    }


def scan_preceding_key(value_cell, candidates):
    key_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in candidates
        if candidate.get("cell_kind") == "key-node"
    }
    value_offset = int(value_cell.get("cell_offset") or 0)
    preceding = [offset for offset in key_by_offset if offset < value_offset]
    if not preceding:
        return None
    nearest_offset = max(preceding)
    return key_by_offset[nearest_offset] if value_offset - nearest_offset <= 1024 * 1024 else None


def free_value(name: str) -> bytes:
    writer = HiveWriter()
    writer.write_value(name, REG_DWORD, (7).to_bytes(4, "little"))
    return bytes(writer.cells[4:])  # inline data, so there is just one cell


def append_hbin(blob: bytes, free_payloads: tuple[bytes, ...]) -> bytes:
    """Append a second 4 KiB hbin consisting entirely of free cells."""
    writer = HiveWriter()
    for payload in free_payloads:
        writer.alloc(payload, free=True)
    hbin = bytearray(4096)
    struct.pack_into("<4sII", hbin, 0, b"hbin", len(blob) - 4096, len(hbin))
    hbin[32 : 32 + len(writer.cells)] = writer.cells
    end = 32 + len(writer.cells)
    struct.pack_into("<i", hbin, end, len(hbin) - end)

    updated = bytearray(blob) + hbin
    struct.pack_into("<I", updated, 40, len(updated) - 4096)
    checksum = 0
    for (word,) in struct.iter_unpack("<I", updated[:508]):
        checksum ^= word
    struct.pack_into("<I", updated, 508, checksum)
    return bytes(updated)


class RegistryDeletedContextTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "NTUSER.DAT"

    def assert_matches_scan(self, blob: bytes, free_count: int):
        self.path.write_bytes(blob)
        scanned: dict[int, Sequence[Mapping[str, object]]] = {}

        class RecordingIndex(registry._RegistryRecoveryIndex):
            def __init__(self, candidates: Sequence[Mapping[str, object]]) -> None:
                super().__init__(candidates)
                scanned[id(self)] = candidates

        def neighbor(candidate, index):
            return scan_neighbor_context(candidate, scanned[id(index)])

        def preceding(value_cell, index):
            return scan_preceding_key(value_cell, scanned[id(index)])

        with (
            patch.object(registry, "_RegistryRecoveryIndex", RecordingIndex),
            patch.object(registry, "registry_allocator_neighbor_context", wraps=neighbor) as reference,
            patch.object(registry, "nearest_preceding_key", preceding),
        ):
            expected = [row.to_dict() for row in registry.collect_registry_hive(self.path)]
            self.assertEqual(reference.call_count, free_count)
        actual = [row.to_dict() for row in registry.collect_registry_hive(self.path)]
        self.assertEqual(sum(row["artifact_type"] == "registry-deleted-cell-candidate" for row in actual), free_count)
        # Compare JSON without sorting keys to catch row/field reordering and boolean/integer changes.
        self.assertEqual([json.dumps(row) for row in actual], [json.dumps(row) for row in expected])
        return [row["details"] for row in actual if row["artifact_type"].endswith("-recovery-candidate")]

    def test_empty_and_single_candidate_match_scan(self) -> None:
        for payloads in ((), (free_value("Single"),)):
            with self.subTest(count=len(payloads)):
                blob = HiveWriter().build(Key("ROOT"), free_payloads=payloads)
                recovered = self.assert_matches_scan(blob, len(payloads))
                self.assertEqual(len(recovered), len(payloads))

    def test_adjacent_and_cross_bin_neighbors_match_scan(self) -> None:
        writer = HiveWriter()
        key = bytearray(writer.nk_payload(Key("First"), root=False))
        struct.pack_into("<I", key, 0x10, 32)  # include the allocated root in the recovery index
        first = writer.build(Key("ROOT"), free_payloads=(bytes(key), free_value("Adjacent")))
        blob = append_hbin(first, (free_value("Across"),))
        recovered = self.assert_matches_scan(blob, 3)
        adjacent = recovered[1]["registry_recovery_evidence"]["allocator_neighbor_context"]
        self.assertEqual(adjacent["previous_gap_to_candidate"], 0)
        self.assertFalse(adjacent["same_hbin_next"])
        self.assertEqual(adjacent["next_cell"]["hbin_offset"], 8192)

    def test_ties_unsorted_offsets_and_parent_cutoff_match_scan(self) -> None:
        writer = HiveWriter()
        key = writer.nk_payload(Key("Original"), root=False)
        blob = writer.build(Key("ROOT"), free_payloads=(key, free_value("Value")))
        scan_cells = registry.iter_registry_free_cell_candidates

        def colliding_candidates(hive):
            # Physical cells cannot overlap. Inject scanner output to exercise
            # the lookup contract with distinguishable ties and nonpositive offsets.
            cells, stats = scan_cells(hive)
            key, value = cells
            offset = key["cell_offset"]
            limit = offset + 1024 * 1024
            return [
                dict(value, cell_offset=limit + 1),
                key,
                dict(key, name="Second", cell_size=48),
                dict(value, cell_offset=offset),
                dict(value, cell_offset=limit),
                dict(value, cell_offset=0),
                dict(value, cell_offset=-8),
            ], stats

        with patch.object(registry, "iter_registry_free_cell_candidates", colliding_candidates):
            recovered = self.assert_matches_scan(blob, 7)
        self.assertEqual(
            [row["parent_key_confidence"] for row in recovered if "parent_key_confidence" in row],
            ["unknown", "unknown", "nearest-preceding-key", "unknown", "unknown"],
        )
        self.assertTrue(recovered[4]["parent_key_path_candidate"].endswith(r"\Second"))

    def test_explicit_value_list_keeps_input_key_order(self) -> None:
        writer = HiveWriter()
        keys = [writer.alloc(writer.nk_payload(Key(name), root=False), free=True) for name in ("A", "B")]
        value = writer.alloc(free_value("Linked"), free=True)
        value_list = writer.alloc(struct.pack("<I", value))
        for key in keys:
            writer.patch_u32(key, 0x24, 1)
            writer.patch_u32(key, 0x28, value_list)
        blob = writer.build(Key("ROOT"))
        scan_cells = registry.iter_registry_free_cell_candidates

        def reversed_candidates(hive):
            cells, stats = scan_cells(hive)
            return cells[::-1], stats

        with patch.object(registry, "iter_registry_free_cell_candidates", reversed_candidates):
            recovered = self.assert_matches_scan(blob, 3)
        self.assertEqual(recovered[-1]["parent_key_confidence"], "key-value-list")
        self.assertTrue(recovered[-1]["parent_key_path_candidate"].endswith(r"\B"))
