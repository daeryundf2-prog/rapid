"""D19 review: Jump List link bounds, Prefetch acquisitions, CASE/UCO acquisitions,
SRUM ID-map SIDs and LNK tracker UUID nodes (synthetic fixtures only)."""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.execution import WindowsExecutionProvider
from rapidtriage.artifacts.windows.prefetch import (
    WindowsPrefetchProvider,
    build_prefetch_trusted_diff,
)
from rapidtriage.artifacts.windows.recent_files import (
    RECENT_ROOT,
    WindowsRecentFilesProvider,
)
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.case_export import export_case_uco_jsonld
from tests.test_r3_prefetch_decoding import build_pf
from tests.test_rapidtriage_case_export import _build_case_db
from tests.windows_artifact_fixtures import _minimal_ese_database_with_catalog
from tests.xpress_huffman_encoder import mam

LNK_CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
MY_COMPUTER = uuid.UUID("20d04fe0-3aea-1069-a2d8-08002b30309d").bytes_le
OTHER_TARGET = r"C:\Fixtures\Other.txt"


def lnk_header(flags: int) -> bytes:
    head = bytearray(76)
    struct.pack_into("<I16sI", head, 0, 76, LNK_CLSID, flags)
    struct.pack_into("<I", head, 0x3C, 1)
    return bytes(head)


def namespace_link() -> bytes:
    """HasLinkTargetIDList only: one 'My Computer' root item, no file-system path."""
    items = struct.pack("<HBB16sH", 20, 0x1F, 0x50, MY_COMPUTER, 0)
    return lnk_header(0x01) + struct.pack("<H", len(items)) + items + bytes(4)


def relative_path_link(path: str, extra: bytes = b"") -> bytes:
    """HasRelativePath + IsUnicode: the target path lives in StringData."""
    value = path.encode("utf-16le")
    return lnk_header(0x88) + struct.pack("<H", len(value) // 2) + value + extra + bytes(4)


def custom_destinations(links: list[bytes]) -> bytes:
    objects = b"".join(LNK_CLSID + link for link in links)
    return struct.pack("<IIIII", 2, 1, 0, 2, len(links)) + objects + struct.pack("<I", 0xBABFFBAB)


class CustomDestinationLinkBoundsTests(unittest.TestCase):
    """D19-1: each link's target comes from its own bytes, never the next link's."""

    def entries(self, links: list[bytes]) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "Users" / "Sample" / Path(*RECENT_ROOT) / "CustomDestinations"
            folder.mkdir(parents=True)
            (folder / "3141592653589793.customDestinations-ms").write_bytes(custom_destinations(links))
            rows = list(WindowsRecentFilesProvider().collect(root))
        return [row.details for row in rows if row.artifact_type == "jumplist-entry"]

    def test_namespace_link_alone_paired_and_reversed(self) -> None:
        folder, disk = namespace_link(), relative_path_link(OTHER_TARGET)
        alone = self.entries([folder])
        paired = self.entries([folder, disk])
        reversed_ = self.entries([disk, folder])
        self.assertEqual([d["target_path"] for d in alone], [""])
        self.assertEqual([d["lnk_offset"] for d in paired], [36, 36 + 16 + len(folder)])
        self.assertEqual([d["target_path"] for d in paired], ["", OTHER_TARGET])
        self.assertEqual([d["target_path"] for d in reversed_], [OTHER_TARGET, ""])
        # The folder link's own embedded paths never include the neighbour's file path.
        for rows, folder_index in ((paired, 0), (reversed_, 1)):
            self.assertNotIn(OTHER_TARGET, rows[folder_index].get("embedded_paths") or [])


def prefetch_acquisition(root: Path, run_count: int) -> tuple[dict[str, object], dict[str, object]]:
    """One compressed v30 Prefetch file per acquisition folder; returns (Rapid row, reference row)."""
    clock = datetime(2024, 1, 1, tzinfo=timezone.utc)
    directory = r"\VOLUME{00000000-0000-0000-0000-000000000001}"
    inner = build_pf(
        version=30,
        executable="SAMPLE.EXE",
        paths=[directory + r"\Fixtures\SAMPLE.EXE"],
        run_times=[clock - timedelta(hours=index) for index in range(run_count)],
        run_count=run_count,
        volumes=[(directory, 0x12345678, clock, [])],
    )
    wrapped = mam(inner)
    path = root / "Windows" / "Prefetch" / "SAMPLE.EXE-1A2B3C4D.pf"
    path.parent.mkdir(parents=True)
    path.write_bytes(wrapped)
    rapid = next(r.to_dict() for r in WindowsPrefetchProvider().collect(root) if r.artifact_type == "prefetch-file")
    reference = {
        "executable": inner[16:76].decode("utf-16le").rstrip("\0"),
        "prefetch_hash": f"{struct.unpack_from('<I', inner, 0x4C)[0]:08X}",
        "run_count": struct.unpack_from("<I", inner, 0xD0)[0],
        "source_sha256": hashlib.sha256(wrapped).hexdigest(),
    }
    return rapid, reference


class PrefetchAcquisitionDiffTests(unittest.TestCase):
    """D19-2: two acquisitions of one Prefetch file are compared one by one."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.a, cls.ref_a = prefetch_acquisition(root / "acq_a", 1)
        cls.b, cls.ref_b = prefetch_acquisition(root / "acq_b", 2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def diff(self, rapid: list, trusted: list) -> dict[str, object]:
        return build_prefetch_trusted_diff(rapid, trusted, trusted_tool="PECmd")

    def test_fixture_acquisitions_differ(self) -> None:
        self.assertEqual((self.ref_a["run_count"], self.ref_b["run_count"]), (1, 2))
        self.assertNotEqual(self.ref_a["source_sha256"], self.ref_b["source_sha256"])

    def test_both_acquisitions_match_in_either_order(self) -> None:
        for trusted in ([self.ref_a, self.ref_b], [self.ref_b, self.ref_a]):
            for rapid in ([self.a, self.b], [self.b, self.a]):
                out = self.diff(rapid, trusted)
                self.assertEqual((out["status"], out["matched_count"]), ("pass", 2))
                self.assertEqual(out["acquisition_identity"]["compared_by_sha256"], 2)

    def test_missing_acquisition_fails_regardless_of_reference_order(self) -> None:
        for rapid in ([self.a], [self.b]):
            for trusted in ([self.ref_a, self.ref_b], [self.ref_b, self.ref_a]):
                out = self.diff(rapid, trusted)
                self.assertEqual(out["status"], "diffs-present")
                self.assertFalse(out["commercial_grade_evidence"])
                self.assertGreaterEqual(out["extra_in_trusted_count"] + out["mismatch_count"], 1)
                self.assertEqual(out["rapid_indexed_count"], 1)
                self.assertEqual(out["trusted_indexed_count"], 2)
                self.assertLess(out["matched_count"], 2)

    def test_same_bytes_twice_do_not_stand_in_for_two_acquisitions(self) -> None:
        out = self.diff([self.a, self.a], [self.ref_a, self.ref_b])
        self.assertEqual(out["status"], "diffs-present")

    def test_single_controls(self) -> None:
        self.assertEqual(self.diff([self.b], [self.ref_b])["status"], "pass")
        self.assertEqual(self.diff([self.a], [self.ref_b])["status"], "diffs-present")

    def test_duplicate_rows_without_source_identity_are_not_a_pass(self) -> None:
        def anonymous(row: dict[str, object]) -> dict[str, object]:
            return {key: value for key, value in row.items() if key != "source_sha256"}

        def rapid_anonymous(row: dict[str, object]) -> dict[str, object]:
            details = {k: v for k, v in dict(row["details"]).items() if k not in ("source_hashes", "source_path")}
            return {"details": details}

        out = self.diff(
            [rapid_anonymous(self.a), rapid_anonymous(self.a)],
            [anonymous(self.ref_a), anonymous(self.ref_a)],
        )
        self.assertEqual(out["status"], "acquisition-identity-unresolved")
        self.assertFalse(out["commercial_grade_evidence"])
        self.assertEqual(out["acquisition_identity"]["ambiguous_unresolved_count"], 2)


class UcoAcquisitionGraphTests(unittest.TestCase):
    """D19-3: every acquisition row the summary counts is a node in the graph."""

    def test_reacquisition_and_unlinked_control_are_in_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "case.db"
            _build_case_db(db_path)  # EVD-1 with one linked acquisition (SRC-A)
            database = open_case_database(db_path)
            for label, link in (("repeat-synthetic", "EVD-1"), ("independent-control", "")):
                database.record_acquisition_metadata(
                    case_id="CASE-UCO-1",
                    evidence_source_citation_id=link,
                    source_identifier=label,
                    whole_source_sha256=hashlib.sha256(label.encode()).hexdigest(),
                )
            records = database.list_acquisition_metadata("CASE-UCO-1")
            payload = export_case_uco_jsonld(database, case_id="CASE-UCO-1")
            document = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        self.assertEqual(len(records), 3)
        summary = document["rapidtriage:exportSummary"]
        self.assertEqual(summary["row_counts"]["acquisition_metadata"], 3)
        self.assertFalse(summary["truncated"])
        graph_text = json.dumps(document["@graph"])
        for record in records:
            self.assertIn(record["citation_id"], graph_text)
            self.assertIn(record["source_identifier"], graph_text)
            self.assertIn(record["whole_source_sha256"], graph_text)
        nodes = document["@graph"][1:]
        provenance = [n for n in nodes if "case-investigation:ProvenanceRecord" in n["@type"]]
        self.assertEqual(summary["node_counts"]["provenance"], len(provenance))
        evidence_id = next(n["@id"] for n in provenance if n.get("rapidtriage:evidenceSourceId") is not None)
        reacquisition = next(n for n in provenance if n.get("rapidtriage:sourceIdentifier") == "repeat-synthetic")
        self.assertEqual(reacquisition["uco-core:object"], [{"@id": evidence_id}])
        control = next(n for n in provenance if n.get("rapidtriage:sourceIdentifier") == "independent-control")
        self.assertNotIn("uco-core:object", control)


ESE_PAGE = 4096
ESE_CATALOG_FIELDS = [4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4]


def ese_catalog_entry(fields: dict[int, int], name: str) -> bytes:
    fixed = b"".join(fields.get(i, 0).to_bytes(n, "little") for i, n in enumerate(ESE_CATALOG_FIELDS, 1))
    encoded = name.encode("ascii")
    return bytes(2) + struct.pack("<BBH", 12, 128, 4 + len(fixed) + 2) + fixed + bytes(2) + struct.pack("<H", len(encoded)) + encoded


def ese_page(flags: int, nodes: list[bytes]) -> bytes:
    result = bytearray(ESE_PAGE)
    offset = 0
    for index, node in enumerate(nodes):
        result[40 + offset : 40 + offset + len(node)] = node
        struct.pack_into("<HH", result, ESE_PAGE - 4 * (index + 2), len(node), offset)
        offset += len(node)
    struct.pack_into("<HHI", result, 32, offset, 0x1000 | (1 + len(nodes)), flags)
    return bytes(result)


def id_map_row(id_type: int, id_index: int, blob: bytes) -> bytes:
    fixed = struct.pack("<Bi", id_type, id_index)
    tagged = struct.pack("<HH", 256, 4) + blob
    return bytes(2) + struct.pack("<BBH", 2, 127, 4 + len(fixed) + 1) + fixed + bytes(1) + tagged


class SrumIdMapSidTests(unittest.TestCase):
    """D19-12: an IdType 3 SruDbIdMapTable row is a user SID, not an app identifier."""

    def test_id_type_3_decodes_as_sid_and_type_0_stays_app(self) -> None:
        sid_blob = bytes.fromhex("010100000000000512000000")  # S-1-5-18
        catalog = ese_page(3, [
            ese_catalog_entry({2: 1, 3: 2, 4: 5}, "SruDbIdMapTable"),
            ese_catalog_entry({1: 2, 2: 2, 3: 1, 4: 2, 5: 1}, "IdType"),
            ese_catalog_entry({1: 2, 2: 2, 3: 2, 4: 4, 5: 4}, "IdIndex"),
            ese_catalog_entry({1: 2, 2: 2, 3: 256, 4: 11}, "IdBlob"),
        ])
        rows_page = ese_page(0x802, [id_map_row(0, 1, "sample.exe".encode("utf-16le")), id_map_row(3, 2, sid_blob)])
        data = _minimal_ese_database_with_catalog()[: 5 * ESE_PAGE] + catalog + rows_page
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SRUDB.dat").write_bytes(data)
            rows = {
                r.details["row_fields"]["IdIndex"]: r.details
                for r in WindowsExecutionProvider().collect(root)
                if r.artifact_type == "srum-schema-row"
            }
        app, user = rows[1], rows[2]
        self.assertEqual(app["app_identity"], "sample.exe")
        self.assertTrue(app["validation_checks"]["has_app_identity"])
        self.assertEqual(app["id_map_identity_kind"], "app-identifier")
        self.assertEqual(app["user_sid"], "")
        self.assertEqual(user["app_identity"], "")
        self.assertFalse(user["validation_checks"]["has_app_identity"])
        self.assertTrue(user["validation_checks"]["has_user_sid"])
        self.assertEqual(user["user_sid"], "S-1-5-18")
        self.assertEqual(user["id_map_identity_kind"], "user-sid")
        self.assertEqual(user["row_fields"]["IdBlob"]["hex"], sid_blob.hex())


def tracker_block(node: int, version: int) -> tuple[bytes, uuid.UUID]:
    droid = uuid.UUID(fields=(0x12345678, 0x1234, 0x1234, 0x80, 0x11, node), version=version)
    volume = uuid.UUID("00000000-0000-4000-8000-000000000001")
    block = struct.pack("<IIII16s", 96, 0xA0000003, 88, 0, b"SAMPLE") + (volume.bytes_le + droid.bytes_le) * 2
    return block, droid


class LnkTrackerNodeTests(unittest.TestCase):
    """D19-13: a multicast (random) UUIDv1 node is kept as a node, never as a MAC address."""

    def tracker(self, node: int, version: int) -> tuple[dict[str, object], uuid.UUID]:
        block, droid = tracker_block(node, version)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "Users" / "Sample" / Path(*RECENT_ROOT)
            folder.mkdir(parents=True)
            (folder / "sample.lnk").write_bytes(relative_path_link("sample.txt", block))
            details = next(
                r.details for r in WindowsRecentFilesProvider().collect(root) if r.artifact_type == "recent-shortcut"
            )
        return details, droid

    def test_unicast_v1_node_is_mac_candidate(self) -> None:
        details, droid = self.tracker(0x020000000042, 1)
        tracker = details["tracker_data"]
        self.assertEqual(str(tracker["droid_file_identifier"]).strip("{}").lower(), str(droid))
        self.assertEqual(details["tracker_droid_file_mac_address"], "02:00:00:00:00:42")
        self.assertEqual(tracker["birth_droid_file_mac_address"], "02:00:00:00:00:42")
        self.assertEqual(tracker["droid_file_node_kind"], "unicast-mac-candidate")
        self.assertEqual(tracker["validation_status"], "candidate-requires-known-answer-corpus")

    def test_multicast_v1_node_is_not_a_mac(self) -> None:
        details, droid = self.tracker(0x030000000042, 1)
        tracker = details["tracker_data"]
        self.assertEqual(str(tracker["droid_file_identifier"]).strip("{}").lower(), str(droid))
        self.assertEqual(details["tracker_droid_file_mac_address"], "")
        self.assertEqual(tracker["droid_file_mac_address"], "")
        self.assertEqual(tracker["birth_droid_file_mac_address"], "")
        self.assertEqual(tracker["droid_file_node"], "03:00:00:00:00:42")
        self.assertEqual(tracker["birth_droid_file_node"], "03:00:00:00:00:42")
        self.assertEqual(tracker["droid_file_node_kind"], "multicast-random-node-not-mac")

    def test_v4_has_no_node(self) -> None:
        details, _droid = self.tracker(0x030000000042, 4)
        tracker = details["tracker_data"]
        self.assertEqual(details["tracker_droid_file_mac_address"], "")
        self.assertEqual(tracker["droid_file_node"], "")
        self.assertEqual(tracker["droid_file_node_kind"], "not-uuid-v1")


if __name__ == "__main__":
    unittest.main()
