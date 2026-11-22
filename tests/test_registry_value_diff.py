"""Denominator and row-stream checks for the Windows image comparison."""

from __future__ import annotations

import json
import runpy
import struct
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/registry-value-diff.py"))


class RegistryValueDiffTests(unittest.TestCase):
    def test_compare_preserves_duplicates_types_and_distinct_value_slots(self):
        left, right = defaultdict(Counter), defaultdict(Counter)
        for value in ("old", "old", 1):
            SCRIPT["add"](left, "Run", "sample", (value,))
        for value in ("old", "1"):
            SCRIPT["add"](right, "run", "SAMPLE", (value,))
        SCRIPT["add"](right, "run", "another", ("old",))
        self.assertEqual(SCRIPT["summarize"](left, right), {
            "matched": 1, "differing": 1, "rapid_only": 1, "reference_only": 1,
        })

    def test_extra_free_index_pointer_does_not_hide_allocated_siblings(self):
        from tests.test_parser_quality_registry import HiveWriter, Key

        root = Key("ROOT")
        for name in ("before", "stale", "valid"):
            root.key(name)
        data = bytearray(HiveWriter().build(root))
        parent = 4100 + struct.unpack_from("<I", data, 36)[0]
        index = 4100 + struct.unpack_from("<I", data, parent + 28)[0]
        cells = [4096 + struct.unpack_from("<I", data, index + 4 + slot * 8)[0] for slot in range(3)]
        stale_size = struct.unpack_from("<i", data, cells[1])[0]
        struct.pack_into("<i", data, cells[1], -stale_size)
        struct.pack_into("<I", data, parent + 20, 2)
        self.assertEqual(SCRIPT["live_uninstall_offsets"](data, parent, index), ([cells[0], cells[2]], 1))
        struct.pack_into("<I", data, parent + 20, 3)
        with self.assertRaisesRegex(ValueError, "unreconciled"):
            SCRIPT["live_uninstall_offsets"](data, parent, index)

    def test_rejects_truncated_provider_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "artifacts"
            folder.mkdir()
            head = folder / "rapidtriage-artifacts-windows-os-account.json"
            head.write_text(json.dumps({
                "root": str(root), "record_count": 1, "artifacts": [],
                "summary": {"parser_error_count": 0, "artifact_count": 1},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete windows-os-account"):
                SCRIPT["rapid_tables"](root)

    def test_cancelled_collector_with_zero_parser_errors_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "artifacts"
            folder.mkdir()
            for provider, status in (("windows-os-account", "cancelled-partial"),
                                     ("windows-registry", "completed")):
                (folder / f"rapidtriage-artifacts-{provider}.json").write_text(json.dumps({
                    "root": str(root), "artifacts": [], "summary": {
                        "parser_error_count": 0, "artifact_count": 0, "collection_status": status,
                    },
                }), encoding="utf-8")
            sam = root / "Windows/System32/config/SAM"
            sam.parent.mkdir(parents=True)
            sam.touch()
            with patch.dict("sys.modules", {"Registry": Mock()}), patch.dict(
                SCRIPT["compare"].__globals__, {"reference_rows": lambda *_: []}
            ):
                report = SCRIPT["compare"](root, root)
            self.assertEqual(report["families"]["accounts"]["status"], "partial")

    def test_binary_reference_does_not_discard_text_siblings(self):
        actual, expected = defaultdict(Counter), defaultdict(Counter)
        for table in (actual, expected):
            SCRIPT["add"](table, "Run", "valid", ("text",))
        SCRIPT["add"](actual, "Run", "other", ("0102",))
        SCRIPT["add"](expected, "Run", "other", (b"\x01\x02",))
        self.assertEqual(SCRIPT["summarize"](actual, expected), {
            "matched": 1, "differing": 1, "rapid_only": 0, "reference_only": 0,
        })

    def test_registry_identity_uses_single_character_case_mapping(self):
        actual, expected = defaultdict(Counter), defaultdict(Counter)
        SCRIPT["add"](actual, r"Run\straße", "slot", ("first",))
        SCRIPT["add"](expected, r"Run\strasse", "slot", ("first",))
        SCRIPT["add"](actual, "Run", "Maße", ("second",))
        SCRIPT["add"](expected, "Run", "Masse", ("second",))
        self.assertEqual(SCRIPT["summarize"](actual, expected), {
            "matched": 0, "differing": 0, "rapid_only": 2, "reference_only": 2,
        })

    def test_reference_only_empty_hive_cannot_establish_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "artifacts"
            folder.mkdir()
            for provider in ("windows-os-account", "windows-registry"):
                (folder / f"rapidtriage-artifacts-{provider}.json").write_text(json.dumps({
                    "root": str(root), "artifacts": [], "summary": {
                        "parser_error_count": 0, "artifact_count": 0, "collection_status": "completed",
                    },
                }), encoding="utf-8")
            hive = root / "Windows/System32/config/SAM"
            hive.parent.mkdir(parents=True)
            hive.touch()
            with patch.dict("sys.modules", {"Registry": Mock()}), patch.dict(
                SCRIPT["compare"].__globals__, {"reference_rows": lambda *_: []}
            ):
                accounts = SCRIPT["compare"](root, root)["families"]["accounts"]
            self.assertEqual(accounts["status"], "partial")
            self.assertEqual(accounts["reference_only_hives"], 1)


class IndependentRegistryReaderTests(unittest.TestCase):
    @staticmethod
    def read_hive(blob):
        from io import BytesIO

        try:
            from Registry import Registry
        except ImportError as exc:
            raise unittest.SkipTest("python-registry comparison reader unavailable") from exc
        return Registry.Registry(BytesIO(blob))

    def test_reference_value_types_and_inline_big_endian_dword(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        run = root.path(SCRIPT["VERSION"] + r"\Run")
        run.value("text", 1, sz("abc")).value("expand", 2, sz("%TEMP%"))
        run.value("little", 4, b"\x04\x03\x02\x01").value("big", 5, b"\x01\x02\x03\x04")
        run.value("wide", 11, (1 << 52).to_bytes(8, "little")).value("binary", 3, b"\xab\xcd")
        run.value("multi", 7, sz("one\0two\0"))
        hive = self.read_hive(HiveWriter().build(root))
        rows = {name: item for _, name, (item,) in SCRIPT["reference_rows"](hive, "run_keys", "software", Counter())}
        self.assertEqual(rows, {
            "text": "abc", "expand": "%TEMP%", "little": 0x01020304, "big": 0x01020304,
            "wide": 1 << 52, "binary": b"\xab\xcd", "multi": ["one", "two"],
        })

    def test_free_cells_on_the_reference_path_fail_closed(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        path = SCRIPT["VERSION"] + r"\Run"
        root.path(path).value("slot", 1, sz("example"))
        blob = HiveWriter().build(root)
        key = self.read_hive(blob).open(path)
        vk = key.value("slot")._vkrecord
        for label, offset in (
            ("key", key._nkrecord.offset() - 4), ("index", key._nkrecord.parent().offset() - 4),
            ("value list", vk.parent().offset() - 4), ("value", vk.offset() - 4),
            ("external data", vk.data_offset()),
        ):
            with self.subTest(label=label):
                corrupt = bytearray(blob)
                struct.pack_into("<i", corrupt, offset, -struct.unpack_from("<i", blob, offset)[0])
                hive = self.read_hive(corrupt)
                with self.assertRaisesRegex(ValueError, "cell"):
                    list(SCRIPT["reference_rows"](hive, "run_keys", "software", Counter()))

    def test_coalesced_free_cell_hides_old_allocated_header(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        path = SCRIPT["VERSION"] + r"\Run"
        root.path(path).value("slot", 1, sz("a"))
        class PaddedWriter(HiveWriter):
            def write_value(self, name, value_type, data):
                self.alloc(bytes(4), free=True)
                return super().write_value(name, value_type, data)

        blob = bytearray(PaddedWriter().build(root))
        key = self.read_hive(blob).open(path)
        old_vk = key.value("slot")._vkrecord.offset() - 4
        # Coalescing leaves the previous VK size and payload inside a free cell.
        struct.pack_into("<i", blob, old_vk - 8, 8 - struct.unpack_from("<i", blob, old_vk)[0])
        with self.assertRaisesRegex(ValueError, "cell"):
            list(SCRIPT["reference_rows"](self.read_hive(blob), "run_keys", "software", Counter()))

    def test_allocated_run_key_with_wrong_parent_is_unavailable(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        path = SCRIPT["VERSION"] + r"\Run"
        root.path(path).value("slot", 1, sz("test"))
        blob = bytearray(HiveWriter().build(root))
        node = self.read_hive(blob).open(path)._nkrecord
        struct.pack_into("<I", blob, node.offset() + 16, 32)  # point to the root
        with self.assertRaisesRegex(ValueError, "child key link"):
            list(SCRIPT["reference_rows"](self.read_hive(blob), "run_keys", "software", Counter()))

    def test_literal_default_value_name_cannot_join_unnamed_slot(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        key = root.path(SCRIPT["VERSION"] + r"\Run")
        key.value("", 1, sz("one")).value("(default)", 1, sz("two"))
        with self.assertRaisesRegex(ValueError, "ambiguous.*value name"):
            list(SCRIPT["reference_rows"](self.read_hive(HiveWriter().build(root)), "run_keys", "software", Counter()))

    def test_live_hive_comparison_retains_segmented_binary_and_text_siblings(self):
        import hashlib

        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        key = Key("ROOT")
        mount = r"HKLM\SOFTWARE"
        path = SCRIPT["VERSION"] + r"\Run"
        key.path(path).value("same", 1, sz("value")).value("large", 3, b"x" * 17000)
        blob = HiveWriter().build(key)
        self.read_hive(blob)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "Windows/System32/config/SOFTWARE"
            source.parent.mkdir(parents=True)
            source.write_bytes(blob)
            rows = [{
                "artifact_type": "registry-persistence-entry", "path": str(source),
                "details": {
                    "hive_mount": mount, "key_path": mount + "\\" + path, "persistence_category": "Run",
                    "value_name": name, "command": command, "source_hashes": {"sha256": hashlib.sha256(blob).hexdigest()},
                },
            } for name, command in (("same", "value"), ("large", "text projection"))]
            (root / "artifacts").mkdir()
            for provider, artifacts in (("windows-registry", rows), ("windows-os-account", [])):
                head = root / "artifacts" / f"rapidtriage-artifacts-{provider}.json"
                head.write_text(json.dumps({"root": str(root), "artifacts": artifacts, "summary": {
                    "parser_error_count": 0, "artifact_count": len(artifacts), "collection_status": "completed",
                }}), encoding="utf-8")
            result = SCRIPT["compare"](root, root)["families"]["run_keys"]
            self.assertEqual((result["compared_hives"], result["unavailable_hives"]), (1, 0))
            self.assertEqual((result["matched"], result["differing"]), (1, 1))

        hive = self.read_hive(blob)
        vk = hive.open(path).value("large")._vkrecord
        index = 4096 + struct.unpack_from("<I", blob, vk.data_offset() + 8)[0]
        segment = 4096 + struct.unpack_from("<I", blob, index + 4)[0]
        for offset in (index, segment):
            with self.subTest(offset=offset):
                corrupt = bytearray(blob)
                struct.pack_into("<i", corrupt, offset, -struct.unpack_from("<i", blob, offset)[0])
                with self.assertRaisesRegex(ValueError, "cell"):
                    list(SCRIPT["reference_rows"](self.read_hive(corrupt), "run_keys", "software", Counter()))

    def test_segmented_multistring_uses_same_terminator_rules(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        text = "x" * 8500
        root.path(SCRIPT["VERSION"] + r"\Run").value("multi", 7, sz(text + "\0z\0"))
        rows = list(SCRIPT["reference_rows"](self.read_hive(HiveWriter().build(root)), "run_keys", "software", Counter()))
        self.assertEqual(rows[0][2][0], [text, "z"])

    def test_sam_name_identity_retains_high_rid_bits(self):
        from tests.test_parser_quality_registry import HiveWriter, Key

        root = Key("ROOT")
        names = root.path(r"SAM\Domains\Account\Users\Names")
        names.key("test_account").value("", 0x2345, b"")
        hive = self.read_hive(HiveWriter().build(root))
        rows = list(SCRIPT["reference_rows"](hive, "accounts", "sam", Counter()))
        self.assertEqual(rows, [(str(0x2345), "", ("test_account",))])

    def test_short_allocated_cells_cannot_borrow_neighbor_bytes(self):
        from tests.test_parser_quality_registry import HiveWriter, Key, sz

        root = Key("ROOT")
        path = SCRIPT["VERSION"] + r"\Run"
        key = root.path(path)
        key.value("", 1, sz("example")).value("second", 1, sz("extra"))
        root.key("Z")
        data = HiveWriter().build(root)
        reader = self.read_hive(data)
        run = reader.open(path)
        vk = run.value("(default)")._vkrecord
        for label, record in (("nk", run._nkrecord), ("vk", vk),
                              ("lh", reader.root()._nkrecord.subkey_list()), ("value list", vk.parent())):
            with self.subTest(label=label):
                blob = bytearray(data)
                cell = record.offset() - 4
                size = -struct.unpack_from("<i", blob, cell)[0]
                struct.pack_into("<i", blob, cell, -8)
                struct.pack_into("<i", blob, cell + 8, size - 8)
                hive = self.read_hive(blob)
                # The shortened VK retains its original adjacent UTF-16 data length
                # (16 bytes). The independent reader still returns the original string.
                if label == "vk":
                    self.assertEqual(hive.open(path).value("(default)").value(), "example")
                with self.assertRaisesRegex(ValueError, "cell"):
                    if label in {"nk", "vk"}:
                        list(SCRIPT["reference_rows"](hive, "run_keys", "software", Counter()))
                    elif label == "lh":
                        SCRIPT["check_record"](hive.root()._nkrecord.subkey_list())
                    else:
                        SCRIPT["check_record"](hive.open(path).value("(default)")._vkrecord)

        # A valid fixed VK header can still declare a name ending in the next cell.
        named = run.value("second")._vkrecord
        blob = bytearray(data)
        struct.pack_into("<H", blob, named.offset() + 2, 16)
        with self.assertRaisesRegex(ValueError, "cell"):
            list(SCRIPT["reference_rows"](self.read_hive(blob), "run_keys", "software", Counter()))
