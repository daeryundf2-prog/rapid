from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows import xpress_lz77
from rapidtriage.cli import main
from rapidtriage.core.kakaotalk_residue_memory import (
    RESIDUE_PAGE_SIZE,
    ResidueSourceStatus,
    iter_residue_segments,
)
from tests.test_rapidtriage_kakaotalk_decrypt import (
    cbor_array_bytes,
    cbor_map,
    cbor_pair_array,
)
from tests.xpress_huffman_encoder import compress as huffman_compress

MESSAGE_JSON = (
    b'{"attachment":"","authorId":7,"chatId":300,"deleted":false,'
    b'"logId":400,"message":"residue message","sendAt":1700000000,"type":1}'
)
KEY_HEX = "cd" * 48
KEY_LITERAL = (
    b"x'" + KEY_HEX.encode("ascii") + b"' TalkChatDB::_InternalOpen PRAGMA kdf_iter"
)


def lz77_compress(data: bytes) -> bytes:
    """Greedy plain-LZ77 ([MS-XCA] §2.3) encoder for fixtures: offsets 1-64, lengths 3-24."""
    out = bytearray(4)
    flag_position, flags, flag_count, half_byte_at = 0, 0, 0, None
    position = 0
    while position < len(data):
        if flag_count == 32:
            out[flag_position : flag_position + 4] = struct.pack("<I", flags)
            flag_position, flags, flag_count = len(out), 0, 0
            out += b"\0\0\0\0"
        best_length, best_offset = 0, 0
        for offset in range(1, min(position, 64) + 1):
            length = 0
            while (
                length < 24
                and position + length < len(data)
                and data[position + length - offset] == data[position + length]
            ):
                length += 1
            if length > best_length:
                best_length, best_offset = length, offset
        if best_length < 3:
            out.append(data[position])
            position += 1
        else:
            flags |= 1 << (31 - flag_count)
            out += struct.pack("<H", ((best_offset - 1) << 3) | min(best_length - 3, 7))
            if best_length - 3 >= 7:
                nibble = best_length - 10
                if half_byte_at is None:
                    half_byte_at = len(out)
                    out.append(nibble)
                else:
                    out[half_byte_at] |= nibble << 4
                    half_byte_at = None
            position += best_length
        flag_count += 1
    flags |= (1 << (32 - flag_count)) - 1
    out[flag_position : flag_position + 4] = struct.pack("<I", flags)
    return bytes(out)


def page_with(*chunks: tuple[int, bytes]) -> bytes:
    page = bytearray(RESIDUE_PAGE_SIZE)
    for offset, chunk in chunks:
        page[offset : offset + len(chunk)] = chunk
    return bytes(page)


def compression_set(pages: list[tuple[int, bytes]], *, method: str) -> bytes:
    """One Win8+ compression set: status dword, PFN descriptors, then the (compressed) page data."""
    plain = b"".join(page for _, page in pages)
    if method == "huffman":
        payload = huffman_compress(plain)
    elif method == "lz77":
        payload = lz77_compress(plain)
    else:
        payload = plain
    status = (
        len(pages) | (len(payload) << 8) | (0x80000000 if method == "huffman" else 0)
    )
    descriptors = b"".join(struct.pack("<Q", pfn << 4) for pfn, _ in pages)
    return struct.pack("<I", status) + descriptors + payload


def build_hiberfil(boot: list[bytes], kernel: list[bytes]) -> bytes:
    boot_blob = b"".join(boot)
    kernel_page = 1 + (len(boot_blob) + RESIDUE_PAGE_SIZE - 1) // RESIDUE_PAGE_SIZE
    header = bytearray(RESIDUE_PAGE_SIZE)
    header[0:4] = b"HIBR"
    struct.pack_into("<I", header, 0x0C, 0x3E0)
    struct.pack_into("<I", header, 0x18, RESIDUE_PAGE_SIZE)
    struct.pack_into("<Q", header, 0x58, 1)
    struct.pack_into("<Q", header, 0x68, 1)
    struct.pack_into("<Q", header, 0x70, kernel_page)
    struct.pack_into("<Q", header, 0x230, 3)
    body = boot_blob.ljust((kernel_page - 1) * RESIDUE_PAGE_SIZE, b"\0")
    return bytes(header) + body + b"".join(kernel)


def synthetic_hiberfil(appstate: bytes = b"") -> bytes:
    return build_hiberfil(
        boot=[compression_set([(0x10, page_with((0, b"boot page")))], method="raw")],
        kernel=[
            compression_set(
                [
                    (0x200, page_with((100, MESSAGE_JSON))),
                    (0x201, page_with((40, KEY_LITERAL))),
                ],
                method="huffman",
            ),
            compression_set(
                [(0x305, page_with((64, appstate or b"plain lz77 page")))],
                method="lz77",
            ),
        ],
    )


class XpressLz77Tests(unittest.TestCase):
    def test_round_trip_with_literals_runs_and_shared_length_nibbles(self) -> None:
        data = b"abcabcabcabc" + b"\0" * 300 + bytes(range(200)) + b"xyz" * 40
        self.assertEqual(xpress_lz77.decompress(lz77_compress(data), len(data)), data)

    def test_truncated_stream_raises(self) -> None:
        data = bytes(range(256)) * 4
        with self.assertRaises(xpress_lz77.XpressLz77Error):
            xpress_lz77.decompress(lz77_compress(data)[:100], len(data))


class ResidueSegmentTests(unittest.TestCase):
    def test_hiberfil_pages_carry_frame_numbers_and_set_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hiberfil = Path(tmp_dir) / "hiberfil.sys"
            hiberfil.write_bytes(synthetic_hiberfil())
            statuses: list[ResidueSourceStatus] = []
            segments = [
                (segment.path.read_bytes(), segment.locate(100 + RESIDUE_PAGE_SIZE))
                for segment in iter_residue_segments([hiberfil], statuses=statuses)
            ]

        self.assertEqual(statuses[0].status, "read")
        self.assertEqual(statuses[0].pages_read, 4)
        self.assertTrue(statuses[0].layout.startswith("HIBR-windows8+-x64-0x3e0"))
        data, provenance = segments[0]
        assert provenance is not None
        self.assertEqual(
            data[RESIDUE_PAGE_SIZE + 100 : RESIDUE_PAGE_SIZE + 100 + len(MESSAGE_JSON)],
            MESSAGE_JSON,
        )
        self.assertEqual(provenance["page_number"], 0x200)
        self.assertEqual(provenance["source_offset"], 3 * RESIDUE_PAGE_SIZE)
        self.assertEqual(provenance["confidence"], "triage")

    def test_pagefile_overlap_owns_each_offset_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            pagefile = Path(tmp_dir) / "pagefile.sys"
            pagefile.write_bytes(b"\0" * (5 * RESIDUE_PAGE_SIZE))
            statuses: list[ResidueSourceStatus] = []
            owners = []
            for segment in iter_residue_segments(
                [pagefile], statuses=statuses, segment_bytes=2 * RESIDUE_PAGE_SIZE
            ):
                base = segment.pages[0][1]
                owners.extend(
                    base + offset
                    for offset in range(0, len(segment.path.read_bytes()), 512)
                    if segment.locate(offset)
                )

        self.assertEqual(sorted(owners), list(range(0, 5 * RESIDUE_PAGE_SIZE, 512)))
        self.assertGreater(statuses[0].segments_scanned, 2)

    def test_unsupported_and_corrupt_hiberfils_are_reported_not_raised(self) -> None:
        cases = {
            "wiped": b"\0" * (4 * RESIDUE_PAGE_SIZE),
            "layout": b"HIBR"
            + b"\0" * 8
            + struct.pack("<I", 0x123)
            + b"\0" * (RESIDUE_PAGE_SIZE - 16),
            "corrupt": synthetic_hiberfil()[:-10],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            results = {}
            for name, blob in cases.items():
                path = Path(tmp_dir) / name / "hiberfil.sys"
                path.parent.mkdir()
                path.write_bytes(blob)
                statuses: list[ResidueSourceStatus] = []
                pages = sum(
                    len(segment.pages)
                    for segment in iter_residue_segments([path], statuses=statuses)
                )
                results[name] = (statuses[0], pages)

        self.assertEqual(results["wiped"][0].status, "error")
        self.assertIn("zeroed", results["wiped"][0].errors[0])
        self.assertIn("unsupported hiberfil layout", results["layout"][0].errors[0])
        self.assertEqual(results["corrupt"][0].status, "partial")
        self.assertEqual(results["corrupt"][1], 3)


class ResidueAnalysisCommandTests(unittest.TestCase):
    def test_memory_carve_reports_hiberfil_and_pagefile_residue_with_provenance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "image"
            root.mkdir()
            (root / "hiberfil.sys").write_bytes(synthetic_hiberfil())
            (root / "pagefile.sys").write_bytes(
                b"\0" * RESIDUE_PAGE_SIZE + page_with((300, MESSAGE_JSON))
            )
            output = Path(tmp_dir) / "carve.json"

            exit_code = main(
                ["kakaotalk-memory-carve", str(root), "--output", str(output)]
            )

            self.assertEqual(exit_code, 0)
            text = output.read_text(encoding="utf-8")
            payload = json.loads(text)
        summary = payload["summary"]
        self.assertEqual(summary["memory_source_count"], 0)
        self.assertEqual(summary["residue_memory_source_count"], 2)
        self.assertEqual(summary["residue_chat_message_residue_count"], 2)
        self.assertEqual(summary["residue_sqlcipher_key_residue_count"], 1)
        messages = {
            item["source_kind"]: item
            for item in payload["residue_memory"]["chat_message_residues"]
        }
        self.assertEqual(messages["hiberfil"]["page_number"], 0x200)
        self.assertEqual(messages["hiberfil"]["page_offset"], 100)
        self.assertEqual(messages["pagefile"]["source_offset"], RESIDUE_PAGE_SIZE + 300)
        self.assertEqual(messages["pagefile"]["page_number"], 1)
        self.assertTrue(messages["pagefile"]["source_path"].endswith("pagefile.sys"))
        self.assertEqual(
            {item["evidence_class"] for item in messages.values()}, {"memory-residue"}
        )
        self.assertEqual(
            payload["residue_memory"]["sqlcipher_key_residues"][0]["page_number"], 0x201
        )
        self.assertNotIn(KEY_HEX, text)

    def test_sqlcipher_probe_uses_residue_key_literals_as_triage_candidates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "image"
            root.mkdir()
            (root / "hiberfil.sys").write_bytes(synthetic_hiberfil())
            output = Path(tmp_dir) / "probe.json"

            exit_code = main(
                [
                    "kakaotalk-sqlcipher-probe",
                    str(root),
                    "--output",
                    str(output),
                    "--sqlcipher-bin",
                    "rapid-missing-sqlcipher",
                ]
            )

            self.assertEqual(exit_code, 0)
            text = output.read_text(encoding="utf-8")
        payload = json.loads(text)
        self.assertEqual(payload["summary"]["residue_key_candidate_count"], 1)
        candidate = payload["key_candidates"][0]
        self.assertEqual(candidate["source_kind"], "hiberfil")
        self.assertEqual(candidate["confidence"], "triage")
        self.assertEqual(payload["residue_memory_sources"][0]["status"], "read")
        self.assertNotIn(KEY_HEX, text)

    def test_key_store_inspect_checks_appstate_residency_in_hiberfil(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "image"
            user = root / "KakaoTalk" / "users" / ("b" * 40)
            user.mkdir(parents=True)
            appstate = cbor_map(
                {
                    "info_prefix": cbor_array_bytes(b"v2:"),
                    "salt": cbor_array_bytes(b"t" * 32),
                    "wrapped_dek_map": [
                        cbor_pair_array(b"chat_data\\chatLogs_9.edb", bytes(range(40)))
                    ],
                }
            )
            (user / "appstate.dat").write_bytes(appstate)
            (root / "hiberfil.sys").write_bytes(synthetic_hiberfil(appstate))
            output = Path(tmp_dir) / "key-store.json"

            exit_code = main(
                ["kakaotalk-key-store-inspect", str(root), "--output", str(output)]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["residue_key_store_hit_count"], 1)
        hit = payload["key_stores"][0]["residue_memory_hits"][0]
        self.assertTrue(hit["appstate_blob_present"])
        self.assertEqual(hit["page_number"], 0x305)
        self.assertEqual(hit["page_offset"], 64)
        self.assertEqual(hit["evidence_class"], "memory-residue")
        self.assertIn(
            "runtime-key-store-nodes", payload["residue_memory"]["not_applied"]
        )


if __name__ == "__main__":
    unittest.main()
