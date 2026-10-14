"""Parser-quality round 1 — W4 core organisation (files/timeline/indicators/docs/steps/case DB).

Each test reproduces a finding of the 2026-10-13 adversarial review with a
synthetic fixture built in the test (no binary fixtures on disk).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
from collections import Counter
from pathlib import Path

from rapidtriage.core import doc_text
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.case_db.schema import (
    DOCUMENT_TRIGRAM_TABLE,
    apply_schema,
    insert_document_trigram_row,
    sqlite_supports_trigram,
)
from rapidtriage.core.case_db.search import search_indexed_documents
from rapidtriage.core.docs import extract_document_text, run_docs_search
from rapidtriage.core.files import classify_file_categories, run_files_scan
from rapidtriage.core.filetime import (
    datetime_to_filetime,
    filetime_fields,
    filetime_to_datetime,
    filetime_to_iso,
    filetime_to_iso_7,
    normalize_iso_utc,
    plausibility,
    unix_to_iso,
    webkit_to_iso,
)
from rapidtriage.core.indicators import build_indicator_summary
from rapidtriage.core.run.checkpoints import refresh_checkpoint_output_state
from rapidtriage.core.run.markdown import apply_report_disclosures
from rapidtriage.core.run.persist import legacy_run_case_ids, run_case_id
from rapidtriage.core.run.steps import (
    apply_silent_failure_verdicts,
    build_step_rows,
    collect_cap_disclosures,
)
from rapidtriage.core.timeline import (
    TimelineStats,
    extract_artifact_events,
    extract_file_events,
    run_timeline,
)

HANGUL = "계약서를 확인했습니다"


# --- tiny CFB (OLE2) writer for fixtures -------------------------------------------


def build_ole(streams: dict[str, bytes]) -> bytes:
    """Minimal compound file: 512-byte sectors, mini-stream cutoff 0 (all
    streams in regular sectors), one storage level ("BodyText/Section0")."""
    sector = 512
    data_sectors: list[bytes] = []
    entries: list[dict[str, object]] = [{"name": "Root Entry", "type": 5, "start": 0xFFFFFFFE, "size": 0, "child": 0xFFFFFFFF, "right": 0xFFFFFFFF}]
    chains: list[tuple[int, int]] = []

    def add_stream(payload: bytes) -> tuple[int, int]:
        start = len(data_sectors)
        padded = payload + b"\x00" * ((-len(payload)) % sector or (sector if not payload else 0))
        for offset in range(0, len(padded), sector):
            data_sectors.append(padded[offset : offset + sector])
        count = len(padded) // sector
        chains.append((start, count))
        return start, len(payload)

    storages: dict[str, int] = {}
    root_children: list[int] = []
    for name, payload in streams.items():
        parts = name.split("/")
        parent_children = root_children
        if len(parts) == 2:
            if parts[0] not in storages:
                storages[parts[0]] = len(entries)
                entries.append({"name": parts[0], "type": 1, "start": 0, "size": 0, "child": 0xFFFFFFFF, "right": 0xFFFFFFFF, "children": []})
                root_children.append(storages[parts[0]])
            parent_children = entries[storages[parts[0]]]["children"]  # type: ignore[assignment]
        start, size = add_stream(payload)
        parent_children.append(len(entries))
        entries.append({"name": parts[-1], "type": 2, "start": start, "size": size, "child": 0xFFFFFFFF, "right": 0xFFFFFFFF})

    def link(children: list[int]) -> int:
        for left, right in zip(children, children[1:]):
            entries[left]["right"] = right
        return children[0] if children else 0xFFFFFFFF

    entries[0]["child"] = link(root_children)
    for index in storages.values():
        entries[index]["child"] = link(entries[index]["children"])  # type: ignore[arg-type]
    dir_bytes = b""
    for entry in entries:
        name_raw = str(entry["name"]).encode("utf-16le") + b"\x00\x00"
        raw = bytearray(128)
        raw[: len(name_raw)] = name_raw
        struct.pack_into("<H", raw, 0x40, len(name_raw))
        raw[0x42] = int(entry["type"])
        struct.pack_into("<III", raw, 0x44, 0xFFFFFFFF, int(entry["right"]), int(entry["child"]))
        struct.pack_into("<I", raw, 0x74, int(entry["start"]))
        struct.pack_into("<Q", raw, 0x78, int(entry["size"]))
        dir_bytes += bytes(raw)
    dir_bytes += b"\x00" * ((-len(dir_bytes)) % sector)
    dir_start = len(data_sectors)
    for offset in range(0, len(dir_bytes), sector):
        data_sectors.append(dir_bytes[offset : offset + sector])
    chains.append((dir_start, len(dir_bytes) // sector))
    fat_start = len(data_sectors)
    total = fat_start + 1
    fat = [0xFFFFFFFF] * (sector // 4)
    for start, count in chains:
        for index in range(count):
            fat[start + index] = start + index + 1 if index + 1 < count else 0xFFFFFFFE
    fat[fat_start] = 0xFFFFFFFD
    assert total <= len(fat)
    data_sectors.append(struct.pack(f"<{len(fat)}I", *fat))
    header = bytearray(512)
    header[:8] = doc_text.OLE_SIGNATURE
    struct.pack_into("<HHH", header, 0x18, 0x3E, 3, 0xFFFE)
    struct.pack_into("<HH", header, 0x1E, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, dir_start)
    struct.pack_into("<I", header, 0x38, 0)  # mini-stream cutoff 0: no mini stream
    struct.pack_into("<I", header, 0x3C, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x44, 0xFFFFFFFE)
    difat = [fat_start] + [0xFFFFFFFF] * 108
    struct.pack_into("<109I", header, 0x4C, *difat)
    return bytes(header) + b"".join(data_sectors)


def hwp_record(tag: int, payload: bytes) -> bytes:
    return struct.pack("<I", tag | (len(payload) << 20)) + payload


def hwp_para_payload(text: str) -> bytes:
    # extended control (code 2 = section/column def) occupies 8 WCHARs
    control = struct.pack("<H", 2) + b"\x00" * 12 + struct.pack("<H", 2)
    return control + text.encode("utf-16le") + struct.pack("<H", 13)


def build_hwp(text: str, *, flags: int = 1, preview: str = "") -> bytes:
    header = b"HWP Document File".ljust(32, b"\x00") + struct.pack("<II", 0x05000300, flags) + b"\x00" * 216
    records = hwp_record(0x42, b"\x00" * 22) + hwp_record(doc_text.HWPTAG_PARA_TEXT, hwp_para_payload(text))
    compressor = zlib.compressobj(wbits=-15)
    body = compressor.compress(records) + compressor.flush() if flags & 1 else records
    streams = {"FileHeader": header, "BodyText/Section0": body}
    if preview:
        streams["PrvText"] = preview.encode("utf-16le")
    return build_ole(streams)


def build_doc(text: str) -> bytes:
    word = bytearray(0x800)
    struct.pack_into("<H", word, 0, 0xA5EC)
    struct.pack_into("<H", word, 0x0A, 0x0200)  # fWhichTblStm -> 1Table
    body = text.encode("utf-16le")
    word += body
    cp_end = len(text)
    plc = struct.pack("<II", 0, cp_end) + struct.pack("<HIH", 0, 0x800, 0)
    clx = b"\x02" + struct.pack("<I", len(plc)) + plc
    struct.pack_into("<II", word, 0x01A2, 0, len(clx))
    return build_ole({"WordDocument": bytes(word), "1Table": clx})


def biff(record_type: int, payload: bytes) -> bytes:
    return struct.pack("<HH", record_type, len(payload)) + payload


def build_xls(first: str, second: str, label: str) -> bytes:
    """SST with the second string split across a CONTINUE record."""
    second_raw = second.encode("utf-16le")
    split = len(second_raw) // 2 // 2 * 2
    sst = struct.pack("<II", 2, 2)
    sst += struct.pack("<HB", len(first), 1) + first.encode("utf-16le")
    sst += struct.pack("<HB", len(second), 1) + second_raw[:split]
    cont = b"\x01" + second_raw[split:]
    sheet = struct.pack("<IBB", 0, 0, 0) + bytes([len("시트1"), 1]) + "시트1".encode("utf-16le")
    label_payload = struct.pack("<HHH", 0, 0, 0) + struct.pack("<HB", len(label), 1) + label.encode("utf-16le")
    stream = biff(0x0809, b"\x00" * 16) + biff(0x0085, sheet) + biff(0x00FC, sst) + biff(0x003C, cont) + biff(0x0204, label_payload) + biff(0x000A, b"")
    return build_ole({"Workbook": stream})


def build_ppt(text: str) -> bytes:
    atom = struct.pack("<HHI", 0x0000, 0x0FA0, len(text.encode("utf-16le"))) + text.encode("utf-16le")
    container = struct.pack("<HHI", 0x000F, 0x03E8, len(atom)) + atom
    return build_ole({"PowerPoint Document": container, "Current User": b"\x00" * 20})


def build_pdf_type0(text: str) -> bytes:
    codes = list(range(1, len(text) + 1))
    content = b"BT /F1 12 Tf 72 720 Td <" + b"".join(f"{code:04X}".encode() for code in codes) + b"> Tj ET"
    cmap = b"begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + str(len(codes)).encode() + b" beginbfchar\n"
    for code, char in zip(codes, text):
        cmap += f"<{code:04X}> <{ord(char):04X}>\n".encode()
    cmap += b"endbfchar\nendcmap"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        None,
        b"<< /Type /Font /Subtype /Type0 /BaseFont /Malgun /Encoding /Identity-H /ToUnicode 6 0 R >>",
        None,
    ]
    out = bytearray(b"%PDF-1.7\n")
    for index, body in enumerate(objects, start=1):
        if index == 4:
            stream = zlib.compress(content)
            out += f"4 0 obj << /Length {len(stream)} /Filter /FlateDecode >>\nstream\n".encode() + stream + b"\nendstream\nendobj\n"
        elif index == 6:
            stream = zlib.compress(cmap)
            out += f"6 0 obj << /Length {len(stream)} /Filter /FlateDecode >>\nstream\n".encode() + stream + b"\nendstream\nendobj\n"
        else:
            out += f"{index} 0 obj ".encode() + body + b" endobj\n"
    out += b"trailer << /Root 1 0 R >>\n%%EOF\n"
    return bytes(out)


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


# --- filetime ----------------------------------------------------------------------


class FiletimeTests(unittest.TestCase):
    def test_filetime_round_trip_preserves_100ns_and_pre_1970(self) -> None:
        ticks = 133_000_000_001_234_567
        self.assertEqual(filetime_to_iso(ticks), "2022-06-18T04:26:40.123456+00:00")
        self.assertEqual(filetime_to_iso_7(ticks), "2022-06-18T04:26:40.1234567Z")
        self.assertEqual(filetime_fields("run_time_1", ticks), {"run_time_1": filetime_to_iso(ticks), "run_time_1_100ns": ticks})
        moment = filetime_to_datetime(ticks)
        assert moment is not None
        self.assertEqual(datetime_to_filetime(moment), ticks - 7)  # datetime keeps microseconds only
        self.assertIsNone(filetime_to_iso(0))
        self.assertEqual(unix_to_iso(-86400), "1969-12-31T00:00:00+00:00")
        self.assertEqual(webkit_to_iso(13_300_000_000_000_000), "2022-06-18T04:26:40+00:00")
        self.assertEqual(normalize_iso_utc("2020-01-01T09:00:00.1234567+09:00"), "2020-01-01T00:00:00.123456+00:00")
        self.assertEqual(plausibility(dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)), "before-min")
        self.assertEqual(plausibility(dt.datetime(2104, 1, 1, tzinfo=dt.timezone.utc)), "future")


# --- files ---------------------------------------------------------------------------


class FilesCategorisationTests(unittest.TestCase):
    def test_categories_use_extension_tables_and_relative_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ReportArchive-evidence"
            (root / "Users" / "u" / "Documents").mkdir(parents=True)
            docs = root / "Users" / "u" / "Documents"
            (docs / "계약.hwp").write_bytes(build_hwp(HANGUL))
            (docs / "setup.exe").write_bytes(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00")
            (docs / "noext").write_bytes(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00")
            (docs / "fake-mz.bin").write_bytes(b"MZ not really a PE")
            (docs / "shortcut.lnk").write_bytes(b"L\x00\x00\x00")
            (docs / "crash").write_bytes(b"MDMP" + b"\x00" * 32)
            (docs / "report-notes.cell").write_bytes(b"PK\x03\x04")
            (docs / "inbox-message.txt").write_text("plain text", encoding="utf-8")
            (docs / "Thumbs.db.unknownext").write_bytes(b"\x00" * 8)

            self.assertEqual(classify_file_categories(docs / "noext", root=root)[0], ["executables"])
            self.assertEqual(classify_file_categories(docs / "fake-mz.bin", root=root)[0], ["other"])
            self.assertEqual(classify_file_categories(docs / "shortcut.lnk", root=root)[0], ["other"])
            self.assertEqual(classify_file_categories(docs / "crash", root=root)[0], ["memory-dumps"])

            payload = run_files_scan(root, categories=["documents", "executables", "emails", "memory-dumps", "archives"])
            by_name = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(by_name["계약.hwp"]["categories"], ["documents"])
            self.assertEqual(by_name["report-notes.cell"]["categories"], ["documents"])
            self.assertEqual(by_name["setup.exe"]["categories"], ["executables"])
            self.assertEqual(by_name["inbox-message.txt"]["categories"], ["documents"])  # no "emails" by name
            self.assertNotIn("archives", by_name["계약.hwp"]["categories"])  # root name "ReportArchive" ignored
            self.assertNotIn("shortcut.lnk", by_name)
            summary = payload["summary"]
            self.assertEqual(summary["excluded_file_count"], 3)
            self.assertEqual(summary["excluded_category_counts"], {"other": 3})
            self.assertEqual(summary["exclusion_reason_counts"], {"category-not-selected": 3})
            # folder input = acquisition copy: host times are source_file_* only
            self.assertEqual(summary["time_origin"], "acquisition-copy")
            self.assertIsNone(summary["newest_modified_at"])
            hwp = by_name["계약.hwp"]
            self.assertEqual(hwp["modified_at_origin"], "acquisition-copy")
            self.assertTrue(hwp["source_file_mtime"])
            self.assertIsNone(hwp["fs_modified_at"])
            self.assertEqual(hwp["relative_path"], "Users/u/Documents/계약.hwp")
            self.assertFalse(summary["duplicate_groups_truncated"])

    def test_copy_times_never_become_timeline_events(self) -> None:
        stats = TimelineStats()
        payload = {
            "command": "files",
            "summary": {"time_origin": "acquisition-copy"},
            "candidates": [
                {"path": "C:/e/a.txt", "name": "a.txt", "modified_at": "2026-10-07T00:00:00+00:00",
                 "modified_at_origin": "acquisition-copy", "time_origin": "acquisition-copy",
                 "source_file_mtime": "2026-10-07T00:00:00+00:00", "fs_modified_at": None},
                {"path": "C:/e/b.txt", "name": "b.txt", "modified_at": "2024-01-01T00:00:00+00:00",
                 "modified_at_origin": "listing", "time_origin": "acquisition-copy",
                 "fs_modified_at": "2024-01-01T00:00:00+00:00", "fs_created_at": "2023-01-01T00:00:00+00:00"},
            ],
        }
        events = extract_file_events(payload, Path("files.json"), stats=stats)
        self.assertEqual({event["path"] for event in events}, {"C:/e/b.txt"})
        self.assertEqual(Counter(event["timestamp_kind"] for event in events), {"modified": 1, "created": 1})
        self.assertEqual(stats.copy_time_candidates, 1)


# --- timeline ----------------------------------------------------------------------------


def artifacts_payload(kind: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {"command": "artifacts", "kind": kind, "artifacts": rows}


class TimelineMappingTests(unittest.TestCase):
    def test_explicit_mapping_dedupe_range_and_reference_rows(self) -> None:
        run_times = [f"2025-05-{day:02d}T01:00:00+00:00" for day in range(1, 9)]
        prefetch = artifacts_payload(
            "windows-prefetch",
            [
                {"artifact_type": "prefetch-file", "path": "C:/e/Prefetch/A.EXE-1.pf", "details": {
                    "last_run_times": run_times, "run_time_1": run_times[0], "last_run_at": run_times[0],
                    "modified_at": "2026-10-07T08:52:29+00:00", "timestamp": "2026-10-07T08:52:29+00:00"}},
                {"artifact_type": "prefetch-reference", "path": "C:/e/Prefetch/A.EXE-1.pf",
                 "details": {"timestamp": "", "referenced_path": "\\VOLUME{1}\\X"}},
            ],
        )
        stats = TimelineStats()
        events = extract_artifact_events(prefetch, Path("prefetch.json"), stats=stats)
        # run_time_1 and last_run_times[0] share one record key: the builder dedupes them.
        self.assertEqual(sorted({event["timestamp_kind"] for event in events}), [f"run-{index}" for index in range(1, 9)])
        self.assertFalse(any(event["timestamp"].startswith("2026-10") for event in events))
        self.assertEqual(stats.excluded_types["prefetch-reference"], 1)

        eventlog = artifacts_payload(
            "eventlog",
            [
                {"artifact_type": "eventlog-event", "path": "C:/e/Security.evtx", "details": {
                    "timestamp": "2025-02-23T14:09:15+00:00", "record_id": "7", "event_id": "4624", "event_category": "logon-success"}},
                {"artifact_type": "eventlog-detection", "path": "C:/e/Security.evtx", "details": {
                    "event_created_at": "2025-02-23T14:09:15+00:00", "timestamp": "2025-02-23T14:09:15+00:00",
                    "record_id": "7", "rule": {"id": "R1"}}},
                {"artifact_type": "eventlog-event", "path": "C:/e/Security.evtx", "details": {
                    "timestamp": "1617-01-21T01:29:21+00:00", "record_id": "8"}},
                {"artifact_type": "amcache-schema-row", "path": "C:/e/Amcache.hve", "details": {
                    "link_date_raw": "11/12/2104 20:36:41", "key_last_written_at": "2025-05-14T15:13:02+00:00"}},
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            evt_path = write_json(Path(tmp) / "eventlog.json", eventlog)
            pf_path = write_json(Path(tmp) / "prefetch.json", prefetch)
            files_path = write_json(Path(tmp) / "files.json", {"command": "files", "candidates": [], "summary": {"time_origin": "acquisition-copy"}})
            docs_path = write_json(Path(tmp) / "docs.json", {"command": "docs", "candidates": [], "results": []})
            payload = run_timeline(root=Path(tmp), files_inputs=[files_path], docs_inputs=[docs_path], artifacts_inputs=[evt_path, pf_path])
        summary = payload["summary"]
        types = Counter(event["event_type"] for event in payload["events"])
        self.assertEqual(types["eventlog-logon-success"], 1)
        self.assertNotIn("eventlog-detection", types)
        self.assertEqual(summary["eventlog_detections_merged"], 1)
        merged = next(event for event in payload["events"] if event["event_type"] == "eventlog-logon-success")
        self.assertEqual(merged["details"]["detections"][0]["rule_id"], "R1")
        self.assertEqual(summary["out_of_range_reason_counts"], {"before-1980": 1, "after-now-plus-1d": 1})
        self.assertEqual(summary["timezone"]["storage"], "UTC")
        self.assertTrue(all(event["timezone"] for event in payload["events"]))
        self.assertTrue(all(event["timestamp_kind"] for event in payload["events"]))

    def test_row_contracts_and_registry_timezone(self) -> None:
        rows = artifacts_payload(
            "mixed",
            [
                {"artifact_type": "media-image", "path": "C:/e/a.jpg", "details": {
                    "timestamp": "2021-10-28T07:01:19", "timestamp_kind": "exif-datetime-original",
                    "timestamp_timezone": "local-unknown", "source_file_mtime": "2026-10-07T00:00:00+00:00"}},
                {"artifact_type": "windows-usb-device", "path": "C:/e/SYSTEM", "details": {
                    "timeline_events": [{"timestamp": "2025-01-02T03:04:05+00:00", "kind": "first-install"},
                                        {"timestamp": "2025-01-03T03:04:05+00:00", "kind": "last-arrival"}]}},
                {"artifact_type": "browser-top-site", "path": "C:/e/Top Sites", "details": {"timestamp": None}},
                {"artifact_type": "registry-summary", "path": "C:/e/SYSTEM", "details": {
                    "timezone": {"key_name": "Korea Standard Time", "utc_offset": "+09:00", "bias": -540}}},
                {"artifact_type": "registry-key-tree-node", "path": "C:/e/SYSTEM", "details": {"last_written_at": "2025-01-01T00:00:00+00:00"}},
            ],
        )
        stats = TimelineStats()
        events = extract_artifact_events(rows, Path("mixed.json"), stats=stats)
        kinds = {(event["details"]["artifact_type"], event["timestamp_kind"]) for event in events}
        self.assertEqual(
            kinds,
            {("media-image", "exif-datetime-original"), ("windows-usb-device", "first-install"), ("windows-usb-device", "last-arrival")},
        )
        image = next(event for event in events if event["details"]["artifact_type"] == "media-image")
        self.assertEqual(image["timezone"], "local-unknown")
        self.assertEqual(stats.evidence_timezone["name"], "Korea Standard Time")
        self.assertNotIn("browser-top-site", stats.unmapped_types)


# --- indicators -------------------------------------------------------------------------


class IndicatorPolicyTests(unittest.TestCase):
    def test_evidence_fields_only_ip_validation_and_cap_disclosure(self) -> None:
        sha1 = "55efb424933087d755b18468bc574db4463d9ce6"
        rows = [
            {"artifact_type": "amcache-schema-row", "path": "C:/e/Amcache.hve", "details": {
                "sha1": sha1, "version": "10.0.0.1", "executable_path": "C:\\app-1.0.0.30\\a.exe",
                "manifest_sha256": "a" * 64, "row_identity_hash": "b" * 64,
                "source_hashes": {"sha256": "c" * 64}}},
            {"artifact_type": "eventlog-event", "path": "C:/e/Security.evtx", "details": {
                "source_ip": "203.0.113.7", "remote_ip": "1.2.3.4", "message": "connect 192.168.0.10 ok",
                "referenced_path": "\\VOLUME{x}\\APP\\3.0.0.14\\" + "d" * 32 + ".DLL",
                "event_message": "see http://schemas.microsoft.com/win/2004/08/events/event and https://evil.example/x"}},
            {"artifact_type": "registry-key-tree-node", "path": "C:/e/SYSTEM", "details": {"value": "8.8.8.8"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("windows-execution", rows))
            payload = build_indicator_summary({"outputs": {"artifacts_windows-execution": str(art)}}, max_indicators=3)
        summary = payload["summary"]
        self.assertGreater(summary["total_before_cap"], 3)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["display_label"], "지표 후보")
        self.assertEqual(summary["rule_count"], 0)
        self.assertFalse(summary["yara"]["engine_available"])
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("windows-execution", rows))
            full = build_indicator_summary({"outputs": {"artifacts_windows-execution": str(art)}}, max_indicators=0)
        values = {(item["type"], item["value"]) for item in full["indicators"]}
        self.assertIn(("sha1", sha1), values)
        self.assertIn(("ip", "203.0.113.7"), values)
        self.assertIn(("ip", "1.2.3.4"), values)  # version-shaped but IP-context field
        self.assertIn(("ip", "192.168.0.10"), values)
        self.assertIn(("domain", "evil.example"), values)
        for rejected in (("ip", "10.0.0.1"), ("ip", "1.0.0.30"), ("ip", "3.0.0.14"), ("ip", "8.8.8.8"),
                         ("sha256", "a" * 64), ("sha256", "b" * 64), ("sha256", "c" * 64), ("md5", "d" * 32),
                         ("domain", "schemas.microsoft.com")):
            self.assertNotIn(rejected, values)
        private = next(item for item in full["indicators"] if item["value"] == "192.168.0.10")
        self.assertEqual(private["severity"], "info")
        self.assertGreaterEqual(full["summary"]["rejected_token_counts"]["ip:version-like"], 2)


# --- docs ---------------------------------------------------------------------------------


class DocumentTextTests(unittest.TestCase):
    def test_hwp_record_parser_strips_controls(self) -> None:
        payload = hwp_para_payload(HANGUL)
        self.assertEqual(doc_text.hwp_para_text(payload), HANGUL + "\n")
        records = list(doc_text.iter_hwp_records(hwp_record(doc_text.HWPTAG_PARA_TEXT, payload)))
        self.assertEqual(records[0][0], doc_text.HWPTAG_PARA_TEXT)

    def test_native_extractors_return_korean_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.hwp").write_bytes(build_hwp(HANGUL))
            (root / "b.doc").write_bytes(build_doc("워드 본문 " + HANGUL))
            (root / "c.xls").write_bytes(build_xls("첫번째", "두번째 긴 문자열입니다", "셀 라벨"))
            (root / "d.ppt").write_bytes(build_ppt("발표 슬라이드 " + HANGUL))
            (root / "e.pdf").write_bytes(build_pdf_type0("한글 PDF 본문"))
            with zipfile.ZipFile(root / "f.hwpx", "w") as archive:
                archive.writestr(
                    "Contents/section0.xml",
                    '<hs:sec xmlns:hs="urn:hs" xmlns:hp="urn:hp"><hp:p><hp:run><hp:t>한글 HWPX</hp:t><hp:t> 문단</hp:t></hp:run></hp:p></hs:sec>',
                )
            (root / "g.hwp").write_bytes(build_hwp(HANGUL, flags=0x5, preview="미리보기 텍스트"))
            (root / "h.pdf").write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Encrypt 9 0 R >>\n")
            results = {name: extract_document_text(root / name, Path(name).suffix[1:]) for name in os.listdir(root)}
        self.assertIn(HANGUL, results["a.hwp"].text)
        self.assertEqual(results["a.hwp"].method, "hwp5-bodytext")
        self.assertIn(HANGUL, results["b.doc"].text)
        self.assertEqual(results["b.doc"].method, "doc-piece-table")
        self.assertIn("두번째 긴 문자열입니다", results["c.xls"].text)
        self.assertIn("셀 라벨", results["c.xls"].text)
        self.assertIn("[시트1]", results["c.xls"].text)
        self.assertIn(HANGUL, results["d.ppt"].text)
        self.assertIn("한글 PDF 본문", results["e.pdf"].text)
        self.assertIn("한글 HWPX 문단", results["f.hwpx"].text)
        self.assertTrue(results["g.hwp"].encrypted)
        self.assertEqual(results["g.hwp"].status, "encrypted")
        self.assertIn("미리보기", results["g.hwp"].text)
        self.assertTrue(results["h.pdf"].encrypted)
        for result in results.values():
            self.assertGreaterEqual(doc_text.printable_ratio(result.text), 0.8)

    def test_binary_text_is_rejected_and_candidates_disclose_status(self) -> None:
        rejected = doc_text.finalize("\x01\x02\x03\x04ab", method="x")
        self.assertEqual(rejected.status, "binary-rejected")
        self.assertEqual(rejected.text, "")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.hwp").write_bytes(build_hwp(HANGUL))
            (root / "empty.pdf").write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n2 0 obj << /Length 0 >>\nstream\n\nendstream\nendobj\n")
            payload = run_docs_search(root, ["계약서"], manifest={"providers": []})
        candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
        self.assertTrue(candidates["a.hwp"]["matched"])
        self.assertEqual(candidates["empty.pdf"]["text_status"], "no-text")
        self.assertTrue(candidates["empty.pdf"]["text_reason"])
        self.assertEqual(payload["summary"]["zero_text_count"], 1)
        self.assertEqual(payload["summary"]["match_count"], 1)

    @unittest.skipUnless(sqlite_supports_trigram(), "SQLite < 3.34 has no trigram tokenizer")
    def test_trigram_index_finds_korean_substrings(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        apply_schema(connection)
        connection.execute(
            "INSERT INTO case_record (case_id, name, citation_prefix, created_at, updated_at) VALUES ('c', 'c', 'C', 'now', 'now')"
        )
        cursor = connection.execute(
            "INSERT INTO indexed_document (citation_id, case_id, source_type, title, body, indexed_at) VALUES ('C-1', 'c', 'document', 't', ?, 'now')",
            (HANGUL,),
        )
        connection.execute("INSERT INTO indexed_document_fts(rowid, title, body) VALUES (?, 't', ?)", (cursor.lastrowid, HANGUL))
        insert_document_trigram_row(connection, int(cursor.lastrowid), "t", HANGUL)
        self.assertTrue(connection.execute(f"SELECT count(*) FROM {DOCUMENT_TRIGRAM_TABLE}").fetchone()[0])
        self.assertEqual(len(search_indexed_documents(connection, "c", ["계약서"], 10)), 1)  # particle attached
        self.assertEqual(len(search_indexed_documents(connection, "c", ["계약"], 10)), 1)  # 2 chars: prefix
        self.assertEqual(len(search_indexed_documents(connection, "c", ["없는말"], 10)), 0)


# --- steps / report / checkpoints ------------------------------------------------------------


class StepWarningTests(unittest.TestCase):
    def test_caps_and_silent_failures_raise_step_warnings(self) -> None:
        outputs = {name: Path(name) for name in ("manifest", "docs", "docs_index", "files", "docs_extract_manifest",
                                                   "files_extract_manifest", "timeline", "timeline_report", "indicators")}
        outputs["artifacts_eventlog"] = Path("e.json")
        outputs["artifacts_synthetic-media"] = Path("s.json")
        rows = build_step_rows(
            manifest_payload={"providers": [1]},
            docs_payload={"summary": {"candidate_count": 1, "match_count": 1}},
            files_payload={"summary": {"scanned_file_count": 2, "candidate_count": 1, "fuzzy_text_duplicates_truncated": True}},
            docs_extract_payload={"disabled": True, "summary": {}},
            files_extract_payload={"disabled": True, "summary": {}},
            artifact_payloads={
                "eventlog": {"summary": {"artifact_count": 0, "collection_status": "partial", "collection_notes": ["EVTX 없음"]}},
                "synthetic-media": {"summary": {"artifact_count": 1, "collection_status": "skipped", "skip_reasons": {"의존성 없음": 1}}},
            },
            timeline_payload={"summary": {"event_count": 1}},
            indicators_payload={"summary": {"indicator_count": 2, "truncated": True}},
            outputs=outputs,
        )
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["files"]["warning_level"], "warning")
        self.assertIn("summary.fuzzy_text_duplicates_truncated", by_name["files"]["cap_disclosures"])
        self.assertEqual(by_name["indicators"]["warning_level"], "warning")
        self.assertEqual(by_name["artifacts-eventlog"]["warning_level"], "warning")
        self.assertIn("eventlog: EVTX 없음", by_name["artifacts-eventlog"]["warning_messages"])
        self.assertEqual(by_name["artifacts-synthetic-media"]["status"], "skipped")
        apply_silent_failure_verdicts(rows, {"checks": [{"id": "artifact-yield-eventlog", "level": "failed", "message": "m", "detail": "d"}]})
        self.assertEqual(by_name["artifacts-eventlog"]["warning_level"], "failed")
        self.assertEqual(collect_cap_disclosures({"summary": {"a": {"b_truncated": True}}, "candidates": [{"x_truncated": True}]}), ["summary.a.b_truncated"])

    def test_report_disclosures_and_checkpoint_refresh(self) -> None:
        markdown = "# r\n\n- Document matches: 3\n- File candidates: 2\n\n## Mode profile\n\n- Profile: Deep - uncapped extraction\n"
        summary = {"disclosures": {"documents": {"candidate_count": 9, "indexed_with_text_count": 7, "encrypted_count": 1},
                                   "missing_tools": {"yara": {"available": False, "note": "YARA 없음"}},
                                   "caps": {"files": ["summary.fuzzy_text_duplicates_truncated"]},
                                   "acquisition_copy_note": "사본 시각 설명",
                                   "timezone": {"evidence_timezone": {"name": "Korea Standard Time", "utc_offset": "+09:00"}}}}
        text = apply_report_disclosures(markdown, summary)
        self.assertNotIn("Document matches", text)
        self.assertIn("문서 후보: 9", text)
        self.assertNotIn("uncapped", text)
        self.assertIn("YARA 없음", text)
        self.assertIn("Korea Standard Time", text)
        self.assertIn("fuzzy_text_duplicates_truncated", text)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.json"
            stale = {"stage": "files", "status": "completed", "output": str(output), "exists": False, "size_bytes": None, "reused": False}
            output.write_text("{}", encoding="utf-8")
            refreshed = refresh_checkpoint_output_state(stale)
        self.assertTrue(refreshed["exists"])
        self.assertEqual(refreshed["size_bytes"], 2)

    def test_single_run_case_identity(self) -> None:
        self.assertEqual(run_case_id(Path("C:/x/run-subset7")), "run-subset7")
        self.assertEqual(run_case_id(Path("C:/x/case 1")), "run-case-1")
        self.assertEqual(legacy_run_case_ids(Path("C:/x/run-subset7")), ["run-run-subset7"])


# --- case DB linkage ------------------------------------------------------------------------


class CaseDbLinkageTests(unittest.TestCase):
    def test_import_links_events_artifacts_files_documents_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            doc = evidence / "a.txt"
            doc.write_text("계약서 본문", encoding="utf-8")
            sha = "e" * 64
            files = write_json(root / "files.json", {"command": "files", "summary": {}, "candidates": [{
                "path": str(doc), "name": "a.txt", "extension": ".txt", "size": 5, "modified_at": "2026-10-07T00:00:00+00:00",
                "modified_at_origin": "acquisition-copy", "time_origin": "acquisition-copy", "fs_modified_at": None,
                "fs_created_at": None, "is_deleted": None, "sha256": sha, "categories": ["documents"], "reasons": {}}]})
            docs = write_json(root / "docs.json", {"command": "docs", "summary": {}, "candidates": [
                {"path": str(doc), "kind": "txt", "size": 5, "modified_at": ""}], "results": []})
            artifacts = write_json(root / "artifacts.json", artifacts_payload("windows-prefetch", [
                {"artifact_type": "prefetch-file", "provider": "p", "path": str(doc), "supported": True,
                 "details": {"last_run_times": ["2025-05-01T00:00:00+00:00"]}}]))
            timeline = write_json(root / "timeline.json", {"command": "timeline", "summary": {}, "events": [{
                "timestamp": "2025-05-01T00:00:00+00:00", "timestamp_kind": "run-1", "timezone": "UTC", "source": "artifacts",
                "event_type": "artifact-prefetch-file-run-1", "path": str(doc), "summary": "s",
                "details": {"source_record": {"kind": "windows-prefetch", "row_index": 0, "output": "artifacts_windows-prefetch"}}}]})
            database = CaseDatabase(root / "case.db")
            database.initialize()
            result = database.import_run_output(
                {"root": str(evidence), "outputs": {"files": str(files), "docs": str(docs), "artifacts_windows-prefetch": str(artifacts),
                                                     "timeline": str(timeline)}},
                case_id="run-x",
                hash_files=False,
            )
            counts = result["summary"]
            self.assertEqual(counts["hash_record_count"], 1)
            self.assertEqual(counts["event_with_artifact_id_count"], 1)
            self.assertEqual(counts["event_with_file_record_id_count"], 1)
            self.assertEqual(counts["artifact_with_file_record_id_count"], 1)
            self.assertEqual(counts["indexed_document_with_file_record_id_count"], 1)
            with database.connect() as connection:
                event = connection.execute("SELECT timestamp_kind, timezone FROM event").fetchone()
                record = connection.execute("SELECT modified_at, hash_sha256, mime_type FROM file_record").fetchone()
            self.assertEqual((event["timestamp_kind"], event["timezone"]), ("run-1", "UTC"))
            self.assertIsNone(record["modified_at"])  # acquisition-copy time stays out
            self.assertEqual(record["hash_sha256"], sha)
            self.assertEqual(record["mime_type"], "text/plain")


if __name__ == "__main__":
    unittest.main()
