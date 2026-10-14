"""Parser-quality round 2 — R2-B core organisation.

Timeline dedupe/range/timezone/compaction, indicator false positives and cap
policy, row-level truncation warnings, files inventory/hash/signature
linkage, docs (PDF owner-password decryption, binary salvage, UTF-16 text,
2-character Korean search), checkpoints and tree routing. Every fixture is
built in the test; each test fails on the round-1 code.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import tempfile
import unittest
import zlib
from collections import Counter
from pathlib import Path

from rapidtriage.api.app.tree import artifact_type_domain
from rapidtriage.artifacts.windows.filesystem import (
    collect_signature_mismatch_artifacts,
)
from rapidtriage.cli import build_parser
from rapidtriage.core import doc_text
from rapidtriage.core.artifact_taxonomy import KNOWN_DYNAMIC_ARTIFACT_TYPES
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.case_db.schema import apply_schema
from rapidtriage.core.case_db.search import search_indexed_documents
from rapidtriage.core.docs import (
    build_docs_size_cap_disclosure,
    extract_document_text,
    search_docs_index_payload,
)
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.indicators import build_indicator_summary
from rapidtriage.core.models import DocumentCandidate
from rapidtriage.core.run import RUN_MAX_INDICATORS, timeline_reference_time
from rapidtriage.core.run.checkpoints import (
    record_run_checkpoint,
    write_run_checkpoints,
)
from rapidtriage.core.run.markdown import build_disclosure_section
from rapidtriage.core.run.steps import apply_row_truncation_warnings
from rapidtriage.core.run.summary import (
    build_run_disclosures,
    infer_processing_profile_label,
)
from rapidtriage.core.timeline import (
    TimelineStats,
    extract_artifact_events,
    run_timeline,
    write_timeline_result,
)


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def artifacts_payload(kind: str, rows: list[dict[str, object]], *, type_counts: dict[str, int] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"command": "artifacts", "kind": kind, "artifacts": rows}
    if type_counts is not None:
        payload["summary"] = {"artifact_type_counts": type_counts}
    return payload


def same_record_same_time(events: list[dict[str, object]]) -> list[tuple[object, ...]]:
    keys = Counter(
        (
            event["path"],
            (event["details"].get("source_record") or {}).get("row_index"),
            event["details"].get("element"),
            event["timestamp"],
        )
        for event in events
    )
    return [key for key, count in keys.items() if count > 1]


# --- timeline ---------------------------------------------------------------------------


class TimelineDedupeTests(unittest.TestCase):
    def test_label_variants_of_one_record_and_instant_collapse_with_labels(self) -> None:
        t1 = "2025-05-01T01:00:00.1234567+00:00"
        t2 = "2025-05-02T01:00:00+00:00"
        rows = [
            {"artifact_type": "jumplist-entry", "path": "C:/e/a.automaticDestinations-ms", "details": {
                "entry_name": "e1", "timestamp": t1, "timestamp_kind": "last_access", "destlist_last_modified_at": t1,
                "target_accessed_at": t2, "target_modified_at": t2}},
            {"artifact_type": "browser-cookie", "path": "C:/e/Cookies", "details": {
                "rowid": 7, "timestamp": t2, "timestamp_kind": "created", "created_at": t2, "last_accessed_at": t2}},
            {"artifact_type": "prefetch-file", "path": "C:/e/A.pf", "details": {
                "timestamp": t1, "timestamp_kind": "run", "last_run_times": [t1], "run_time_1": t1}},
            {"artifact_type": "windows-usb-device", "path": "C:/e/SYSTEM", "details": {
                "key_path": "USBSTOR\\x", "last_arrival_at": t2, "timeline_events": [{"timestamp": t2, "kind": "last-arrival-at"}]}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("mixed", rows))
            files = write_json(Path(tmp) / "files.json", {"command": "files", "candidates": [], "summary": {}})
            docs = write_json(Path(tmp) / "docs.json", {"command": "docs", "candidates": [], "results": []})
            payload = run_timeline(root=Path(tmp), files_inputs=[files], docs_inputs=[docs], artifacts_inputs=[art])
        events = payload["events"]
        self.assertEqual(same_record_same_time(events), [])
        by_type = {event["details"]["artifact_type"]: [] for event in events}
        for event in events:
            by_type[event["details"]["artifact_type"]].append(event)
        self.assertEqual(len(by_type["jumplist-entry"]), 2)
        labels = {tuple(event.get("labels") or [event["timestamp_kind"]]) for event in by_type["jumplist-entry"]}
        self.assertIn(("destlist-last-modified", "last-access"), labels)
        self.assertIn(("target-accessed", "target-modified"), {tuple(sorted(item)) for item in labels})
        self.assertEqual(len(by_type["browser-cookie"]), 1)
        self.assertEqual(set(by_type["browser-cookie"][0]["labels"]), {"created", "accessed"})
        self.assertEqual(len(by_type["prefetch-file"]), 1)
        self.assertEqual(set(by_type["prefetch-file"][0]["labels"]), {"run", "run-1"})
        self.assertEqual([event["timestamp_kind"] for event in by_type["windows-usb-device"]], ["last-arrival"])
        self.assertGreaterEqual(payload["summary"]["label_variants_merged"], 3)
        for event in events:
            self.assertNotIn("record_key", event)
            self.assertNotIn("input_file", event)
            self.assertNotIn("parser", event["details"])

    def test_key_level_times_once_per_key_and_build_stamps_are_not_events(self) -> None:
        key_time = "2025-05-29T08:50:47.7106952+00:00"
        rows = [
            {"artifact_type": "shimcache-schema-entry", "path": "C:/e/SYSTEM", "details": {
                "executable_path": f"C:\\app{index}.exe", "source_key": "ControlSet001\\AppCompatCache",
                "key_last_written_at": key_time, "timestamp": f"2024-0{index + 1}-01T00:00:00+00:00", "timestamp_kind": "file-modified"}}
            for index in range(3)
        ] + [
            {"artifact_type": "bam-schema-entry", "path": "C:/e/SYSTEM", "details": {
                "executable_path": "C:\\b.exe", "source_key": "bam\\S-1", "key_last_written_at": key_time,
                "timestamp": key_time, "timestamp_kind": "last_execution"}},
            {"artifact_type": "amcache-schema-row", "path": "C:/e/Amcache.hve", "details": {
                "executable_path": "C:\\c.exe", "link_date_raw": "11/12/2104 20:36:41", "compile_time": "2006-12-10T19:34:42+00:00",
                "key_last_written_at": "2025-05-14T15:13:02+00:00"}},
        ]
        stats = TimelineStats()
        events = extract_artifact_events(artifacts_payload("windows-execution", rows), Path("x.json"), stats=stats)
        from rapidtriage.core.timeline import TimelineBuilder

        builder = TimelineBuilder(stats)
        builder.extend(events)
        kept = builder.events()
        shim_key = [event for event in kept if event["event_type"] == "artifact-shimcache-schema-entry-last-written"]
        self.assertEqual(len(shim_key), 1)
        self.assertEqual(sum(stats.key_level_collapsed.values()), 2)
        bam = [event for event in kept if event["details"]["artifact_type"] == "bam-schema-entry"]
        self.assertEqual(len(bam), 1)  # last-execution == key LastWrite: one event, two labels
        self.assertEqual(set(bam[0]["labels"]), {"last-execution", "last-written"})
        self.assertFalse([event for event in kept if "link" in event["event_type"] or "compile" in event["event_type"]])
        self.assertEqual(stats.build_stamp_fields["amcache-schema-row.link_date_raw"], 1)

    def test_aggregate_rows_are_not_re_emitted(self) -> None:
        visit = "2025-02-25T23:59:15.562416+00:00"
        rows = [
            {"artifact_type": "browser-history-downloads", "path": "C:/e/History", "details": {
                "history": [{"url": "https://a.example/", "last_visited_at": visit}]}},
            {"artifact_type": "browser-history", "path": "C:/e/History", "details": {
                "url": "https://a.example/", "timestamp": visit, "timestamp_kind": "last-visited"}},
        ]
        payload = artifacts_payload("browser", rows, type_counts={"browser-history-downloads": 1, "browser-history": 1})
        stats = TimelineStats()
        events = extract_artifact_events(payload, Path("b.json"), stats=stats)
        self.assertEqual([event["details"]["artifact_type"] for event in events], ["browser-history"])
        self.assertEqual(stats.aggregate_types_skipped["browser-history-downloads"], 1)
        sessions = artifacts_payload(
            "eventlog",
            [{"artifact_type": "eventlog-logon-session", "path": "C:/e", "details": {"started_at": visit}}],
            type_counts={"eventlog-logon-session": 1, "eventlog-event": 5},
        )
        self.assertEqual(extract_artifact_events(sessions, Path("e.json"), stats=stats), [])

    def test_reference_time_range_dos_zero_and_timezones(self) -> None:
        reference = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc)
        rows = [
            {"artifact_type": "recycle-bin-entry", "path": "C:/e/$I1", "details": {"entry_name": "a", "deleted_at": "2025-06-03T00:00:00+00:00"}},
            {"artifact_type": "recycle-bin-entry", "path": "C:/e/$I2", "details": {"entry_name": "b", "deleted_at": "1980-01-01T00:00:00+00:00"}},
            {"artifact_type": "recycle-bin-entry", "path": "C:/e/$I3", "details": {"entry_name": "c", "deleted_at": "2025-05-31T00:00:00+00:00"}},
            {"artifact_type": "amcache-schema-row", "path": "C:/e/Amcache.hve", "details": {
                "executable_path": "C:\\d.exe", "decoded_values": {"InstallDate": "12/31/2020 00:00:00"}}},
            {"artifact_type": "media-image", "path": "C:/e/a.jpg", "details": {
                "timestamp": "2021-01-27T07:50:59.311+09:00", "timestamp_kind": "exif-datetime-original", "timestamp_timezone": "+09:00"}},
            {"artifact_type": "media-image", "path": "C:/e/b.jpg", "details": {
                "timestamp": "2021-01-27T07:50:59", "timestamp_kind": "exif-datetime-original", "timestamp_timezone": "+09:00"}},
            {"artifact_type": "media-image", "path": "C:/e/c.jpg", "details": {
                "timestamp": "2021-02-24T19:11:32.68", "timestamp_kind": "exif-datetime-original", "timestamp_timezone": "exif-local"}},
        ]
        stats = TimelineStats(now=reference, reference_basis="acquisition")
        events = extract_artifact_events(artifacts_payload("mixed", rows), Path("m.json"), stats=stats)
        by_path = {event["path"]: event for event in events}
        self.assertNotIn("C:/e/$I1", by_path)
        self.assertNotIn("C:/e/$I2", by_path)
        self.assertIn("C:/e/$I3", by_path)
        self.assertEqual(stats.out_of_range["after-acquisition-plus-1d"], 1)
        self.assertEqual(stats.out_of_range["dos-zero-sentinel"], 1)
        self.assertEqual(stats.as_dict()["valid_range"]["max_basis"], "acquisition + 1 day")
        install = by_path["C:/e/Amcache.hve"]
        self.assertEqual((install["timestamp"], install["timezone"]), ("2020-12-31T00:00:00", "local-unknown"))
        self.assertEqual((by_path["C:/e/a.jpg"]["timestamp"], by_path["C:/e/a.jpg"]["timezone"]), ("2021-01-26T22:50:59.311000+00:00", "UTC"))
        self.assertEqual(by_path["C:/e/a.jpg"]["details"]["source_timezone"], "+09:00")
        self.assertEqual(by_path["C:/e/b.jpg"]["timestamp"], "2021-01-26T22:50:59+00:00")  # naive + offset label converted
        self.assertEqual((by_path["C:/e/c.jpg"]["timestamp"], by_path["C:/e/c.jpg"]["timezone"]), ("2021-02-24T19:11:32.680000", "exif-local"))

    def test_preview_truncation_is_disclosed_not_warned_and_amcache_inventory_mapped(self) -> None:
        rows = [
            {"artifact_type": "eventlog-event", "path": "C:/e/A.evtx", "details": {
                "timestamp": "2025-02-23T14:09:15+00:00", "record_id": "1", "event_message_truncated": True}},
            {"artifact_type": "eventlog-file", "path": "C:/e/A.evtx", "details": {"text_truncated_rows": 1, "payload_truncated_rows": 0}},
            {"artifact_type": "amcache-device-pnp", "path": "C:/e/Amcache.hve", "details": {
                "key_path": "Root/InventoryDevicePnp/x","key_last_written_at": "2025-03-01T00:00:00+00:00",
                "timestamp": "2025-03-01T00:00:00+00:00", "timestamp_label": "last_written"}},
        ]
        stats = TimelineStats()
        events = extract_artifact_events(artifacts_payload("eventlog", rows), Path("e.json"), stats=stats)
        self.assertEqual([event["timestamp_kind"] for event in events if event["details"]["artifact_type"] == "amcache-device-pnp"], ["last-written"])
        disclosure = stats.row_truncation_disclosure()["eventlog"]
        self.assertEqual(disclosure["rows_with_truncation"], 0)
        self.assertEqual(disclosure["preview_only_rows"], 1)
        steps = [{"name": "artifacts-eventlog", "warning_level": "none", "warning_messages": []}]
        apply_row_truncation_warnings(
            steps, timeline_payload={"summary": {"input_row_truncation": stats.row_truncation_disclosure()}}, docs_payload={}
        )
        self.assertEqual(steps[0]["warning_level"], "notice")
        self.assertFalse(steps[0].get("truncated"))

    def test_run_disclosures_copy_caps_and_aggregate_row_truncation(self) -> None:
        cap_policy = {"mode": "uncapped", "max_indicators": None, "kept": 3, "total_before_cap": 3, "note": "상한 없음"}
        size_caps = {"max_input_bytes": 1, "too_large_count": 2, "binary_rejected_count": 0, "truncated": True, "note": "크기 상한 초과 2건"}
        steps = [
            {"name": "artifacts-eventlog", "row_truncation": {
                "rows_with_truncation": 2, "flag_counts": {"x": 2}, "count_fields": {"payload_truncated_rows": 3},
                "preview_only_rows": 1, "preview_flag_counts": {}, "preview_count_fields": {"text_truncated_rows": 4}}},
            {"name": "artifacts-browser", "row_truncation": {"rows_with_truncation": 0, "preview_only_rows": 2}},
            {"name": "docs"},
        ]
        disclosures = build_run_disclosures(
            files_payload={}, docs_payload={"summary": {"size_caps": size_caps}}, timeline_payload={},
            indicators_payload={"summary": {"cap_policy": cap_policy}}, artifact_payloads={}, steps=steps,
        )
        self.assertEqual(disclosures["indicators"]["cap_policy"], cap_policy)
        self.assertEqual(disclosures["documents"]["size_caps"], size_caps)
        truncation = disclosures["input_row_truncation"]
        self.assertEqual((truncation["payload_truncated_rows"], truncation["preview_truncated_rows"], truncation["level"]), (5, 7, "warning"))
        self.assertEqual(set(truncation["by_step"]), {"artifacts-eventlog", "artifacts-browser"})
        self.assertIn("timeline_excluded", disclosures)  # existing keys kept
        section = build_disclosure_section(disclosures)
        self.assertIn("지표 상한: 상한 없음", section)
        self.assertIn("문서 크기 상한: 크기 상한 초과 2건", section)
        self.assertIn("행 단위 절단: 원문 일부만 보존 5건", section)
        empty = build_run_disclosures(
            files_payload={}, docs_payload={}, timeline_payload={}, indicators_payload={}, artifact_payloads={}, steps=[{"name": "docs"}],
        )
        self.assertIsNone(empty["indicators"]["cap_policy"])
        self.assertIsNone(empty["documents"]["size_caps"])
        self.assertEqual(empty["input_row_truncation"], {"payload_truncated_rows": 0, "preview_truncated_rows": 0, "level": "none", "by_step": {}})
        preview_only = build_run_disclosures(
            files_payload={}, docs_payload={}, timeline_payload={}, indicators_payload={}, artifact_payloads={}, steps=steps[1:2],
        )
        self.assertEqual(preview_only["input_row_truncation"]["level"], "notice")

    def test_reference_time_from_complete_fingerprint_only(self) -> None:
        start = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
        complete = {"summary": {"latest_mtime_epoch": dt.datetime(2026, 10, 7, tzinfo=dt.timezone.utc).timestamp(), "truncated": False}}
        self.assertEqual(timeline_reference_time(complete, start)[1], "acquisition")
        self.assertEqual(timeline_reference_time({**complete, "summary": {**complete["summary"], "truncated": True}}, start), (start, "run-start"))

    def test_compact_writer_is_valid_json_and_row_truncation_is_disclosed(self) -> None:
        rows = [
            {"artifact_type": "eventlog-event", "path": "C:/e/Security.evtx", "details": {
                "timestamp": "2025-02-23T14:09:15+00:00", "record_id": "7", "event_id": "4688", "event_category": "process-created",
                "event_family": "execution", "parser": "p", "coverage_status": "c", "event_tags": ["a"], "source_path": "C:/e/Security.evtx",
                "command_line": "x" * 600, "command_line_truncated": True}},
            {"artifact_type": "synthetic-media-scan-summary", "path": "C:/e", "details": {"scan_capped": True}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("eventlog", rows))
            files = write_json(Path(tmp) / "files.json", {"command": "files", "candidates": [], "summary": {}})
            docs = write_json(Path(tmp) / "docs.json", {"command": "docs", "candidates": [], "results": []})
            payload = run_timeline(root=Path(tmp), files_inputs=[files], docs_inputs=[docs], artifacts_inputs=[art])
            out = Path(tmp) / "timeline.json"
            write_timeline_result(payload, out)
            reread = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(reread["events"], json.loads(json.dumps(payload["events"], ensure_ascii=False)))
        event = payload["events"][0]
        self.assertNotIn("event_tags", event["details"])
        self.assertNotIn("coverage_status", event["details"])
        self.assertLessEqual(len(event["details"]["command_line"]), 260)
        truncation = payload["summary"]["input_row_truncation"]["eventlog"]
        self.assertEqual(truncation["flag_counts"]["eventlog-event.command_line_truncated"], 1)
        self.assertEqual(truncation["flag_counts"]["synthetic-media-scan-summary.scan_capped"], 1)
        steps = [{"name": "artifacts-eventlog", "warning_level": "none", "warning_messages": []},
                 {"name": "docs", "warning_level": "none", "warning_messages": []}]
        apply_row_truncation_warnings(
            steps,
            timeline_payload=payload,
            docs_payload={"summary": {"text_status_counts": {"too-large": 8, "binary-rejected": 2, "ok": 3}}},
        )
        self.assertEqual(steps[0]["warning_level"], "warning")
        self.assertTrue(steps[0]["truncated"])
        self.assertEqual(steps[1]["warning_level"], "warning")
        self.assertTrue(any("too-large" in message for message in steps[1]["warning_messages"]))
        self.assertNotIn("without size limits", infer_processing_profile_label(
            read_only=False, dry_run=False, max_extract_size_bytes=0, max_file_count=0, caps_applied=True))


# --- indicators -------------------------------------------------------------------------


class IndicatorFalsePositiveTests(unittest.TestCase):
    def run_rows(self, rows: list[dict[str, object]], **kwargs: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("eventlog", rows))
            return build_indicator_summary({"outputs": {"artifacts_eventlog": str(art)}}, **kwargs)  # type: ignore[arg-type]

    def test_binary_blobs_are_not_hashes_and_hostnames_are_validated(self) -> None:
        sha1 = "55efb424933087d755b18468bc574db4463d9ce6"
        rows = [
            {"artifact_type": "eventlog-event", "path": "C:/e/Security.evtx", "details": {"event_data": {
                "ClientAddress": "0200c06cc0a8006e0000000000000000",
                "RemoteAddress": "020001bdc0a800640000000000000000",
                "Transport": "4e80be107c860de896384b3eff50504dc2d76ac7151df3102a4450637a032146",
                "SolidStateDevice": "010007000000000003000000000000e0",
                "Binary": "67007500700064006100740065000000",
                "ClientName": "192.168.0.120",
                "Hashes": "SHA1=" + sha1.upper()}}},
            {"artifact_type": "wer-report", "path": "C:/e/Report.wer", "details": {
                "bucket": "5cfa9230ab152b2fefaf521510a2db5f",
                "fields": {"DynamicSig[25].Value": "bf407e2963722e340fbb29fd22b44ab0", "ApplicationIdentity": "0517af9064b2a51543ee460b85ab66b2"}}},
            {"artifact_type": "eventlog-event", "path": "C:/e/System.evtx", "details": {"event_message": (
                "Reserved http://+:80/wsman/ and https://*:5358/ and http://192.168.0.1/login and https://good.example.com/x")}},
            {"artifact_type": "eventlog-event", "path": "C:/e/PS.evtx", "details": {
                "script_block_text": "@{ ModuleVersion = '1.0.0.0' }", "description": "build 1.71.99.0 ok",
                "key_path": "HKLM\\SYSTEM\\ControlSet001\\Services\\SMSvcHost 3.0.0.0"}},
        ]
        payload = self.run_rows(rows, max_indicators=None)
        values = {(item["type"], item["value"]) for item in payload["indicators"]}
        hashes = {value for kind, value in values if kind in ("md5", "sha1", "sha256")}
        self.assertEqual(hashes, {sha1})
        domains = {value for kind, value in values if kind == "domain"}
        self.assertEqual(domains, {"good.example.com"})
        urls = {value for kind, value in values if kind == "url"}
        self.assertFalse([url for url in urls if "+" in url or "*" in url])
        ips = {value for kind, value in values if kind == "ip"}
        self.assertEqual(ips, {"192.168.0.120", "192.168.0.1"})
        rejected = payload["summary"]["rejected_token_counts"]
        self.assertGreaterEqual(rejected["hash:binary-blob-field"], 5)
        self.assertGreaterEqual(rejected["url:wildcard-host"], 2)
        self.assertEqual(rejected["domain:ip-address"], 1)
        self.assertEqual(payload["summary"]["cap_policy"]["mode"], "uncapped")

    def test_run_and_cli_defaults_are_uncapped_and_disclosed(self) -> None:
        self.assertIsNone(RUN_MAX_INDICATORS)
        args = build_parser().parse_args(["indicators", "run-dir"])
        self.assertEqual(args.limit, 0)
        rows = [{"artifact_type": "eventlog-event", "path": "C:/e/a.evtx", "details": {
            "url": f"https://h{index}.example.com/"}} for index in range(5)]
        capped = self.run_rows(rows, max_indicators=2)["summary"]
        self.assertEqual(capped["cap_policy"]["mode"], "capped")
        self.assertTrue(capped["truncated"])
        uncapped = self.run_rows(rows, max_indicators=0)["summary"]
        self.assertEqual(uncapped["indicator_count"], uncapped["total_before_cap"])


# --- files / case DB --------------------------------------------------------------------


class FilesInventoryTests(unittest.TestCase):
    def test_inventory_hashes_signature_and_case_db_linkage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            (root / "Users").mkdir(parents=True)
            (root / "Users" / "a.txt").write_text("같은 내용", encoding="utf-8")
            (root / "Users" / "b.txt").write_text("같은 내용", encoding="utf-8")
            (root / "Users" / "notes.xyz").write_bytes(b"other category")
            (root / "Users" / "CALC.EXE-1.pf").write_bytes(b"ABCD" * 32)  # .pf without MAM/SCCA
            (root / "Users" / "fake.jpg").write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
            payload = run_files_scan(root, categories=["documents"], inventory_all_files=True)
            fs_mismatches = list(collect_signature_mismatch_artifacts(root))
            summary = payload["summary"]
            inventory = {Path(item["path"]).name: item for item in payload["inventory"]}
            self.assertEqual(set(inventory), {"notes.xyz", "CALC.EXE-1.pf", "fake.jpg"})
            self.assertIn("other", inventory["notes.xyz"]["categories"])
            self.assertEqual(summary["inventory_count"], 3)
            self.assertGreaterEqual(summary["inventory_category_counts"]["other"], 1)
            candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(candidates["a.txt"]["recovery"]["deletion_state"], "unknown")  # acquisition copy
            self.assertIsNone(candidates["a.txt"]["is_deleted"])
            self.assertEqual(inventory["notes.xyz"]["deletion_state"], "unknown")
            self.assertEqual(candidates["a.txt"]["hashes"]["sha256"], hashlib.sha256("같은 내용".encode()).hexdigest())
            self.assertEqual(summary["signature_mismatch_count"], len(fs_mismatches))
            self.assertEqual(summary["signature_mismatch_count"], 2)
            files_json = write_json(Path(tmp) / "files.json", payload)
            timeline = write_json(Path(tmp) / "timeline.json", {"command": "timeline", "summary": {}, "events": [{
                "timestamp": "2025-05-01T00:00:00+00:00", "timestamp_kind": "event", "timezone": "UTC", "source": "artifacts",
                "event_type": "x", "path": str(root / "Users" / "notes.xyz"), "summary": "s", "details": {}}]})
            database = CaseDatabase(Path(tmp) / "case.db")
            database.initialize()
            result = database.import_run_output(
                {"root": str(root), "outputs": {"files": str(files_json), "timeline": str(timeline)}},
                case_id="run-x",
                hash_files=False,
            )
            counts = result["summary"]
            self.assertEqual(counts["file_record_count"], 5)
            self.assertEqual(counts["hash_record_count"], 6)  # 2 hashed files x md5/sha1/sha256
            self.assertEqual(counts["event_with_file_record_id_count"], 1)
            with database.connect() as connection:
                hashed = connection.execute("SELECT count(*) FROM file_record WHERE hash_sha256 IS NOT NULL").fetchone()[0]
            self.assertEqual(hashed, 2)


# --- docs ---------------------------------------------------------------------------------

PDF_PADDING = bytes.fromhex("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")


def rc4(key: bytes, data: bytes) -> bytes:
    return doc_text._rc4(key, data)


def build_pdf(objects: dict[int, bytes], trailer: bytes) -> bytes:
    out = b"%PDF-1.4\n"
    for number, body in objects.items():
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    return out + b"trailer\n" + trailer + b"\n%%EOF\n"


def stream_object(dictionary: bytes, data: bytes) -> bytes:
    return dictionary[:-2] + f" /Length {len(data)} >>".encode() + b"\nstream\n" + data + b"\nendstream"


def encrypted_rc4_pdf(text: str, *, user_password: bytes = b"") -> bytes:
    file_id = bytes(range(16))
    owner = bytes(range(100, 132))
    permissions = -4
    padded = (user_password + PDF_PADDING)[:32]
    digest = hashlib.md5(padded + owner + (permissions & 0xFFFFFFFF).to_bytes(4, "little") + file_id).digest()
    for _ in range(50):
        digest = hashlib.md5(digest[:16]).digest()
    key = digest[:16]
    check = rc4(key, hashlib.md5(PDF_PADDING + file_id).digest())
    for index in range(1, 20):
        check = rc4(bytes(byte ^ index for byte in key), check)
    user = check + bytes(16)
    content = zlib.compress(f"BT /F1 12 Tf 72 700 Td ({text}) Tj ET".encode("latin-1"))
    object_key = hashlib.md5(key + (4).to_bytes(3, "little") + (0).to_bytes(2, "little")).digest()[:16]
    encrypted = rc4(object_key, content)
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        4: stream_object(b"<< /Filter /FlateDecode >>", encrypted),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        6: f"<< /Filter /Standard /V 2 /R 3 /Length 128 /P {permissions} /O <{owner.hex()}> /U <{user.hex()}> >>".encode(),
    }
    return build_pdf(objects, f"<< /Root 1 0 R /Encrypt 6 0 R /ID [<{file_id.hex()}> <{file_id.hex()}>] >>".encode())


def mixed_font_pdf() -> bytes:
    """A ToUnicode Hangul font next to a simple font drawing glyph-id bytes
    (control characters after cp1252 decoding): the KT 개인정보 동의서 shape."""
    cmap = b"begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfrange <0001> <0078> <AC00> endbfrange\nendcmap"
    hangul_codes = "".join(f"{code:04x}" for code in range(1, 121))
    lines = [f"BT /F1 12 Tf 72 {700 - 20 * row} Td <{hangul_codes[row * 160:(row + 1) * 160]}> Tj ET" for row in range(3)]
    junk = "".join(chr(code) for code in range(1, 32) if chr(code) not in "\n\r\t()\\")
    lines += [f"BT /F2 12 Tf 72 {600 - 20 * row} Td ({junk}{junk}) Tj ET" for row in range(3)]
    content = zlib.compress("\n".join(lines).encode("latin-1"))
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R /F2 7 0 R >> >> /Contents 4 0 R >>",
        4: stream_object(b"<< /Filter /FlateDecode >>", content),
        5: b"<< /Type /Font /Subtype /Type0 /BaseFont /KTfont /Encoding /Identity-H /ToUnicode 6 0 R >>",
        6: stream_object(b"<< >>", cmap),
        7: b"<< /Type /Font /Subtype /Type1 /BaseFont /SDGothic >>",
    }
    return build_pdf(objects, b"<< /Root 1 0 R >>")


class DocumentTextR2Tests(unittest.TestCase):
    def test_owner_password_only_pdf_is_decrypted_user_password_pdf_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            owner_only = Path(tmp) / "owner.pdf"
            owner_only.write_bytes(encrypted_rc4_pdf("Owner only contract"))
            protected = Path(tmp) / "user.pdf"
            protected.write_bytes(encrypted_rc4_pdf("Secret", user_password=b"1234"))
            opened = extract_document_text(owner_only, "pdf")
            closed = extract_document_text(protected, "pdf")
        self.assertEqual(opened.status, "ok")
        self.assertIn("Owner only contract", opened.text)
        self.assertTrue(any("소유자 암호" in warning for warning in opened.warnings))
        self.assertEqual(closed.status, "encrypted")
        self.assertIn("사용자 암호", closed.reason)

    def test_real_text_pdf_with_glyph_noise_is_salvaged_not_binary_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "4.KT 개인정보_활용동의서.pdf"
            path.write_bytes(mixed_font_pdf())
            result = extract_document_text(path, "pdf")
        self.assertEqual(result.status, "ok")
        self.assertIn("가각갂", result.text)
        self.assertGreaterEqual(sum(1 for char in result.text if 0xAC00 <= ord(char) <= 0xD7A3), 120)
        self.assertFalse(any(ord(char) < 32 and char not in "\n\t" for char in result.text))
        self.assertTrue(result.warnings)
        self.assertEqual(doc_text.printable_ratio("ab\ufffd\ufffdcd"), 1.0)  # replacement chars are not binary
        self.assertEqual(doc_text.finalize("\x01\x02\x03\x04ab", method="x").status, "binary-rejected")

    def test_utf16_text_without_bom_is_decoded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "WER.tmp.txt"
            path.write_bytes("Version=1\r\nEventType=APPCRASH 계약\r\n".encode("utf-16-le") * 4)
            result = extract_document_text(path, "txt")
        self.assertEqual(result.status, "ok")
        self.assertIn("EventType=APPCRASH 계약", result.text)

    def test_size_cap_disclosure_counts_too_large(self) -> None:
        candidates = [
            DocumentCandidate(path="C:/e/a.xlsx", kind="xlsx", size=10, modified_at=""),
            DocumentCandidate(path="C:/e/b.pdf", kind="pdf", size=10, modified_at=""),
        ]
        candidates[0].text_status = "too-large"
        candidates[0].text_reason = "archive member exceeds text extraction size limit: xl/worksheets/sheet1.xml"
        disclosure = build_docs_size_cap_disclosure(candidates)
        self.assertEqual(disclosure["too_large_count"], 1)
        self.assertTrue(disclosure["truncated"])
        self.assertEqual(disclosure["too_large_samples"][0]["path"], "C:/e/a.xlsx")


class KoreanSubstringSearchTests(unittest.TestCase):
    def test_docs_index_matches_two_character_terms_inside_tokens(self) -> None:
        index = {
            "documents": [{"id": 0, "path": "C:/e/a.hwp"}, {"id": 1, "path": "C:/e/b.hwp"}],
            "terms": {"근로계약서를": [{"document_id": 0, "count": 2}], "계약": [{"document_id": 1, "count": 1}]},
        }
        result = search_docs_index_payload(index, ["계약"])
        self.assertEqual({item["document_id"] for item in result["results"]}, {0, 1})
        self.assertEqual(result["summary"]["match_mode"], "token+substring")
        self.assertIn("recall_note", result["summary"])
        self.assertEqual(result["summary"]["missing_terms"], [])

    def test_case_db_two_character_korean_term_finds_compounds(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        apply_schema(connection)
        connection.execute(
            "INSERT INTO case_record (case_id, name, citation_prefix, created_at, updated_at) VALUES ('c', 'c', 'C', 'now', 'now')"
        )
        for number, body in enumerate(("근로계약서를 작성했습니다", "임대차 계약 해지", "관계없는 문서")):
            cursor = connection.execute(
                "INSERT INTO indexed_document (citation_id, case_id, source_type, title, body, indexed_at) VALUES (?, 'c', 'document', 't', ?, 'now')",
                (f"C-{number}", body),
            )
            connection.execute("INSERT INTO indexed_document_fts(rowid, title, body) VALUES (?, 't', ?)", (cursor.lastrowid, body))
        matches = search_indexed_documents(connection, "c", ["계약"], 10)
        self.assertEqual({match["citation_id"] for match in matches}, {"C-0", "C-1"})
        self.assertTrue(all(match["match_method"] == "substring-scan" for match in matches))
        self.assertIn("계약", matches[0]["preview"])


# --- checkpoints / tree -----------------------------------------------------------------


class CheckpointAndTreeTests(unittest.TestCase):
    def test_checkpoint_gates_do_not_list_checks_satisfied_in_the_same_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "files.json"
            records: list[dict[str, object]] = []
            record_run_checkpoint(records, "files", output, reused=False)  # recorded before the write
            output.write_text("{}", encoding="utf-8")
            record_run_checkpoint(records, "persist", output, reused=False)
            path = Path(tmp) / "checkpoints.json"
            write_run_checkpoints(
                path,
                output_dir=Path(tmp),
                input_fingerprint={},
                resume_requested=False,
                resume_effective=False,
                resume_disabled_reason="",
                checkpoints=records,
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
        for checkpoint in payload["checkpoints"]:
            missing = checkpoint["core_accuracy_gates"][0]["missing_required_checks"]
            self.assertNotIn("checkpoint resume decision manifest emitted", missing)
            self.assertNotIn("output path and size captured", missing)
        self.assertIn("persist", [item["stage"] for item in payload["checkpoints"]])

    def test_tree_routes_network_interface_to_os_and_registers_amcache_types(self) -> None:
        self.assertEqual(artifact_type_domain("windows-registry", "windows-network-interface"), "os")
        self.assertEqual(artifact_type_domain("windows-execution", "amcache-device-pnp"), "devices")
        self.assertEqual(artifact_type_domain("windows-execution", "amcache-driver-binary"), "execution")
        for artifact_type in ("amcache-driver-binary", "amcache-device-pnp", "amcache-application-shortcut", "amcache-device-census"):
            self.assertIn(artifact_type, KNOWN_DYNAMIC_ARTIFACT_TYPES)


if __name__ == "__main__":
    unittest.main()
