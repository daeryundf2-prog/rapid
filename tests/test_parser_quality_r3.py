"""Parser-quality round 3 — fixes found by the round-2 real-data review.

Browser autofill masking (Korean form conventions, value heuristics, default
masking), Amcache inventory key-time collapse, indicator URL case /
loopback / MD5-SHA1 rule hashes, content-derived artifact ids, warning-level
wording and counts, synthetic-media scan coverage, binary-text salvage scope
and desktop.ini noise hints, acquisition-anchored timeline range, report
copy-time wording, EVTX undecodable template names, memory IP next to device
ids and the scheduler worker-limit label. Every fixture is built in the test;
each test fails on the round-2 code.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts import memory
from rapidtriage.artifacts.windows import browser, eventlog
from rapidtriage.core import doc_text
from rapidtriage.core.artifact_store import (
    ARTIFACT_ID_SCHEME,
    attach_artifact_record_contracts,
)
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.case_db.helpers import normalize_path_for_db
from rapidtriage.core.docs import run_docs_search
from rapidtriage.core.indicators import build_indicator_summary, url_indicator_status
from rapidtriage.core.reporting import (
    append_candidate_rows,
    build_processing_decision_rows,
)
from rapidtriage.core.rules import load_rule_set
from rapidtriage.core.run import timeline_reference_time
from rapidtriage.core.run.markdown import build_disclosure_section
from rapidtriage.core.run.scheduler import build_parser_scheduler_manifest
from rapidtriage.core.run.steps import apply_row_truncation_warnings
from rapidtriage.core.run.summary import (
    build_run_disclosures,
    count_warning_levels,
    derive_counts,
    summarize_file_candidates,
)
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    extract_artifact_events,
)


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def artifacts_payload(kind: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {"command": "artifacts", "kind": kind, "artifacts": rows}


# --- 1. browser autofill masking ------------------------------------------------------


class BrowserAutofillMaskingTests(unittest.TestCase):
    def test_korean_form_field_conventions_are_masked(self) -> None:
        for name, value in (
            ("inquiManRgno1", "830518"),
            ("mf_txppWframe_edtResno1", "830518"),
            ("mf_txppWframe_edtBsno1", "576"),
            ("brno2", "96"),
            ("inp_sujinjaNm", "김이든"),
            ("PATNAM", "홍길동"),
            ("edtPatnam", "PIAO YAYIN"),
            ("ctl00$ContentPlaceHolder1$txtSearch_ChartNm", "박송"),
            ("srchFnm", "유성환"),
            ("user_nm", "원종은"),
            ("c_mbrFlnm", "홍길동"),
            ("srchBday", "520211"),
            ("joinJuso", "서울시"),
            ("edtHp2", "1234"),
        ):
            result = browser.browser_pii_value(name, value)
            self.assertTrue(result["value_masked"], name)
            self.assertEqual(result["mask_reason"], "personal-field-name", name)
            self.assertNotIn(value, json.dumps(result, ensure_ascii=False))

    def test_person_name_and_resident_number_values_are_masked(self) -> None:
        for name, value, reason in (
            ("입력", "배수현", "personal-value-korean-name"),
            ("wq_uuid_54", "남궁민수", "personal-value-korean-name"),
            ("990101", "830518", "personal-value-resident-number"),
            ("x2", "1234567", "personal-value-resident-number"),
            ("CLOUD_ID_2", "010 - 8403 - 1050", "personal-value-pattern"),
            ("CLOUD_ID_3", "1983 / 05 / 18", "personal-value-pattern"),
        ):
            result = browser.browser_pii_value(name, value)
            self.assertEqual((result["value_masked"], result["mask_reason"]), (True, reason), value)
        for value in ("날씨", "202402", "105105", "보건업"):  # no surname / not YYMMDD
            self.assertFalse(browser.browser_pii_value("검색어", value)["value_masked"], value)

    def test_autofill_rows_mask_by_default_and_placeholders_carry_no_value(self) -> None:
        free_text = browser.browser_pii_value("내용 (사건 관련성)", "임대 계약서가 이상하다고 이야기", default_mask=True)
        self.assertEqual((free_text["value_masked"], free_text["mask_reason"]), (True, "form-input-default"))
        self.assertTrue(free_text["value_sha256"])
        placeholder = browser.browser_pii_value("달력에서 선택", "edge_default_dummy_empty_value", default_mask=True)
        self.assertTrue(placeholder["value_placeholder"])
        self.assertEqual(placeholder["mask_reason"], "browser-placeholder")
        self.assertNotIn("edge_default_dummy", placeholder["value_preview"])

    def test_address_tokens_of_unknown_types_are_masked(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            "CREATE TABLE addresses (guid TEXT, use_count INT, use_date INT, date_modified INT, label TEXT, record_type INT);"
            "CREATE TABLE address_type_tokens (guid TEXT, type INT, value TEXT);"
            "INSERT INTO addresses VALUES ('g1', 1, 1700000000, 1700000000, '', 0);"
            "INSERT INTO address_type_tokens VALUES ('g1', 109, '위례광장로 300');"
        )
        context = browser.BrowserRowContext(provider="p", user="u", browser="edge", profile="Default")
        records = browser.chromium_address_rows(context, connection, Path("Web Data"))
        fields = records[0].details["address_fields"]
        self.assertEqual(fields[0]["field_name"], "TYPE_109")
        self.assertTrue(fields[0]["value_masked"])
        self.assertNotIn("위례", json.dumps(fields, ensure_ascii=False))


# --- 2/7. timeline: Amcache inventory collapse, acquisition-anchored range -------------


class TimelineInventoryAndRangeTests(unittest.TestCase):
    def test_amcache_inventory_key_times_collapse_per_hive_section(self) -> None:
        rows = []
        for index in range(40):
            stamp = "2025-05-29T10:01:52.2703092+00:00" if index < 38 else f"2025-05-30T03:2{index - 38}:00+00:00"
            rows.append(
                {
                    "artifact_type": "amcache-driver-binary",
                    "path": "C:/e/Amcache.hve",
                    "details": {
                        "source_path": "C:/e/Amcache.hve",
                        "section": "InventoryDriverBinary",
                        "key_name": f"driver{index}.sys",
                        "key_path": f"Root\\InventoryDriverBinary\\driver{index}.sys",
                        "key_last_written_at": stamp,
                        "timestamp": stamp,
                        "timestamp_label": "last_written",
                        "driver_link_time": "2023-07-25T07:09:38+00:00",
                    },
                }
            )
        stats = TimelineStats(now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        builder = TimelineBuilder(stats)
        builder.extend(extract_artifact_events(artifacts_payload("windows-execution", rows), Path("x.json"), stats=stats))
        events = builder.events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["timestamp"], "2025-05-29T10:01:52.2703092+00:00")
        self.assertEqual(event["details"]["key_count"], 40)
        self.assertEqual(event["details"]["keys_at_timestamp"], 38)
        self.assertEqual(event["details"]["distinct_key_times"], 3)
        self.assertEqual(stats.key_level_collapsed["artifact-amcache-driver-binary-last-written"], 39)
        self.assertNotIn("driver_link_time", json.dumps([e["event_type"] for e in events]))

    def test_reference_time_falls_back_to_uncapped_acquisition_listing(self) -> None:
        start = dt.datetime(2026, 10, 14, 5, 52, tzinfo=dt.timezone.utc)
        truncated = {"summary": {"latest_mtime_epoch": 1.0e9, "truncated": True}}
        files = {
            "summary": {"time_origin": "acquisition-copy", "limit_reached": False},
            "candidates": [{"source_file_mtime": "2026-10-07T09:15:22+00:00"}],
            "inventory": [{"source_file_mtime": "2026-10-09T00:55:53.221109+00:00"}],
        }
        reference, basis = timeline_reference_time(truncated, start, files)
        self.assertEqual((reference.isoformat(), basis), ("2026-10-09T00:55:53.221109+00:00", "acquisition-listing"))
        capped = {**files, "summary": {**files["summary"], "limit_reached": True}}
        self.assertEqual(timeline_reference_time(truncated, start, capped), (start, "run-start"))
        stats = TimelineStats(now=reference, reference_basis=basis)
        self.assertEqual(stats.as_dict()["valid_range"]["max_basis"], "acquisition-listing + 1 day")


# --- 3. indicators ----------------------------------------------------------------------


class IndicatorTests(unittest.TestCase):
    def run_rows(self, rows: list[dict[str, object]], **kwargs: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            art = write_json(Path(tmp) / "a.json", artifacts_payload("eventlog", rows))
            return build_indicator_summary({"outputs": {"artifacts_eventlog": str(art)}}, max_indicators=None, **kwargs)  # type: ignore[arg-type]

    def test_url_case_is_kept_and_loopback_registrations_rejected(self) -> None:
        rows = [
            {"artifact_type": "eventlog-event", "path": "C:/e/A.evtx", "details": {"event_message": (
                "GET https://Example.COM/Download/Setup.EXE?Token=AbC then https://example.com/download/setup.exe?token=abc "
                "group http://127.0.0.1:4567:127.0.0.1/webcube/ and http://localhost:8080/x and http://[::1]/y")}},
        ]
        payload = self.run_rows(rows)
        urls = [item for item in payload["indicators"] if item["type"] == "url"]
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0]["value"], "https://Example.COM/Download/Setup.EXE?Token=AbC")
        self.assertEqual(urls[0]["value_fold"], "https://example.com/download/setup.exe?token=abc")
        self.assertEqual(urls[0]["count"], 2)
        rejected = payload["summary"]["rejected_token_counts"]
        self.assertEqual(rejected["url:malformed-netloc"], 1)
        self.assertEqual(rejected["url:loopback-host"], 1)
        self.assertEqual(url_indicator_status("https://127.0.0.1:39091:127.0.0.1/"), "malformed-netloc")
        self.assertEqual(url_indicator_status("http://[::1]:8080/y"), "loopback-host")

    def test_md5_and_sha1_rule_hashes_match_indicators(self) -> None:
        md5 = "0123456789abcdef0123456789abcdef"
        sha1 = "55efb424933087d755b18468bc574db4463d9ce6"
        with tempfile.TemporaryDirectory() as tmp:
            rules = load_rule_set(write_json(Path(tmp) / "r.json", {"rules": [
                {"id": "md5-rule", "hash": md5.upper()}, {"id": "sha1-rule", "hash": [sha1]}]}))
        rows = [{"artifact_type": "amcache-schema-row", "path": "C:/e/Amcache.hve", "details": {"sha1": sha1, "md5": md5}}]
        payload = self.run_rows(rows, rule_set=rules)
        matched = {item["type"]: item.get("matched_rules") for item in payload["indicators"]}
        self.assertEqual(matched["sha1"], ["sha1-rule"])
        self.assertEqual(matched["md5"], ["md5-rule"])


# --- 4. artifact ids ----------------------------------------------------------------------


class ArtifactIdTests(unittest.TestCase):
    @staticmethod
    def ids(rows: list[dict[str, object]]) -> list[str]:
        payload = attach_artifact_record_contracts(
            {"provider": {"name": "p"}, "artifacts": [json.loads(json.dumps(row)) for row in rows]}, kind="windows-registry", root="C:/e"
        )
        return [row["artifact_record"]["artifact_id"] for row in payload["artifacts"]]

    def test_ids_do_not_depend_on_row_position_and_twins_are_distinct(self) -> None:
        def row(name: str, index: int) -> dict[str, object]:
            return {"artifact_type": "registry-user-activity", "path": "C:/e/NTUSER.DAT",
                    "details": {"source_path": "C:/e/NTUSER.DAT", "key_path": name, "source_index": index}}

        base = [row("A", 0), row("B", 1), row("C", 2)]
        shifted = [row("X", 0), row("A", 1), row("B", 2), row("C", 3)]
        self.assertEqual(self.ids(base), self.ids(shifted)[1:])
        twins = self.ids([row("A", 0), row("A", 1), row("A", 2)])
        self.assertEqual(len(set(twins)), 3)
        self.assertEqual(twins[1], twins[0] + "-2")
        self.assertEqual(twins, self.ids([row("A", 5), row("A", 6), row("A", 7)]))
        self.assertEqual(ARTIFACT_ID_SCHEME, "content-sha256-v2")


# --- 5. warning wording / counts, synthetic-media coverage --------------------------------


class WarningLevelTests(unittest.TestCase):
    def test_step_rows_print_their_own_level_and_notices_are_not_issues(self) -> None:
        steps = [
            {"name": "artifacts-email", "warning_level": "notice", "warning_messages": ["No email artifact rows were collected."]},
            {"name": "docs", "warning_level": "warning", "warning_messages": ["문서 8건: 크기 상한 초과로 본문 미추출 (too-large)"]},
        ]
        rows = build_processing_decision_rows(steps, {})
        self.assertIn("`artifacts-email` notice: No email artifact rows were collected.", rows)
        self.assertIn("`docs` warning: 문서 8건: 크기 상한 초과로 본문 미추출 (too-large)", rows)
        warnings = [{"step": "a", "level": "notice"}, {"step": "b", "level": "warning"}, {"step": "c", "level": "notice"}]
        self.assertEqual(count_warning_levels(warnings), (1, 2))
        counts = derive_counts({"processing": {"warning_count": 3, "warnings": warnings}, "steps": [{"parser_error_count": 1}]})
        self.assertEqual((counts["validation_issues"], counts["validation_notices"]), (2, 2))

    def test_capped_synthetic_media_scan_reports_files_not_scanned(self) -> None:
        for extra, reason in (({}, "파일 수 상한 512개"), ({"scan_cap_reason": "cpu-time-budget", "scan_cpu_budget_seconds": 120.0}, "CPU 시간 예산 120초 소진")):
            stats = TimelineStats()
            stats.observe_row_truncation("synthetic-media", "synthetic-media-scan-summary", {
                "scan_capped": True, "unscanned_candidate_count": 592, "scan_file_count": 512, "skipped_oversize_count": 0,
                "max_files": 512, **extra})
            steps = [{"name": "artifacts-synthetic-media", "warning_level": "none", "warning_messages": []}]
            apply_row_truncation_warnings(
                steps, timeline_payload={"summary": {"input_row_truncation": stats.row_truncation_disclosure()}}, docs_payload={}
            )
            self.assertEqual(steps[0]["warning_messages"], [f"synthetic-media: 후보 1104개 중 592개 파일 미선별 ({reason})"])
            self.assertEqual(steps[0]["warning_level"], "warning")


# --- 6. docs: salvage scope, desktop.ini noise hint ---------------------------------------


class DocsSalvageAndNoiseTests(unittest.TestCase):
    def test_binary_salvage_only_for_container_formats(self) -> None:
        text = "정상적인 한글 문장과 English words together 123\n" * 10 + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c" * 80
        self.assertEqual(doc_text.finalize(text, method="pdf-native").status, "ok")
        for method in ("log-text", "ini-text", "xml-text", "txt-text"):
            self.assertEqual(doc_text.finalize(text, method=method).status, "binary-rejected", method)

    def test_desktop_ini_shell_class_info_hits_get_a_noise_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "desktop.ini").write_text("[.ShellClassInfo]\nIconResource=C:\\Windows\\System32\\shell32.dll,4\n", encoding="utf-8")
            (root / "notes.txt").write_text("run the shell script tomorrow", encoding="utf-8")
            payload = run_docs_search(root, ["shell"])
        by_name = {Path(str(item["path"])).name: item for item in payload["results"]}
        self.assertEqual(by_name["desktop.ini"]["noise_hint"], "shell-class-info")
        self.assertNotIn("noise_hint", by_name["notes.txt"])


# --- 8. report copy times / atime disclosure ----------------------------------------------


class ReportCopyTimeTests(unittest.TestCase):
    def test_candidates_never_print_copy_time_as_modified(self) -> None:
        items = summarize_file_candidates([
            {"path": "C:/e/a.db", "categories": ["databases"], "size": 1, "modified_at": "2026-10-09T00:55:53+00:00",
             "modified_at_origin": "acquisition-copy", "fs_modified_at": None},
            {"path": "C:/e/b.db", "categories": ["databases"], "size": 1, "modified_at": "2026-10-09T00:55:53+00:00",
             "modified_at_origin": "acquisition-copy", "fs_modified_at": "2025-01-02T03:04:05+00:00"},
        ], limit=5)
        lines: list[str] = []
        append_candidate_rows(lines, items)
        self.assertIn("수정 시각: 취득 사본(원본 아님)", lines[0])
        self.assertNotIn("2026-10-09", lines[0])
        self.assertIn("modified=2025-01-02T03:04:05+00:00", lines[1])

    def test_disclosures_explain_atime_may_reflect_tool_reads(self) -> None:
        disclosures = build_run_disclosures(
            files_payload={"summary": {"time_origin": "acquisition-copy"}}, docs_payload={}, timeline_payload={},
            indicators_payload={}, artifact_payloads={}, steps=[],
        )
        section = build_disclosure_section(disclosures)
        self.assertIn("마지막 접근 시각", section)
        self.assertIn("이 도구가 파일을 읽은 시각", section)


# --- 9. EVTX undecodable names, memory IPs, scheduler label ---------------------------------


class MinorFixTests(unittest.TestCase):
    def test_duplicated_empty_event_data_names_are_undecoded(self) -> None:
        fields, invalid, _renamed = eventlog.sanitize_event_data_keys(
            {"ageIdentifier\x00\u0d02": "KB1", "": "5064", "ErrorCode": "0x0", "_2": "Arbiter"}
        )
        self.assertEqual(list(fields), ["data_0", "data_1", "ErrorCode", "data_3"])
        self.assertEqual(invalid, ["data_0", "data_1", "data_3"])
        self.assertIn("event_data_key_status", eventlog.EVENTLOG_TRIAGE_PIVOT_KEYS)

    def test_ip_next_to_device_id_text_is_not_an_address(self) -> None:
        def utf16(text: str) -> bytes:
            return text.encode("utf-16le")

        data = b"\x00" * 16 + utf16("10.6.0.1") + b"\x00" * 8 + utf16("vid&00020b05_pid&8502") + b"\x00" * 8
        data += utf16(" connected to the update server at 192.168.0.100 ") + b"\x00" * 8
        pivots: list[dict[str, object]] = []
        memory.collect_memory_pivots(data, 0, pivots, set())
        self.assertEqual(sorted(p["value"] for p in pivots if p["type"] == "ip"), ["192.168.0.100"])

    def test_worker_limit_source_matches_cpu_worker_limit(self) -> None:
        manifest = build_parser_scheduler_manifest(kinds=["browser", "eventlog"], max_workers=2, events=[], pending_count=0)
        policy = manifest["resource_policy"]
        self.assertEqual(policy["cpu_worker_limit"], 2)
        self.assertIn("scheduled parser kinds=2", policy["worker_limit_source"])
        self.assertTrue(policy["worker_limit_source"].endswith("= 2"))
        self.assertNotIn("min(4", policy["worker_limit_source"])

    def test_case_db_links_events_through_unresolved_path_aliases(self) -> None:
        # Files rows hold resolved paths; CI temp dirs reach the same file
        # through aliases (macOS /var -> /private/var, Windows RUNNER~1).
        with tempfile.TemporaryDirectory() as tmp:
            root = (Path(tmp) / "evidence").resolve()
            (root / "Users").mkdir(parents=True)
            (root / "Users" / "notes.txt").write_text("hello", encoding="utf-8")
            database = CaseDatabase(Path(tmp) / "case.db")
            database.initialize()
            database._file_ids = {normalize_path_for_db(str(root / "Users" / "notes.txt")): 7}
            alias = str(root / "Users" / ".." / "Users" / "notes.txt")
            self.assertEqual(database._file_id_for(alias), 7)
            self.assertIsNone(database._file_id_for(str(root / "Users" / "missing.txt")))


if __name__ == "__main__":
    unittest.main()
