"""D22 adversarial review regressions (synthetic fixtures only).

* #2  a bookmark's submission pointer is re-resolved by its row digest after the
      timeline is regenerated (a #52 note never cites #41).
* #4  a browser comparison does not pass while the acquisition is unnamed.
* #6  file names that differ by a backtick print differently in every report format.
* #7  an explicit evidence zone converts transition-day wall clocks by round trip.
* #11 two correct browser acquisitions compared together do not cross their paths.
* #14 a JSON web access time without an offset is not assumed to be UTC.
* #18 a PCA message longer than the field bound states its truncation and length.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

from rapidtriage.artifacts.windows import browser, system
from rapidtriage.artifacts.windows.pca import (
    MAX_PCA_MESSAGE_CHARS,
    collect_pca_text_files,
)
from rapidtriage.cli import main
from rapidtriage.core.case import (
    create_or_update_case_payload,
    save_case_payload,
    source_row_sha256,
)
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    write_case_report_exports,
)
from rapidtriage.core.report_markdown import (
    inline_segments,
    markdown_code,
    markdown_text,
)
from rapidtriage.core.submission import build_submission_manifest
from rapidtriage.core.timeline import run_timeline, write_timeline_result
from rapidtriage.core.timeline_export import build_unified_timeline_export
from tests.test_d12_eventlog import START, collect, session_event
from tests.test_d14_artefacts import build_wal_only_history
from tests.test_d16_run import browser_aggregate
from tests.test_d16_time import BookmarkRowIdentityTests, _write_evtx
from tests.test_parser_quality_eventlog import filetime


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BookmarkPointerReresolutionTests(unittest.TestCase):
    """#2: the submission cites the bookmarked row, found by its digest, or withholds it."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        fixture = BookmarkRowIdentityTests()
        self.timeline = fixture._timeline(self.root)
        pointer = fixture._pointers(self.timeline)["52"]
        self.case = create_or_update_case_payload(
            self.root / "case.json",
            source_path=self.timeline,
            source_pointer=pointer,
            note="review-52",
            include_in_report=True,
        )
        save_case_payload(self.root / "case.json", self.case)
        self.saved = self.case["bookmarks"][0]["reference"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def cited_row(self, manifest: dict) -> dict:
        reference = manifest["items"][0]["reference"]
        events = json.loads(Path(reference["file"]).read_text(encoding="utf-8"))["events"]
        return events[int(reference["pointer"].rsplit("/", 1)[-1])]

    def regenerate(self, *, extra_artifacts: list[Path] = (), files: Path | None = None) -> None:
        payload = run_timeline(
            root=self.root,
            files_inputs=[files or self.root / "files.json"],
            docs_inputs=[self.root / "docs.json"],
            artifacts_inputs=[self.root / "artifacts.json", *extra_artifacts],
        )
        write_timeline_result(payload, self.timeline)

    def test_unchanged_timeline_keeps_and_verifies_the_pointer(self) -> None:
        manifest = build_submission_manifest(self.case, allowed_roots=[self.root])
        item = manifest["items"][0]
        self.assertEqual(item["reference"]["pointer"], self.saved["pointer"])
        self.assertEqual(item["reference"]["row_verification"]["status"], "verified")
        self.assertEqual(self.cited_row(manifest)["details"]["record_id"], "52")

    def test_earlier_event_added_still_cites_52(self) -> None:
        more = self.root / "additional"
        more.mkdir()
        _write_evtx(more, [session_event(41, 4624, filetime(START - timedelta(hours=1), 0), user="Synthetic")])
        additional = self.root / "additional.json"
        additional.write_text(
            json.dumps({"command": "artifacts", "kind": "eventlog", "artifacts": [row.to_dict() for row in collect(more)]}),
            encoding="utf-8",
        )
        self.regenerate(extra_artifacts=[additional])
        manifest = build_submission_manifest(self.case, allowed_roots=[self.root])
        self.assertEqual(manifest["summary"]["skipped_count"], 0)
        item = manifest["items"][0]
        row = self.cited_row(manifest)
        self.assertEqual(item["note"], "review-52")
        self.assertEqual(row["details"]["record_id"], "52")
        self.assertEqual(source_row_sha256(row), self.saved["row_sha256"])
        self.assertNotEqual(item["reference"]["pointer"], self.saved["pointer"])
        self.assertEqual(
            item["reference"]["row_verification"],
            {"status": "pointer-corrected", "row_sha256_matches": True, "saved_pointer": self.saved["pointer"]},
        )
        self.assertEqual(item["evidence"]["hashes"]["sha256"], sha256_file(self.root / "events.evtx"))

    def test_earlier_file_event_added_still_cites_52(self) -> None:
        files = self.root / "early-files.json"
        files.write_text(
            json.dumps({"command": "files", "candidates": [{"path": "early.txt", "fs_modified_at": "2023-12-31T00:00:00Z"}]}),
            encoding="utf-8",
        )
        self.regenerate(files=files)
        manifest = build_submission_manifest(self.case, allowed_roots=[self.root])
        row = self.cited_row(manifest)
        self.assertEqual(row["details"]["record_id"], "52")
        self.assertEqual(source_row_sha256(row), self.saved["row_sha256"])

    def test_row_gone_from_regenerated_timeline_is_withheld(self) -> None:
        empty = self.root / "empty-artifacts.json"
        empty.write_text(json.dumps({"command": "artifacts", "kind": "eventlog", "artifacts": []}), encoding="utf-8")
        payload = run_timeline(
            root=self.root,
            files_inputs=[self.root / "files.json"],
            docs_inputs=[self.root / "docs.json"],
            artifacts_inputs=[empty],
        )
        write_timeline_result(payload, self.timeline)
        manifest = build_submission_manifest(self.case, allowed_roots=[self.root])
        self.assertEqual(manifest["items"], [])
        self.assertEqual([item["reason"] for item in manifest["skipped"]], ["reference-row-not-found"])

    def test_row_present_twice_is_withheld_as_ambiguous(self) -> None:
        document = json.loads(self.timeline.read_text(encoding="utf-8"))
        target = next(event for event in document["events"] if event["details"].get("record_id") == "52")
        others = [event for event in document["events"] if event is not target]
        document["events"] = [*others, target, dict(target)]
        self.timeline.write_text(json.dumps(document), encoding="utf-8")
        manifest = build_submission_manifest(self.case, allowed_roots=[self.root])
        self.assertEqual([item["reason"] for item in manifest["skipped"]], ["reference-row-ambiguous"])


class BrowserAcquisitionVerdictTests(unittest.TestCase):
    """#4 and #11: acquisition identity decides the verdict and pairs repeated rows."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        seeds = []
        for number in range(2):
            context = base / f"seed-{number}"
            context.mkdir()
            build_wal_only_history(context, ("profile-a",))
            database = next((context / "inputs").rglob("History"))
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE sample_revision (revision INTEGER)")
                connection.execute("INSERT INTO sample_revision VALUES (?)", (number,))
                connection.commit()
            seeds.append((sha256_file(database), context / "inputs"))
        # Folder labels sort opposite to the database checksums: ordering each side
        # on its own (rapid by hash, reference by path) would cross the pairs.
        cls.rapid: list[dict] = []
        cls.reference: list[dict] = []
        for label, (digest, inputs) in zip(("alpha", "beta"), sorted(seeds, reverse=True)):
            local = base / label
            shutil.copytree(inputs, local)
            cls.rapid.append(browser_aggregate(local)["unified_timeline"][0])
            database = next(local.rglob("History"))
            with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as connection:
                row_id, url, title, visits, stamp = connection.execute(
                    "SELECT id, url, title, visit_count, last_visit_time FROM urls"
                ).fetchone()
            cls.reference.append(
                {
                    "user": "profile-a",
                    "browser": "chrome",
                    "profile": "Default",
                    "timeline_type": "visit",
                    "timestamp": (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=stamp)).isoformat(),
                    "title": title,
                    "url": url,
                    "visit_count": visits,
                    "source_table": "urls",
                    # Resolved like the collector's path (Windows temp dirs use 8.3 short names).
                    "source_path": str(database.resolve()),
                    "source_row_id": row_id,
                    "source_sha256": digest,
                }
            )
        cls.path_only = [{k: v for k, v in row.items() if k != "source_sha256"} for row in cls.reference]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def diff(self, rapid: list[dict], trusted: list[dict]) -> dict:
        return browser.build_browser_timeline_trusted_diff(rapid, trusted, trusted_tool="sqlite")

    def test_two_correct_acquisitions_pass_by_path_and_by_hash_in_either_order(self) -> None:
        for label, trusted in (
            ("path", self.path_only),
            ("path reversed", self.path_only[::-1]),
            ("hash", self.reference),
            ("hash reversed", self.reference[::-1]),
        ):
            with self.subTest(label):
                result = self.diff(self.rapid, trusted)
                self.assertEqual((result["status"], result["matched_count"]), ("pass", 2))
                self.assertTrue(result["commercial_grade_evidence"])
                self.assertEqual(result["mismatches"], [])

    def test_one_acquisition_twice_still_fails_against_both(self) -> None:
        for trusted in (self.path_only, self.reference):
            result = self.diff([self.rapid[0], self.rapid[0]], trusted)
            self.assertEqual(result["status"], "diffs-present")
            self.assertFalse(result["commercial_grade_evidence"])

    def test_reference_row_without_acquisition_is_unresolved_not_pass(self) -> None:
        unnamed = {k: v for k, v in self.path_only[0].items() if k != "source_path"}
        result = self.diff(self.rapid[:1], [unnamed])
        self.assertEqual(result["status"], "acquisition-identity-unresolved")
        self.assertFalse(result["commercial_grade_evidence"])
        self.assertEqual(result["acquisition_identity"]["unresolved_count"], 1)
        self.assertIn("browser-acquisition-identity-unresolved", result["reportability_decision"]["blockers"])
        named = self.diff(self.rapid[:1], self.path_only[:1])
        self.assertEqual((named["status"], named["commercial_grade_evidence"]), ("pass", True))


class _ListItems(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[str] = []
        self.current: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "li":
            self.current = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "li" and self.current is not None:
            self.items.append("".join(self.current))
            self.current = None

    def handle_data(self, data: str) -> None:
        if self.current is not None:
            self.current.append(data)


class ReportFileNameEncodingTests(unittest.TestCase):
    """#6: names differing by a backtick (or other markup) stay distinct in every format."""

    # `*` and `\` are not allowed in Windows file names; the encoder test below still covers them.
    NAMES = ("sample-a.txt", "sample`-a.txt", "``x`` .txt", "end`.txt", "_x_.txt") + (
        () if os.name == "nt" else ("sample**b**.txt", "end\\`.txt")
    )

    def test_names_survive_markdown_html_docx_and_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            evidence = base / "evidence"
            evidence.mkdir()
            for number, name in enumerate(self.NAMES):
                (evidence / name).write_text(str(number), encoding="utf-8")
            files = base / "files.json"
            self.assertEqual(main(["files", str(evidence), "--output", str(files)]), 0)
            count = len(json.loads(files.read_text(encoding="utf-8"))["candidates"])
            self.assertEqual(count, len(self.NAMES))
            for index in range(count):
                case = create_or_update_case_payload(
                    base / "case.json", source_path=files, source_pointer=f"/candidates/{index}", include_in_report=True
                )
                save_case_payload(base / "case.json", case)
            manifest = build_submission_manifest(case, allowed_roots=[evidence])
            expected = {item["evidence"]["name"]: item["evidence"]["hashes"]["sha256"] for item in manifest["items"]}
            self.assertEqual(sorted(expected), sorted(self.NAMES))
            for name, digest in expected.items():
                self.assertEqual(digest, sha256_file(evidence / name))
            outputs = write_case_report_exports(
                build_case_report_markdown(run_summary={}, case_payload=case, submission_manifest=manifest),
                base / "report.md",
            )

            def names(lines: list[str]) -> list[str]:
                return sorted(line.split("파일명:", 1)[1].strip() for line in lines if "파일명:" in line)

            html = _ListItems()
            html.feed(Path(outputs["html"]).read_text(encoding="utf-8"))
            with ZipFile(outputs["docx"]) as archive:
                paragraphs = ElementTree.fromstring(archive.read("word/document.xml")).findall(".//{*}p")
                docx = ["".join(paragraph.itertext()) for paragraph in paragraphs]
            pdf = [
                bytes.fromhex(chunk.decode()).decode("utf-16-be")
                for chunk in re.findall(rb"<([A-F0-9]+)> Tj", Path(outputs["pdf"]).read_bytes())
            ]
            for label, lines in (("html", html.items), ("docx", docx), ("pdf", pdf)):
                with self.subTest(label):
                    self.assertEqual(names(lines), sorted(self.NAMES))

    def test_encoders_round_trip_through_the_reader(self) -> None:
        for value in [*self.NAMES, "", " padded ", "C:\\$Recycle.Bin\\S-1", "a*b", "back\\", "tab\there"]:
            with self.subTest(value=value):
                code = "".join(text for _kind, text in inline_segments(markdown_code(value)))
                self.assertEqual(code, value.replace("\t", "\u2409"))
                self.assertEqual("".join(text for _kind, text in inline_segments(markdown_text(value))), value)


class EvidenceZoneTransitionTests(unittest.TestCase):
    """#7: New York 2024 transition days under ``assume_local_timezone``."""

    STAMPS = (
        "2024-03-10T01:30:00",
        "2024-03-10T02:30:00",
        "2024-03-10T03:30:00",
        "2024-03-11T03:30:00",
        "2024-11-03T01:30:00",
    )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        timeline = base / "timeline.json"
        timeline.write_text(
            json.dumps({"events": [{"timestamp": stamp, "timezone": "local-unknown", "event_type": "registry-profile"} for stamp in self.STAMPS]}),
            encoding="utf-8",
        )
        self.summary = base / "summary.json"
        self.summary.write_text(json.dumps({"outputs": {"timeline": str(timeline)}}), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def export(self, **options: str) -> dict:
        return build_unified_timeline_export(self.summary, assume_local_timezone="America/New_York", **options)

    def test_each_wall_clock_gets_its_round_trip_instants(self) -> None:
        rows = {row["timestamp"]: row for row in self.export()["events"]}
        self.assertEqual(rows["2024-03-10T01:30:00"]["assumed_utc"], "2024-03-10T06:30:00.0000000Z")
        self.assertEqual(rows["2024-03-10T03:30:00"]["assumed_utc"], "2024-03-10T07:30:00.0000000Z")
        self.assertEqual(rows["2024-03-11T03:30:00"]["assumed_utc"], "2024-03-11T07:30:00.0000000Z")
        gap = rows["2024-03-10T02:30:00"]
        self.assertNotIn("assumed_utc", gap)
        self.assertEqual(gap["assumed_utc_status"], "nonexistent-local-time")
        repeated = rows["2024-11-03T01:30:00"]
        self.assertNotIn("assumed_utc", repeated)
        self.assertEqual(repeated["assumed_utc_status"], "ambiguous-repeated-local-time")
        self.assertEqual(
            repeated["assumed_utc_candidates"], ["2024-11-03T05:30:00.0000000Z", "2024-11-03T06:30:00.0000000Z"]
        )

    def test_exact_utc_ranges_decide_only_on_valid_instants(self) -> None:
        at_0730 = self.export(start="2024-03-10T07:30:00Z", end="2024-03-10T07:30:00Z")
        self.assertEqual([row["timestamp"] for row in at_0730["events"]], ["2024-03-10T03:30:00"])
        self.assertIn("2024-03-10T02:30:00", [row["timestamp"] for row in at_0730["zone_undetermined_events"]])
        for instant in ("2024-11-03T05:30:00Z", "2024-11-03T06:30:00Z"):
            with self.subTest(instant):
                exact = self.export(start=instant, end=instant)
                self.assertEqual(exact["events"], [])
                self.assertEqual([row["timestamp"] for row in exact["zone_undetermined_events"]], ["2024-11-03T01:30:00"])
        both = self.export(start="2024-11-03T05:00:00Z", end="2024-11-03T07:00:00Z")
        self.assertEqual([row["timestamp"] for row in both["events"]], ["2024-11-03T01:30:00"])


class JsonWebAccessZoneTests(unittest.TestCase):
    """#14: only records that state an offset are converted to UTC."""

    def test_offsetless_json_time_stays_local_and_undetermined(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "nginx"
            source.mkdir()
            for name, stamp in (
                ("explicit_utc", "2024-01-01T09:00:00Z"),
                ("explicit_offset", "2024-01-01T09:00:00+09:00"),
                ("unspecified", "2024-01-01T09:00:00"),
            ):
                (source / f"{name}.log").write_text(
                    json.dumps({"time": stamp, "method": "GET", "uri": "/manual", "status": 200}) + "\n", encoding="utf-8"
                )
            samples = {
                Path(record.path).stem: record.details["parsed_log"]["timeline_samples"][0]
                for record in system.collect_webshell_and_server_log_artifacts(base)
            }
        self.assertEqual(samples["explicit_utc"]["normalized_time"], "2024-01-01T09:00:00+00:00")
        self.assertEqual(samples["explicit_offset"]["normalized_time"], "2024-01-01T00:00:00+00:00")
        unspecified = samples["unspecified"]
        self.assertIsNone(unspecified["normalized_time"])
        self.assertEqual(unspecified["local_time"], "2024-01-01T09:00:00")
        self.assertEqual(unspecified["timezone"], "local-unknown")
        self.assertEqual(unspecified["time_parse_status"], "json-iso8601-zone-undetermined")


class PcaMessageBoundTests(unittest.TestCase):
    """#18: the message field is either whole or explicitly marked with its full length."""

    def test_message_lengths_around_the_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "Windows" / "appcompat" / "pca" / "PcaGeneralDb0.txt"
            path.parent.mkdir(parents=True)
            lengths = (999, 1000, 1001, 1024)
            messages = ["x" * (length - 3) + "END" for length in lengths]
            lines = [rf"2024-03-01 01:02:03.1234567|2|C:\sample\reader.exe|Sample|||id|{message}" for message in messages]
            path.write_text("\r\n".join(lines), encoding="utf-16")
            rows = sorted(
                (record.details for record in collect_pca_text_files(root, "windows")),
                key=lambda details: details["source_line"],
            )
        self.assertEqual(len(rows), 4)
        for details, message in zip(rows, messages):
            with self.subTest(length=len(message)):
                truncated = len(message) > MAX_PCA_MESSAGE_CHARS
                self.assertEqual(details["message_length"], len(message))
                self.assertEqual(details["message_truncated"], truncated)
                self.assertEqual(details["message_sha256"], hashlib.sha256(message.encode("utf-8")).hexdigest())
                self.assertEqual(details["message"], message[:MAX_PCA_MESSAGE_CHARS])
                self.assertEqual(details["message"].endswith("END"), not truncated)


if __name__ == "__main__":
    unittest.main()
