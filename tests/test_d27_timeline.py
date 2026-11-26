"""D27 timeline findings: time basis in same-instant merges (#1), key-row
citations across input files (#8), report time-basis statement (#11)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.run.markdown import build_disclosure_section
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    build_timeline_report,
    run_timeline,
)

STAMP = "2024-11-03T01:30:00"
PROFILE = "Users/profile/NTUSER.DAT"


def registry_timeline(directory: Path, *rows: list[dict[str, object]]) -> dict[str, object]:
    """Timeline of one synthetic windows-registry export per ``rows`` list; the root is empty."""
    root = directory / "root"
    root.mkdir()
    inputs = []
    for number, artifacts in enumerate(rows):
        target = directory / f"input{number}.json"
        target.write_text(json.dumps({"command": "artifacts", "kind": "windows-registry", "artifacts": artifacts}))
        inputs.append(target)
    return run_timeline(root=root, artifacts_inputs=inputs)


def install_state(install_date: str, last_written: str) -> dict[str, object]:
    return {
        "artifact_type": "registry-install-state",
        "path": PROFILE,
        "details": {"install_date": install_date, "key_last_written_at": last_written, "key_path": "sample"},
    }


def builder_event(timestamp: str, timezone: str, label: str) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "timestamp_kind": label,
        "timezone": timezone,
        "source": "artifacts",
        "event_type": f"artifact-sample-{label}",
        "path": PROFILE,
        "summary": label,
        "details": {"source_record": {"output": "artifacts_windows-registry", "row_index": 0}},
        "record_key": f"{PROFILE}|row=0|",
    }


def feature_usage(application: str) -> dict[str, object]:
    return {
        "artifact_type": "execution-feature-usage",
        "path": PROFILE,
        "details": {"application": application, "key_path": "sample", "key_last_written_at": STAMP + "Z"},
    }


class TimeBasisMergeTests(unittest.TestCase):
    """#1: a local-unknown wall time never absorbs a UTC instant with the same digits."""

    def test_local_install_time_and_utc_key_time_stay_two_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = registry_timeline(Path(directory), [install_state(STAMP, STAMP + "Z")])
        events = sorted(
            ([event["timestamp"], event["timezone"], event.get("labels") or [event["timestamp_kind"]]] for event in payload["events"]),
            key=lambda item: item[1],
        )
        self.assertEqual(
            events,
            [
                ["2024-11-03T01:30:00+00:00", "UTC", ["last-written"]],
                [STAMP, "local-unknown", ["installed"]],
            ],
        )

    def test_explicit_offsets_for_one_instant_still_merge(self) -> None:
        for install_date in ("2024-11-03T10:30:00+09:00", "2024-11-02T20:30:00-05:00"):
            with self.subTest(install_date=install_date), tempfile.TemporaryDirectory() as directory:
                payload = registry_timeline(Path(directory), [install_state(install_date, STAMP + "Z")])
                self.assertEqual(len(payload["events"]), 1)
                event = payload["events"][0]
                self.assertEqual((event["timestamp"], event["timezone"]), ("2024-11-03T01:30:00+00:00", "UTC"))
                self.assertEqual(sorted(event["labels"]), ["installed", "last-written"])

    def test_builder_keeps_bases_apart_in_either_order(self) -> None:
        local = (STAMP, "local-unknown", "installed")
        absolute = (STAMP + "+00:00", "UTC", "last-written")
        for first, second in ((local, absolute), (absolute, local)):
            with self.subTest(first=first[1]):
                builder = TimelineBuilder(TimelineStats())
                builder.extend([builder_event(*first), builder_event(*second)])
                self.assertEqual(
                    [(event["timestamp"], event["timezone"], event.get("labels")) for event in builder.events()],
                    [(first[0], first[1], None), (second[0], second[1], None)],
                )

    def test_builder_merges_wall_clocks_of_one_basis(self) -> None:
        builder = TimelineBuilder(TimelineStats())
        builder.extend([builder_event(STAMP, "local-unknown", "installed"), builder_event(STAMP, "local-unknown", "registered")])
        self.assertEqual([event.get("labels") for event in builder.events()], [["installed", "registered"]])

    def test_row_times_without_a_zone_repeating_a_local_field_join_it(self) -> None:
        # ``timestamp`` / ``timeline_events`` with no declared zone default to UTC; the same
        # text as a mapped local field of the row is that field republished, not a UTC instant.
        cases = {
            "undeclared": ({}, STAMP, [[STAMP, "local-unknown", ["installed", "observed", "seen"]]]),
            "declared-utc": (
                {"timestamp_timezone": "UTC"},
                STAMP,
                [[STAMP + "+00:00", "UTC", ["observed"]], [STAMP, "local-unknown", ["installed", "seen"]]],
            ),
            "explicit-offset": (
                {},
                STAMP + "Z",
                [[STAMP + "+00:00", "UTC", ["observed"]], [STAMP, "local-unknown", ["installed", "seen"]]],
            ),
        }
        for name, (extra, timestamp, expected) in cases.items():
            row = install_state(STAMP, "")
            row["details"].update(
                {"timestamp": timestamp, "timestamp_kind": "observed", "timeline_events": [{"timestamp": STAMP, "kind": "seen"}], **extra}
            )
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                payload = registry_timeline(Path(directory), [row])
                events = [
                    [event["timestamp"], event["timezone"], sorted(event.get("labels") or [event["timestamp_kind"]])]
                    for event in payload["events"]
                ]
                self.assertEqual(sorted(events, key=lambda item: item[1]), expected)


class KeyRowCitationTests(unittest.TestCase):
    """#8: each key-row citation resolves to its own input file and value."""

    def test_key_rows_from_two_files_resolve_to_their_own_rows(self) -> None:
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                root = folder / "root"
                root.mkdir()
                inputs = []
                for application in ("alpha", "beta"):
                    target = folder / f"{application}.json"
                    target.write_text(
                        json.dumps({"command": "artifacts", "kind": "windows-registry", "artifacts": [feature_usage(application)]})
                    )
                    inputs.append(target)
                if reverse:
                    inputs.reverse()
                payload = run_timeline(root=root, artifacts_inputs=inputs)
                self.assertEqual(len(payload["events"]), 1)
                details = payload["events"][0]["details"]
                self.assertEqual(details["key_row_count"], 2)
                rows = details["key_rows"]
                self.assertEqual(len({(row["input_file"], row["output"], row["row_index"]) for row in rows}), 2)
                self.assertEqual(details["source_record"]["input_file"], rows[0]["input_file"])
                for row in rows:
                    cited = json.loads(Path(row["input_file"]).read_text())["artifacts"][row["row_index"]]
                    self.assertEqual(cited["details"]["application"], row["value"])
                    self.assertEqual(Path(row["input_file"]).stem, row["value"])
                self.assertEqual([row["value"] for row in rows], [Path(path).stem for path in inputs])


class ReportTimeBasisTests(unittest.TestCase):
    """#11: the report header, the disclosure and every row agree about offsets."""

    def test_header_disclosure_and_rows_agree(self) -> None:
        cases = {
            "local-only": ([install_state(STAMP, "")], 0, 1, "local-wall-clock"),
            "utc-only": ([feature_usage("alpha")], 1, 0, "UTC"),
            "mixed": ([install_state(STAMP, STAMP + "Z")], 1, 1, "UTC+local-wall-clock"),
        }
        for name, (rows, utc, local, storage) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                payload = registry_timeline(Path(directory), rows)
                report = build_timeline_report(payload)
                disclosure = payload["summary"]["timezone"]
                self.assertEqual(
                    (disclosure["storage"], disclosure["utc_event_count"], disclosure["local_wall_clock_event_count"]),
                    (storage, utc, local),
                )
                self.assertEqual(disclosure["local_wall_clock_by_timezone"], {"local-unknown": local} if local else {})
                self.assertNotIn("모든 이벤트 시각은 UTC", report)
                self.assertNotIn("모든 이벤트 시각은 UTC", disclosure["note"])
                header = next(line for line in report.splitlines() if line.startswith("- 저장 시간대:"))
                self.assertEqual(f"UTC ISO 8601(+00:00) {utc}건" in header, bool(utc), header)
                self.assertEqual(f"오프셋 없는 현지 벽시계 시각 {local}건" in header, bool(local), header)
                self.assertEqual("UTC 아님" in disclosure["note"], bool(local))
                self.assertIn(f"- 시간대 미확정 이벤트: {local}건", report)
                timeline = report.split("## Timeline", 1)[1].splitlines()
                event_lines = [line for line in timeline if line.startswith("- `")]
                self.assertEqual(len(event_lines), utc + local)
                for line in event_lines:
                    offset_free = line.startswith(f"- `{STAMP}`")
                    self.assertEqual("timezone=local-unknown (시간대 미확정" in line, offset_free, line)
                    self.assertEqual(line.startswith(f"- `{STAMP}+00:00`"), not offset_free, line)
                section = build_disclosure_section({"timezone": disclosure})
                self.assertIn("오프셋이 확인된 시각은 UTC (ISO 8601, +00:00)", section)
                self.assertEqual(f"현지 벽시계 시각 {local}건" in section, bool(local), section)


if __name__ == "__main__":
    unittest.main()
