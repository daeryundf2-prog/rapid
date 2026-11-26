"""D27 timeline findings: time basis in same-instant merges (#1)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.timeline import TimelineBuilder, TimelineStats, run_timeline

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


if __name__ == "__main__":
    unittest.main()
