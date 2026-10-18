"""R3 O2: event-log channel groups (kind summary counts, ``/tree`` nodes, server ``channel=`` filter)."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core import artifacts as core_artifacts
from rapidtriage.core.eventlog_channels import (
    CHANNEL_COUNTS_KEY,
    GROUP_LABELS,
    SCM_COUNT_KEY,
    ChannelCounter,
    channel_group,
    channel_group_nodes,
)
from rapidtriage.core.models import ArtifactRecord

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.tree import build_artifact_domain_groups
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_analyses import write_run

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

TOKEN = "channel-test-token"

# (channel, provider, artifact_type) of the synthetic eventlog kind.
ROWS = [
    ("Security", "Microsoft-Windows-Security-Auditing", "eventlog-event"),
    ("Security", "Microsoft-Windows-Security-Auditing", "eventlog-event"),
    ("Security", "Microsoft-Windows-Security-Auditing", "eventlog-detection"),
    ("System", "Service Control Manager", "eventlog-event"),
    ("System", "Microsoft-Windows-Kernel-General", "eventlog-event"),
    ("Application", "Application Error", "eventlog-event"),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", "eventlog-event"),
    ("Windows PowerShell", "PowerShell", "eventlog-event"),
    ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "eventlog-event"),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-Windows Firewall With Advanced Security", "eventlog-event"),
    ("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", "eventlog-event"),
    ("Microsoft-Windows-Storage-ClassPnP/Operational", "Microsoft-Windows-StorDiag", "eventlog-event"),
    ("Microsoft-Windows-Ntfs/Operational", "Microsoft-Windows-Ntfs", "eventlog-event"),
    ("Microsoft-Windows-UserPnp/DeviceInstall", "Microsoft-Windows-UserPnp", "eventlog-event"),
    ("OAlerts", "Microsoft Office 16 Alerts", "eventlog-event"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager", "eventlog-event"),
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "eventlog-event"),
    ("Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Bits-Client", "eventlog-event"),
    ("", "", "eventlog-file"),
    ("", "", "eventlog-summary"),
]


def record(index: int, channel: str, provider: str, artifact_type: str) -> ArtifactRecord:
    details: dict[str, object] = {"source_path": f"C:\\logs\\{index}.evtx", "event_id": str(4600 + index)}
    if channel:
        details["channel"] = channel
        details["provider_name"] = provider
    return ArtifactRecord(provider="windows-eventlog", artifact_type=artifact_type, path=f"C:\\logs\\{index}.evtx", supported=True, details=details)


class FakeEventlogCollector:
    name = "windows-eventlog"
    collector_kind = "eventlog"
    description = "synthetic event log rows"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path):
        for index, (channel, provider, artifact_type) in enumerate(ROWS):
            yield record(index, channel, provider, artifact_type)


class ChannelGroupTests(unittest.TestCase):
    def test_partition_mapping(self) -> None:
        expected = {
            "Security": "security",
            "security": "security",
            "System": "system",
            "Application": "application",
            "Windows PowerShell": "powershell",
            "Microsoft-Windows-PowerShell/Operational": "powershell",
            "PowerShellCore/Operational": "powershell",
            "Microsoft-Windows-Windows Defender/WHC": "defender",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": "firewall",
            "Microsoft-Windows-TaskScheduler/Maintenance": "task-scheduler",
            "Microsoft-Windows-Storage-ClassPnP/Operational": "storage",
            "Microsoft-Windows-Ntfs/Operational": "storage",
            "Microsoft-Windows-UserPnp/DeviceInstall": "user-pnp",
            "OAlerts": "office-alerts",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational": "rdp",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational": "rdp",
            "Microsoft-Windows-Bits-Client/Operational": "other",
            "Securityx": "other",
            "": "none",
            "   ": "none",
        }
        for channel, group in expected.items():
            self.assertEqual(channel_group(channel), group, channel)

    def test_nodes_partition_the_total_and_are_korean_sorted(self) -> None:
        counter = ChannelCounter()
        for index, item in enumerate(ROWS):
            counter.observe(record(index, *item).to_dict())
        summary = counter.summary()
        self.assertEqual(sum(summary[CHANNEL_COUNTS_KEY].values()), len(ROWS))
        self.assertEqual(summary[SCM_COUNT_KEY], 1)
        nodes = channel_group_nodes(summary[CHANNEL_COUNTS_KEY], summary[SCM_COUNT_KEY])
        by_id = {node["id"]: node for node in nodes}
        self.assertEqual(sum(node["count"] for node in nodes if node["partition"]), len(ROWS))
        self.assertEqual(by_id["security"]["count"], 3)
        self.assertEqual(by_id["security"]["channels"], ["Security"])
        self.assertEqual(by_id["powershell"]["channels"], ["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"])
        self.assertEqual(by_id["storage"]["count"], 2)
        self.assertEqual(by_id["rdp"]["count"], 2)
        self.assertEqual(by_id["services"]["count"], 1)
        self.assertFalse(by_id["services"]["partition"])
        self.assertEqual(by_id["services"]["channels"], ["System"])
        self.assertEqual(by_id["other"]["channels"], ["Microsoft-Windows-Bits-Client/Operational"])
        self.assertEqual(by_id["none"]["count"], 2)
        self.assertEqual(by_id["none"]["channels"], [])
        labels = [node["label"] for node in nodes]
        self.assertEqual(set(labels), set(GROUP_LABELS.values()))
        hangul = [label for label in labels if "\uac00" <= label[0] <= "\ud7a3"]
        self.assertEqual(labels[: len(hangul)], sorted(hangul))  # Hangul first (가나다), then Latin
        self.assertEqual(labels[len(hangul) :], ["Office Alerts", "PowerShell", "Windows Defender"])

    def test_group_without_rows_keeps_a_canonical_channel(self) -> None:
        by_id = {node["id"]: node for node in channel_group_nodes({"Security": 4})}
        self.assertEqual(by_id["office-alerts"]["count"], 0)
        self.assertEqual(by_id["office-alerts"]["channels"], ["OAlerts"])
        self.assertIsNone(by_id["services"]["count"])  # older summaries: SCM count unknown

    def test_kind_summary_counts_channels_in_memory_and_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(core_artifacts, "get_artifact_collector", return_value=FakeEventlogCollector()):
            inline = core_artifacts.run_artifact_collection(Path(tmp), kind="eventlog", use_cache=False)
            streamed = core_artifacts.run_artifact_collection(Path(tmp), kind="eventlog", records_path=Path(tmp) / "out" / "rows.jsonl")
        for payload in (inline, streamed):
            summary = payload["summary"]
            self.assertEqual(sum(summary[CHANNEL_COUNTS_KEY].values()), summary["artifact_count"])
            self.assertEqual(summary[CHANNEL_COUNTS_KEY]["Security"], 3)
            self.assertEqual(summary[CHANNEL_COUNTS_KEY][""], 2)
            self.assertEqual(summary[SCM_COUNT_KEY], 1)

    def test_other_kinds_get_no_channel_counts(self) -> None:
        other = FakeEventlogCollector()
        other.collector_kind = "windows-system"
        with tempfile.TemporaryDirectory() as tmp, patch.object(core_artifacts, "get_artifact_collector", return_value=other):
            payload = core_artifacts.run_artifact_collection(Path(tmp), kind="windows-system", use_cache=False)
        self.assertNotIn(CHANNEL_COUNTS_KEY, payload["summary"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ChannelApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        evidence = base / "evidence"
        evidence.mkdir()
        rows = [record(index, *item).to_dict() for index, item in enumerate(ROWS)]
        records = base / "eventlog.jsonl"
        records.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
        counter = ChannelCounter()
        for row in rows:
            counter.observe(row)
        system_rows = base / "system.jsonl"
        system_rows.write_text(
            json.dumps({"artifact_type": "service", "path": "C:\\svc", "details": {"channel": "Security"}}) + "\n"
            + json.dumps({"artifact_type": "service", "path": "C:\\svc2", "details": {}}) + "\n",
            encoding="utf-8",
        )
        type_counts: dict[str, int] = {}
        for _channel, _provider, artifact_type in ROWS:
            type_counts[artifact_type] = type_counts.get(artifact_type, 0) + 1
        run_dir = write_run(
            base,
            "run",
            evidence,
            extra_outputs={
                "artifacts_eventlog": {
                    "records_path": str(records),
                    "record_count": len(rows),
                    "artifacts": [],
                    "summary": {"artifact_count": len(rows), "artifact_type_counts": type_counts, **counter.summary()},
                },
                "artifacts_windows-system": {
                    "records_path": str(system_rows),
                    "record_count": 2,
                    "artifacts": [],
                    "summary": {"artifact_count": 2, "artifact_type_counts": {"service": 2}},
                },
            },
        )
        store = RunJobStore()
        self.run_id = store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.url = f"/api/runs/{self.run_id}/artifacts"

    def channels_of(self, page: dict) -> list[str]:
        return [row["details"].get("channel", "") for row in page["artifacts"]]

    def test_channel_filter_exact_and_repeatable(self) -> None:
        page = self.client.get(self.url, params={"kind": "eventlog", "channel": "Security", "limit": 50}).json()["artifacts"]["eventlog"]
        self.assertEqual(self.channels_of(page), ["Security"] * 3)
        self.assertEqual(page["matched"], 3)
        self.assertEqual(page["pagination"]["channels"], ["Security"])
        many = self.client.get(
            self.url,
            params=[("kind", "eventlog"), ("channel", "Windows PowerShell"), ("channel", "Microsoft-Windows-PowerShell/Operational"), ("limit", "50")],
        ).json()["artifacts"]["eventlog"]
        self.assertEqual(many["matched"], 2)
        # exact, case-sensitive: neither a prefix nor another case matches
        for value in ("Secur", "security", "Microsoft-Windows-PowerShell"):
            page = self.client.get(self.url, params={"kind": "eventlog", "channel": value, "limit": 50}).json()["artifacts"]["eventlog"]
            self.assertEqual(page["matched"], 0, value)

    def test_channel_composes_with_artifact_type(self) -> None:
        page = self.client.get(
            self.url, params={"kind": "eventlog", "channel": "Security", "artifact_type": "eventlog-detection", "limit": 50}
        ).json()["artifacts"]["eventlog"]
        self.assertEqual(page["matched"], 1)
        self.assertEqual(page["artifacts"][0]["record_index"], 2)

    def test_channel_across_kinds_is_safe(self) -> None:
        body = self.client.get(self.url, params={"channel": "Security", "limit": 50}).json()
        cross = body["cross_kind"]
        self.assertEqual(cross["matched"], 4)  # 3 eventlog rows + the one windows-system row with that channel
        self.assertEqual(cross["channels"], ["Security"])
        self.assertEqual(len(body["artifacts"]["windows-system"]["artifacts"]), 1)

    def test_channel_with_sort(self) -> None:
        params = {"kind": "eventlog", "channel": "System", "sort": "details.event_id:desc", "limit": 50}
        deadline = time.monotonic() + 20
        while True:
            page = self.client.get(self.url, params=params).json()["artifacts"]["eventlog"]
            if page["sort"]["status"] != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual(page["sort"]["status"], "ready")
        self.assertEqual(self.channels_of(page), ["System", "System"])
        self.assertEqual([row["details"]["event_id"] for row in page["artifacts"]], ["4604", "4603"])

    def test_bad_channel_values_are_korean_422(self) -> None:
        cases = [
            {"kind": "eventlog", "channel": "", "limit": 10},
            {"kind": "eventlog", "channel": "   ", "limit": 10},
            {"kind": "eventlog", "channel": "x" * 257, "limit": 10},
            {"kind": "eventlog", "channel": "Secu\x01rity", "limit": 10},
        ]
        for params in cases:
            response = self.client.get(self.url, params=params)
            self.assertEqual(response.status_code, 422, params)
            self.assertIn("channel", response.json()["detail"])
            self.assertRegex(response.json()["detail"], "[가-힣]")
        too_many = [("kind", "eventlog"), ("limit", "10"), *(("channel", f"C{index}") for index in range(257))]
        self.assertEqual(self.client.get(self.url, params=too_many).status_code, 422)

    def test_channel_group_filter_matches_tree_counts(self) -> None:
        tree = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        eventlog = next(
            kind
            for node in tree["nodes"]
            if node["id"] == "artifacts"
            for group in node["children"]
            for kind in group["children"]
            if kind["id"] == "artifacts:eventlog"
        )
        for group in eventlog["channel_groups"]:
            page = self.client.get(self.url, params={"kind": "eventlog", "channel_group": group["id"], "limit": 100}).json()
            kind_page = page["artifacts"]["eventlog"]
            self.assertEqual(kind_page["matched"], group["count"], group["id"])
            self.assertEqual(kind_page["pagination"]["channel_groups"], [group["id"]])
        services = self.client.get(self.url, params={"kind": "eventlog", "channel_group": "services", "limit": 10}).json()
        self.assertEqual(
            [row["details"]["provider_name"] for row in services["artifacts"]["eventlog"]["artifacts"]], ["Service Control Manager"]
        )
        # channel and channel_group are OR-ed; unknown group ids are a Korean 422
        both = self.client.get(
            self.url, params=[("kind", "eventlog"), ("channel_group", "rdp"), ("channel", "OAlerts"), ("limit", "50")]
        ).json()["artifacts"]["eventlog"]
        self.assertEqual(both["matched"], 3)
        bad = self.client.get(self.url, params={"kind": "eventlog", "channel_group": "Security", "limit": 10})
        self.assertEqual(bad.status_code, 422)
        self.assertIn("channel_group", bad.json()["detail"])
        self.assertRegex(bad.json()["detail"], "[가-힣]")

    def test_channel_requires_positive_limit(self) -> None:
        response = self.client.get(self.url, params={"kind": "eventlog", "channel": "Security", "limit": 0})
        self.assertEqual(response.status_code, 400)

    def test_tree_carries_channel_groups(self) -> None:
        tree = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        kinds = [
            kind
            for node in tree["nodes"]
            if node["id"] == "artifacts"
            for group in node["children"]
            for kind in group["children"]
            if kind["id"] == "artifacts:eventlog"
        ]
        self.assertEqual(len(kinds), 1)
        eventlog = kinds[0]
        groups = {group["id"]: group for group in eventlog["channel_groups"]}
        self.assertEqual(sum(group["count"] for group in groups.values() if group["partition"]), eventlog["count"])
        self.assertEqual(groups["security"]["count"], 3)
        self.assertEqual(groups["services"]["count"], 1)
        self.assertEqual(eventlog["channel_counts"]["Security"], 3)
        # Each group's channel list, sent back as channel=, pages exactly that group's rows.
        for group in groups.values():
            if not group["channels"] or not group["partition"]:
                continue
            params = [("kind", "eventlog"), ("limit", "100"), *(("channel", value) for value in group["channels"])]
            page = self.client.get(self.url, params=params).json()["artifacts"]["eventlog"]
            self.assertEqual(page["matched"], group["count"], group["id"])

    def test_old_outputs_have_no_channel_groups(self) -> None:
        groups = build_artifact_domain_groups({"eventlog": {"artifact_count": 2, "artifact_type_counts": {"eventlog-event": 2}}})
        self.assertNotIn("channel_groups", groups[0]["children"][0])


class ChannelReviewTests(unittest.TestCase):
    """R3 adversarial-review regressions C3, C11, C12."""

    def test_distinct_channel_names_are_capped_with_group_overflow(self) -> None:
        """C3: hostile EVTX with 5,000 distinct channels: 1,000 names kept, the rest counted per group."""
        from rapidtriage.core.eventlog_channels import (
            CHANNEL_OVERFLOW_KEY,
            CHANNEL_TRUNCATED_KEY,
            MAX_CHANNEL_NAME_CHARS,
            MAX_CHANNEL_NAMES,
        )

        counter = ChannelCounter()
        for index in range(5_000):
            counter.observe(record(index, f"Microsoft-Windows-PowerShell/Junk{index}", "x", "eventlog-event").to_dict())
        counter.observe(record(0, "Custom/" + "A" * 5_000, "x", "eventlog-event").to_dict())
        summary = counter.summary()
        self.assertEqual(len(summary[CHANNEL_COUNTS_KEY]), MAX_CHANNEL_NAMES)
        self.assertTrue(summary[CHANNEL_TRUNCATED_KEY])
        self.assertEqual(summary[CHANNEL_OVERFLOW_KEY], {"other": 1, "powershell": 5_000 - MAX_CHANNEL_NAMES})
        self.assertTrue(all(len(name) <= MAX_CHANNEL_NAME_CHARS for name in summary[CHANNEL_COUNTS_KEY]))
        nodes = {node["id"]: node for node in channel_group_nodes(summary[CHANNEL_COUNTS_KEY], 0, summary[CHANNEL_OVERFLOW_KEY])}
        self.assertEqual(nodes["powershell"]["count"], 5_000)
        self.assertEqual(sum(node["count"] for node in nodes.values() if node["partition"]), 5_001)
        self.assertNotIn(CHANNEL_TRUNCATED_KEY, ChannelCounter().summary())

    def test_channel_whitespace_round_trips(self) -> None:
        """C11: a channel stored with surrounding blanks is counted, listed and filtered stripped."""
        from rapidtriage.api.app.artifact_filter import normalize_channel_filter

        row = record(0, "  Security ", "Microsoft-Windows-Security-Auditing", "eventlog-event").to_dict()
        counter = ChannelCounter()
        counter.observe(row)
        self.assertEqual(counter.summary()[CHANNEL_COUNTS_KEY], {"Security": 1})
        channel_filter = normalize_channel_filter([" Security "])
        assert channel_filter is not None
        self.assertTrue(channel_filter.matches(row))

    def test_none_group_matches_only_eventlog_rows(self) -> None:
        """C12: 채널 없음 across kinds never matches a browser / messenger row."""
        from rapidtriage.core.eventlog_channels import ChannelFilter

        none = ChannelFilter(groups=frozenset({"none"}))
        self.assertTrue(none.matches(record(0, "", "x", "eventlog-file").to_dict()))
        self.assertFalse(none.matches({"artifact_type": "browser-history", "details": {"url": "https://example.test"}}))
        self.assertFalse(none.matches({"artifact_type": "eventlog-event", "details": {"channel": "Security"}}))


if __name__ == "__main__":
    unittest.main()
