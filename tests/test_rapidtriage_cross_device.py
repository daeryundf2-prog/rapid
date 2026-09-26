"""R4-2: cross-device IOC correlation tests."""
from __future__ import annotations

import unittest

from rapidtriage.core.cross_device import build_cross_device_ioc_package


def _entry(run_id: str, root: str, indicators: list[dict]) -> dict:
    return {"run_id": run_id, "label": root, "root": root, "indicators": indicators}


class CrossDeviceIocTests(unittest.TestCase):
    def test_shared_ioc_across_two_runs(self) -> None:
        package = build_cross_device_ioc_package(
            [
                _entry("run-a", "C:/evidence/pc1", [
                    {"type": "domain", "value": "evil.example", "count": 3, "sources": [{"path": "/browser/history"}]},
                    {"type": "sha256", "value": "aa" * 32, "count": 1, "sources": [{"path": "/files/mal.exe"}]},
                ]),
                _entry("run-b", "C:/evidence/usb1", [
                    {"type": "domain", "value": "evil.example", "count": 1, "sources": [{"path": "/logs/dns"}]},
                    {"type": "sha256", "value": "aa" * 32, "count": 2, "sources": [{"path": "/copy/mal.exe"}]},
                ]),
            ]
        )
        self.assertEqual(package["profile_version"], "cross-device-ioc-v1")
        shared = {(i["type"], i["value"]) for i in package["shared_iocs"]}
        self.assertIn(("domain", "evil.example"), shared)
        self.assertIn(("sha256", "aa" * 32), shared)
        self.assertEqual(package["summary"]["shared_ioc_count"], 2)
        self.assertEqual(package["summary"]["movement_hint_count"], 2)
        sha_hint = next(h for h in package["movement_hints"] if h["type"] == "sha256")
        self.assertEqual(sorted(sha_hint["run_ids"]), ["run-a", "run-b"])

    def test_single_run_indicator_is_not_shared(self) -> None:
        package = build_cross_device_ioc_package(
            [
                _entry("run-a", "/pc1", [{"type": "ip", "value": "10.0.0.1", "count": 1}]),
                _entry("run-b", "/usb", [{"type": "ip", "value": "192.168.0.1", "count": 1}]),
            ]
        )
        self.assertEqual(package["shared_iocs"], [])
        self.assertEqual(package["summary"]["shared_ioc_count"], 0)

    def test_device_counts_track_shared_and_unique(self) -> None:
        package = build_cross_device_ioc_package(
            [
                _entry("run-a", "/pc", [
                    {"type": "domain", "value": "shared.example", "count": 1},
                    {"type": "domain", "value": "only-a.example", "count": 1},
                ]),
                _entry("run-b", "/laptop", [
                    {"type": "domain", "value": "shared.example", "count": 2},
                    {"type": "domain", "value": "only-b.example", "count": 1},
                ]),
            ]
        )
        devices = {d["run_id"]: d for d in package["devices"]}
        self.assertEqual(devices["run-a"]["indicator_count"], 2)
        self.assertEqual(devices["run-a"]["shared_count"], 1)
        self.assertEqual(devices["run-a"]["unique_count"], 1)

    def test_sightings_keep_source_provenance(self) -> None:
        package = build_cross_device_ioc_package(
            [
                _entry("run-a", "/pc", [{"type": "hash", "value": "deadbeef", "count": 1, "sources": [{"path": "/a.exe", "artifact": "mft"}]}]),
                _entry("run-b", "/usb", [{"type": "hash", "value": "deadbeef", "count": 1, "sources": [{"path": "/b.exe"}]}]),
            ]
        )
        ioc = package["shared_iocs"][0]
        self.assertEqual(ioc["run_count"], 2)
        paths = {s["sources"][0].get("path") for s in ioc["sightings"] if s["sources"]}
        self.assertEqual(paths, {"/a.exe", "/b.exe"})

    def test_min_runs_threshold(self) -> None:
        package = build_cross_device_ioc_package(
            [
                _entry("run-a", "/a", [{"type": "domain", "value": "x.example", "count": 1}]),
                _entry("run-b", "/b", [{"type": "domain", "value": "x.example", "count": 1}]),
            ],
            min_runs=3,
        )
        self.assertEqual(package["shared_iocs"], [])

    def test_empty_runs_produce_empty_package(self) -> None:
        package = build_cross_device_ioc_package([])
        self.assertEqual(package["summary"]["run_count"], 0)
        self.assertEqual(package["shared_iocs"], [])
        self.assertIn("correlation candidates", package["report_use_boundary"])


if __name__ == "__main__":
    unittest.main()
