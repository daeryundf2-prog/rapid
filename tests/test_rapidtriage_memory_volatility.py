from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageMemoryVolatilityTests(unittest.TestCase):
    def test_parser_exposes_memory_volatility_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("memory-volatility", help_text)

    def test_memory_volatility_collects_process_network_and_malfind_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_volatility_fixtures(root)
            output = root / "memory-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "memory-volatility", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "memory-volatility")
            self.assertEqual(payload["provider"]["name"], "memory-volatility-artifacts")
            self.assertEqual(payload["summary"]["artifact_count"], 3)
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertEqual(artifact_types, {"memory-process", "memory-network", "memory-malfind"})

            process = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "memory-process")
            self.assertEqual(process["details"]["process_name"], "powershell.exe")
            self.assertIn("suspicious-command-line", process["details"]["risk_flags"])
            self.assertIn("sha256", process["details"]["source_hashes"])

            network = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "memory-network")
            self.assertIn("external-network-connection", network["details"]["risk_flags"])
            self.assertEqual(network["details"]["foreign_address"], "203.0.113.10:443")

            malfind = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "memory-malfind")
            self.assertIn("malfind-row", malfind["details"]["risk_flags"])
            self.assertIn("writable-executable-memory", malfind["details"]["risk_flags"])


def write_volatility_fixtures(root: Path) -> None:
    (root / "windows.pslist.json").write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "PID": 4242,
                        "PPID": 888,
                        "ImageFileName": "powershell.exe",
                        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA",
                        "Offset(V)": "0xffffaa0011223344",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "windows.netscan.jsonl").write_text(
        json.dumps(
            {
                "PID": 4242,
                "ImageFileName": "powershell.exe",
                "LocalAddr": "10.0.0.5:51512",
                "ForeignAddr": "203.0.113.10:443",
                "State": "ESTABLISHED",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "windows.malfind.json").write_text(
        json.dumps(
            [
                {
                    "PID": 4242,
                    "Process": "powershell.exe",
                    "Protection": "PAGE_EXECUTE_READWRITE",
                    "Offset": "0x000001234000",
                }
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
