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
            self.assertEqual(process["details"]["process_key"], "4242:powershell.exe")
            self.assertEqual(process["details"]["parent_process_key"], "888")
            self.assertIn("encoded-command", process["details"]["command_line_indicators"])
            self.assertIn("suspicious-command-line", process["details"]["risk_flags"])
            self.assertIn("sha256", process["details"]["source_hashes"])

            network = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "memory-network")
            self.assertIn("external-network-connection", network["details"]["risk_flags"])
            self.assertEqual(network["details"]["foreign_address"], "203.0.113.10:443")

            malfind = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "memory-malfind")
            self.assertIn("malfind-row", malfind["details"]["risk_flags"])
            self.assertIn("writable-executable-memory", malfind["details"]["risk_flags"])

    def test_memory_dump_scan_finds_bitlocker_and_network_pivots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            key = "000000-000011-000022-000033-000044-000055-000066-000077"
            (root / "incident.raw").write_bytes(
                b"RAM\x00"
                + key.encode("ascii")
                + b"\x00powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA\x00https://c2.example.test/task\x00198.51.100.44"
            )
            (root / "Cache0000.bin").write_bytes(b"BM not a memory dump")
            output = root / "memory-dump-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "memory-volatility", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["artifact_count"], 1)
            artifact = payload["artifacts"][0]
            self.assertEqual(artifact["artifact_type"], "memory-dump-indicators")
            details = artifact["details"]
            self.assertIn("bitlocker-recovery-key-validated", details["risk_flags"])
            self.assertIn("process-string-candidate", details["risk_flags"])
            self.assertIn("suspicious-memory-string", details["risk_flags"])
            self.assertIn("network-indicator", details["risk_flags"])
            pivots = details["indicator_pivots"]
            self.assertTrue(any(pivot["type"] == "bitlocker-recovery-key" for pivot in pivots))
            self.assertTrue(any(pivot["type"] == "process-candidate" for pivot in pivots))
            self.assertTrue(any(pivot.get("value") == "https://c2.example.test/task" for pivot in pivots))
            self.assertTrue(any(pivot.get("value") == "198.51.100.44" for pivot in pivots))
            key_pivot = next(pivot for pivot in pivots if pivot["type"] == "bitlocker-recovery-key")
            self.assertEqual(key_pivot["value_redacted"], "000000-***-000077")
            self.assertEqual(key_pivot["validation"]["status"], "valid")
            process_pivot = next(pivot for pivot in pivots if pivot["type"] == "process-candidate")
            self.assertEqual(process_pivot["value"]["process_name"], "powershell.exe")
            self.assertIn("encoded-command", process_pivot["value"]["command_line_indicators"])
            self.assertNotIn(key, json.dumps(payload))

    def test_disk_memory_files_and_crash_dumps_are_scanned_as_visible_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "pagefile.sys").write_bytes(
                b"Chrome Incognito page cache "
                b"https://www.google.com/search?q=secret+plan "
                b"https://chatgpt.com/c/abc123 powershell.exe -enc AAAA"
            )
            (root / "MEMORY.DMP").write_bytes(b"crash dump cmd.exe /c whoami 203.0.113.77")
            output = root / "memory-disk-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "memory-volatility", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertIn("disk-memory-file-indicators", artifact_types)
            self.assertIn("crash-dump-indicators", artifact_types)

            pagefile = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "disk-memory-file-indicators"
            )
            self.assertEqual(pagefile["details"]["memory_file_kind"], "pagefile")
            self.assertIn("network-indicator", pagefile["details"]["risk_flags"])
            self.assertIn("private-browsing-url-candidate", pagefile["details"]["risk_flags"])
            self.assertIn("ai-service-url-candidate", pagefile["details"]["risk_flags"])
            self.assertIn("search-query-url-candidate", pagefile["details"]["risk_flags"])
            self.assertTrue(
                any(pivot.get("value") == "https://www.google.com/search?q=secret+plan" for pivot in pagefile["details"]["indicator_pivots"])
            )
            web_profile = pagefile["details"]["web_recovery_profile"]
            self.assertEqual(web_profile["profile_version"], "memory-web-recovery-profile-v1")
            self.assertEqual(web_profile["private_browsing_candidate_count"], 2)
            self.assertEqual(web_profile["ai_service_candidate_count"], 1)
            self.assertEqual(web_profile["search_query_candidate_count"], 1)
            self.assertIn("ChatGPT", web_profile["ai_services"])
            self.assertEqual(web_profile["query_term_samples"][0]["value_preview"], "secret plan")
            google_pivot = next(
                pivot for pivot in pagefile["details"]["indicator_pivots"] if "google.com/search" in str(pivot.get("value"))
            )
            self.assertIn("private-browsing-context", google_pivot["classification"]["categories"])
            self.assertIn("search-query", google_pivot["classification"]["categories"])

            crash = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "crash-dump-indicators")
            self.assertEqual(crash["details"]["memory_file_kind"], "crash-dump")
            self.assertIn("process-string-candidate", crash["details"]["risk_flags"])


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
