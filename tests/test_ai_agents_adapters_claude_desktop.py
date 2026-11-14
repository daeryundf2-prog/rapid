"""R7 AI lane B: Claude desktop and claude-swap adapters (S2 personal/corporate accounts) on
SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.claude_desktop import ClaudeDesktopAdapter
from rapidtriage.artifacts.ai_agents.adapters.claude_swap import ClaudeSwapAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class ClaudeDesktopAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-cdesk-"))
        mf.build_all(cls.tmp, only=("claude_desktop", "claude_swap"))
        cls.rows = mf.collect_rows(ClaudeDesktopAdapter, cls.tmp)
        cls.swap = mf.collect_rows(ClaudeSwapAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_desktop_known_answer_counts(self) -> None:
        expected = mf.CLAUDE_DESKTOP_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-account", "account_rows"),
            ("ai-mcp-server", "mcp_rows"),
            ("ai-credential-presence", "credential_rows"),
            ("ai-usage-stat", "usage_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)

    def test_desktop_links_accounts_and_logs(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["local_s1"]["linked_session_id"], "sess-A")
        self.assertEqual(sessions["local_s1"]["turns"], 5)
        self.assertEqual(sessions["local_s1"]["client_versions"], ["2.1.304"])
        accounts = sorted((r.details["sessions"], r.details["tool_account_key"].startswith("claude-acct-")) for r in mf.by_type(self.rows, "ai-account"))
        self.assertEqual(accounts, [(1, True), (2, True)])
        self.assertTrue(all("acct-uuid" not in r.details["tool_account_key"] for r in mf.by_type(self.rows, "ai-account")))
        mcp = sorted((r.details["server"], r.details["status"]) for r in mf.by_type(self.rows, "ai-mcp-server"))
        self.assertEqual(mcp, [("fs", "configured"), ("fs", "connected"), ("remote-x", "disconnected")])
        usage = mf.by_type(self.rows, "ai-usage-stat")[0].details
        self.assertEqual((usage["samples"], usage["max_plan_utilization"]), (2, 0.6))
        kinds = {r.details["presence_kind"] for r in mf.by_type(self.rows, "ai-tool-presence")}
        self.assertTrue({"browser-extension-native-host", "msix-package", "app-log"} <= kinds)

    def test_swap_accounts_and_switches(self) -> None:
        expected = mf.CLAUDE_SWAP_EXPECTED
        accounts = [r.details for r in mf.by_type(self.swap, "ai-account")]
        self.assertEqual(len(accounts), expected["account_rows"])
        self.assertEqual(sorted((a["org_label"], a["email_domain"], a["active"]) for a in accounts), [("Corp Org", "corp.example", False), ("Personal", "gmail.example", True)])
        switches = [r.details for r in mf.by_type(self.swap, "ai-account-switch")]
        self.assertEqual(len(switches), expected["switch_rows"])
        self.assertEqual((switches[0]["from_account"], switches[0]["to_account"]), ("swap-1", "swap-2"))
        self.assertEqual(switches[1]["to_account"], "swap-2")
        self.assertEqual(switches[0]["timestamp_kind"], "switched")
        self.assertEqual(len(mf.by_type(self.swap, "ai-credential-presence")), expected["credential_rows"])

    def test_no_secret_or_email_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows + self.swap], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
