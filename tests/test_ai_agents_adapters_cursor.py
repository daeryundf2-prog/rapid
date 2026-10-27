"""R7 AI lane B: Cursor adapter known answers (Q-AI3) on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters._iface import AiLimits
from rapidtriage.artifacts.ai_agents.adapters.cursor import CursorAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class CursorAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-cursor-"))
        mf.build_all(cls.tmp, only=("cursor",))
        cls.rows = mf.collect_rows(CursorAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.CURSOR_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-agent-tool-call", "tool_calls"),
            ("ai-agent-file-touch", "file_touches"),
            ("ai-code-attribution", "attribution_rows"),
            ("ai-usage-stat", "usage_rows"),
            ("ai-credential-presence", "credential_rows"),
            ("ai-account", "account_rows"),
            ("ai-mcp-server", "mcp_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)
        db = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "database" and "globalStorage" in str(r.details["source_path"]))
        self.assertEqual(db["undecoded_values"], expected["undecoded_values"])
        self.assertEqual(db["kv_prefix_counts"]["bubbleId"], 5)

    def test_sessions_messages_and_roles(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["comp-2"]["parent_session_id"], "comp-1")
        self.assertTrue(sessions["comp-2"]["is_subagent"])
        self.assertEqual(sessions["comp-2"]["undecoded_bubbles"], 1)
        self.assertEqual(sessions["comp-1"]["cwd"].lower(), "c:\\users\\u1\\proj")
        roles = [r.details["role"] for r in mf.by_type(self.rows, "ai-agent-message") if r.details["session_id"] == "comp-1"]
        self.assertEqual(roles, ["user", "assistant", "assistant"])
        ops = sorted((r.details["op"], r.details["op_source"]) for r in mf.by_type(self.rows, "ai-agent-file-touch"))
        self.assertEqual(ops, [("delete", "command-heuristic"), ("edit", "codeBlockDiff"), ("edit", "tool-input")])

    def test_attribution_usage_and_secrets(self) -> None:
        commits = {r.details["commit"]: r.details for r in mf.by_type(self.rows, "ai-code-attribution") if r.details["commit"]}
        self.assertEqual(commits["c0ffee1"]["ai_percent"], 60.0)
        self.assertEqual((commits["c0ffee1"]["ai_lines"], commits["c0ffee1"]["human_lines"]), (60, 40))
        files = {r.details["file"].rsplit("\\", 1)[-1]: r.details["ai_lines"] for r in mf.by_type(self.rows, "ai-code-attribution") if r.details["file"]}
        self.assertEqual(files, {"app.py": 2, "util.py": 1})
        periods = sorted(r.details["period"] for r in mf.by_type(self.rows, "ai-usage-stat"))
        self.assertEqual(periods, ["2026-09-20", "2026-09-21"])
        creds = sorted(r.details["credential_kind"] for r in mf.by_type(self.rows, "ai-credential-presence"))
        self.assertEqual(creds, ["auth-token", "secret-storage"])
        account = mf.by_type(self.rows, "ai-account")[0].details
        self.assertEqual(account["email_domain"], "corp.example")
        browser = next(r.details for r in mf.by_type(self.rows, "ai-agent-tool-call") if r.details["tool_kind"] == "browser")
        self.assertIn("[가림]", browser["target_url"])
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])

    def test_oversized_global_db_reads_headers_only(self) -> None:
        rows = mf.collect_rows(CursorAdapter, self.tmp, AiLimits(max_sqlite_bytes=1))
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(rows, "ai-agent-session")}
        self.assertIn("comp-1", sessions)
        self.assertEqual(sessions["comp-1"]["messages"], 0)
        db = next(r.details for r in mf.by_type(rows, "ai-tool-presence") if r.details.get("meta_only"))
        self.assertIn("sqlite-over-size-cap", db["meta_only_reason"])


if __name__ == "__main__":
    unittest.main()
