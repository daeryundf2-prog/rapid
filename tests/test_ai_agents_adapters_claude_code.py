"""R7 AI lane B: Claude Code adapter known answers (Q-AI1) on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters._iface import AiLimits
from rapidtriage.artifacts.ai_agents.adapters.claude_code import ClaudeCodeAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class ClaudeCodeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-cc-"))
        mf.build_all(cls.tmp, only=("claude_code",))
        cls.rows = mf.collect_rows(ClaudeCodeAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.CLAUDE_CODE_EXPECTED
        sessions = mf.by_type(self.rows, "ai-agent-session")
        self.assertEqual(len(sessions), expected["sessions"])
        self.assertEqual(sum(1 for s in sessions if s.details["parent_session_id"]), expected["subagent_sessions"])
        messages = mf.by_type(self.rows, "ai-agent-message")
        self.assertEqual(sum(1 for m in messages if m.details.get("source") != "history.jsonl"), expected["messages_session"])
        self.assertEqual(sum(1 for m in messages if m.details.get("source") == "history.jsonl"), expected["messages_history"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-tool-call")), expected["tool_calls"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-file-touch")), expected["file_touches"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-mcp-server")), expected["mcp_rows"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-credential-presence")), expected["credential_rows"])
        destructive = [r for r in mf.by_type(self.rows, "ai-agent-tool-call") if r.details["destructive"]]
        self.assertEqual(len(destructive), expected["destructive_calls"])
        summary = mf.summary_of(self.rows)
        self.assertEqual(summary["unknown_record_types"], expected["unknown_types"])

    def test_parent_child_linkage(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["sess-A:a1"]["parent_session_id"], "sess-A")
        self.assertEqual(sessions["sess-A:a2"]["parent_session_id"], "sess-A")
        self.assertTrue(sessions["sess-A:a1"]["is_subagent"])
        self.assertEqual(sessions["sess-A"]["title"], "Fix app")
        self.assertEqual(sessions["sess-A"]["tokens_in"], 150)
        self.assertEqual(sessions["sess-A"]["file_history_files"], 2)
        self.assertEqual(sessions["sess-B"]["client_versions"], ["2.1.308"])
        self.assertEqual(sessions["sess-A"]["client_versions"], ["2.1.293"])
        self.assertEqual(sessions["sess-C"]["bad_lines"], 1)

    def test_tool_calls_file_touches_and_results(self) -> None:
        calls = {r.details["call_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-tool-call")}
        self.assertEqual(calls["t1"]["tool_kind"], "shell")
        self.assertEqual(calls["t1"]["exit_code"], 0)
        self.assertGreater(calls["t1"]["result_bytes"], 0)
        self.assertEqual(calls["t2"]["tool_kind"], "edit")
        self.assertEqual(calls["t4"]["tool_kind"], "mcp")
        self.assertEqual((calls["t4"]["mcp_server"], calls["t4"]["mcp_tool"]), ("github", "create_issue"))
        self.assertTrue(calls["t5"]["destructive"])
        ops = sorted((r.details["op"], r.details["touched_path"].rsplit("\\", 1)[-1]) for r in mf.by_type(self.rows, "ai-agent-file-touch"))
        self.assertEqual(ops, [("delete", "build"), ("edit", "app.py"), ("read", ".env"), ("read", "README.md"), ("read", "proj"), ("write", "notes.md")])

    def test_mcp_account_and_sidecars(self) -> None:
        mcp = sorted((r.details["server"], r.details["status"]) for r in mf.by_type(self.rows, "ai-mcp-server"))
        self.assertEqual(mcp, [("github", "used"), ("local-fs", "configured"), ("remote", "configured"), ("srvAuth", "needs-auth"), ("srvFail", "failed"), ("srvPend", "pending")])
        remote = next(r.details for r in mf.by_type(self.rows, "ai-mcp-server") if r.details["server"] == "remote")
        self.assertTrue(remote["remote"])
        account = mf.by_type(self.rows, "ai-account")[0].details
        self.assertEqual((account["email_domain"], account["org_label"]), ("corp.example", "Corp Org"))
        cleanup = mf.by_type(self.rows, "ai-retention-cleanup")[0].details
        self.assertEqual((cleanup["cleaned_at"], cleanup["retention_days"]), ("2026-10-01T00:00:00Z", 30))
        creds = {Path(r.details["source_path"]).name: r.details for r in mf.by_type(self.rows, "ai-credential-presence")}
        self.assertEqual(set(creds), {".credentials.json", "1234.abcd.key"})
        self.assertFalse(creds[".credentials.json"]["value_collected"])
        image_message = next(r.details for r in mf.by_type(self.rows, "ai-agent-message") if r.details.get("has_image"))
        self.assertGreater(image_message["image_bytes"], 0)
        self.assertNotIn("iVBOR", json.dumps(image_message))
        history = [r.details for r in mf.by_type(self.rows, "ai-agent-message") if r.details.get("source") == "history.jsonl"]
        self.assertTrue(history[1]["has_pasted"])
        self.assertIn("[가림", history[1]["pasted_text"])

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])

    def test_caps_truncation_and_budget(self) -> None:
        rows = mf.collect_rows(ClaudeCodeAdapter, self.tmp, AiLimits(max_messages_per_session=2, max_tool_calls_per_session=1, max_message_bytes=8))
        sess = next(r.details for r in mf.by_type(rows, "ai-agent-session") if r.details["session_id"] == "sess-A")
        self.assertEqual((sess["messages"], sess["messages_emitted"], sess["messages_capped"]), (4, 2, True))
        self.assertEqual((sess["tool_calls"], sess["tool_calls_emitted"], sess["tool_calls_capped"]), (5, 1, True))
        first = next(r.details for r in mf.by_type(rows, "ai-agent-message") if r.details["session_id"] == "sess-A")
        self.assertTrue(first["truncated"])
        self.assertLessEqual(len(first["text"].encode()), 8)
        tiny = mf.collect_rows(ClaudeCodeAdapter, self.tmp, AiLimits(max_adapter_read_bytes=600))
        summary = mf.summary_of(tiny)
        self.assertTrue(summary["read_budget_exhausted"])
        self.assertLessEqual(summary["read_bytes"], 600)
        self.assertLess(len(mf.by_type(tiny, "ai-agent-session")), 5)


if __name__ == "__main__":
    unittest.main()
