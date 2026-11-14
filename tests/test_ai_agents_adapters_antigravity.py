"""R7 AI lane B: Antigravity adapter known answers (Q-AI4) on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.antigravity import AntigravityAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class AntigravityAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-agy-"))
        mf.build_all(cls.tmp, only=("antigravity",))
        cls.rows = mf.collect_rows(AntigravityAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.ANTIGRAVITY_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-agent-tool-call", "tool_calls"),
            ("ai-agent-file-touch", "file_touches"),
            ("ai-mcp-server", "mcp_rows"),
            ("ai-credential-presence", "credential_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["conv-1"]["steps_total"], expected["conv1_steps"])

    def test_parent_child_steps_and_blobs(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["conv-2"]["parent_session_id"], "conv-1")
        self.assertEqual(sessions["conv-2"]["nesting_depth"], 1)
        self.assertFalse(sessions["conv-1"]["step_payload_decoded"])
        self.assertGreater(sessions["conv-1"]["step_payload_bytes"], 0)
        self.assertEqual(sessions["conv-1"]["fts_chunks"], 1)
        self.assertEqual(sessions["conv-1"]["cascade_id"], "cascade-1")
        self.assertEqual(sessions["conv-2"]["transcript"], "transcript_full.jsonl")
        self.assertEqual((sessions["conv-1"]["tokens_in"], sessions["conv-1"]["tokens_out"]), (100, 50))
        self.assertTrue(sessions["conv-3"]["killed"])
        # protobuf payloads are never decoded: no step text reaches any row
        self.assertNotIn("protobuf", json.dumps([r.details for r in self.rows], default=str))

    def test_mcp_tool_calls_and_file_touches(self) -> None:
        mcp = {r.details["server"]: r.details["tools"] for r in mf.by_type(self.rows, "ai-mcp-server")}
        self.assertEqual(mcp, {"fs": ["read"], "github": ["create_issue", "list_repos"]})
        names = sorted(r.details["tool_name"] for r in mf.by_type(self.rows, "ai-agent-tool-call"))
        self.assertEqual(names, ["run_command", "view_file", "write_to_file"])
        ops = sorted(r.details["op"] for r in mf.by_type(self.rows, "ai-agent-file-touch"))
        self.assertEqual(ops, ["create", "create", "read", "workspace", "write"])
        scratch = [r.details for r in mf.by_type(self.rows, "ai-agent-file-touch") if r.details["op"] == "create"]
        self.assertTrue(all(d["exists_in_evidence"] and not d["content_collected"] for d in scratch))
        roles = sorted(r.details["role"] for r in mf.by_type(self.rows, "ai-agent-message"))
        self.assertEqual(roles, ["agent", "assistant", "user", "user"])
        summary = mf.summary_of(self.rows)
        self.assertEqual(summary["unknown_record_types"], {"FUTURE_STEP_KIND": 1})

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
