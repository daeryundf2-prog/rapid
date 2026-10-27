"""R7 AI lane B: Kiro adapter known answers on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.kiro import KiroAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class KiroAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-kiro-"))
        mf.build_all(cls.tmp, only=("kiro",))
        cls.rows = mf.collect_rows(KiroAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.KIRO_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-mcp-server", "mcp_rows"),
            ("ai-credential-presence", "credential_rows"),
            ("ai-instruction-file", "instruction_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)

    def test_session_meta_and_mcp_log(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["sess_k1"]["agent_mode"], "spec")
        self.assertEqual(sessions["sess_k1"]["model"], "claude-sonnet-4")
        self.assertEqual(sessions["sess_k1"]["index_events"], 1)
        self.assertEqual(sessions["sess_k2"]["started_at"], "2026-09-02T01:00:00Z")
        mcp = {r.details["server"]: r.details for r in mf.by_type(self.rows, "ai-mcp-server")}
        self.assertEqual({k: v["status"] for k, v in mcp.items()}, {"aws-docs": "failed", "fetch": "connected"})
        # Kiro log lines have no zone: never a UTC row time, kept as wall clock.
        self.assertIsNone(mcp["fetch"]["timestamp"])
        self.assertEqual(mcp["fetch"]["timestamp_local"], "2026-08-29T01:00:01")

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
