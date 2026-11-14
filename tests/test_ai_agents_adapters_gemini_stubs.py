"""R7 AI lane B: Gemini CLI adapter and presence-only stubs on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.gemini_cli import GeminiCliAdapter
from rapidtriage.artifacts.ai_agents.adapters.stubs import STUB_ADAPTERS
from tests.fixtures.ai_agents import make_fixtures as mf


class GeminiCliAndStubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-gemini-"))
        mf.build_all(cls.tmp, only=("gemini_cli", "antigravity", "stubs"))
        cls.rows = mf.collect_rows(GeminiCliAdapter, cls.tmp)
        cls.stub_rows = [row for cls_ in STUB_ADAPTERS.values() for row in mf.collect_rows(cls_, cls.tmp)]

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_gemini_known_answer_counts(self) -> None:
        expected = mf.GEMINI_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-agent-tool-call", "tool_calls"),
            ("ai-agent-file-touch", "file_touches"),
            ("ai-mcp-server", "mcp_rows"),
            ("ai-credential-presence", "credential_rows"),
            ("ai-account", "account_rows"),
            ("ai-instruction-file", "instruction_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)

    def test_gemini_shares_folder_with_antigravity_and_marks_coverage(self) -> None:
        home = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "tool-home")
        self.assertEqual(home["shared_with"], ["antigravity"])
        self.assertFalse(any("conversation_summaries" in str(r.details["source_path"]) for r in self.rows))
        session = mf.by_type(self.rows, "ai-agent-session")[0].details
        self.assertEqual(session["coverage_status"], "schema-not-validated")
        self.assertEqual((session["tokens_in"], session["model"]), (10, "gemini-2.5-pro"))
        self.assertEqual(mf.by_type(self.rows, "ai-mcp-server")[0].details["transport"], "http")
        self.assertEqual(mf.by_type(self.rows, "ai-account")[0].details["email_domain"], "gmail.example")

    def test_stubs_presence_only(self) -> None:
        tools = {r.details["tool"] for r in self.stub_rows if r.artifact_type == "ai-tool-presence" and r.details["presence_kind"] == "tool-data"}
        self.assertEqual(len(tools), len(mf.STUBS_EXPECTED["tools"]))
        self.assertEqual({r.artifact_type for r in self.stub_rows}, {"ai-tool-presence", "ai-credential-presence"})
        self.assertTrue(all(r.details["coverage_status"] == "schema-not-validated" for r in self.stub_rows))
        self.assertEqual(len([r for r in self.stub_rows if r.artifact_type == "ai-credential-presence"]), mf.STUBS_EXPECTED["credential_rows"])

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows + self.stub_rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
