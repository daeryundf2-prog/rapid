"""R7 AI lane B: OmO adapter known answers on SYNTHETIC fixtures only."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.omo import OmoAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class OmoAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-omo-"))
        mf.build_all(cls.tmp, only=("omo",))
        cls.rows = mf.collect_rows(OmoAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.OMO_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-agent-tool-call", "tool_calls"),
            ("ai-agent-file-touch", "file_touches"),
            ("ai-instruction-file", "instruction_rows"),
            ("ai-credential-presence", "credential_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)

    def test_sessions_ulw_and_config(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["0000-uuid1"]["project_label"], "C--Users-u1-proj")
        self.assertEqual(sessions["0000-uuid1"]["started_at"], "2026-10-09T01:02:03.456Z")
        self.assertEqual(sessions["ulw:run1"]["title"], "ship it")
        self.assertEqual(sessions["ulw:run1"]["ended_at"], "2026-10-09T04:00:00Z")
        call = mf.by_type(self.rows, "ai-agent-tool-call")[0].details
        self.assertTrue(call["destructive"])
        self.assertEqual(mf.by_type(self.rows, "ai-agent-file-touch")[0].details["op"], "delete")
        settings = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "settings")
        self.assertFalse(settings["content_collected"])
        self.assertEqual(settings["backup_copies"], 1)
        home = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "tool-home")
        self.assertEqual(home["version"], "5.1.28")

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
