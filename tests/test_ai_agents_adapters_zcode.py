"""R7 AI lane B: ZCode adapter known answers (Q-AI5 destructive tool calls) on SYNTHETIC fixtures."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters.zcode import ZcodeAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


class ZcodeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-zcode-"))
        mf.build_all(cls.tmp, only=("zcode",))
        cls.rows = mf.collect_rows(ZcodeAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.ZCODE_EXPECTED
        for artifact_type, key in (
            ("ai-agent-session", "sessions"),
            ("ai-agent-message", "messages"),
            ("ai-agent-tool-call", "tool_calls"),
            ("ai-agent-file-touch", "file_touches"),
            ("ai-usage-stat", "usage_rows"),
            ("ai-credential-presence", "credential_rows"),
        ):
            self.assertEqual(len(mf.by_type(self.rows, artifact_type)), expected[key], artifact_type)
        destructive = [r.details for r in mf.by_type(self.rows, "ai-agent-tool-call") if r.details["destructive"]]
        self.assertEqual(len(destructive), expected["destructive"])

    def test_tool_usage_fields_parent_and_usage(self) -> None:
        calls = {r.details["call_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-tool-call")}
        self.assertEqual((calls["call1"]["destructive_source"], calls["call1"]["approval"], calls["call1"]["exit_code"]), ("tool-record", "approved", 0))
        self.assertEqual(calls["call1"]["command"], "rm -rf /home/u1/tmp")
        self.assertFalse(calls["call2"]["destructive"])
        self.assertTrue(calls["call2"]["read_only"])
        self.assertEqual(mf.by_type(self.rows, "ai-agent-file-touch")[0].details["op"], "delete")
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["z2"]["parent_session_id"], "z1")
        self.assertEqual((sessions["z1"]["tokens_in"], sessions["z1"]["model"], sessions["z1"]["todos"]), (100, "glm-4.6", 1))
        usage = mf.by_type(self.rows, "ai-usage-stat")[0].details
        self.assertEqual((usage["model"], usage["tokens"], usage["requests"]), ("glm-4.6", 180, 2))
        settings = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "settings")
        self.assertEqual(settings["base_url_hosts"], ["api.z.ai"])
        raw = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details["presence_kind"] == "raw-model-io")
        self.assertFalse(raw["content_collected"])

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
