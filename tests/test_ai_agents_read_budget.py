"""R7 AI scan findings (Q-AI9): read budget newest-first, complete skipped-files sidecar, run
disclosure, ``ai_read_mb`` / ``RAPIDTRIAGE_AI_READ_MB``; body emails kept as evidence while account
identity rows stay masked."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.ai_agents import AI_SKIPPED_SIDECAR_NAME, AiAgentsProvider
from rapidtriage.artifacts.ai_agents.adapters._iface import AiLimits
from rapidtriage.artifacts.ai_agents.adapters.claude_code import ClaudeCodeAdapter
from rapidtriage.artifacts.ai_agents.adapters.codex import CodexAdapter
from rapidtriage.artifacts.ai_agents.base import (
    DEFAULT_AI_READ_MB,
    default_adapter_read_bytes,
)
from tests.fixtures.ai_agents import make_fixtures as mf

FILE_COUNT = 300
FILE_BYTES = 64 * 1024
MIB = 1024 * 1024
T0 = 1_790_000_000  # 2026-09-21 UTC


def _session_file(path: Path, sid: str) -> None:
    record = json.dumps(
        {
            "type": "user",
            "sessionId": sid,
            "timestamp": "2026-09-21T00:00:00Z",
            "message": {"role": "user", "content": f"session {sid}"},
        }
    )
    data = (record + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data + b"\n" * (FILE_BYTES - len(data)))


def build_many_sessions(root: Path, count: int = FILE_COUNT) -> list[str]:
    """``count`` Claude Code sessions of exactly :data:`FILE_BYTES`; session ``s{i}`` has mtime
    ``T0 + i`` (higher index = newer). Returns the ids newest first."""
    projects = root / "Users" / "u1" / ".claude" / "projects"
    for index in range(count):
        # File names run against age so neither name order nor creation order equals newest-first.
        path = projects / f"slug-{index % 7}" / f"{count - index:04d}-s{index}.jsonl"
        _session_file(path, f"s{index}")
        os.utime(path, (T0 + index, T0 + index))
    return [f"s{index}" for index in reversed(range(count))]


class ReadBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-budget-"))
        cls.newest = build_many_sessions(cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_default_budget_and_env_override(self) -> None:
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_AI_READ_MB": ""}):
            self.assertEqual(DEFAULT_AI_READ_MB, 4096)
            self.assertEqual(default_adapter_read_bytes(), 4096 * MIB)
            self.assertEqual(AiLimits().max_adapter_read_bytes, 4096 * MIB)
            self.assertEqual(AiAgentsProvider().limits().max_adapter_read_bytes, 4096 * MIB)
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_AI_READ_MB": "7"}):
            self.assertEqual(AiLimits().max_adapter_read_bytes, 7 * MIB)
            # the run option wins over the environment
            self.assertEqual(AiAgentsProvider().with_options(ai_read_mb=3).limits().max_adapter_read_bytes, 3 * MIB)
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_AI_READ_MB": "not-a-number"}):
            self.assertEqual(default_adapter_read_bytes(), 4096 * MIB)

    def test_adapter_parses_newest_first_and_lists_every_skip(self) -> None:
        budget_files = 40
        rows = mf.collect_rows(ClaudeCodeAdapter, self.tmp, AiLimits(max_adapter_read_bytes=budget_files * FILE_BYTES))
        parsed = [r.details["session_id"] for r in mf.by_type(rows, "ai-agent-session")]
        self.assertEqual(sorted(parsed), sorted(self.newest[:budget_files]))
        self.assertEqual(parsed, self.newest[:budget_files])  # rows come out newest first too
        summary = mf.summary_of(rows)
        self.assertTrue(summary["read_budget_exhausted"])
        self.assertEqual(summary["read_files"], budget_files)
        self.assertEqual(summary["read_bytes"], budget_files * FILE_BYTES)
        self.assertEqual(summary["skipped_for_budget_count"], FILE_COUNT - budget_files)
        self.assertEqual(summary["skipped_for_budget_bytes"], (FILE_COUNT - budget_files) * FILE_BYTES)
        self.assertEqual(len(summary["skipped_for_budget"]), 50)  # row preview; the full list is the sidecar
        self.assertEqual(summary["read_order"], "newest-first")

    def test_provider_sidecar_and_disclosure(self) -> None:
        out = self.tmp / "out"
        provider = AiAgentsProvider().with_options(ai_read_mb=1, output_dir=out)
        records = list(provider.collect(self.tmp))
        expected_parsed = MIB // FILE_BYTES  # 16
        expected_skipped = FILE_COUNT - expected_parsed  # 284
        parsed = [r.details["session_id"] for r in records if r.artifact_type == "ai-agent-session" and r.details["tool"] == "claude-code"]
        self.assertEqual(parsed, self.newest[:expected_parsed])
        sidecar = json.loads((out / AI_SKIPPED_SIDECAR_NAME).read_text(encoding="utf-8"))
        self.assertEqual(sidecar["skipped_count"], expected_skipped)
        self.assertEqual(len(sidecar["entries"]), expected_skipped)
        self.assertEqual(sidecar["skipped_by_tool"], {"claude-code": expected_skipped})
        self.assertEqual(sidecar["read_budget_bytes_per_adapter"], MIB)
        skipped_ids = {Path(entry["path"]).stem.split("-", 1)[1] for entry in sidecar["entries"]}
        self.assertEqual(skipped_ids, set(self.newest[expected_parsed:]))
        self.assertTrue(all(entry["size_bytes"] == FILE_BYTES and entry["tool"] == "claude-code" for entry in sidecar["entries"]))
        summary = next(r.details for r in records if r.details.get("presence_kind") == "adapter-summary" and r.details["tool"] == "claude-code")
        self.assertEqual(summary["skipped_sidecar"], AI_SKIPPED_SIDECAR_NAME)
        self.assertIn(f"AI 기록 읽기 상한 도달: claude-code {expected_skipped}파일 미수집", " ".join(provider.collection_notes))

    def test_no_sidecar_or_note_when_budget_suffices(self) -> None:
        out = self.tmp / "out-large"
        provider = AiAgentsProvider().with_options(ai_read_mb=64, output_dir=out)
        records = list(provider.collect(self.tmp))
        sessions = [r for r in records if r.artifact_type == "ai-agent-session" and r.details["tool"] == "claude-code"]
        self.assertEqual(len(sessions), FILE_COUNT)
        self.assertFalse((out / AI_SKIPPED_SIDECAR_NAME).exists())
        self.assertFalse([note for note in provider.collection_notes if "읽기 상한" in note])


class BodyEmailDecisionTests(unittest.TestCase):
    """Coordinator decision (known limitations): an address inside a message body / command /
    instruction text is evidence and stays as written; account identity rows and path components
    are masked."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-body-email-"))
        mf.build_all(cls.tmp, only=("codex", "claude_swap"))
        cls.records = list(AiAgentsProvider().collect(cls.tmp))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_body_email_preserved(self) -> None:
        texts = [str(r.details.get("text") or "") for r in self.records if r.artifact_type == "ai-agent-message" and r.details["tool"] == "codex"]
        self.assertTrue(any(mf.BODY_EMAIL in text for text in texts), texts)
        # the adapter alone keeps it too (no masking pass between adapter and provider)
        rows = mf.collect_rows(CodexAdapter, self.tmp)
        self.assertTrue(any(mf.BODY_EMAIL in str(r.details.get("text") or "") for r in mf.by_type(rows, "ai-agent-message")))

    def test_claude_swap_account_rows_masked(self) -> None:
        accounts = [r for r in self.records if r.artifact_type == "ai-account" and r.details["tool"] == "claude-swap"]
        self.assertEqual(len(accounts), 2)
        blob = json.dumps([r.details for r in accounts] + [r.path for r in accounts], ensure_ascii=False)
        for local in ("alice.secret", "bob.private"):
            self.assertNotIn(local, blob)
        self.assertEqual(sorted(r.details["email_domain"] for r in accounts), ["corp.example", "gmail.example"])


if __name__ == "__main__":
    unittest.main()
