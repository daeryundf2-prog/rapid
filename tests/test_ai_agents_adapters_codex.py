"""R7 AI lane B: Codex adapter known answers (Q-AI2: WAL-only thread, read-only open)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters._common import (
    immutable_uri,
    open_sqlite_ro,
)
from rapidtriage.artifacts.ai_agents.adapters._iface import AiLimits
from rapidtriage.artifacts.ai_agents.adapters.codex import CodexAdapter
from tests.fixtures.ai_agents import make_fixtures as mf


def _snapshot(paths: list[Path]) -> dict[str, tuple[int, int, str]]:
    return {str(p): (p.stat().st_mtime_ns, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths if p.exists()}


class CodexAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-codex-"))
        cls.home = mf.build_all(cls.tmp, only=("codex",))
        cls.state = cls.home / ".codex" / "sqlite" / "state_5.sqlite"
        cls.files = [cls.state, Path(str(cls.state) + "-wal"), Path(str(cls.state) + "-shm")]
        cls.before = _snapshot(cls.files)
        cls.rows = mf.collect_rows(CodexAdapter, cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_known_answer_counts(self) -> None:
        expected = mf.CODEX_EXPECTED
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-session")), expected["sessions"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-message")), expected["messages"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-tool-call")), expected["tool_calls"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-agent-file-touch")), expected["file_touches"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-usage-stat")), expected["usage_rows"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-mcp-server")), expected["mcp_rows"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-instruction-file")), expected["instruction_rows"])
        self.assertEqual(len(mf.by_type(self.rows, "ai-credential-presence")), expected["credential_rows"])

    def test_wal_only_thread_is_read_and_sources_are_untouched(self) -> None:
        self.assertTrue(all(p.exists() for p in self.files), "fixture must keep -wal/-shm")
        ids = {r.details["session_id"] for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertIn("thread-3", ids)
        state = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if str(r.details["source_path"]).endswith("state_5.sqlite"))
        self.assertTrue(state["wal_included"])
        # immutable=1 ignores the WAL: the newest thread is invisible that way (documented trade-off).
        immutable = sqlite3.connect(immutable_uri(self.state), uri=True)
        try:
            self.assertEqual(immutable.execute("SELECT count(*) FROM threads").fetchone()[0], 2)
        finally:
            immutable.close()
        self.assertEqual(_snapshot(self.files), self.before)
        # A second full run leaves the sidecars in place and unchanged too, and no scratch copy stays behind.
        scratch_before = {p.name for p in Path(tempfile.gettempdir()).glob("rt-ai-sqlite-*")}
        mf.collect_rows(CodexAdapter, self.tmp)
        self.assertEqual(_snapshot(self.files), self.before)
        self.assertTrue(os.path.exists(str(self.state) + "-wal"))
        self.assertEqual({p.name for p in Path(tempfile.gettempdir()).glob("rt-ai-sqlite-*")} - scratch_before, set())

    def test_plain_read_only_open_rewrites_shm(self) -> None:
        """Why WAL databases are read through a scratch copy: ``mode=ro`` alone touches the ``-shm``."""
        tmp = Path(tempfile.mkdtemp(prefix="ai-codex-shm-"))
        try:
            home = mf.build_all(tmp, only=("codex",))
            state = home / ".codex" / "sqlite" / "state_5.sqlite"
            shm = Path(str(state) + "-shm")
            before = hashlib.sha256(shm.read_bytes()).hexdigest()
            conn = sqlite3.connect(f"file:{state.resolve().as_posix()}?mode=ro", uri=True)
            try:
                self.assertEqual(conn.execute("SELECT count(*) FROM threads").fetchone()[0], 3)
            finally:
                conn.close()
            self.assertNotEqual(hashlib.sha256(shm.read_bytes()).hexdigest(), before)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_wal_over_cap_falls_back_to_immutable(self) -> None:
        conn, with_wal = open_sqlite_ro(self.state, AiLimits(max_sqlite_bytes=1))
        try:
            self.assertFalse(with_wal)
            self.assertEqual(conn.execute("SELECT count(*) FROM threads").fetchone()[0], 2)
        finally:
            conn.close()
        self.assertEqual(_snapshot(self.files), self.before)

    def test_parent_child_usage_and_destructive(self) -> None:
        sessions = {r.details["session_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-session")}
        self.assertEqual(sessions["thread-2"]["parent_session_id"], "thread-1")
        self.assertEqual(sessions["thread-1"]["goal_status"], "done")
        self.assertEqual(sessions["thread-5"]["tokens_in"], 70)
        self.assertIn("[가림]", sessions["thread-1"]["git_origin"])
        usage = {(r.details["period"], r.details["model"]): r.details["tokens"] for r in mf.by_type(self.rows, "ai-usage-stat")}
        self.assertEqual(usage, {("2026-10-13", "gpt-5"): 1500, ("2026-10-14", "gpt-5-mini"): 200})
        calls = {r.details["call_id"]: r.details for r in mf.by_type(self.rows, "ai-agent-tool-call")}
        self.assertTrue(calls["c1"]["destructive"])
        self.assertEqual(calls["c9"]["exit_code"], 1)
        ops = sorted(r.details["op"] for r in mf.by_type(self.rows, "ai-agent-file-touch"))
        self.assertEqual(ops, ["delete", "read"])
        logs = next(r.details for r in mf.by_type(self.rows, "ai-tool-presence") if r.details.get("presence_kind") == "log-db")
        self.assertEqual(logs["log_rows"], 3)
        self.assertFalse(logs["bodies_collected"])
        summary = mf.summary_of(self.rows)
        self.assertEqual(summary["unknown_record_types"], {"ghost_snapshot_v9": 1})

    def test_oversized_db_is_meta_only(self) -> None:
        rows = mf.collect_rows(CodexAdapter, self.tmp, AiLimits(max_sqlite_bytes=1))
        dev = next(r.details for r in mf.by_type(rows, "ai-tool-presence") if str(r.details["source_path"]).endswith("codex-dev.db"))
        self.assertTrue(dev["meta_only"])
        self.assertEqual(dev["meta_only_reason"], "sqlite-over-size-cap")
        sources = [r.details.get("source") for r in mf.by_type(rows, "ai-agent-message")]
        self.assertNotIn("thread_timeline_ledger", sources)

    def test_no_secret_in_rows(self) -> None:
        blob = json.dumps([r.details for r in self.rows], ensure_ascii=False, default=str)
        self.assertEqual([s for s in mf.secret_values() if s in blob], [])


if __name__ == "__main__":
    unittest.main()
