"""R7 AI lane B: shared rules of the session adapters (Q-AI1/Q-AI7/Q-AI8) on SYNTHETIC fixtures.

* every fixture secret / email local part is absent from every emitted row AND every timeline
  event built from those rows (global grep);
* credential files are never opened (``open`` is watched during a full run);
* masking of API key prefixes, bearer tokens and secret assignments;
* timeline events for session start/end, messages, tool calls, file touches, account switches,
  cleanup markers and AI-attributed commits.
"""

from __future__ import annotations

import builtins
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.ai_agents import adapters as lane_b
from rapidtriage.artifacts.ai_agents.adapters._common import (
    cap_text,
    command_paths,
    iter_profiles,
    to_iso,
)
from rapidtriage.artifacts.ai_agents.adapters._iface import (
    AiLimits,
    registered_adapters,
)
from rapidtriage.artifacts.ai_agents.base import AI_ARTIFACT_TYPES
from rapidtriage.artifacts.ai_agents.redact import (
    mask_api_keys,
    mask_email,
    redact_text,
)
from rapidtriage.core.timeline import TIMELINE_FIELD_MAP, iter_artifact_detail_events
from tests.fixtures.ai_agents import make_fixtures as mf

LANE_B_MODULES = {module.__name__ for module in lane_b.ADAPTER_MODULES}
# Row types lane B adds beyond lane A's AI_ARTIFACT_TYPES (hand-off: register them there).
LANE_B_EXTRA_TYPES: set[str] = set()  # ai-account-switch / ai-retention-cleanup are now in AI_ARTIFACT_TYPES
CREDENTIAL_NAMES = (
    ".credentials.json",
    "1234.abcd.key",
    "auth.json",
    "s1",
    "lock1",
    "daemon.auth",
    "credentials.json",
    "client.key",
    "buddy-tokens.json",
    "ssh-remote-server-state.json",
    "Cookies",
    ".creds-1-alice.secret@corp.example.enc",
    "oauth_creds.json",
    "jetski-standalone-oauth-token",
    "hosts.json",
    "snapshot-bash-1.sh",
    "omo.jsonc",
    "r1.jsonl",
)


def lane_b_adapters() -> list:
    return [adapter for adapter in registered_adapters() if type(adapter).__module__ in LANE_B_MODULES]


class AllAdaptersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="ai-all-"))
        mf.build_all(cls.tmp)
        cls.opened: list[str] = []
        real_open, real_io_open = builtins.open, io.open

        def watch(opener):
            def wrapper(file, *args, **kwargs):
                cls.opened.append(str(file))
                return opener(file, *args, **kwargs)

            return wrapper

        with mock.patch.object(builtins, "open", watch(real_open)), mock.patch.object(io, "open", watch(real_io_open)):
            cls.records = [row for adapter in lane_b_adapters() for row in mf.collect_rows(type(adapter), cls.tmp)]
        cls.events = [event for record in cls.records for event in iter_artifact_detail_events(record.artifact_type, record.details)]

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_registry_has_every_lane_b_adapter(self) -> None:
        names = {adapter.name for adapter in lane_b_adapters()}
        expected = {"claude_code", "codex", "cursor", "antigravity", "kiro", "omo", "zcode", "claude_desktop", "claude_swap", "gemini_cli"}
        expected |= {f"stub_{name}" for name in ("copilot", "github_copilot", "windsurf", "devin", "opencode", "aider", "goose", "cline")}
        self.assertEqual(names, expected)
        self.assertTrue(all(adapter.tool for adapter in lane_b_adapters()))

    def test_row_types_are_known(self) -> None:
        types = {record.artifact_type for record in self.records}
        self.assertEqual(types - set(AI_ARTIFACT_TYPES), LANE_B_EXTRA_TYPES)
        self.assertEqual({t for t in types if t not in TIMELINE_FIELD_MAP}, set())

    def test_global_secret_grep_rows_and_timeline(self) -> None:
        secrets = mf.secret_values()
        rows_blob = json.dumps([record.details for record in self.records], ensure_ascii=False, default=str)
        self.assertEqual([s for s in secrets if s in rows_blob], [], "secret value in an emitted row")
        events_blob = json.dumps(self.events, ensure_ascii=False, default=str)
        self.assertEqual([s for s in secrets if s in events_blob], [], "secret value in a timeline event")
        self.assertGreater(len(self.records), 150)
        self.assertGreater(len(self.events), 80)

    def test_credential_files_never_opened(self) -> None:
        opened_names = {Path(path).name for path in self.opened}
        self.assertTrue({"settings.json", "history.jsonl", "sequence.json", "mcp.log"} <= opened_names, "the open() watch saw the reads")
        self.assertEqual(opened_names & set(CREDENTIAL_NAMES), set())
        creds = [record for record in self.records if record.artifact_type == "ai-credential-presence"]
        self.assertGreaterEqual(len(creds), 20)
        self.assertTrue(all(record.details["value_collected"] is False for record in creds))
        self.assertTrue(all("sha256" not in record.details for record in creds))

    def test_timeline_kinds(self) -> None:
        kinds = {str(event["timestamp_kind"]) for event in self.events}
        for kind in ("started", "ended", "message", "run", "accessed", "modified", "deleted", "observed", "switched", "cleanup", "committed", "added", "completed"):
            self.assertIn(kind, kinds)
        switch = next(e for e in self.events if e["timestamp_kind"] == "switched")
        self.assertEqual(switch["timestamp"], "2026-10-10T09:00:00Z")
        self.assertTrue(all(e.get("timezone") == "UTC" for e in self.events))

    def test_every_session_has_tool_and_coverage(self) -> None:
        for record in self.records:
            self.assertIn(record.details["coverage_status"], ("local-verified", "schema-not-validated"), record.artifact_type)
            self.assertTrue(record.details["tool"])
        unvalidated = {record.details["tool"] for record in self.records if record.details["coverage_status"] == "schema-not-validated"}
        self.assertTrue({"github-copilot", "github-copilot-cli", "windsurf", "devin", "opencode", "aider", "goose", "cline", "gemini-cli"} <= unvalidated)


class RedactionTests(unittest.TestCase):
    def test_every_prefix_is_hashed_and_masked(self) -> None:
        for value in (mf.SK_ANT, mf.SK_PROJ, mf.SK_PLAIN, mf.AIZA, mf.HF, mf.GHP, mf.GH_PAT, mf.XAI, mf.GSK, mf.AKIA):
            masked = mask_api_keys(f"key: {value} end")
            self.assertNotIn(value, masked)
            self.assertIn("[가림:", masked)
            self.assertEqual(masked, mask_api_keys(f"key: {value} end"))  # stable hash
        self.assertTrue(mask_api_keys(mf.SK_ANT).startswith("sk-ant-[가림:"))
        self.assertTrue(mask_api_keys(mf.SK_PROJ).startswith("sk-proj-[가림:"))

    def test_ordinary_text_stays_readable(self) -> None:
        for text in ("pip install sk-learn", "import hf_hub", "max_tokens=4096", "skip-ahead", "AKIA short", "token count: 5", "debug=true"):
            self.assertEqual(redact_text(text), text)

    def test_bearer_env_json_and_query_values(self) -> None:
        text = f'Authorization: Bearer {mf.BEARER} OPENAI_API_KEY="{mf.TOKEN_BARE}" {{"access_token": "{mf.CRED_FILE}"}} https://x.example/?token={mf.TOKEN_QUERY}'
        out = redact_text(text)
        for secret in (mf.BEARER, mf.TOKEN_BARE, mf.CRED_FILE, mf.TOKEN_QUERY):
            self.assertNotIn(secret, out)
        self.assertIn("OPENAI_API_KEY=", out)

    def test_cap_and_email(self) -> None:
        text, truncated, original = cap_text("가" * 100, 10)
        self.assertTrue(truncated)
        self.assertLessEqual(len(text.encode()), 10)
        self.assertEqual(original, 300)
        self.assertEqual(cap_text("short", 10), ("short", False, 5))
        domain, local = mask_email("Mail: Alice.Secret@Corp.Example")
        self.assertEqual(domain, "corp.example")
        self.assertEqual(len(local), 12)
        self.assertEqual(mask_email("no address"), ("", ""))


class HelperTests(unittest.TestCase):
    def test_iter_profiles_from_a_path(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ai-prof-"))
        try:
            for user in ("u1", "u2", "Public", "Default"):
                (tmp / "Users" / user).mkdir(parents=True)
            profiles = iter_profiles([tmp], "windows")
            self.assertEqual(sorted(p.user for p in profiles if p.home != tmp), ["u1", "u2"])
            self.assertTrue(all(p.os == "windows" for p in profiles))
            # the same home given twice (overlapping roots / profiles) yields one profile -> one Found per adapter
            again = iter_profiles([tmp / "Users" / "u1", *profiles], "windows")
            self.assertEqual(sum(1 for p in again if p.home.name == "u1"), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_to_iso_and_command_paths(self) -> None:
        self.assertEqual(to_iso(1790157600000), "2026-09-23T10:00:00Z")
        self.assertEqual(to_iso("2026-09-20T10:00:00.500Z"), "2026-09-20T10:00:00.500Z")
        self.assertEqual(to_iso("2026-08-29 01:00:01.000"), "2026-08-29T01:00:01")
        self.assertEqual(to_iso("not a time"), "")
        self.assertEqual(command_paths('copy "C:\\a b\\x.txt" E:\\usb\\x.txt'), [("read", "C:\\a b\\x.txt"), ("write", "E:\\usb\\x.txt")])
        self.assertEqual(command_paths("echo hi > C:\\out\\log.txt"), [("write", "C:\\out\\log.txt")])
        self.assertEqual(command_paths("del /q C:\\case\\evidence.e01"), [("delete", "C:\\case\\evidence.e01")])

    def test_limits_defaults_match_plan(self) -> None:
        limits = AiLimits()
        self.assertEqual((limits.max_message_bytes, limits.max_messages_per_session, limits.max_tool_calls_per_session), (16 * 1024, 2000, 5000))
        self.assertEqual((limits.max_adapter_read_bytes, limits.max_sqlite_bytes), (200 * 1024 * 1024, 1024 * 1024 * 1024))


if __name__ == "__main__":
    unittest.main()
