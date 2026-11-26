"""Synthetic evidence only. Each test builds its own profile tree."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import weakref
from collections import Counter
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import get_artifact_collector
from rapidtriage.artifacts.ai_agent_records import utc
from rapidtriage.artifacts.ai_agents import LINE_BYTES
from rapidtriage.core.ai_agent_kinds import AI_AGENT_LABELS
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.run.profiles import RUN_PROFILES
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import extract_artifact_events


class AgentFixture(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "evidence"
        self.root.mkdir()

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode())
        return target

    def lines(self, path, *records):
        return self.write(path, b"\n".join(json.dumps(row, ensure_ascii=False).encode() for row in records) + b"\n")

    def rows(self, kind):
        result = list(get_artifact_collector(kind).collect(self.root))
        for row in result:
            validate(row.details, load_schema("artifacts.schema.json")["$defs"]["agentDetails"])
            self.assertIn("schema-version-not-validated", row.details["flags"])
            self.assertEqual(row.details["source_path"], row.path)
        return result


class AgentTests(AgentFixture):
    def test_claude_blocks_and_streamed_timeline(self):
        path = "Users/profile/.claude/projects/project/agents/session.jsonl"
        stamp = "2026-05-01T12:00:00+09:00"
        common = {"timestamp": stamp, "sessionId": "s1", "cwd": "/sample", "schemaVersion": "future"}
        self.lines(path, {**common, "type": "user", "message": {"content": "한글 질문"}},
                   {**common, "type": "assistant", "message": {"model": "sample-model", "content": [
                       {"type": "text", "text": "응답"}, {"type": "tool_use", "name": "Edit", "id": "c1",
                                                        "input": {"file_path": "새파일.py"}}]}},
                   {**common, "type": "user", "message": {"content": [
                       {"type": "tool_result", "tool_use_id": "c1", "content": "완료"}]}})
        user, answer, call, result = self.rows("claude-code")
        self.assertEqual(user.details["text"], "한글 질문")
        self.assertEqual(answer.details["model"], "sample-model")
        self.assertEqual(call.details["file_paths"], ["새파일.py"])
        self.assertEqual(call.details["cwd"], "/sample")
        self.assertEqual(result.details["tool_name"], "Edit")
        self.assertEqual(call.details["schema_version"], "future")
        self.assertEqual(call.details["source_line"], 2)
        self.assertEqual(call.details["timestamp_raw"], stamp)
        payload = run_artifact_collection(self.root, kind="claude-code", records_path=self.root.parent / "rows.jsonl",
                                          preview_limit=1)
        self.assertEqual(payload["record_count"], 4)
        validate(payload, load_schema("artifacts.schema.json"))
        self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
        events = extract_artifact_events(payload, self.root.parent / "artifacts-claude-code.json")
        self.assertEqual(len(events), 4)
        self.assertTrue(all(e["timestamp"].startswith("2026-05-01T03:00:00") for e in events))

    def test_codex_rollout_and_history(self):
        filename = "home/profile/.codex/sessions/2026/05/01/rollout.jsonl"
        self.lines(filename, {"type": "session_meta", "payload": {"id": "s2", "cwd": "/project"}},
                   {"type": "turn_context", "payload": {"model": "sample", "cwd": "/turn"}},
                   {"type": "event_msg", "payload": {"type": "user_message", "message": "안녕"}},
                   {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                          "content": [{"type": "input_text", "text": "안녕"}]}},
                   {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command",
                       "call_id": "c", "arguments": json.dumps({"cmd": "echo --api-key fake-value"})}},
                   {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c", "output": "done"}},
                   {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "apply_patch",
                       "input": "*** Begin Patch\n*** Add File: 한글.txt\n+ok\n*** End Patch"}})
        self.lines("home/profile/.codex/history.jsonl", {"session_id": "h", "ts": 1_700_000_000, "text": "질문"})
        rows = self.rows("codex-cli")
        self.assertEqual(len(rows), 5)
        self.assertNotIn("fake-value", str(rows))
        rollout = [row.details for row in rows if row.path == filename]
        self.assertTrue(all(r["cwd"] == "/turn" and r["model"] == "sample" and r["session_id"] == "s2" for r in rollout))
        self.assertEqual(rollout[2]["tool_name"], "exec_command")
        self.assertEqual(rollout[3]["file_paths"], ["한글.txt"])
        history = next(row for row in rows if row.path.endswith("history.jsonl"))
        self.assertEqual(history.details["timestamp_utc"], "2023-11-14T22:13:20+00:00")

    def test_gemini_session_formats(self):
        base = "home/profile/.gemini/tmp/project/"
        chat = {"sessionId": "s3", "messages": [{"type": "user", "content": [{"text": "검토"}]},
            {"type": "gemini", "model": "sample", "timestamp": "2026-04-01T00:00:00Z", "content": "확인",
             "toolCalls": [{"id": "t", "name": "read_file", "args": {"file_path": "memo.txt"},
                            "result": [{"functionResponse": {"response": {"output": "읽음"}}}]}]}]}
        self.write(base + "chats/session-one.json", chat)
        self.lines(base + "chats/session-two.jsonl", {"sessionId": "s4"}, chat["messages"][0], {"$rewindTo": "prior"})
        self.write(base + "logs.json", [{"sessionId": "s5", "type": "user", "message": "로그"}])
        rows = self.rows("gemini-cli")
        self.assertEqual(Counter(r.artifact_type for r in rows), {
            "agent-message": 4, "agent-tool-call": 1, "agent-tool-result": 1, "agent-parse-note": 1})
        tool_result = next(r for r in rows if r.artifact_type == "agent-tool-result")
        self.assertEqual(tool_result.details["text"], "읽음")
        self.assertEqual(tool_result.details["message_index"], 1)
        self.assertEqual(tool_result.details["session_id"], "s3")

    def test_settings_and_mcp_names_only(self):
        config = {"mcpServers": {"sample": {"command": "runner", "args": ["plain-marker"],
                                           "env": {"EXAMPLE_SETTING": "plain-marker"}}}}
        for path in (".claude.json", ".claude/settings.local.json", ".gemini/settings.json",
                     ".cursor/mcp.json", "project/.mcp.json"):
            self.write("Users/profile/" + path, {**config, "model": "sample", "extra": "plain-marker"})
        self.write("Users/profile/.vscode/mcp.json", {"servers": config["mcpServers"]})
        self.write("Users/profile/.codex/config.toml", b'model = "sample"\n[mcp_servers.sample]\ncommand = "runner"\n'
                   b'[mcp_servers.sample.env]\nEXAMPLE_SETTING = "plain-marker"\n')
        self.write("Users/other/.claude.json", {"projects": {"/sample": config}})
        servers = self.rows("agent-mcp")
        self.assertEqual(len(servers), 8)
        for row in servers:
            self.assertEqual(row.details["env_names"], ["EXAMPLE_SETTING"])
            self.assertEqual(row.details["command_line"], "runner")
            self.assertEqual(row.details["server_name"], "sample")
        self.assertNotIn("plain-marker", str(servers))
        self.assertEqual(len(self.rows("claude-code")), 3)
        self.assertEqual(self.rows("codex-cli")[0].details["model"], "sample")
        self.assertEqual(self.rows("gemini-cli")[0].details["model"], "sample")

    def test_editor_reads_private_wal_copy_and_selected_keys(self):
        path = self.root / "Users/profile/Library/Application Support/Cursor/User/globalStorage/state.vscdb"
        path.parent.mkdir(parents=True)
        db = sqlite3.connect(path)
        self.addCleanup(db.close)
        db.execute("PRAGMA journal_mode=WAL")
        for table in ("ItemTable", "cursorDiskKV"):
            db.execute(f"CREATE TABLE {table}(key TEXT PRIMARY KEY, value BLOB)")
        db.execute("INSERT INTO ItemTable VALUES (?,?)", ("unrelated", "ignored"))
        db.execute("INSERT INTO ItemTable VALUES (?,?)", ("composer.composerData", json.dumps(
            {"composerId": "old", "conversation": [{"type": 1, "text": "질문"}]})))
        db.execute("INSERT INTO cursorDiskKV VALUES (?,?)", ("bubbleId:s4:b", json.dumps({
            "type": 2, "text": "답변", "createdAt": 1_700_000_000_000, "modelInfo": {"modelName": "sample"},
            "toolFormerData": {"name": "read", "rawArgs": '{"path":"test.txt"}'}}).encode()))
        db.execute("INSERT INTO cursorDiskKV VALUES (?,?)", ("bubbleId:s4:broken", "{"))
        db.commit()
        def evidence():
            return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.parent.iterdir()}
        before = evidence()
        rows = self.rows("editor-chat")
        self.assertEqual(before, evidence())
        self.assertEqual([r.artifact_type for r in rows], ["agent-message", "agent-message", "agent-tool-call", "agent-parse-note"])
        self.assertEqual(rows[1].details["session_id"], "s4")
        self.assertEqual(rows[1].details["timestamp_utc"], "2023-11-14T22:13:20+00:00")
        self.assertEqual(rows[2].details["file_paths"], ["test.txt"])
        self.assertEqual(rows[3].details["source_rowid"], 2)
        self.assertEqual(rows[3].details["source_table"], "cursorDiskKV")

    def test_damaged_and_oversized_lines_resume_at_exact_byte(self):
        bad = b'{"bad":\xff}\n'
        big = b"x" * (LINE_BYTES + 50) + b"\r\n"
        body = json.dumps({"text": "검사", "session_id": "s"}).encode()
        self.write(".codex/history.jsonl", bad + big + body)
        first, second, good = self.rows("codex-cli")
        self.assertEqual([first.details["reason"], second.details["reason"]], ["invalid-json-line", "line-size-limit"])
        self.assertEqual(sum(r.details["damaged_count"] for r in (first, second)), 2)
        self.assertEqual(second.details["source_offset"], len(bad))
        self.assertEqual(good.details["source_offset"], len(bad + big))
        self.assertEqual(good.details["source_line"], 3)
        self.assertEqual(good.details["text"], "검사")
        report = run_artifact_collection(self.root, kind="codex-cli", use_cache=False)
        self.assertEqual(report["summary"]["parser_error_count"], 2)

    def test_limit_and_symlink_boundaries(self):
        path = self.lines("Users/profile/.codex/history.jsonl", {"text": "첫째"}, {"text": "둘째"})
        self.write("unrelated/history.jsonl", {"text": "ignore"})
        self.lines("rapidtriage-run-output/.codex/history.jsonl", {"text": "ignore"})
        outside = self.root.parent / "private"
        outside.write_bytes(b"{}")
        (path.parent / "sessions").mkdir()
        (path.parent / "sessions/link.jsonl").symlink_to(outside)
        with patch("rapidtriage.artifacts.ai_agents.ROWS_PER_SOURCE", 1):
            rows = self.rows("codex-cli")
            self.assertEqual([r.artifact_type for r in rows], ["agent-message", "agent-parse-note"])
            self.assertEqual(rows[-1].details["reason"], "row-limit")
        with patch("rapidtriage.artifacts.ai_agents.STREAM_BYTES", path.read_bytes().index(b"\n") + 2):
            rows = self.rows("codex-cli")
            self.assertEqual([r.artifact_type for r in rows], ["agent-message", "agent-parse-note"])
            self.assertEqual(rows[-1].details["reason"], "stream-byte-limit")

    def test_redaction_and_unknown_time(self):
        marker = "fixture-only-marker"
        msg = f'https://example.invalid/?sig={marker} --password "{marker} space" Authorization: Bearer {marker}'
        self.lines(".claude/projects/p/log.jsonl", {"type": "user", "timestamp": "2026-05-01T11:00:00",
                                                    "message": {"content": msg}})
        row, = self.rows("claude-code")
        self.assertNotIn(marker, str(row.to_dict()))
        self.assertIn("[가림]", row.details["text"])
        self.assertIsNone(row.details["timestamp_utc"])
        self.assertIn("timestamp-not-normalized", row.details["flags"])

    def test_event_only_rollout_and_duplicate_occurrences(self):
        event = {"type": "event_msg", "payload": {"type": "user_message", "message": "again"}}
        replay = {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "again"}}
        self.lines(".codex/sessions/events.jsonl", event, replay, event, {
            "type": "event_msg", "payload": {"type": "agent_message", "message": "answer"}})
        rows = self.rows("codex-cli")
        self.assertEqual([(r.details["source_line"], r.details["text"]) for r in rows],
                         [(2, "again"), (3, "again"), (4, "answer")])

    def test_replay_matching_stays_within_the_source_turn(self):
        def turn(ident, minute, replayed, cwd=None):
            stamp = f"2024-01-01T00:{minute}:00Z"
            context = {"cwd": cwd or "/" + ident, **({"turn_id": ident} if ident.startswith("t") else {})}
            records = [{"type": "turn_context", "payload": context},
                       {"type": "event_msg", "timestamp": stamp,
                        "payload": {"type": "user_message", "message": "same text"}}]
            if replayed:
                records.append({"type": "response_item", "timestamp": stamp, "payload": {
                    "type": "message", "role": "user", "content": [{"type": "input_text", "text": "same text"}]}})
            return records

        def rows(*turns):
            path = self.lines(".codex/sessions/turns.jsonl", *(r for t in turns for r in t))
            result = [(r.details["source_line"], r.details["cwd"], r.details["timestamp_utc"], r.details["flags"])
                      for r in self.rows("codex-cli")]
            path.unlink()
            return result

        def stamp(minute):
            return f"2024-01-01T00:{minute}:00+00:00"

        base = ["schema-version-not-validated", "version-unknown"]
        # A replay recorded only in the second turn must not consume the first turn's prompt.
        for first, second in (("t-first", "t-second"), ("first", "second")):
            self.assertEqual(rows(turn(first, "01", False), turn(second, "02", True)),
                             [(2, "/" + first, stamp("01"), base), (5, "/" + second, stamp("02"), base)])
        # The same text three times; only the last turn has a replay.
        self.assertEqual([r[:3] for r in rows(turn("t1", "01", False), turn("t2", "02", False), turn("t3", "03", True))],
                         [(2, "/t1", stamp("01")), (4, "/t2", stamp("02")), (7, "/t3", stamp("03"))])
        # Control: each turn has its replay, so each turn yields exactly its replay row.
        self.assertEqual([r[:3] for r in rows(turn("t1", "01", True), turn("t2", "02", True), turn("t3", "03", True))],
                         [(3, "/t1", stamp("01")), (6, "/t2", stamp("02")), (9, "/t3", stamp("03"))])
        # A turn_context repeated with the same recorded turn_id (after compaction) stays one turn.
        repeated = turn("t1", "01", False) + [{"type": "turn_context", "payload": {"turn_id": "t1", "cwd": "/t1"}},
                                              turn("t1", "01", True)[-1]]
        self.assertEqual([r[:3] for r in rows(repeated)], [(4, "/t1", stamp("01"))])
        # Two progress copies and one replay in one turn: the unpaired copy says the pairing is by order.
        ambiguous = turn("t1", "01", False) + turn("t1", "02", True)[1:]
        self.assertEqual(rows(ambiguous), [(3, "/t1", stamp("02"), base + ["replay-pairing-ambiguous"]),
                                           (4, "/t1", stamp("02"), base)])

    def test_editor_windows_and_linux_key_layouts(self):
        for prefix in ("Users/profile/AppData/Roaming/Code", "home/profile/.config/Code - Insiders"):
            path = self.root / prefix / "User/globalStorage/state.vscdb"
            path.parent.mkdir(parents=True)
            db = sqlite3.connect(path)
            try:
                db.execute("CREATE TABLE ItemTable(key TEXT, value TEXT)")
                db.execute("INSERT INTO ItemTable VALUES (?,?)", ("workbench.panel.chat.view.copilot.chatdata",
                           json.dumps({"sessionId": "s", "requests": [{"message": {"text": "안녕"},
                                      "response": [{"value": "확인"}]}]})))
                db.commit()
            finally:
                db.close()
        self.assertEqual(Counter(r.details["text"] for r in self.rows("editor-chat")), {"안녕": 2, "확인": 2})

    def test_limits_and_invalid_configs(self):
        self.write("Users/profile/.gemini/settings.json", b"{")
        self.write("Users/profile/.codex/config.toml", b"[not closed")
        self.assertEqual(self.rows("gemini-cli")[0].details["reason"], "invalid-document")
        self.assertEqual(self.rows("codex-cli")[0].details["reason"], "invalid-document")
        with patch("rapidtriage.artifacts.ai_agents.DOCUMENT_BYTES", 4):
            self.assertEqual(self.rows("codex-cli")[0].details["reason"], "document-size-limit")
        self.write("Users/profile/AppData/Roaming/Cursor/User/globalStorage/state.vscdb", b"fixture")
        with patch("rapidtriage.artifacts.ai_agent_editor.DB_BYTES", 4):
            self.assertEqual(self.rows("editor-chat")[0].details["reason"], "database-size-limit")

    def test_unexpected_field_types_never_export_nested_values(self):
        self.lines(".codex/sessions/session.jsonl", {"type": "response_item", "payload": {
            "type": "function_call", "name": {"env": "private-marker"}, "call_id": ["private-marker"]}},
            {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "next"}})
        rows = self.rows("codex-cli")
        self.assertEqual(len(rows), 2)
        self.assertNotIn("private-marker", str(rows))

    def test_registration(self):
        for kind in AI_AGENT_LABELS:
            self.assertEqual(artifact_type_domain(kind, ""), "execution")
            for mode in ("seizure", "fraud", "hacking", "recovery"):
                self.assertIn(kind, RUN_PROFILES[mode].artifacts_kinds)


class AdversarialAgentTests(AgentFixture):
    """Hostile or unusual synthetic inputs: secrets, caps, sidecars, clocks, versions and host isolation."""

    def test_tool_results_and_commands_mask_every_authorization_scheme(self):
        secrets = ["tok-alpha-1", "dig-beta-2", "cookie-gamma-3", "AKIAABCDEFGHIJKLMNOP",
                   "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl", "aws-delta-4", "ghp_fixtureonlytoken000"]
        output = (f"GET / HTTP/1.1\r\nAuthorization: Token {secrets[0]}\r\n"
                  f"Proxy-Authorization: Digest username=\"u\", response=\"{secrets[1]}\"\r\n"
                  f"Cookie: sid={secrets[2]}; theme=dark\r\nkey {secrets[3]} jwt {secrets[4]}\n"
                  f"aws_secret_access_key = {secrets[5]}\n{{'authorization': 'Bearer {secrets[6]}'}}")
        self.lines(".codex/sessions/s.jsonl", {"type": "session_meta", "payload": {"id": "s", "cli_version": "0.0-test"}},
                   {"type": "response_item", "payload": {"type": "function_call", "name": "shell", "call_id": "c",
                    "arguments": json.dumps({"command": ["curl", "-H", f"Authorization: Token {secrets[0]}", "x"]})}},
                   {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c", "output": output}})
        self.lines(".claude/projects/p/s.jsonl", {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "text", "text": output}]}]}})
        rows = self.rows("codex-cli") + self.rows("claude-code")
        self.assertEqual(Counter(r.artifact_type for r in rows),
                         {"agent-tool-call": 1, "agent-tool-result": 2})
        dumped = json.dumps([r.to_dict() for r in rows], ensure_ascii=False)
        for secret in secrets:
            self.assertNotIn(secret, dumped)
        result = next(r for r in rows if r.artifact_type == "agent-tool-result").details["text"]
        self.assertIn("Authorization: [가림]", result)
        self.assertIn("GET / HTTP/1.1", result)

    def test_mcp_env_values_headers_urls_and_command_secrets_never_exported(self):
        secret = "mcp-fixture-secret"
        servers = {"remote": {"url": f"https://user:{secret}@example.invalid/mcp?key={secret}",
                              "headers": {"Authorization": f"Bearer {secret}"}},
                   "local": {"command": f"npx server --api-key {secret} --token={secret}",
                             "args": ["--password", secret], "env": {"OPENAI_API_KEY": secret, "GITHUB_TOKEN": secret}}}
        self.write("Users/p/.claude.json", {"mcpServers": servers, "projects": {"/w": {"mcpServers": servers}}})
        self.write("Users/p/.cursor/mcp.json", {"mcpServers": servers})
        self.write("Users/p/.codex/config.toml", (
            f'[mcp_servers.local]\ncommand = "env API_KEY={secret} run"\nenv = {{ SERVICE_TOKEN = "{secret}" }}\n'
            f'bearer_token_env_var = "REMOTE_TOKEN"\nhttp_headers = {{ Authorization = "Bearer {secret}" }}\n'
            f'env_http_headers = {{ "X-Api-Key" = "HEADER_ENV" }}\n').encode())
        rows = self.rows("agent-mcp")
        self.assertEqual(len(rows), 7)
        self.assertNotIn(secret, json.dumps([r.to_dict() for r in rows]))
        codex = next(r for r in rows if r.path.endswith("config.toml")).details
        self.assertEqual(sorted(codex["env_names"]), ["HEADER_ENV", "REMOTE_TOKEN", "SERVICE_TOKEN"])
        local = next(r for r in rows if r.details["server_name"] == "local" and r.path.endswith(".cursor/mcp.json"))
        self.assertEqual(local.details["env_names"], ["OPENAI_API_KEY", "GITHUB_TOKEN"])

    def test_timestamps_are_strict_utc_and_keep_the_raw_value(self):
        cases = {
            "2026-05-01T12:00:00+09:00": "2026-05-01T03:00:00+00:00",
            "2026-05-01T03:00:00.123Z": "2026-05-01T03:00:00.123000+00:00",
            "2026-05-01T03:00:00.123456789z": "2026-05-01T03:00:00.123456789+00:00",
            "2026-05-01t03:00:00.000-00:30": "2026-05-01T03:30:00+00:00",
            "2026-05-01T03:00:00": None, "2026-05-01 03:00:00Z": None, "2026-W18-5T03:00:00Z": None,
            "20260501T030000Z": None, "2026-05-01T03Z": None, "2026-05-01T24:00:00Z": None,
            " 2026-05-01T03:00:00Z": None, "2026-05-01T03:00:60Z": None, "0001-01-01T00:00:00+01:00": None,
        }
        for raw, expected in cases.items():
            self.assertEqual(utc(raw, ""), expected, raw)
        self.assertEqual(utc(1_700_000_000_123, "ms"), "2023-11-14T22:13:20.123000+00:00")
        self.assertEqual(utc(-1, "s"), "1969-12-31T23:59:59+00:00")
        for raw, unit in ((True, "s"), (1_700_000_000, ""), (float("nan"), "s"), (float("inf"), "ms"), (10 ** 30, "ms")):
            self.assertIsNone(utc(raw, unit), raw)
        self.lines(".claude/projects/p/s.jsonl", *({"type": "user", "timestamp": raw, "message": {"content": "t"}}
                                                    for raw in ("2026-05-01T12:00:00.5+09:00", 1_700_000_000, "bad")))
        exact, numeric, bad = self.rows("claude-code")
        self.assertEqual(exact.details["timestamp_raw"], "2026-05-01T12:00:00.5+09:00")
        self.assertEqual(exact.details["timestamp_utc"], "2026-05-01T03:00:00.500000+00:00")
        self.assertNotIn("timestamp-not-normalized", exact.details["flags"])
        for row, raw in ((numeric, 1_700_000_000), (bad, "bad")):
            self.assertEqual(row.details["timestamp_raw"], raw)
            self.assertIsNone(row.details["timestamp_utc"])
            self.assertIn("timestamp-not-normalized", row.details["flags"])

    def test_out_of_range_offsets_are_not_normalized(self):
        # RFC 3339 section 5.6: time-numoffset hour 00-23, minute 00-59. Python's parser would
        # otherwise roll "+01:60" over to "+02:00" and report an exact but unsupported instant.
        for raw in ("2024-01-01T12:00:00+01:60", "2024-01-01T12:00:00-00:60", "2024-01-01T12:00:00+24:00",
                    "2024-01-01T12:00:00+99:99"):
            self.assertIsNone(utc(raw, ""), raw)
        self.assertEqual(utc("2024-01-01T12:00:00+23:59", ""), "2023-12-31T12:01:00+00:00")
        times = ["2024-11-03T01:30:00-04:00", "2024-11-03T01:30:00-05:00", "2024-01-01T12:00:00+01:60",
                 "2024-01-01T12:00:00-00:60", "2016-12-31T23:59:60Z"]
        self.lines(".codex/sessions/offsets.jsonl", *({"type": "event_msg", "timestamp": raw,
                                                       "payload": {"type": "user_message", "message": str(i)}}
                                                      for i, raw in enumerate(times)))
        rows = [r.details for r in self.rows("codex-cli")]
        self.assertEqual([r["timestamp_raw"] for r in rows], times)
        self.assertEqual([r["timestamp_utc"] for r in rows],
                         ["2024-11-03T05:30:00+00:00", "2024-11-03T06:30:00+00:00", None, None, None])
        self.assertEqual(["timestamp-not-normalized" in r["flags"] for r in rows], [False, False, True, True, True])

    def test_unknown_versions_are_flagged_not_guessed(self):
        self.lines(".codex/sessions/known.jsonl", {"type": "session_meta", "payload": {"id": "k", "cli_version": "9.9.9"}},
                   {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "a"}})
        self.lines(".codex/sessions/unknown.jsonl",
                   {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "b"}})
        self.lines(".claude/projects/p/s.jsonl", {"type": "user", "version": True, "schemaVersion": False,
                                                  "message": {"content": "c"}})
        known, unknown = sorted(self.rows("codex-cli"), key=lambda r: r.path)
        claude, = self.rows("claude-code")
        self.assertEqual(known.details["app_version"], "9.9.9")
        self.assertNotIn("version-unknown", known.details["flags"])
        for row in (unknown, claude):
            self.assertEqual((row.details["app_version"], row.details["schema_version"]), ("", ""))
            self.assertIn("version-unknown", row.details["flags"])

    def test_huge_jsonl_without_newlines_and_huge_documents_stay_bounded(self):
        path = self.write(".codex/history.jsonl", b"x" * (3 * LINE_BYTES + 7))
        note, = self.rows("codex-cli")
        self.assertEqual((note.details["reason"], note.details["source_offset"]), ("line-size-limit", 0))
        record = json.dumps({"text": "ok"}).encode() + b"\n"
        path.write_bytes(record * 50)
        with patch("rapidtriage.artifacts.ai_agents.STREAM_BYTES", len(record) * 3 + 4):
            rows = self.rows("codex-cli")
        self.assertEqual([r.artifact_type for r in rows], ["agent-message"] * 3 + ["agent-parse-note"])
        self.assertEqual(rows[-1].details["source_offset"], len(record) * 3 + 4)
        self.write(".gemini/tmp/h/chats/session-big.json",
                   {"sessionId": "g", "messages": [{"type": "user", "content": str(i)} for i in range(40)]})
        with patch("rapidtriage.artifacts.ai_agents.ROWS_PER_SOURCE", 5):
            rows = self.rows("gemini-cli")
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[-1].details["reason"], "row-limit")

    def _editor_db(self, prefix, rows, *, wal=False):
        path = self.root / prefix / "User/globalStorage/state.vscdb"
        path.parent.mkdir(parents=True)
        db = sqlite3.connect(path)
        self.addCleanup(db.close)
        if wal:
            db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE cursorDiskKV(key TEXT PRIMARY KEY, value BLOB)")
        db.executemany("INSERT INTO cursorDiskKV VALUES (?,?)", rows)
        db.commit()
        return path, db

    def test_sqlite_row_and_value_caps_close_the_snapshot(self):
        bubbles = [(f"bubbleId:s:{i}", json.dumps({"type": 1, "text": f"m{i}"})) for i in range(30)]
        bubbles.append(("bubbleId:s:big", json.dumps({"type": 1, "text": "y" * 4096})))
        self._editor_db("Users/p/AppData/Roaming/Cursor", bubbles)
        scratch = Path(tempfile.mkdtemp(prefix="scratch-"))
        self.addCleanup(shutil.rmtree, scratch, True)
        with patch.object(tempfile, "tempdir", str(scratch)):
            with patch("rapidtriage.artifacts.ai_agents.ROWS_PER_SOURCE", 4):
                rows = self.rows("editor-chat")
            self.assertEqual([r.details.get("reason") for r in rows], [None] * 4 + ["row-limit"])
            # The early stop closed the generator, so the private snapshot directory is already gone.
            self.assertEqual(list(scratch.iterdir()), [])
            with patch("rapidtriage.artifacts.ai_agent_editor.VALUE_BYTES", 1024):
                rows = self.rows("editor-chat")
            self.assertEqual(list(scratch.iterdir()), [])
        self.assertEqual(len(rows), 31)
        self.assertEqual(rows[-1].details["reason"], "empty-or-oversize-editor-value")
        self.assertEqual(rows[-1].details["source_key"], "bubbleId:s:big")

    def test_capped_wal_read_closes_every_cursor_before_the_copy_is_deleted(self):
        # An unfinished cursor keeps SQLite's file handle open after connection.close(), and
        # Windows cannot delete an open file. Checked at close time, so it fails on every OS.
        self._editor_db("home/p/.config/Cursor",
                        [(f"bubbleId:s:{i}", json.dumps({"type": 1, "text": f"m{i}"})) for i in range(10)], wal=True)
        unclosed = []
        connect = sqlite3.connect

        class Tracking(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.cursors = []

            def execute(self, *args):
                cursor = super().execute(*args)
                self.cursors.append(weakref.ref(cursor))
                return cursor

            def close(self):
                for cursor in filter(None, (ref() for ref in self.cursors)):
                    try:
                        cursor.fetchone()
                    except sqlite3.ProgrammingError:
                        continue
                    unclosed.append(cursor)
                super().close()

        scratch = Path(tempfile.mkdtemp(prefix="scratch-"))
        self.addCleanup(shutil.rmtree, scratch, True)
        with patch.object(tempfile, "tempdir", str(scratch)), \
                patch("rapidtriage.core.sqlite_snapshot.sqlite3.connect",
                      lambda *args, **kwargs: connect(*args, factory=Tracking, **kwargs)), \
                patch("rapidtriage.artifacts.ai_agents.ROWS_PER_SOURCE", 3):
            rows = self.rows("editor-chat")
            self.assertEqual(list(scratch.iterdir()), [])
        self.assertEqual([r.details.get("reason") for r in rows], [None] * 3 + ["row-limit"])
        self.assertEqual(unclosed, [])

    def test_snapshot_cleanup_failure_is_a_warning_not_a_source_row(self):
        self._editor_db("Users/p/AppData/Roaming/Code", [("bubbleId:s:1", json.dumps({"type": 1, "text": "kept"}))])
        scratch = Path(tempfile.mkdtemp(prefix="scratch-"))
        self.addCleanup(shutil.rmtree, scratch, True)

        def locked(holder):
            holder._finalizer.detach()
            raise PermissionError("file in use")

        with patch.object(tempfile, "tempdir", str(scratch)), \
                patch.object(tempfile.TemporaryDirectory, "cleanup", autospec=True, side_effect=locked), \
                self.assertWarnsRegex(RuntimeWarning, "working copy could not be removed"):
            rows = self.rows("editor-chat")
        self.assertEqual([(r.artifact_type, r.details["text"]) for r in rows], [("agent-message", "kept")])

    def test_sqlite_wal_is_read_from_a_copy_and_sidecars_are_never_touched(self):
        path, db = self._editor_db("Users/p/Library/Application Support/Cursor",
                                   [("bubbleId:s:1", json.dumps({"type": 1, "text": "wal-only"}))], wal=True)
        wal = path.with_name(path.name + "-wal")
        self.assertGreater(wal.stat().st_size, 0)
        def state():
            return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_size) for p in path.parent.iterdir()}
        before = state()
        row, = self.rows("editor-chat")
        self.assertEqual(row.details["text"], "wal-only")
        self.assertEqual(state(), before)
        db.close()
        outside = self.root.parent / "host-wal"
        outside.write_bytes(wal.read_bytes() if wal.exists() else b"")
        if wal.exists():
            wal.unlink()
        wal.symlink_to(outside)
        note, = self.rows("editor-chat")
        self.assertEqual(note.details["reason"], "source-unreadable")
        self.assertTrue(note.details["parser_error"])

    def test_hot_rollback_journal_is_refused_without_modifying_evidence(self):
        path, db = self._editor_db("home/p/.config/Cursor", [("bubbleId:s:1", json.dumps({"type": 1, "text": "x"}))])
        db.close()
        journal = path.with_name(path.name + "-journal")
        journal.write_bytes(bytes.fromhex("d9d505f920a163d7") + (1).to_bytes(4, "big") + bytes(16) + b"\0" * 512)
        before = {p.name: p.read_bytes() for p in path.parent.iterdir()}
        note, = self.rows("editor-chat")
        self.assertEqual(note.details["reason"], "source-unreadable")
        self.assertEqual({p.name: p.read_bytes() for p in path.parent.iterdir()}, before)

    def test_profile_discovery_across_platform_layouts_inside_evidence_only(self):
        chat = {"version": 3, "sessionId": "vs", "requests": [{"message": {"text": "질문"}, "timestamp": 1_700_000_000_000,
                                                              "response": [{"value": "답"}]}]}
        layouts = {
            "claude-code": ["Users/w/.claude/projects/C--w/s.jsonl", "Users/m/.claude/projects/-m/s.jsonl",
                            "home/l/.claude/projects/-l/s.jsonl"],
            "codex-cli": ["Users/w/.codex/sessions/2026/01/01/r.jsonl", "home/l/.codex/sessions/2026/01/01/r.jsonl"],
            "gemini-cli": ["Users/w/.gemini/tmp/h/chats/session-1.jsonl", "home/l/.gemini/tmp/h/chats/session-1.jsonl"],
        }
        for path in layouts["claude-code"]:
            self.lines(path, {"type": "user", "message": {"content": "x"}})
        for path in layouts["codex-cli"]:
            self.lines(path, {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "x"}})
        for path in layouts["gemini-cli"]:
            self.lines(path, {"type": "user", "content": "x"})
        self.lines("Users/m/.claude/history.jsonl", {"display": "프롬프트", "timestamp": 1_700_000_000_000, "project": "/m/w"})
        for prefix in ("Users/w/AppData/Roaming/Code", "Users/m/Library/Application Support/Code - Insiders",
                       "home/l/.config/VSCodium"):
            self.write(prefix + "/User/workspaceStorage/abc/chatSessions/one.json", chat)
        self.write("Users/m/Library/Application Support/Cursor/User/globalStorage/emptyWindowChatSessions/two.json", chat)
        db = self.root / "home/l/.config/Code/User/workspaceStorage/abc/state.vscdb"
        db.parent.mkdir(parents=True)
        with closing(sqlite3.connect(db)) as conn:
            conn.execute("CREATE TABLE ItemTable(key TEXT, value TEXT)")
            conn.execute("INSERT INTO ItemTable VALUES (?,?)", ("workbench.panel.chat.view.copilot.chatdata", json.dumps(chat)))
            conn.commit()
        self.write("Users/w/.codex/sessions-not/r.jsonl", b'{"type":"response_item"}\n')
        self.write("Users/w/AppData/Roaming/Code/User/chatSessions/stray.json", chat)
        host = Path(tempfile.mkdtemp(prefix="host-home-"))
        self.addCleanup(shutil.rmtree, host, True)
        (host / ".codex").mkdir()
        (host / ".codex/history.jsonl").write_text(json.dumps({"text": "host-only"}) + "\n")
        with patch.dict(os.environ, {"HOME": str(host), "USERPROFILE": str(host)}), \
                patch.object(Path, "home", return_value=host):
            for kind, paths in layouts.items():
                rows = self.rows(kind)
                expected = set(paths) | ({"Users/m/.claude/history.jsonl"} if kind == "claude-code" else set())
                self.assertEqual({r.path for r in rows}, expected, kind)
                self.assertNotIn("host-only", str(rows))
            editor = self.rows("editor-chat")
        self.assertEqual(len({r.path for r in editor}), 5)
        self.assertEqual(Counter(r.details["text"] for r in editor), {"질문": 5, "답": 5})
        session_file = next(r for r in editor if r.path.endswith("one.json"))
        self.assertEqual((session_file.details["schema_version"], session_file.details["session_id"]), ("3", "vs"))
        history = next(r for r in self.rows("claude-code") if r.path.endswith("history.jsonl"))
        self.assertEqual((history.details["text"], history.details["cwd"], history.details["timestamp_utc"]),
                         ("프롬프트", "/m/w", "2023-11-14T22:13:20+00:00"))
