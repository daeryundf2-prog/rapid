"""SYNTHETIC AI-agent evidence trees for the R7 AI lane B adapter tests.

Everything here is invented: session ids, user ``u1``, ``C:\\Users\\u1\\proj``, emails on
``example`` domains and every token. Secret-looking values are assembled at run time
(:func:`secret_values`) so no key-shaped literal sits in the repository; the tests grep every
emitted row and timeline event for them.

Usage: ``python tests/fixtures/ai_agents/make_fixtures.py <out-dir>`` (or :func:`build_all`).
Nothing is read from this PC's real home folder.
"""

from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import sys
from pathlib import Path

CWD = "C:\\Users\\u1\\proj"


def _fake(prefix: str, body: str, length: int) -> str:
    return prefix + (body * length)[:length]


# Assembled secrets (never literal key shapes in the source).
SK_ANT = _fake("sk-" + "ant-api03-", "FaKe0", 40)
SK_PROJ = _fake("sk-" + "proj-", "FaKe1", 40)
SK_PLAIN = _fake("sk" + "-", "FaKe2", 32)
AIZA = _fake("AI" + "za", "FaKe3", 35)
HF = _fake("hf" + "_", "FaKe4", 34)
GHP = _fake("gh" + "p_", "FaKe5", 36)
GH_PAT = _fake("github" + "_pat_", "FaKe6_", 60)
XAI = _fake("xa" + "i-", "FaKe7", 40)
GSK = _fake("gs" + "k_", "FaKe8", 40)
AKIA = _fake("AK" + "IA", "FAKE9", 16)
TOKEN_QUERY = "tq" + "Secret" + "Value" + "1234"
TOKEN_BARE = "tb" + "Secret" + "Value" + "5678"
BEARER = "br" + "Secret" + "Token" + "ABCDEFGH"
CRED_FILE = "CRED" + "FILE" + "Secret" + "0001"
COOKIE_FILE = "COOKIE" + "Secret" + "0002"
CURSOR_SECRET = "CURSOR" + "Secret" + "Value" + "0003"
CURSOR_ACCESS = "CURSOR" + "Access" + "Token" + "0004"
ANTIGRAVITY_AUTH = "AGY" + "Auth" + "Status" + "0005"
ZCODE_KEY = "ZCODE" + "Api" + "Key" + "0006"
SWAP_CRED = "SWAP" + "Cred" + "0007"
GEMINI_TOKEN = "GEMINI" + "Oauth" + "0008"
EMAIL_LOCALS = ("alice.secret", "bob.private", "carol.hidden", "dave.cursor")


def secret_values() -> list[str]:
    """Every value that must never appear in an emitted row or timeline event."""
    return [
        SK_ANT, SK_PROJ, SK_PLAIN, AIZA, HF, GHP, GH_PAT, XAI, GSK, AKIA,
        TOKEN_QUERY, TOKEN_BARE, BEARER, CRED_FILE, COOKIE_FILE, CURSOR_SECRET, CURSOR_ACCESS,
        ANTIGRAVITY_AUTH, ZCODE_KEY, SWAP_CRED, GEMINI_TOKEN, *EMAIL_LOCALS,
    ]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


def _json(path: Path, value: object) -> Path:
    return _write(path, json.dumps(value, ensure_ascii=False, indent=1))


def _jsonl(path: Path, records: list[object]) -> Path:
    lines = [r if isinstance(r, str) else json.dumps(r, ensure_ascii=False) for r in records]
    return _write(path, "\n".join(lines) + "\n")


def _db(path: Path, script: str, rows: dict[str, list[tuple]] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.executescript(script)
        for table, values in (rows or {}).items():
            for value in values:
                marks = ",".join("?" for _ in value)
                conn.execute(f"INSERT INTO {table} VALUES ({marks})", value)
        conn.commit()
    finally:
        conn.close()
    return path


# --- Claude Code ---------------------------------------------------------------------------

CLAUDE_CODE_EXPECTED = {
    "sessions": 5,
    "subagent_sessions": 2,
    "messages_session": 10,
    "messages_history": 2,
    "tool_calls": 7,
    "file_touches": 6,
    "mcp_rows": 6,
    "unknown_types": {"future-type": 1},
    "credential_rows": 2,
    "destructive_calls": 1,
}


def _cc(rtype: str, sid: str, ts: str, version: str, **extra: object) -> dict:
    record = {"type": rtype, "uuid": f"{sid}-{ts[-9:-1]}", "parentUuid": None, "sessionId": sid, "timestamp": ts, "version": version, "cwd": CWD, "gitBranch": "main", "userType": "external", "isSidechain": False, "permissionMode": "default"}
    record.update(extra)
    return record


def build_claude_code(home: Path) -> None:
    base = home / ".claude"
    _json(base / "settings.json", {"cleanupPeriodDays": 30, "model": "opus", "env": {"ANTHROPIC_API_KEY": SK_ANT, "HTTPS_PROXY": "http://proxy.example:8080"}, "permissions": {"allow": ["Bash(ls:*)"], "deny": []}})
    _write(base / ".last-cleanup", "2026-10-01T00:00:00.000Z")
    _json(base / ".credentials.json", {"claudeAiOauth": {"accessToken": CRED_FILE, "refreshToken": CRED_FILE}})
    _write(base / "CLAUDE.md", f"# House rules\nNever print token={TOKEN_BARE} in logs.\n")
    _write(base / "skills" / "s1" / "SKILL.md", "---\nname: s1\n---\nA fake skill.\n")
    _write(base / "shell-snapshots" / "snapshot-bash-1.sh", f"export OPENAI_API_KEY={SK_PROJ}\n")
    _json(base / "sessions" / "1234.json", {"pid": 1234, "sessionId": "sess-A", "cwd": CWD, "startedAt": 1791594000000})
    _write(base / "sessions" / "1234.abcd.key", CRED_FILE)
    _write(base / "file-history" / "sess-A" / "f1@v1", "x")
    _write(base / "file-history" / "sess-A" / "f2@v1", "y")
    _jsonl(
        base / "history.jsonl",
        [
            {"display": "list the files", "pastedContents": {}, "project": CWD, "sessionId": "sess-A", "timestamp": 1791594000000},
            {"display": "use this config [Pasted text #1]", "pastedContents": {"1": {"id": 1, "type": "text", "content": f"GITHUB_TOKEN={GHP}\nurl=https://api.example.com/?token={TOKEN_QUERY}"}}, "project": CWD, "sessionId": "sess-B", "timestamp": 1791597600000},
        ],
    )
    _json(
        home / ".claude.json",
        {
            "primaryApiKey": SK_PLAIN,
            "oauthAccount": {"emailAddress": "alice.secret@corp.example", "organizationName": "Corp Org", "accountUuid": "00000000-0000-0000-0000-00000000aaaa"},
            "mcpServers": {"local-fs": {"command": "npx", "args": ["-y", "@example/mcp-fs"], "env": {"API_TOKEN": TOKEN_BARE}}},
            "projects": {CWD: {"mcpServers": {"remote": {"type": "http", "url": f"https://mcp.example.com/sse?token={TOKEN_QUERY}"}}}},
        },
    )
    proj = base / "projects" / "C--Users-u1-proj"
    v1, v2 = "2.1.293", "2.1.308"
    image = base64.b64encode(b"\x89PNG fake image bytes" * 20).decode()
    _jsonl(
        proj / "sess-A.jsonl",
        [
            _cc("user", "sess-A", "2026-10-10T01:00:00.000Z", v1, message={"role": "user", "content": f"Please list {CWD} files. My key is {SK_ANT}"}),
            _cc(
                "assistant", "sess-A", "2026-10-10T01:00:05.000Z", v1,
                message={"role": "assistant", "model": "claude-opus-4", "content": [
                    {"type": "thinking", "thinking": "plan"},
                    {"type": "text", "text": "I will run a command"},
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": f"dir {CWD} && type {CWD}\\.env"}},
                ], "usage": {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 50}},
            ),
            _cc("user", "sess-A", "2026-10-10T01:00:06.000Z", v1, message={"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": f"OPENAI={AKIA}\nfiles"}]}, toolUseResult={"stdout": "files", "exitCode": 0}),
            _cc(
                "assistant", "sess-A", "2026-10-10T01:01:00.000Z", v1,
                message={"role": "assistant", "model": "claude-opus-4", "content": [
                    {"type": "tool_use", "id": "t2", "name": "Edit", "input": {"file_path": f"{CWD}\\app.py", "old_string": "a", "new_string": f"KEY='{XAI}'"}},
                    {"type": "tool_use", "id": "t3", "name": "Read", "input": {"file_path": f"{CWD}\\README.md"}},
                ]},
            ),
            _cc("user", "sess-A", "2026-10-10T01:01:01.000Z", v1, message={"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t2", "content": "ok"}, {"type": "tool_result", "tool_use_id": "t3", "content": "readme", "is_error": False}]}),
            _cc("attachment", "sess-A", "2026-10-10T01:01:02.000Z", v1, attachment={"type": "mcp_server_status", "failed": ["srvFail"], "pending": ["srvPend"], "needsAuth": [{"name": "srvAuth"}]}),
            _cc(
                "assistant", "sess-A", "2026-10-10T01:02:00.000Z", v1,
                message={"role": "assistant", "model": "claude-opus-4", "content": [
                    {"type": "text", "text": "Done"},
                    {"type": "tool_use", "id": "t4", "name": "mcp__github__create_issue", "input": {"title": "x"}},
                ]},
            ),
            _cc("user", "sess-A", "2026-10-10T01:03:00.000Z", v1, message={"role": "user", "content": [{"type": "text", "text": "see screenshot"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image}}]}),
            _cc("custom-title", "sess-A", "2026-10-10T01:03:01.000Z", v1, customTitle="Fix app"),
            _cc("assistant", "sess-A", "2026-10-10T01:04:00.000Z", v1, message={"role": "assistant", "model": "claude-opus-4", "content": [{"type": "tool_use", "id": "t5", "name": "Bash", "input": {"command": f"rm -rf {CWD}\\build"}}]}),
        ],
    )
    sub = proj / "sess-A" / "subagents"
    _jsonl(
        sub / "agent-a1.jsonl",
        [
            _cc("user", "sess-A", "2026-10-10T01:00:10.000Z", v1, agentId="a1", isSidechain=True, message={"role": "user", "content": "Search for TODO"}),
            _cc("assistant", "sess-A", "2026-10-10T01:00:11.000Z", v1, agentId="a1", isSidechain=True, message={"role": "assistant", "model": "claude-haiku", "content": [{"type": "text", "text": "Searching"}, {"type": "tool_use", "id": "s1", "name": "Grep", "input": {"pattern": "TODO", "path": CWD}}]}),
        ],
    )
    _jsonl(
        sub / "agent-a2.jsonl",
        [
            _cc("user", "sess-A", "2026-10-10T01:00:20.000Z", v1, agentId="a2", isSidechain=True, message={"role": "user", "content": "Write notes"}),
            _cc("assistant", "sess-A", "2026-10-10T01:00:21.000Z", v1, agentId="a2", isSidechain=True, message={"role": "assistant", "content": [{"type": "tool_use", "id": "s2", "name": "Write", "input": {"file_path": f"{CWD}\\notes.md", "content": f"Authorization: Bearer {BEARER}"}}]}),
        ],
    )
    _jsonl(
        proj / "sess-B.jsonl",
        [
            _cc("user", "sess-B", "2026-10-11T02:00:00.000Z", v2, message={"role": "user", "content": "hello"}, entrypoint="cli"),
            _cc("future-type", "sess-B", "2026-10-11T02:00:01.000Z", v2, payload={"x": 1}),
            _cc("assistant", "sess-B", "2026-10-11T02:00:02.000Z", v2, message={"role": "assistant", "model": "claude-sonnet-4", "content": [{"type": "text", "text": "hi"}], "usage": {"input_tokens": 10, "output_tokens": 5}}),
            _cc("queue-operation", "sess-B", "2026-10-11T02:00:03.000Z", v2, operation="enqueue"),
        ],
    )
    _jsonl(
        proj / "sess-C.jsonl",
        [
            _cc("user", "sess-C", "2026-10-12T03:00:00.000Z", v2, message={"role": "user", "content": "x"}),
            "{not json",
            _cc("system", "sess-C", "2026-10-12T03:00:01.000Z", v2, content="compact"),
        ],
    )


# --- Codex ---------------------------------------------------------------------------------

CODEX_EXPECTED = {
    "sessions": 5,
    "sessions_without_wal": 4,
    "messages": 9,
    "tool_calls": 2,
    "file_touches": 2,
    "usage_rows": 2,
    "mcp_rows": 2,
    "instruction_rows": 4,
    "credential_rows": 3,
}

_THREADS_SQL = """
PRAGMA journal_mode=WAL;
CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, created_at INTEGER, updated_at INTEGER, source TEXT, model_provider TEXT,
  cwd TEXT, title TEXT, sandbox_policy TEXT, approval_mode TEXT, tokens_used INTEGER, has_user_event INTEGER, archived INTEGER,
  archived_at INTEGER, git_sha TEXT, git_branch TEXT, git_origin_url TEXT, cli_version TEXT, first_user_message TEXT,
  agent_nickname TEXT, agent_role TEXT, memory_mode TEXT, model TEXT, reasoning_effort TEXT, agent_path TEXT,
  created_at_ms INTEGER, updated_at_ms INTEGER, thread_source TEXT, preview TEXT);
CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT, status TEXT);
CREATE TABLE thread_dynamic_tools (thread_id TEXT, position INTEGER, name TEXT, description TEXT, input_schema TEXT, defer_loading INTEGER, namespace TEXT);
CREATE TABLE remote_control_enrollments (websocket_url TEXT, account_id TEXT);
"""


def _thread(tid: str, created_s: int, tokens: int, model: str, first: str, version: str) -> tuple:
    return (
        tid, f"C:\\Users\\u1\\.codex\\sessions\\{tid}.jsonl", created_s, created_s + 600, "cli", "openai", CWD, f"title {tid}",
        "workspace-write", "on-request", tokens, 1, 0, None, "abc123", "main", f"https://user:{TOKEN_BARE}@git.example.com/r.git",
        version, first, None, None, None, model, "medium", None, created_s * 1000, (created_s + 600) * 1000, "user", "preview",
    )


def _insert(conn: sqlite3.Connection, rows: dict[str, list[tuple]]) -> None:
    for table, values in rows.items():
        for value in values:
            conn.execute(f"INSERT INTO {table} VALUES ({','.join('?' for _ in value)})", value)


def wal_db(path: Path, script: str, base_rows: dict[str, list[tuple]], wal_rows: dict[str, list[tuple]]) -> Path:
    """A WAL-mode database whose ``wal_rows`` exist only in the ``-wal`` sidecar (the three files
    are copied while the writer is still open, so its closing checkpoint never folds them in)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    work = path.parent / ("_work_" + path.name)
    for suffix in ("", "-wal", "-shm"):
        Path(str(work) + suffix).unlink(missing_ok=True)
        Path(str(path) + suffix).unlink(missing_ok=True)
    conn = sqlite3.connect(work)
    try:
        conn.executescript(script)
        conn.execute("PRAGMA wal_autocheckpoint=0")
        _insert(conn, base_rows)
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        _insert(conn, wal_rows)
        conn.commit()
        for suffix in ("", "-wal", "-shm"):
            shutil.copyfile(str(work) + suffix, str(path) + suffix)
    finally:
        conn.close()
    for suffix in ("", "-wal", "-shm"):
        Path(str(work) + suffix).unlink(missing_ok=True)
    return path


def build_codex(home: Path) -> None:
    base = home / ".codex"
    t0 = 1791853200  # 2026-10-13T03:00:00Z
    wal_db(
        base / "sqlite" / "state_5.sqlite",
        _THREADS_SQL,
        {
            "threads": [
                _thread("thread-1", t0, 1000, "gpt-5", f"fix the build, key {SK_PROJ}", "0.50.0"),
                _thread("thread-2", t0 + 60, 500, "gpt-5", "subtask", "0.50.0"),
            ],
            "thread_spawn_edges": [("thread-1", "thread-2", "completed")],
            "thread_dynamic_tools": [("thread-1", 0, "fs_read", "d", "{}", 0, "ns")],
            "remote_control_enrollments": [("wss://example.invalid/ws", "acct-1")],
        },
        {"threads": [_thread("thread-3", t0 + 86400, 200, "gpt-5-mini", "newest thread only in WAL", "0.51.0")]},
    )
    remove = json.dumps({"command": ["powershell", "-c", f"Remove-Item {CWD}\\old.txt"]})
    ledger = [
        ("thread-1", 1, {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "fix the build"}], "timestamp": "2026-10-13T03:00:01Z"}),
        ("thread-1", 2, {"type": "reasoning", "summary": [], "timestamp": "2026-10-13T03:00:02Z"}),
        ("thread-1", 3, {"payload": {"type": "function_call", "name": "shell", "call_id": "c1", "arguments": remove}, "timestamp": "2026-10-13T03:00:03Z"}),
        ("thread-1", 4, {"type": "function_call_output", "call_id": "c1", "output": json.dumps({"output": "", "metadata": {"exit_code": 0}}), "timestamp": "2026-10-13T03:00:04Z"}),
        ("thread-1", 5, {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "removed"}], "timestamp": "2026-10-13T03:00:05Z"}),
        ("thread-1", 6, {"type": "ghost_snapshot_v9", "timestamp": "2026-10-13T03:00:06Z"}),
    ]
    _db(
        base / "sqlite" / "codex-dev.db",
        """
        CREATE TABLE local_thread_catalog (host_id TEXT, thread_id TEXT, display_title TEXT, source_created_at INTEGER, source_updated_at INTEGER,
          cwd TEXT, source_kind TEXT, source_detail TEXT, model_provider TEXT, git_branch TEXT, thread_source TEXT, project_id TEXT,
          conversation_origin TEXT, chatgpt_async_status TEXT);
        CREATE TABLE thread_timeline_ledger (host_id TEXT, thread_id TEXT, sequence INTEGER, record_id TEXT, payload_json TEXT);
        CREATE TABLE automations (id TEXT, name TEXT, prompt TEXT, status TEXT, rrule TEXT, model TEXT, cwds TEXT);
        CREATE TABLE automation_runs (thread_id TEXT, thread_title TEXT, source_cwd TEXT, archived_user_message TEXT, archived_assistant_message TEXT, created_at INTEGER);
        """,
        {
            "local_thread_catalog": [
                ("h", "thread-1", "title thread-1", t0, t0 + 600, CWD, "cli", "", "openai", "main", "user", "p1", "", ""),
                ("h", "thread-4", "cloud only", t0 + 7200, t0 + 7300, "C:\\Users\\u1\\other", "cloud", "", "openai", "dev", "user", "p2", "", ""),
            ],
            "thread_timeline_ledger": [("h", tid, seq, f"r{seq}", json.dumps(payload)) for tid, seq, payload in ledger],
            "automation_runs": [("thread-4", "nightly", CWD, f"run nightly with api_key={TOKEN_BARE}", "nightly done", t0 + 7200)],
        },
    )
    _db(
        base / "sqlite" / "logs_2.sqlite",
        "CREATE TABLE logs (id INTEGER, ts INTEGER, ts_nanos INTEGER, level TEXT, target TEXT, feedback_log_body TEXT, module_path TEXT, file TEXT, line INTEGER, thread_id TEXT, process_uuid TEXT, estimated_bytes INTEGER);",
        {"logs": [(i, t0 + i, 0, "INFO", "codex", f"request body Authorization: Bearer {BEARER}", "", "", 0, "thread-1", "p", 10) for i in range(3)]},
    )
    _db(
        base / "sqlite" / "memories_1.sqlite",
        "CREATE TABLE stage1_outputs (thread_id TEXT, raw_memory TEXT, rollout_summary TEXT, rollout_slug TEXT, generated_at INTEGER, usage_count INTEGER);",
        {"stage1_outputs": [("thread-1", f"user prefers PowerShell; secret={TOKEN_BARE}", "summary", "slug", t0, 1)]},
    )
    _db(
        base / "sqlite" / "goals_1.sqlite",
        "CREATE TABLE thread_goals (thread_id TEXT, goal_id TEXT, objective TEXT, status TEXT, token_budget INTEGER, tokens_used INTEGER, time_used_seconds INTEGER);",
        {"thread_goals": [("thread-1", "g1", "make the build green", "done", 1000, 900, 60)]},
    )
    cat = json.dumps({"command": ["bash", "-lc", f"cat {CWD}\\a.txt"]})
    _jsonl(
        base / "sessions" / "2026" / "10" / "14" / "rollout-2026-10-14T05-00-00-thread-5.jsonl",
        [
            {"timestamp": "2026-10-14T05:00:00Z", "type": "session_meta", "payload": {"id": "thread-5", "timestamp": "2026-10-14T05:00:00Z", "cwd": CWD, "cli_version": "0.49.0", "git": {"branch": "feat", "repository_url": "https://git.example.com/r.git"}}},
            {"timestamp": "2026-10-14T05:00:01Z", "type": "turn_context", "payload": {"model": "gpt-5-codex", "cwd": CWD}},
            {"timestamp": "2026-10-14T05:00:02Z", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"read the file, token is {SK_PLAIN}"}]}},
            {"timestamp": "2026-10-14T05:00:03Z", "type": "response_item", "payload": {"type": "function_call", "name": "shell", "call_id": "c9", "arguments": cat}},
            {"timestamp": "2026-10-14T05:00:04Z", "type": "response_item", "payload": {"type": "function_call_output", "call_id": "c9", "output": json.dumps({"output": "text", "metadata": {"exit_code": 1}})}},
            {"timestamp": "2026-10-14T05:00:05Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]}},
            {"timestamp": "2026-10-14T05:00:06Z", "type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 70, "output_tokens": 30}}}},
        ],
    )
    _write(base / "memories" / ".git" / "HEAD", "ref: refs/heads/main\n")
    _write(base / "memories" / "rollout_summaries" / "thread-1.md", "# thread-1\nFixed the build.\n")
    _write(base / "attachments" / "pasted-text-1.txt", f"pasted: OPENAI_API_KEY={SK_PROJ}\n")
    _write(base / "AGENTS.md", "# Agents\nBe careful.\n")
    _write(
        base / "config.toml",
        f'model = "gpt-5"\n\n[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "@example/docs"]\nenv = {{ DOCS_TOKEN = "{TOKEN_BARE}" }}\n\n'
        f'[mcp_servers.remote]\nurl = "https://mcp.example.net/x?api_key={TOKEN_QUERY}"\n',
    )
    _json(base / "auth.json", {"OPENAI_API_KEY": SK_PROJ, "tokens": {"access_token": CRED_FILE}})
    _write(base / ".sandbox-secrets" / "s1", CRED_FILE)
    _write(base / "mcp-oauth-locks" / "lock1", CRED_FILE)


# --- Cursor --------------------------------------------------------------------------------

CURSOR_EXPECTED = {
    "sessions": 4,
    "messages": 7,
    "tool_calls": 3,
    "file_touches": 3,
    "attribution_rows": 4,
    "usage_rows": 2,
    "credential_rows": 2,
    "account_rows": 1,
    "mcp_rows": 1,
    "undecoded_values": 1,
}

_VSCDB_SQL = "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);"


def build_cursor(home: Path) -> None:
    user = home / "AppData" / "Roaming" / "Cursor" / "User"
    t = "2026-09-20T10:00:0{}.000Z"
    bubbles = {
        "bubbleId:comp-1:b1": {"type": 1, "text": f"refactor app.py, key {AIZA}", "createdAt": t.format(1)},
        "bubbleId:comp-1:b2": {"type": 2, "text": "Running", "createdAt": t.format(2), "toolFormerData": {"name": "run_terminal_cmd", "toolCallId": "tc1", "status": "completed", "params": json.dumps({"command": f"del {CWD}\\tmp.txt"}), "result": "ok"}},
        "bubbleId:comp-1:b3": {"type": 2, "text": "Edited", "createdAt": t.format(3), "toolFormerData": {"name": "edit_file", "params": json.dumps({"target_file": f"{CWD}\\app.py"})}},
        "bubbleId:comp-2:b4": {"type": 1, "text": "explore the repo", "createdAt": t.format(4)},
    }
    kv: list[tuple] = [(k, json.dumps(v).encode()) for k, v in bubbles.items()]
    kv += [
        ("bubbleId:comp-2:b5", b"\x00\x01binary-not-json"),
        ("composerData:comp-1", json.dumps({"composerId": "comp-1", "name": "Refactor", "createdAt": 1790157600000, "fullConversationHeadersOnly": [{"bubbleId": "b1", "type": 1}, {"bubbleId": "b2", "type": 2}, {"bubbleId": "b3", "type": 2}], "modelConfig": {"modelName": "claude-4-sonnet"}})),
        ("codeBlockDiff:comp-1:d1", json.dumps({"uri": {"fsPath": f"{CWD}\\app.py"}, "newModelDiffWrtV0": []})),
        ("agentKv:xyz", b"\x01\x02"),
        ("checkpointId:comp-1:c1", "{}"),
        ("futurePrefix:abc", "{}"),
    ]
    _db(
        user / "globalStorage" / "state.vscdb",
        _VSCDB_SQL
        + "CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);"
        + "CREATE TABLE composerHeaders (composerId TEXT, workspaceId TEXT, createdAt INTEGER, lastUpdatedAt INTEGER, isArchived INTEGER, isSubagent INTEGER, recency INTEGER, checkpointAt INTEGER, value TEXT, subagentTypeName TEXT);",
        {
            "ItemTable": [
                ('secret://{"extensionId":"cursor.auth","key":"x"}', CURSOR_SECRET.encode()),
                ("cursorAuth/accessToken", CURSOR_ACCESS),
                ("cursorAuth/cachedEmail", "dave.cursor@corp.example"),
                ("aiCodeTracking.dailyStats.v1.5.2026-09-20", json.dumps({"date": "2026-09-20", "tabSuggestedLines": 10, "tabAcceptedLines": 5, "composerSuggestedLines": 40, "composerAcceptedLines": 30})),
                ("aiCodeTracking.dailyStats.v1.5.2026-09-21", json.dumps({"date": "2026-09-21", "tabAcceptedLines": 2})),
                ("browserAutomation.history", json.dumps([{"url": f"https://example.com/page?token={TOKEN_QUERY}", "timestamp": 1790157700000}])),
                ("cloudAgentRepository.agents.a1", "{}"),
            ],
            "cursorDiskKV": kv,
            "composerHeaders": [
                ("comp-1", "ws-1", 1790157600000, 1790157900000, 0, 0, 1, None, json.dumps({"name": "Refactor"}), None),
                ("comp-2", "ws-1", 1790157650000, 1790157700000, 0, 1, 2, None, json.dumps({"parentComposerId": "comp-1"}), "explore"),
            ],
        },
    )
    _json(user / "workspaceStorage" / "ws-1" / "workspace.json", {"folder": "file:///c%3A/Users/u1/proj"})
    _db(user / "workspaceStorage" / "ws-1" / "state.vscdb", _VSCDB_SQL, {"ItemTable": [("aiService.prompts", json.dumps([{"text": "hi from workspace", "commandType": 4}]))]})
    dot = home / ".cursor"
    _db(
        dot / "ai-tracking" / "ai-code-tracking.db",
        """
        CREATE TABLE ai_code_hashes (hash TEXT, source TEXT, fileExtension TEXT, fileName TEXT, requestId TEXT, conversationId TEXT, timestamp INTEGER, model TEXT, createdAt INTEGER);
        CREATE TABLE scored_commits (commitHash TEXT, branchName TEXT, scoredAt INTEGER, linesAdded INTEGER, linesDeleted INTEGER, tabLinesAdded INTEGER,
          composerLinesAdded INTEGER, humanLinesAdded INTEGER, commitMessage TEXT, commitDate TEXT, v1AiPercentage REAL, v2AiPercentage REAL);
        """,
        {
            "ai_code_hashes": [
                ("h1", "composer", "py", f"{CWD}\\app.py", "r1", "comp-1", 1790157700000, "claude-4-sonnet", 1790157700000),
                ("h2", "composer", "py", f"{CWD}\\app.py", "r1", "comp-1", 1790157710000, "claude-4-sonnet", 1790157710000),
                ("h3", "tab", "py", f"{CWD}\\util.py", "r2", "", 1790157720000, "tab-model", 1790157720000),
            ],
            "scored_commits": [
                ("c0ffee1", "main", 1790160000000, 100, 10, 20, 40, 40, f"feat: x (token={TOKEN_BARE})", "2026-09-20T11:00:00Z", 55.0, 60.0),
                ("c0ffee2", "main", 1790170000000, 10, 0, 0, 0, 10, "docs", "2026-09-20T14:00:00Z", 0.0, 0.0),
            ],
        },
    )
    _jsonl(dot / "projects" / "C-Users-u1-proj" / "agent-transcripts" / "t1.jsonl", [{"role": "user", "content": "hello"}, {"role": "assistant", "content": [{"type": "text", "text": "hi"}]}, {"kind": "meta"}])
    _json(dot / "mcp.json", {"mcpServers": {"browser": {"command": "npx", "args": ["@example/browser-mcp"], "env": {"KEY": SK_PLAIN}}}})


# --- driver --------------------------------------------------------------------------------

BUILDERS = {
    "claude_code": build_claude_code,
    "codex": build_codex,
    "cursor": build_cursor,
}


def build_all(root: Path, only: tuple[str, ...] = ()) -> Path:
    """Create ``root/Users/u1`` with every adapter's synthetic tree; returns the home path."""
    home = root / "Users" / "u1"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    for name, builder in BUILDERS.items():
        if not only or name in only:
            builder(home)
    return home


def collect_rows(adapter_cls: type, root: Path, limits: object = None, os_hint: str = "windows") -> list:
    """Run one adapter over ``root`` (detect + collect every found item) and return the run's
    ``ArtifactRecord`` rows (lane A ``AiRow.to_record()``: ``artifact_type`` + flat ``details``)."""
    from rapidtriage.artifacts.ai_agents.adapters._iface import (
        AiLimits,
        EvidenceProfile,
    )

    adapter = adapter_cls()
    profile = EvidenceProfile(home=root / "Users" / "u1", user="u1", os=os_hint, system_root=root)
    rows: list = []
    for found in adapter.detect([profile], os_hint):
        rows.extend(row.to_record() for row in adapter.collect(found, limits or AiLimits()))
    return rows


def by_type(rows: list, artifact_type: str) -> list:
    return [row for row in rows if row.artifact_type == artifact_type]


def summary_of(rows: list) -> dict:
    """The adapter run summary row (``ai-tool-presence`` / ``presence_kind=adapter-summary``)."""
    return next(row.details for row in rows if row.artifact_type == "ai-tool-presence" and row.details.get("presence_kind") == "adapter-summary")


if __name__ == "__main__":  # pragma: no cover - manual use
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "ai-agent-fixtures")
    print(build_all(out))
