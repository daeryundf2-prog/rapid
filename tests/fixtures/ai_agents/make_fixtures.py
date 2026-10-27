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


# --- Antigravity ---------------------------------------------------------------------------

ANTIGRAVITY_EXPECTED = {
    "sessions": 3,
    "messages": 4,
    "tool_calls": 3,
    "file_touches": 5,
    "mcp_rows": 2,
    "credential_rows": 1,
    "conv1_steps": 3,
}


def build_antigravity(home: Path) -> None:
    base = home / ".gemini" / "antigravity"
    _db(
        base / "conversation_summaries.db",
        """
        CREATE TABLE conversation_summaries (conversation_id TEXT, title TEXT, preview TEXT, step_count INTEGER, last_modified_time INTEGER,
          workspace_uris TEXT, status TEXT, source TEXT, project_id TEXT, agent_name TEXT, parent_conversation_id TEXT, nesting_depth INTEGER,
          battle_id TEXT, winning_conversation_id TEXT, not_fully_idle INTEGER, killed INTEGER, last_user_input_time INTEGER,
          last_user_input_step_index INTEGER, app_data_dir TEXT, raw_summary BLOB, group_id TEXT);
        CREATE VIRTUAL TABLE conversations_fts USING fts5(conversation_id, chunk_index, title, user_body, agent_body);
        """,
        {
            "conversation_summaries": [
                ("conv-1", "Build site", f"build it with {AIZA}", 10, 1790841600, json.dumps(["file:///c%3A/Users/u1/proj"]), "IDLE", "IDE", "proj", "main", "", 0, None, None, 0, 0, 1790841500, 3, "", b"\x08\x01", ""),
                ("conv-2", "Sub check", "check", 2, 1790841700, "[]", "IDLE", "IDE", "proj", "checker", "conv-1", 1, None, None, 0, 0, 1790841650, 1, "", b"", ""),
                ("conv-3", "Old chat", "old", 4, 1790000000, "[]", "IDLE", "IDE", "", "main", "", 0, None, None, 0, 1, 1790000000, 1, "", b"", ""),
            ],
            "conversations_fts": [("conv-1", 0, "Build site", f"user text {AIZA}", "agent text")],
        },
    )
    steps_sql = """
        CREATE TABLE steps (idx INTEGER, step_type INTEGER, status INTEGER, has_subtrajectory INTEGER, metadata BLOB, error_details BLOB,
          permissions BLOB, task_details BLOB, render_info BLOB, step_payload BLOB, step_format INTEGER);
        CREATE TABLE trajectory_meta (trajectory_id TEXT, cascade_id TEXT, trajectory_type INTEGER, source INTEGER);
    """
    _db(
        base / "conversations" / "conv-1.db",
        steps_sql,
        {
            "steps": [(i, 14 if i else 1, 3, 0, b"", b"", b"", b"", b"", (f"\x0a\x10protobuf {AIZA}" * 3).encode(), 1) for i in range(3)],
            "trajectory_meta": [("traj-1", "cascade-1", 1, 1)],
        },
    )
    _db(base / "conversations" / "conv-2.db", steps_sql, {"steps": [(0, 1, 3, 0, b"", b"", b"", b"", b"", b"\x0a\x01x", 1)]})
    logs = base / "brain" / "conv-1" / ".system_generated" / "logs"
    _jsonl(
        logs / "transcript.jsonl",
        [
            {"content": f"Build a site, my key {AIZA}", "created_at": "2026-09-25T08:00:00Z", "source": "USER_EXPLICIT", "status": "DONE", "step_index": 0, "type": "USER_INPUT"},
            {
                "content": "Creating files", "created_at": "2026-09-25T08:00:01Z", "source": "MODEL", "status": "DONE", "step_index": 1, "type": "PLANNER_RESPONSE",
                "tool_calls": [{"name": "write_to_file", "args": {"TargetFile": f"{CWD}\\index.html", "CodeContent": f"<!-- {GSK} -->"}}, {"name": "run_command", "args": {"CommandLine": "npm install", "Cwd": CWD}}],
                "input_tokens": 100, "output_tokens": 50,
            },
            {"type": "FUTURE_STEP_KIND", "created_at": "2026-09-25T08:00:02Z", "source": "SYSTEM", "step_index": 2},
        ],
    )
    _json(
        base / "brain" / "conv-1" / ".system_generated" / "messages" / "m1.json",
        {"id": "m1", "sender": "main", "recipient": "checker", "priority": 1, "content": "please check index.html", "timestamp": "2026-09-25T08:00:05Z",
         "sourceMetadata": {"tool": {"conversationId": "conv-1", "stepIndex": 2, "toolCall": {"id": "tc9", "name": "view_file", "argumentsJson": json.dumps({"AbsolutePath": f"{CWD}\\index.html"})}}}},
    )
    _write(base / "brain" / "conv-1" / "scratch" / "notes.txt", f"scratch {GSK}")
    _write(base / "brain" / "conv-1" / "plan.md", "# Plan\nbuild\n")
    _jsonl(base / "brain" / "conv-2" / ".system_generated" / "logs" / "transcript_full.jsonl", [{"content": "check it", "created_at": "2026-09-25T08:01:00Z", "source": "USER_IMPLICIT", "step_index": 0, "type": "USER_INPUT"}])
    _json(base / "mcp" / "github" / "create_issue.json", {"name": "create_issue"})
    _json(base / "mcp" / "github" / "list_repos.json", {"name": "list_repos"})
    _json(base / "mcp" / "fs" / "read.json", {"name": "read"})
    _write(base / "scratch" / "out.csv", "a,b\n")
    _db(
        home / "AppData" / "Roaming" / "Antigravity" / "User" / "globalStorage" / "state.vscdb",
        _VSCDB_SQL,
        {"ItemTable": [("antigravityAuthStatus", ANTIGRAVITY_AUTH), ("antigravity.profileUrl", "https://example.invalid/p"), ("antigravity.notification.1", "{}")]},
    )


# --- Kiro ----------------------------------------------------------------------------------

KIRO_EXPECTED = {"sessions": 2, "messages": 2, "mcp_rows": 2, "credential_rows": 1, "instruction_rows": 1}


def build_kiro(home: Path) -> None:
    base = home / ".kiro"
    _json(
        base / "sessions" / "wsh1" / "sess_k1" / "session.json",
        {"id": "sess_k1", "title": "Kiro spec", "createdAt": "2026-08-29T01:00:00Z", "lastModifiedAt": "2026-08-29T02:00:00Z", "modelId": "claude-sonnet-4",
         "agentMode": "spec", "autopilot": True, "rootPaths": [CWD], "workspacePaths": [CWD], "specWorkflow": True, "dataModelVersion": 2, "schemaVersion": 1},
    )
    _json(
        base / "sessions" / "wsh1" / "sess_k2" / "session.json",
        {"id": "sess_k2", "title": "Chat", "createdAt": 1788310800000, "lastModifiedAt": 1788314400000, "modelId": "auto",
         "history": [{"role": "user", "content": f"hi {XAI}"}, {"role": "assistant", "content": "hello"}]},
    )
    _jsonl(base / "session-index" / "wsh1.jsonl", [{"at": 1788224400000, "op": "create", "sessionPath": "wsh1/sess_k1"}, {"at": 1788310800000, "op": "create", "sessionPath": "wsh1/sess_k2"}])
    _write(
        base / "logs" / "20260829T010000" / "mcp.log",
        "2026-08-29 01:00:01.000 [info] [fetch] Starting MCP server\n"
        "2026-08-29 01:00:02.000 [info] [fetch] connected\n"
        f"2026-08-29 01:00:03.000 [error] [aws-docs] failed to start: token={TOKEN_BARE}\n",
    )
    _write(base / "logs" / "20260829T010000" / "kiro.log", "2026-08-29 01:00:00.000 [info] start\n")
    _write(base / "steering" / "product.md", "# Product\n")
    _db(
        home / "AppData" / "Roaming" / "Kiro" / "User" / "globalStorage" / "state.vscdb",
        _VSCDB_SQL,
        {"ItemTable": [("chat.ChatSessionStore.index", "{}"), ("kiro.kiroAgent", "{}"), ("kiroAgent.auth.token", CRED_FILE)]},
    )


# --- OmO -----------------------------------------------------------------------------------

OMO_EXPECTED = {"sessions": 2, "messages": 4, "tool_calls": 1, "file_touches": 1, "instruction_rows": 3, "credential_rows": 2}


def build_omo(home: Path) -> None:
    base = home / ".omo"
    _write(base / "omo.jsonc", f'{{\n  // provider config\n  "apiKey": "{SK_ANT}",\n  "model": "x",\n}}\n')
    _write(base / "omo.jsonc.bak-20261001", "{}")
    _json(base / "install.json", {"version": "5.1.28"})
    sid = "2026-10-09T01-02-03-456Z_0000-uuid1"
    _jsonl(
        base / "agent" / "sessions" / "C--Users-u1-proj" / f"{sid}.jsonl",
        [
            {"type": "session", "id": "uuid1", "cwd": CWD, "timestamp": "2026-10-09T01:02:03.456Z"},
            {"type": "message", "timestamp": "2026-10-09T01:02:04Z", "message": {"role": "user", "content": [{"type": "text", "text": f"refactor, token {GHP}"}]}},
            {"type": "message", "timestamp": "2026-10-09T01:02:05Z", "message": {"role": "assistant", "content": [{"type": "text", "text": "ok"}, {"type": "toolCall", "id": "tc1", "name": "bash", "arguments": {"command": f"Remove-Item -Recurse {CWD}\\dist"}}]}},
            {"type": "custom", "customType": "omo-state", "data": {"sessionId": "uuid1"}},
        ],
    )
    _write(base / "agent" / "auth.json", CRED_FILE)
    _write(base / "lsp-daemon" / "daemon.auth", CRED_FILE)
    _write(base / "memory" / "agents" / "a1" / "notes.md", "# memory\n")
    _write(base / "plans" / "plan1.md", "# plan\n")
    run = base / "ulw-loop" / "run1"
    _write(run / "brief.md", "# brief\n")
    _json(run / "goals.json", {"activeGoalId": "g1", "goals": [{"id": "g1", "objective": "ship it", "status": "done", "startedAt": "2026-10-09T03:00:00Z"}]})
    _jsonl(run / "ledger.jsonl", [{"at": "2026-10-09T03:00:00Z", "goalId": "g1", "kind": "start", "message": "start", "status": "active"}, {"at": "2026-10-09T04:00:00Z", "goalId": "g1", "kind": "finish", "message": f"done token={TOKEN_BARE}", "status": "done"}])
    (base / "migration-backup-20261001-opencode-config").mkdir(parents=True, exist_ok=True)


# --- ZCode ---------------------------------------------------------------------------------

ZCODE_EXPECTED = {"sessions": 2, "messages": 4, "tool_calls": 2, "destructive": 1, "file_touches": 1, "usage_rows": 1, "credential_rows": 2}


def build_zcode(home: Path) -> None:
    base = home / ".zcode"
    ms = 1790500000000
    tool_part = {"type": "tool", "tool": "bash", "callID": "call1", "state": {"status": "completed", "input": {"command": "rm -rf /home/u1/tmp"}, "output": "ok"}}
    _db(
        base / "cli" / "db" / "db.sqlite",
        """
        CREATE TABLE session (id TEXT, project_id TEXT, workspace_id TEXT, parent_id TEXT, slug TEXT, directory TEXT, path TEXT, title TEXT, version TEXT,
          share_url TEXT, summary_additions INTEGER, summary_deletions INTEGER, summary_files INTEGER, time_created INTEGER, time_updated INTEGER,
          time_archived INTEGER, task_type TEXT, trace_id TEXT);
        CREATE TABLE message (id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT, sequence INTEGER);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT, sequence INTEGER);
        CREATE TABLE input_history (id INTEGER, project_id TEXT, session_id TEXT, text TEXT, kind TEXT, time_created INTEGER, attachments TEXT);
        CREATE TABLE model_usage (logical_request_id TEXT, session_id TEXT, turn_id TEXT, trace_id TEXT, provider_id TEXT, model_id TEXT, agent TEXT, mode TEXT,
          task_type TEXT, status TEXT, started_at INTEGER, completed_at INTEGER, duration_ms INTEGER, input_tokens INTEGER, output_tokens INTEGER, reasoning_tokens INTEGER);
        CREATE TABLE tool_usage (session_id TEXT, turn_id TEXT, tool_call_id TEXT, tool_name TEXT, side_effect_scope TEXT, read_only INTEGER, destructive INTEGER,
          approval_status TEXT, status TEXT, started_at INTEGER, completed_at INTEGER, exit_code INTEGER, output_bytes INTEGER, stdout_bytes INTEGER, stderr_bytes INTEGER);
        CREATE TABLE turn_usage (session_id TEXT, turn_id TEXT, input_tokens INTEGER);
        CREATE TABLE todo (session_id TEXT, content TEXT, status TEXT, priority TEXT, position INTEGER);
        CREATE TABLE session_task_link (parent_session_id TEXT, child_session_id TEXT, role TEXT, depth INTEGER, agent_type TEXT, model TEXT, status TEXT);
        """,
        {
            "session": [
                ("z1", "p1", "w1", None, "slug", CWD, CWD, "Cleanup", "1.0.0", None, 1, 2, 1, ms, ms + 60000, None, "chat", "tr1"),
                ("z2", "p1", "w1", "z1", "slug2", CWD, CWD, "Sub", "1.0.0", None, 0, 0, 0, ms + 1000, ms + 2000, None, "subagent", "tr2"),
            ],
            "message": [
                ("m1", "z1", ms + 1, ms + 1, json.dumps({"role": "user", "time": {"created": ms + 1}}), 1),
                ("m2", "z1", ms + 2, ms + 2, json.dumps({"role": "assistant", "modelID": "glm-4.6", "providerID": "zai", "tokens": {"input": 100, "output": 20}, "time": {"created": ms + 2}}), 2),
                ("m3", "z2", ms + 1001, ms + 1001, json.dumps({"role": "user"}), 1),
            ],
            "part": [
                ("p1", "m1", "z1", ms + 1, ms + 1, json.dumps({"type": "text", "text": f"delete the temp folder, key {GSK}"}), 1),
                ("p2", "m2", "z1", ms + 2, ms + 2, json.dumps({"type": "text", "text": "deleting"}), 1),
                ("p3", "m2", "z1", ms + 3, ms + 3, json.dumps(tool_part), 2),
                ("p4", "m3", "z2", ms + 1001, ms + 1001, json.dumps({"type": "text", "text": "sub task"}), 1),
            ],
            "input_history": [(1, "p1", "z1", "delete the temp folder", "prompt", ms, None)],
            "model_usage": [
                ("r1", "z1", "t1", "tr1", "zai", "glm-4.6", "build", "chat", "chat", "ok", ms + 2, ms + 5, 3, 100, 20, 0),
                ("r2", "z1", "t1", "tr1", "zai", "glm-4.6", "build", "chat", "chat", "ok", ms + 6, ms + 9, 3, 50, 10, 0),
            ],
            "tool_usage": [
                ("z1", "t1", "call1", "bash", "workspace", 0, 1, "approved", "completed", ms + 3, ms + 4, 0, 120, 100, 20),
                ("z1", "t1", "call2", "read", "none", 1, 0, "auto", "completed", ms + 5, ms + 6, None, 50, 50, 0),
            ],
            "todo": [("z1", "cleanup", "done", "high", 0)],
            "session_task_link": [("z1", "z2", "subagent", 1, "explore", "glm-4.6", "done")],
        },
    )
    _json(base / "v2" / "config.json", {"providers": [{"id": "zai", "baseURL": "https://api.z.ai/api/coding/paas/v4", "apiKey": ZCODE_KEY, "models": ["glm-4.6"]}]})
    _json(base / "v2" / "credentials.json", {"key": ZCODE_KEY})
    _write(base / "v2" / "certs" / "client.key", ZCODE_KEY)
    _jsonl(base / "cli" / "rollout" / "r1.jsonl", [{"request": {"headers": {"Authorization": f"Bearer {ZCODE_KEY}"}}}])


# --- Claude desktop ------------------------------------------------------------------------

CLAUDE_DESKTOP_EXPECTED = {"sessions": 4, "account_rows": 2, "mcp_rows": 3, "credential_rows": 3, "usage_rows": 1}


def build_claude_desktop(home: Path) -> None:
    local = home / "AppData" / "Local"
    data = local / "Claude-Data" / "claude_pzs8sxrjxfjjc"
    ms = 1790900000000
    sessions = data / "claude-code-sessions"
    for account, name, sid, offset in (("acct-uuid-1", "local_s1", "sess-A", 0), ("acct-uuid-1", "local_s2", "sess-B", 3600000), ("acct-uuid-2", "local_s3", "sess-Z", 7200000)):
        _json(
            sessions / account / f"{name}.json",
            {"cliSessionId": sid, "cwd": CWD, "originCwd": CWD, "model": "claude-opus-4", "effort": "high", "permissionMode": "default",
             "createdAt": ms + offset, "lastActivityAt": ms + offset + 600000, "completedTurns": 5, "isArchived": False, "cliBinaryPin": {"version": "2.1.304", "wrapper": "x"}},
        )
    _json(data / "local-agent-mode-sessions" / "lam1" / "local_lam1.json", {"sessionId": "lam1", "title": "cowork", "createdAt": ms + 9000000, "lastActivityAt": ms + 9600000, "model": "claude-sonnet-4"})
    _jsonl(data / "local-agent-mode-sessions" / "lam1" / "audit.jsonl", [{"e": 1}, {"e": 2}])
    _json(data / "git-worktrees.json", {"p1": {"origin": f"https://x:{TOKEN_BARE}@git.example.com/r.git"}})
    _json(data / "plan-usage-history.json", {"version": 1, "samples": [{"org": "org-1", "t": ms, "u": {"fh": 0.4}}, {"org": "org-1", "t": ms + 3600000, "u": {"fh": 0.6}}]})
    _json(data / "claude_desktop_config.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@example/fs"], "env": {"TOKEN": TOKEN_BARE}}}})
    _json(data / "buddy-tokens.json", {"t": CRED_FILE})
    _json(data / "ssh-remote-server-state.json", {"t": CRED_FILE})
    _write(data / "Network" / "Cookies", COOKIE_FILE)
    logs = local / "Claude" / "logs"
    _write(
        logs / "mcp.log",
        "2026-10-20T01:00:00.000Z [info] [fs] Initializing server...\n"
        "2026-10-20T01:00:01.000Z [info] [fs] Server started and connected successfully\n"
        f"2026-10-20T01:00:05.000Z [error] [remote-x] Server disconnected (Authorization: Bearer {BEARER})\n",
    )
    _write(logs / "main.log", "2026-10-20 01:00:00 [info] session start\n2026-10-20 01:00:01 [info] mcp ready\n2026-10-20 01:00:02 [info] window\n")
    _json(home / "AppData" / "Roaming" / "Claude-NativeHost" / "com.anthropic.claude_browser_extension.json", {"name": "com.anthropic.claude_browser_extension"})
    (local / "Packages" / "Claude_pzs8sxrjxfjjc" / "Settings").mkdir(parents=True, exist_ok=True)


# --- claude-swap ---------------------------------------------------------------------------

CLAUDE_SWAP_EXPECTED = {"account_rows": 2, "switch_rows": 2, "credential_rows": 1}


def build_claude_swap(home: Path) -> None:
    base = home / ".claude-swap-backup"
    _json(
        base / "sequence.json",
        {
            "accounts": {
                "1": {"added": "2026-09-01T00:00:00Z", "email": "alice.secret@corp.example", "organizationName": "Corp Org", "organizationUuid": "org-uuid-1", "uuid": "acc-uuid-1"},
                "2": {"added": "2026-09-05T00:00:00Z", "email": "bob.private@gmail.example", "organizationName": "Personal", "organizationUuid": "org-uuid-2", "uuid": "acc-uuid-2"},
            },
            "activeAccountNumber": 2,
            "lastUpdated": "2026-10-15T00:00:00Z",
            "sequence": [1, 2],
        },
    )
    _write(
        base / "claude-swap.log",
        "2026-10-10T09:00:00Z INFO Switched from account 1 (alice.secret@corp.example) to account 2 (bob.private@gmail.example)\n"
        "2026-10-15T00:00:00Z INFO Switched to account 2\n"
        "2026-10-15T01:00:00Z INFO update check\n",
    )
    _json(base / "configs" / ".claude-config-1-alice.secret@corp.example.json", {"oauthAccount": {}})
    _json(base / "configs" / ".claude-config-2-bob.private@gmail.example.json", {"oauthAccount": {}})
    _write(base / "credentials" / ".creds-1-alice.secret@corp.example.enc", SWAP_CRED)
    _json(base / "cache" / "usage.json", {"u": 1})


# --- Gemini CLI ----------------------------------------------------------------------------

GEMINI_EXPECTED = {"sessions": 1, "messages": 3, "tool_calls": 1, "file_touches": 1, "mcp_rows": 1, "credential_rows": 2, "account_rows": 1, "instruction_rows": 1}


def build_gemini_cli(home: Path) -> None:
    base = home / ".gemini"
    _write(base / "GEMINI.md", "# Gemini rules\n")
    _json(base / "settings.json", {"mcpServers": {"gh": {"httpUrl": f"https://mcp.example.org/mcp?key={TOKEN_QUERY}"}}, "selectedAuthType": "oauth-personal"})
    _json(base / "oauth_creds.json", {"access_token": GEMINI_TOKEN})
    _write(base / "jetski-standalone-oauth-token", GEMINI_TOKEN)
    _json(base / "google_accounts.json", {"active": "carol.hidden@gmail.example", "old": []})
    chat = base / "tmp" / "hash1" / "chats" / "session-2026-10-20T01-00-abc.json"
    _json(
        chat,
        {
            "sessionId": "g1", "projectHash": "hash1", "startTime": "2026-10-20T01:00:00Z", "lastUpdated": "2026-10-20T01:05:00Z",
            "messages": [
                {"id": "1", "timestamp": "2026-10-20T01:00:00Z", "type": "user", "content": f"summarize with {HF}"},
                {"id": "2", "timestamp": "2026-10-20T01:00:10Z", "type": "gemini", "content": "done", "model": "gemini-2.5-pro", "tokens": {"input": 10, "output": 5},
                 "toolCalls": [{"id": "tc", "name": "read_file", "args": {"absolute_path": f"{CWD}\\a.md"}, "status": "success", "timestamp": "2026-10-20T01:00:05Z"}]},
            ],
        },
    )
    _json(base / "tmp" / "hash1" / "logs.json", [{"sessionId": "g1", "messageId": 0, "type": "user", "message": "summarize", "timestamp": "2026-10-20T01:00:00Z"}])


# --- presence-only stubs -------------------------------------------------------------------

STUBS_EXPECTED = {"tools": {"copilot", "github_copilot", "windsurf", "devin", "opencode", "aider", "goose", "cline"}, "credential_rows": 1}


def build_stubs(home: Path) -> None:
    _json(home / ".copilot" / "config.json", {"x": 1})
    _write(home / ".copilot" / "logs" / "process-1-1.log", "log\n")
    _json(home / ".config" / "github-copilot" / "hosts.json", {"github.com": {"oauth_token": CRED_FILE}})
    (home / ".codeium" / "windsurf" / "cascade").mkdir(parents=True, exist_ok=True)
    _write(home / ".codeium" / "windsurf" / "installation_id", "id")
    _json(home / ".devin" / "extensions" / "extensions.json", [])
    _write(home / ".local" / "share" / "opencode" / "storage" / "session" / "s1.json", "{}")
    _write(home / ".aider.chat.history.md", "# aider chat\n")
    _write(home / ".config" / "goose" / "config.yaml", "provider: x\n")
    _json(home / "AppData" / "Roaming" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks" / "t1" / "api_conversation_history.json", [])


# --- driver --------------------------------------------------------------------------------

BUILDERS = {
    "claude_code": build_claude_code,
    "codex": build_codex,
    "cursor": build_cursor,
    "antigravity": build_antigravity,
    "kiro": build_kiro,
    "omo": build_omo,
    "zcode": build_zcode,
    "claude_desktop": build_claude_desktop,
    "claude_swap": build_claude_swap,
    "gemini_cli": build_gemini_cli,
    "stubs": build_stubs,
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
