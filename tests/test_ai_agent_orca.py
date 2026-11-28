"""Orca Bots collector. Synthetic evidence only; layouts follow Orca's public source (stablyai/orca, c46704e1)."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from rapidtriage.artifacts import clear_collect_cache
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import extract_artifact_events
from tests.test_ai_agents import AgentFixture

USER_DATA = "Users/o/Library/Application Support/Orca"
HOME = "Users/o/.orca"
CREATED_MS, CLOSED_MS = 1_790_000_000_000, 1_790_000_600_000
CREATED_UTC, CLOSED_UTC = "2026-09-21T14:13:20+00:00", "2026-09-21T14:23:20+00:00"
TOKEN = "ghp_" + "A" * 36

BOT = {
    "id": "bot-1", "name": "Rapid helper", "hostId": "local", "folder": "rapid-helper", "folderWorkspaceId": "ws-1",
    "agent": "claude", "avatar": None, "paused": False, "permissionMode": "accept-edits",
    "launch": {"model": "claude-opus"}, "notifications": {"needsPermission": True, "taskComplete": True,
                                                          "couldNotFinish": True},
    "members": [{"id": "U1", "name": "MEMBER-NAME-NEVER-EXPORTED"}, {"id": "L1", "name": "x", "source": "linear"}],
    "slack": {"appId": "A1", "teamId": "T1"}, "linear": {"workspaceId": "lw", "workspaceName": "Acme"},
    "github": {}, "chatSessionId": "chat-1", "lookAround": {"on": True, "every": "every-4h", "weekdaysOnly": True,
                                                            "focus": ""},
    "createdAt": CREATED_MS, "updatedAt": CLOSED_MS,
}


def by_type(rows):
    out = {}
    for row in rows:
        out.setdefault(row.artifact_type, []).append(row.details)
    return out


class OrcaBotsTests(AgentFixture):
    def collect(self):
        rows = self.rows("orca-bots")
        payload = run_artifact_collection(self.root, kind="orca-bots", records_path=self.root.parent / "rows.jsonl",
                                          preview_limit=1)
        validate(payload, load_schema("artifacts.schema.json"))
        self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
        events = extract_artifact_events(payload, self.root.parent / "artifacts-orca-bots.json")
        return rows, sorted((e["details"]["artifact_type"], e["timestamp_kind"]) for e in events)

    def database(self, path, script, *rows):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(target) as db:
            db.executescript(script)
            for sql, values in rows:
                db.execute(sql, values)
        db.close()

    def test_bots_work_items_requests_and_dispatches(self):
        self.database(f"{USER_DATA}/profiles/local-default/profile-state.db", """
            CREATE TABLE profile_state_documents (domain TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL,
              domain_version INTEGER NOT NULL, revision INTEGER NOT NULL, updated_at INTEGER NOT NULL,
              content_hash TEXT NOT NULL);
            PRAGMA user_version = 3;""",
            ("INSERT INTO profile_state_documents VALUES (?, ?, 1, 1, 0, 'h')", ("bots", json.dumps([BOT]))),
            ("INSERT INTO profile_state_documents VALUES (?, ?, 1, 1, 0, 'h')",
             ("settings", json.dumps({"SETTINGS-NEVER-READ": 1}))))
        self.database(f"{USER_DATA}/bot-work.sqlite", """
            CREATE TABLE bot_work (id TEXT PRIMARY KEY, bot_id TEXT NOT NULL, source TEXT NOT NULL,
              external_id TEXT NOT NULL, generation INTEGER NOT NULL, task_id TEXT NOT NULL,
              dispatch_id TEXT NOT NULL, host TEXT NOT NULL, asked_in_app INTEGER NOT NULL DEFAULT 0,
              current INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, closed_at INTEGER, close_reason TEXT);""",
            ("INSERT INTO bot_work VALUES ('w1','bot-1','slack','C1/1.2',0,'task-1','disp-1','local',0,0,?,?,'stopped')",
             (CREATED_MS, CLOSED_MS)))
        self.database(f"{USER_DATA}/bot-items.sqlite", """
            CREATE TABLE items (uid TEXT PRIMARY KEY, number INTEGER NOT NULL UNIQUE, owner_bot_id TEXT NOT NULL,
              chat_id TEXT NOT NULL, source TEXT NOT NULL, made_by TEXT, title TEXT NOT NULL, description TEXT,
              done_means TEXT, status TEXT NOT NULL, question_event INTEGER, close_note TEXT, version INTEGER NOT NULL,
              last_event_id INTEGER NOT NULL, last_activity_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL, closed_at INTEGER, others_last_event_id INTEGER NOT NULL DEFAULT 0,
              snoozed_until INTEGER);
            CREATE TABLE item_links (item_uid TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
              added_event INTEGER NOT NULL, PRIMARY KEY (item_uid, kind, ref));
            CREATE TABLE item_events (id INTEGER PRIMARY KEY AUTOINCREMENT, item_uid TEXT NOT NULL, kind TEXT NOT NULL,
              actor TEXT NOT NULL, data TEXT NOT NULL, mail TEXT, action INTEGER NOT NULL, created_at INTEGER NOT NULL);
            PRAGMA user_version = 3;""",
            ("INSERT INTO items VALUES ('i1',7,'bot-1','chat-1',?,?, '로그인 고치기', ?, 'tests pass', 'done', NULL,"
             " 'merged', 3, 3, ?, ?, ?, ?, 0, NULL)",
             (json.dumps({"kind": "thread", "title": "#dev"}), json.dumps({"botId": "bot-1", "chatId": "chat-1"}),
              f"token={TOKEN}", CLOSED_MS, CREATED_MS, CLOSED_MS, CLOSED_MS)),
            ("INSERT INTO item_links VALUES ('i1','pr','https://github.com/o/r/pull/12',2)", ()),
            ("INSERT INTO item_links VALUES ('i1','dispatch','disp-1',2)", ()),
            ("INSERT INTO item_events (item_uid, kind, actor, data, action, created_at) VALUES ('i1','status',?,?,1,?)",
             (json.dumps({"kind": "owner"}), json.dumps({"from": "working", "to": "done", "note": "merged"}),
              CLOSED_MS)),
            ("INSERT INTO item_events (item_uid, kind, actor, data, action, created_at) VALUES ('i1','commented',?,?,2,?)",
             (json.dumps({"kind": "bot", "botId": "bot-1", "chatId": "chat-1"}), json.dumps({"text": "PR 올림"}),
              CLOSED_MS)))
        self.database(f"{USER_DATA}/orchestration.db", """
            CREATE TABLE bot_requests (message_id TEXT PRIMARY KEY, root_key TEXT NOT NULL, from_bot_id TEXT,
              to_bot_id TEXT NOT NULL, purpose TEXT NOT NULL, depth INTEGER NOT NULL, record TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')), send_key TEXT);
            CREATE TABLE bot_request_outcomes (message_id TEXT PRIMARY KEY, outcome TEXT NOT NULL,
              recorded_at TEXT NOT NULL DEFAULT (datetime('now')));
            CREATE TABLE worker_dispatches (dispatch_id TEXT PRIMARY KEY, runtime_epoch TEXT,
              state TEXT NOT NULL DEFAULT 'starting', stage TEXT NOT NULL DEFAULT 'accepted', worktree_id TEXT,
              agent_terminal_handle TEXT, setup_state TEXT NOT NULL DEFAULT 'not_applicable',
              effects TEXT NOT NULL DEFAULT '[]', residual_resources TEXT NOT NULL DEFAULT '[]',
              start_options TEXT NOT NULL DEFAULT '{}', last_error TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
            PRAGMA user_version = 49;""",
            ("INSERT INTO bot_requests VALUES ('m1','root','bot-2','bot-1','handoff',1,?,'2026-09-21 14:13:20',NULL)",
             (json.dumps({"fromBotName": "Reviewer", "toBotName": "Rapid helper",
                          "request": f"이 PR 봐줘 GITHUB_TOKEN={TOKEN}"}),)),
            ("INSERT INTO bot_request_outcomes VALUES ('m1','answered','2026-09-21 14:23:20')", ()),
            # The worker's launch options hold its argv and environment: unlabelled secrets that clean() cannot
            # see, so they are never exported (only state, stage, worktree and the redacted last error).
            ("INSERT INTO worker_dispatches (dispatch_id, state, stage, worktree_id, agent_terminal_handle, effects,"
             " start_options, last_error, created_at, updated_at) VALUES ('disp-1','succeeded','done',"
             "'repo-1::/w/rapid-fix','pty-UNLABELLED-HANDLE',?,?,?,'2026-09-21 14:13:20','2026-09-21 14:23:20')",
             (json.dumps([{"kind": "env-file", "path": "/w/.env"}]),
              json.dumps({"argv": ["claude", "--api-key", "POSITIONAL-SECRET-NEVER-EXPORTED", "-pHUNTER2-NEVER"],
                          "env": {"STRIPE": "STRIPE-LIVE-NEVER-EXPORTED"}}),
              f"auth failed token={TOKEN}")),
            # State changes from JavaScript store ``Date.toISOString()`` instead of SQLite ``datetime`` text.
            ("INSERT INTO worker_dispatches (dispatch_id, state, stage, worktree_id, created_at, updated_at) VALUES"
             " ('disp-2','failed','starting','repo-1::C:\\w\\case','2026-09-21 14:13:20','2026-09-21T14:30:00.123Z')",
             ()))

        rows, events = self.collect()
        found = by_type(rows)
        (bot,) = found["agent-bot"]
        self.assertEqual((bot["bot_id"], bot["text"], bot["bot_agent"], bot["model"], bot["permission_mode"]),
                         ("bot-1", "Rapid helper", "claude", "claude-opus", "accept-edits"))
        self.assertEqual((bot["trigger_channels"], bot["member_sources"], bot["member_count"]),
                         (["slack", "linear", "github"], ["linear", "slack"], "2"))
        self.assertEqual((bot["slack_teams"], bot["linear_workspaces"], bot["session_id"], bot["record_layout"]),
                         (["T1"], ["Acme"], "chat-1", "profile-state"))
        self.assertEqual((bot["timestamp_utc"], bot["updated_utc"], bot["schema_version"]),
                         (CREATED_UTC, CLOSED_UTC, "3"))
        (work,) = found["agent-bot-work"]
        self.assertEqual((work["channel_kind"], work["external_id"], work["dispatch_id"], work["close_reason"]),
                         ("slack", "C1/1.2", "disp-1", "stopped"))
        self.assertEqual((work["current"], work["closed_utc"]), ("false", CLOSED_UTC))
        (item,) = found["agent-bot-item"]
        self.assertEqual((item["text"], item["item_number"], item["state"], item["close_note"], item["session_id"]),
                         ("로그인 고치기", "7", "done", "merged", "chat-1"))
        self.assertEqual((item["pr_links"], item["dispatch_ids"], item["item_source"], item["item_source_title"]),
                         (["https://github.com/o/r/pull/12"], ["disp-1"], "thread", "#dev"))
        self.assertNotIn(TOKEN, item["description"])
        status, comment = found["agent-bot-item-event"]
        self.assertEqual((status["status_from"], status["status_to"], status["text"], status["actor_kind"]),
                         ("working", "done", "merged", "owner"))
        self.assertEqual((comment["text"], comment["actor_bot"], comment["session_id"]), ("PR 올림", "bot-1", "chat-1"))
        (request,) = found["agent-bot-request"]
        self.assertEqual((request["from_bot_name"], request["purpose"], request["outcome"]),
                         ("Reviewer", "handoff", "answered"))
        self.assertTrue(request["text"].startswith("이 PR 봐줘 GITHUB_TOKEN="))
        self.assertEqual((request["timestamp_raw"], request["timestamp_utc"], request["outcome_utc"]),
                         ("2026-09-21 14:13:20", CREATED_UTC, CLOSED_UTC))
        done, failed = found["agent-bot-dispatch"]
        self.assertEqual((done["state"], done["worktree_id"], done["worktree_path"], done["cwd"]),
                         ("succeeded", "repo-1::/w/rapid-fix", "/w/rapid-fix", "/w/rapid-fix"))
        self.assertEqual(done["updated_utc"], CLOSED_UTC)
        self.assertTrue(done["text"].startswith("auth failed token="))
        self.assertEqual(done["command_line"], "")
        self.assertEqual((failed["state"], failed["cwd"], failed["updated_utc"]),
                         ("failed", "C:\\w\\case", "2026-09-21T14:30:00.123000+00:00"))
        exported = json.dumps([r.details for r in rows])
        for hidden in (TOKEN, "SETTINGS-NEVER-READ", "MEMBER-NAME-NEVER-EXPORTED", "POSITIONAL-SECRET-NEVER-EXPORTED",
                       "HUNTER2-NEVER", "STRIPE-LIVE-NEVER-EXPORTED", "UNLABELLED-HANDLE", "/w/.env"):
            self.assertNotIn(hidden, exported)
        self.assertNotIn("agent-parse-note", found)
        self.assertEqual(events, [
            ("agent-bot", "created"), ("agent-bot", "last-updated"), ("agent-bot-dispatch", "last-updated"),
            ("agent-bot-dispatch", "last-updated"), ("agent-bot-dispatch", "started"),
            ("agent-bot-dispatch", "started"), ("agent-bot-item", "completed"), ("agent-bot-item", "created"),
            ("agent-bot-item", "last-updated"), ("agent-bot-item-event", "event"),
            ("agent-bot-item-event", "event"), ("agent-bot-request", "completed"), ("agent-bot-request", "sent"),
            ("agent-bot-work", "ended"), ("agent-bot-work", "started")])

    def test_bot_home_memory_history_look_around_and_cloud_traces_without_tokens(self):
        home = f"{HOME}/bots/rapid-helper"
        self.write(f"{home}/bot.json", {"id": "bot-1", "name": "Rapid helper", "agent": "claude", "avatar": None,
                                        "members": [{"id": "U1", "name": "n"}]})
        self.write(f"{home}/SOUL.md", b"# Rapid helper\nYou fix tests.\n")
        memory = f"# Memory\n- 2026-09-21 MEMORY-BODY-OPT-IN deploy key {TOKEN}\n".encode()
        self.write(f"{home}/MEMORY.md", memory)
        self.write(f"{home}/memory/release.md", b"# Release\nTag on Fridays.\n")
        self.write(f"{home}/AGENTS.md", b"# GENERATED-NEVER-READ\n")
        self.write(f"{home}/.orca/bot-tools.json", {"servers": []})
        self.write(f"{USER_DATA}/bot-memory-history/bot%2F1.json", [{
            "id": "c1", "at": CLOSED_MS, "by": {"kind": "chat", "sessionId": "chat-1", "source": "U2"},
            "change": {"added": [{"line": "- CHANGE-LINE-OPT-IN", "after": None}], "removed": []}, "undoable": True}])
        self.write(f"{USER_DATA}/bot-look-around.json", {"bots": {"bot-1": {
            "runs": [{"sessionId": "run-1", "startedAt": CREATED_MS, "endedAt": CLOSED_MS}],
            "suggestions": [{"id": "s1", "title": "Fix flaky test", "why": "CI red", "ask": "fix it", "source": "github",
                             "createdAt": CLOSED_MS, "runSessionId": "run-1", "status": "open"}],
            "dismissals": [{"title": "DISMISSAL-NEVER-EXPORTED", "at": CLOSED_MS}],
            "tidyUp": {"runs": [{"sessionId": "tidy-1", "startedAt": CLOSED_MS, "error": "usage limit"}]}}}})
        self.write(f"{USER_DATA}/orca-profile-index.json", {"schemaVersion": 1, "activeProfileId": "p1", "profiles": [{
            "id": "p1", "name": "Work", "kind": "cloud-linked", "createdAt": CREATED_MS, "updatedAt": CLOSED_MS,
            "lastOpenedAt": CLOSED_MS, "cloud": {"cloudProfileId": "cp1", "userId": "u1", "email": "o@example.com",
                                                 "activeOrgName": "Acme", "linkedAt": CLOSED_MS}}]})
        self.write(f"{USER_DATA}/profiles/p1/account-session.json.enc", {
            "version": 1, "format": "dev-plaintext-v1", "savedAt": CLOSED_MS,
            "session": {"accessToken": "ACCESS-NEVER-EXPORTED", "refreshToken": "REFRESH-NEVER-EXPORTED"}})
        secret = self.write(f"{USER_DATA}/connector-host-key.json", {"privateKey": "KEY-NEVER-READ"})
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, 0o600)
        self.write(f"{HOME}/linear-token.enc", b"\x00SEALED")
        # Not Orca: the GNOME screen reader shares the name but not the files.
        self.write("Users/o/.local/share/orca/user-settings.conf", b"x")

        rows, events = self.collect()
        found = by_type(rows)
        (bot,) = found["agent-bot"]
        self.assertEqual((bot["bot_id"], bot["bot_folder"], bot["member_count"], bot["record_layout"]),
                         ("bot-1", "rapid-helper", "1", "bot-home"))
        files = {r["memory_file"]: r for r in found["agent-bot-memory-file"]}
        self.assertEqual(sorted(files), ["MEMORY.md", "SOUL.md", "release.md"])
        self.assertEqual((files["release.md"]["memory_role"], files["release.md"]["bot_folder"]),
                         ("memory-topic", "rapid-helper"))
        # Memory text is opt-in: by default only its size, counts and hash.
        self.assertEqual((files["MEMORY.md"]["text"], files["MEMORY.md"]["line_count"],
                          files["MEMORY.md"]["char_count"], files["MEMORY.md"]["file_bytes"]),
                         ("", "2", str(len(memory.decode())), str(len(memory))))
        self.assertEqual(files["MEMORY.md"]["text_sha256"], hashlib.sha256(memory).hexdigest())
        self.assertIn("content-not-exported", files["MEMORY.md"]["flags"])
        (change,) = found["agent-bot-memory-change"]
        self.assertEqual((change["bot_id"], change["author_kind"], change["speaker"], change["session_id"]),
                         ("bot/1", "chat", "U2", "chat-1"))
        self.assertEqual((change["added_count"], change["removed_count"]), ("1", "0"))
        self.assertNotIn("added_lines", change)
        self.assertIn("content-not-exported", change["flags"])
        look, tidy = found["agent-bot-run"]
        self.assertEqual((look["run_kind"], look["session_id"], look["ended_utc"]), ("look-around", "run-1", CLOSED_UTC))
        self.assertEqual((tidy["run_kind"], tidy["text"]), ("tidy-up", "usage limit"))
        (suggestion,) = found["agent-bot-suggestion"]
        self.assertEqual((suggestion["text"], suggestion["channel_kind"], suggestion["state"], suggestion["session_id"]),
                         ("Fix flaky test", "github", "open", "run-1"))
        (profile,) = found["agent-cloud-profile"]
        self.assertEqual((profile["profile_kind"], profile["active"], profile["cloud_email"], profile["cloud_org_name"]),
                         ("cloud-linked", "true", "o@example.com", "Acme"))
        self.assertEqual(profile["linked_utc"], CLOSED_UTC)
        secrets = {r["file_name"]: r for r in found["agent-secret-file"]}
        self.assertEqual(sorted(secrets), ["account-session.json.enc", "connector-host-key.json", "linear-token.enc"])
        session = secrets["account-session.json.enc"]
        self.assertEqual((session["session_format"], session["profile_id"], session["saved_utc"]),
                         ("dev-plaintext-v1", "p1", CLOSED_UTC))
        text = json.dumps([r.details for r in rows])
        for hidden in ("ACCESS-NEVER-EXPORTED", "REFRESH-NEVER-EXPORTED", "KEY-NEVER-READ", "GENERATED-NEVER-READ",
                       "DISMISSAL-NEVER-EXPORTED", "SEALED", "MEMORY-BODY-OPT-IN", "CHANGE-LINE-OPT-IN", "Tag on"):
            self.assertNotIn(hidden, text)
        self.assertFalse(any("user-settings.conf" in r.path or r.path.endswith("bot-tools.json") for r in rows))
        self.assertNotIn("agent-parse-note", found)
        self.assertEqual(events, [
            ("agent-bot-memory-change", "modified"), ("agent-bot-run", "ended"), ("agent-bot-run", "started"),
            ("agent-bot-run", "started"), ("agent-bot-suggestion", "created"), ("agent-cloud-profile", "created"),
            ("agent-cloud-profile", "last-opened"), ("agent-cloud-profile", "linked"),
            ("agent-secret-file", "session-saved")])

    def test_memory_text_is_opt_in_and_never_served_from_the_other_collection_cache(self):
        self.addCleanup(clear_collect_cache)
        self.write(f"{HOME}/bots/rapid-helper/MEMORY.md", f"# Memory\n- MEMORY-BODY-OPT-IN key {TOKEN}\n".encode())
        self.write(f"{USER_DATA}/bot-memory-history/bot-1.json", [{
            "id": "c1", "at": CLOSED_MS, "by": {"kind": "owner"},
            "change": {"added": [{"line": "- added fact"}], "removed": [{"line": f"- old key {TOKEN}"}]}}])

        def collect(**options):
            payload = run_artifact_collection(self.root, kind="orca-bots", collector_options=options or None)
            found = {row["artifact_type"]: row["details"] for row in payload["artifacts"]}
            return payload["collector_options"], found["agent-bot-memory-file"], found["agent-bot-memory-change"]

        # The default run fills the per-process collect cache first; the opt-in run must not reuse it, nor the
        # default run after it reuse the opt-in rows.
        for options, with_text in (({}, False), ({"bot_memory_text": True}, True), ({}, False)):
            recorded, memory, change = collect(**options)
            self.assertEqual(recorded, {"bot_memory_text": with_text})
            if with_text:
                self.assertTrue(memory["text"].startswith("# Memory\n- MEMORY-BODY-OPT-IN key "))
                self.assertNotIn(TOKEN, memory["text"])
                self.assertEqual((change["added_lines"], change["removed_lines"][0][:10]),
                                 (["- added fact"], "- old key "))
                self.assertNotIn(TOKEN, change["removed_lines"][0])
                self.assertNotIn("content-not-exported", memory["flags"] + change["flags"])
            else:
                self.assertEqual(memory["text"], "")
                self.assertNotIn("added_lines", change)
                self.assertIn("content-not-exported", memory["flags"])

    def test_a_cell_that_is_not_utf8_keeps_the_rest_of_the_store(self):
        self.database(f"{USER_DATA}/bot-items.sqlite", """
            CREATE TABLE items (uid TEXT PRIMARY KEY, number INTEGER NOT NULL UNIQUE, owner_bot_id TEXT NOT NULL,
              chat_id TEXT NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL,
              created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE item_links (item_uid TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
              added_event INTEGER NOT NULL);
            PRAGMA user_version = 3;""",
            # Read before the items as context: one bad cell here used to end the whole database.
            ("INSERT INTO item_links VALUES ('i1','url',CAST(? AS TEXT),1)", (b"https://x/\xff",)),
            ("INSERT INTO items VALUES ('i1',1,'bot-1','chat-1','{}',CAST(? AS TEXT),'open',?,?)",
             (b"\xffhi", CREATED_MS, CREATED_MS)),
            ("INSERT INTO items VALUES ('i2',2,'bot-1','chat-1','{}','second','open',?,?)", (CREATED_MS, CREATED_MS)))

        found = by_type(self.rows("orca-bots"))
        self.assertEqual([item["text"] for item in found["agent-bot-item"]], ["\ufffdhi", "second"])
        self.assertNotIn("agent-parse-note", found)
