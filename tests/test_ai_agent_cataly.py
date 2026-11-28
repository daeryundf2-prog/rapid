"""Cataly hub collector. Synthetic evidence only; layouts follow Cataly's public source (src/store/migrations)."""
from __future__ import annotations

import json
import plistlib
import sqlite3

from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import extract_artifact_events
from tests.test_ai_agents import AgentFixture

STATE = "Users/o/.local/state/saessak/cataly"
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE lanes (key TEXT PRIMARY KEY, state TEXT NOT NULL, outcome TEXT, thread TEXT, opened_ms INTEGER NOT NULL,
    closed_ms INTEGER, revision INTEGER NOT NULL, record TEXT NOT NULL) STRICT;
CREATE TABLE lane_history (key TEXT NOT NULL, seq INTEGER NOT NULL, at_ms INTEGER NOT NULL, state TEXT NOT NULL,
    note TEXT NOT NULL, PRIMARY KEY (key, seq)) STRICT;
CREATE TABLE requests (id INTEGER PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL UNIQUE, thread TEXT, next TEXT,
    notes TEXT NOT NULL DEFAULT '', result TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
    closed_ms INTEGER) STRICT;
CREATE TABLE questions (id TEXT PRIMARY KEY, text TEXT NOT NULL, source TEXT NOT NULL, thread TEXT, options TEXT NOT NULL,
    recommended INTEGER, lead_may INTEGER NOT NULL DEFAULT 0, request INTEGER, room TEXT, message TEXT,
    state TEXT NOT NULL, outcome TEXT, created_ms INTEGER NOT NULL, settled_ms INTEGER) STRICT;
CREATE TABLE stream_jobs (name TEXT PRIMARY KEY, spec TEXT NOT NULL, created_ms INTEGER NOT NULL) STRICT;
CREATE TABLE sessions (handle TEXT PRIMARY KEY, role TEXT NOT NULL, runtime TEXT NOT NULL, cwd TEXT NOT NULL,
    name TEXT NOT NULL, model TEXT NOT NULL, thinking TEXT, mode TEXT NOT NULL, expected_id TEXT, expected_file TEXT,
    state TEXT NOT NULL, session_id TEXT, session_file TEXT, pid INTEGER, started_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL, stop_how TEXT, stop_detail TEXT, stop_ms INTEGER, fault TEXT) STRICT;
CREATE TABLE events (id INTEGER PRIMARY KEY, at_ms INTEGER NOT NULL, job TEXT NOT NULL, subject TEXT NOT NULL,
    kind TEXT NOT NULL, severity TEXT NOT NULL, text TEXT NOT NULL, body TEXT, body_path TEXT, lane TEXT, thread TEXT,
    urgent INTEGER NOT NULL, dry INTEGER NOT NULL, fields TEXT) STRICT;
PRAGMA user_version = 10;
"""
OPENED, CLOSED = 1_790_000_000_000, 1_790_000_600_000
TOKEN = "ghp_" + "A" * 36


def exported(rows):
    return json.dumps([row.details for row in rows], ensure_ascii=False)


class CatalyHubTests(AgentFixture):
    def store(self, path=f"{STATE}/cataly.db"):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(target)
        self.addCleanup(db.close)
        db.execute("PRAGMA journal_mode=WAL").close()
        return target, db

    def test_store_rows_come_from_a_private_wal_snapshot_and_reach_the_timeline(self):
        path, db = self.store()
        db.executescript(SCHEMA)
        record = {"key": "fix-login", "title": "로그인 고치기", "brief": "BRIEF-NEVER-EXPORTED", "cwd": "/w/repo",
                  "model": "anthropic/claude-opus", "worktrees": ["/w/repo-fix"], "session_id": "s-lane",
                  "session_file": "/state/sessions/lanes/s-lane.jsonl", "origin": "discord:1/2", "spend": [12000, 0.42],
                  "run_id": "r1", "checks": [{"argv": ["gh", "pr", "list"]}]}
        db.execute("INSERT INTO lanes VALUES ('fix-login','closed','completed','t9',?,?,3,?)",
                   (OPENED, CLOSED, json.dumps(record, ensure_ascii=False)))
        db.execute("INSERT INTO lane_history VALUES ('fix-login',1,?,'running','started')", (OPENED + 1000,))
        db.execute("INSERT INTO requests (id,title,source,thread,next,result,created_ms,updated_ms,closed_ms) VALUES "
                   "(7,'로그인 버그','discord:1/55','t9','PR 확인','merged',?,?,?)", (OPENED - 5000, CLOSED, CLOSED))
        db.execute("INSERT INTO questions (id,text,source,options,recommended,request,state,outcome,created_ms,"
                   "settled_ms) VALUES ('q1','머지할까요?','lead','[\"예\",\"아니요\"]',0,7,'answered','owner: 예',?,?)",
                   (OPENED + 2000, OPENED + 3000))
        db.execute("INSERT INTO stream_jobs VALUES ('watch',?,?)", (json.dumps(
            {"name": "watch", "argv": ["tail", "-f", "x.log", f"--token={TOKEN}"], "filter": "ERROR", "restarts": 3,
             "delay_s": 5, "silence_m": None, "low": False}), OPENED))
        db.execute("INSERT INTO sessions (handle,role,runtime,cwd,name,model,mode,state,session_id,session_file,pid,"
                   "started_ms,updated_ms,stop_how,stop_ms) VALUES ('h1','lane','headless','/w/repo-fix','fix-login',"
                   "'anthropic/claude-opus','fresh','stopped','s-lane','/state/sessions/lanes/s-lane.jsonl',42,?,?,"
                   "'clean',?)", (OPENED, CLOSED, CLOSED))
        db.commit()
        # Written after the last commit's checkpoint opportunity: only the WAL holds this event.
        db.execute("INSERT INTO events (id,at_ms,job,subject,kind,severity,text,body,lane,urgent,dry) VALUES "
                   "(1,?,'lanes','fix-login','lane.closed','info','레인 닫힘','BODY-NEVER-EXPORTED','fix-login',0,0)",
                   (CLOSED,))
        db.commit()
        self.assertTrue(path.with_name("cataly.db-wal").stat().st_size)

        def evidence():
            return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.parent.iterdir()}
        before = evidence()
        rows = self.rows("cataly-hub")
        self.assertEqual(before, evidence())
        self.assertEqual([r.artifact_type for r in rows], [
            "agent-lane", "agent-lane-history", "agent-request", "agent-question", "agent-stream-job",
            "agent-hosted-session", "agent-hub-event"])
        lane, history, request, question, stream, session, event = (r.details for r in rows)
        self.assertEqual((lane["lane_key"], lane["state"], lane["outcome"], lane["thread"]),
                         ("fix-login", "closed", "completed", "t9"))
        self.assertEqual((lane["text"], lane["model"], lane["worktrees"], lane["cwd"]),
                         ("로그인 고치기", "anthropic/claude-opus", ["/w/repo-fix"], "/w/repo"))
        self.assertEqual((lane["spend_tokens"], lane["spend_usd_estimate"]), ("12000", "0.42"))
        self.assertEqual(lane["timestamp_utc"], "2026-09-21T14:13:20+00:00")
        self.assertEqual(lane["closed_utc"], "2026-09-21T14:23:20+00:00")
        # The lane and the hosted session name the same OMP session, which the omp-pi transcript carries.
        self.assertEqual((lane["session_id"], session["session_id"]), ("s-lane", "s-lane"))
        self.assertEqual(session["session_file"], "/state/sessions/lanes/s-lane.jsonl")
        self.assertEqual(lane["schema_version"], "10")
        self.assertEqual((lane["source_table"], lane["source_rowid"]), ("lanes", 1))
        self.assertTrue(lane["snapshot_id"])
        self.assertEqual((history["text"], history["seq"]), ("started", "1"))
        self.assertEqual((request["source_message"], request["next_step"], request["result"]),
                         ("discord:1/55", "PR 확인", "merged"))
        self.assertEqual((question["options"], question["answer"], question["request_id"]),
                         (["예", "아니요"], "owner: 예", "7"))
        self.assertNotIn(TOKEN, stream["command_line"])
        self.assertTrue(stream["command_line"].startswith("tail -f x.log --token="))
        self.assertEqual((event["event_kind"], event["text"], event["lane_key"], event["urgent"]),
                         ("lane.closed", "레인 닫힘", "fix-login", "false"))
        text = exported(rows)
        for hidden in ("BRIEF-NEVER-EXPORTED", "BODY-NEVER-EXPORTED", "gh pr list"):
            self.assertNotIn(hidden, text)

        payload = run_artifact_collection(self.root, kind="cataly-hub", records_path=self.root.parent / "rows.jsonl",
                                          preview_limit=1)
        validate(payload, load_schema("artifacts.schema.json"))
        self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
        events = extract_artifact_events(payload, self.root.parent / "artifacts-cataly-hub.json")
        kinds = sorted((e["details"]["artifact_type"], e["timestamp_kind"]) for e in events)
        self.assertEqual(kinds, [("agent-hub-event", "event"), ("agent-lane", "closed"), ("agent-lane", "opened"),
                                 ("agent-request", "closed"), ("agent-request", "opened")])

    def test_older_or_foreign_stores_and_oversized_values(self):
        _, old = self.store()
        # Schema v1 has events without the v8 ``fields`` column and none of the later tables.
        old.executescript("CREATE TABLE events (id INTEGER PRIMARY KEY, at_ms INTEGER NOT NULL, job TEXT NOT NULL, "
                          "subject TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, text TEXT NOT NULL, "
                          "urgent INTEGER NOT NULL, dry INTEGER NOT NULL);"
                          "CREATE TABLE stream_jobs (name TEXT, spec TEXT, created_ms INTEGER);")
        old.execute("INSERT INTO events (at_ms,job,subject,kind,severity,text,urgent,dry) VALUES "
                    "(1790000000000,'j','s','run.done','info',?,1,0)", ("가" * 9000,))
        old.execute("INSERT INTO stream_jobs VALUES ('big', ?, 1)", ("[" * 10 + "]" * 10,))
        old.commit()
        _, foreign = self.store(f"{STATE}/backup/cataly-v9.db")
        foreign.execute("CREATE TABLE unrelated (x)")
        foreign.commit()
        rows = self.rows("cataly-hub")
        by_path = {}
        for row in rows:
            by_path.setdefault(row.path.rsplit("/", 1)[-1], []).append(row)
        stream, event = by_path["cataly.db"]
        self.assertEqual(stream.details["command_line"], "")
        self.assertEqual(event.details["urgent"], "true")
        self.assertEqual(len(event.details["text"]), 8192)
        self.assertIn("text-length-limit", event.details["flags"])
        self.assertIn("version-unknown", event.details["flags"])
        [note] = by_path["cataly-v9.db"]
        self.assertEqual(note.details["reason"], "hub-tables-missing")

    def test_logs_settings_service_and_install_records(self):
        self.lines(f"{STATE}/logs/events.jsonl",
                   {"id": 4, "at_ms": OPENED, "job": "github", "subject": "pr", "kind": "pr.opened",
                    "severity": "attention", "text": "PR #9", "body": "BODY-NEVER-EXPORTED", "urgent": True, "dry": False},
                   {"id": 5, "text": "no time"})
        self.lines(f"{STATE}/logs/hub.log",
                   {"t": "2026-11-28T01:02:03.123456789Z", "level": "warn", "msg": "relay slow", "url": "KV-NEVER-EXPORTED"},
                   {"t": "2026-11-28T01:02:04Z", "level": "info"})
        self.write(f"{STATE}/logs/sessions/session-h1.err",
                   b"panic at x\n\nAuthorization: Bearer " + TOKEN.encode() + b"\n\xff\n")
        self.write(f"{STATE}/secrets/discord-token", b"TOKEN-NEVER-READ")
        self.write(f"{STATE}/omp-overlay-lane.yml", {
            "tools": {"approval": {"eval": "deny"}}, "goal": {"enabled": True},
            "retry": {"fallbackOn": "usage-limit", "fallbackChains": {"default": ["a/one", "b/two"]}}})
        self.write(f"{STATE}/sessions/lead/lead-session.jsonl", b'{"type":"session","id":"x"}\n')
        self.write("Users/o/.config/saessak/cataly/config.toml", f"""
[lead]
model = "anthropic/claude-opus"
[lanes]
model = "openai/gpt-5"
[sessions]
credentials = ["ANTHROPIC_API_KEY"]
[discord]
owner = "100000000000000002"
token_file = "/Users/o/.config/saessak/cataly/secrets/discord-token"
[telegram]
owner = 100000001
[fallback.chains]
default = ["a/one", "b/two"]
[jobs.mail]
kind = "items"
argv = ["/bin/new-mail", "--password", "{TOKEN}"]
every = "15m"
destinations = ["owner-dm", "log"]
""".encode())
        self.write("Users/o/.local/share/cataly/records/0.2.6.json", {
            "version": "0.2.6", "commit": "f44edab", "target": "aarch64-apple-darwin", "binary_sha256": "ab" * 32,
            "extension_sha256": "cd" * 32, "source": "https://github.com/vntrevx/Cataly/releases/v0.2.6",
            "installed_ms": OPENED, "role": "current"})
        self.write("Users/o/.local/share/cataly/versions/0.2.6/cataly", b"\x7fELF-NEVER-READ")
        self.write("Users/o/Library/LaunchAgents/dev.cataly.saessak.plist", plistlib.dumps({
            "Label": "dev.cataly.saessak", "RunAtLoad": True,
            "ProgramArguments": ["/bin/sh", "-c", "exec \"$1\" hub", "/Users/o/.config/saessak/cataly/secrets/service.env",
                                 "/Users/o/.local/bin/cataly"],
            "EnvironmentVariables": {"PATH": "/usr/bin", "XDG_STATE_HOME": "/Users/o/.local/state/saessak"}}))
        self.write("home/o/.config/systemd/user/cataly.service", b"[Unit]\nDescription=Cataly hub\n\n[Service]\n"
                   b"Environment=\"PATH=/usr/bin\"\nEnvironmentFile=-/home/o/.config/cataly/secrets/service.env\n"
                   b"ExecStart=/home/o/.local/bin/cataly hub\n")
        rows = self.rows("cataly-hub")
        by_file = {}
        for row in rows:
            by_file.setdefault(row.path.rsplit("/", 1)[-1], []).append(row.details)
        self.assertNotIn("lead-session.jsonl", by_file)

        pr, broken = by_file["events.jsonl"]
        self.assertEqual((pr["event_kind"], pr["event_id"], pr["urgent"], pr["timestamp_utc"]),
                         ("pr.opened", "4", "true", "2026-09-21T14:13:20+00:00"))
        self.assertEqual(broken["reason"], "unrecognized-event-record")
        warn, missing = by_file["hub.log"]
        self.assertEqual((warn["level"], warn["text"], warn["timestamp_utc"]),
                         ("warn", "relay slow", "2026-11-28T01:02:03.123456789+00:00"))
        self.assertEqual(missing["reason"], "unrecognized-log-record")
        stderr = [d["text"] for d in by_file["session-h1.err"]]
        self.assertEqual(stderr[0], "panic at x")
        self.assertEqual(len(stderr), 3)
        self.assertNotIn(TOKEN, stderr[1])
        self.assertEqual(stderr[2], "\ufffd")
        [secret] = by_file["discord-token"]
        self.assertEqual(secret["file_name"], "discord-token")
        [overlay] = by_file["omp-overlay-lane.yml"]
        self.assertEqual((overlay["fallback_chains"], overlay["goal_enabled"], overlay["eval_approval"]),
                         ("default=a/one, b/two", "true", "deny"))
        settings, job = by_file["config.toml"]
        self.assertEqual((settings["model"], settings["lanes_model"], settings["fallback_chains"]),
                         ("anthropic/claude-opus", "openai/gpt-5", "default=a/one, b/two"))
        self.assertEqual((settings["discord_owner"], settings["telegram_owner"], settings["slack_owner"]),
                         ("100000000000000002", "100000001", ""))
        self.assertEqual(settings["token_files"], ["/Users/o/.config/saessak/cataly/secrets/discord-token"])
        self.assertEqual(settings["env_names"], ["ANTHROPIC_API_KEY"])
        self.assertEqual((job["job_name"], job["job_kind"], job["destinations"]), ("mail", "items", ["owner-dm", "log"]))
        self.assertNotIn(TOKEN, job["command_line"])
        [record] = by_file["0.2.6.json"]
        self.assertEqual((record["install_version"], record["binary_sha256"], record["app_version"]),
                         ("0.2.6", "ab" * 32, "0.2.6"))
        [binary] = by_file["cataly"]
        self.assertEqual((binary["file_name"], binary["install_version"]), ("cataly", "0.2.6"))
        [agent] = by_file["dev.cataly.saessak.plist"]
        self.assertEqual(agent["service_label"], "dev.cataly.saessak")
        self.assertTrue(agent["command_line"].endswith("/Users/o/.local/bin/cataly"))
        self.assertEqual(agent["env_names"], ["PATH", "XDG_STATE_HOME"])
        [unit] = by_file["cataly.service"]
        self.assertEqual((unit["command_line"], unit["environment_file"], unit["env_names"]),
                         ("/home/o/.local/bin/cataly hub", "/home/o/.config/cataly/secrets/service.env", ["PATH"]))
        text = exported(rows)
        for hidden in ("BODY-NEVER-EXPORTED", "KV-NEVER-EXPORTED", "TOKEN-NEVER-READ", "ELF-NEVER-READ", TOKEN,
                       "/Users/o/.local/state/saessak"):
            self.assertNotIn(hidden, text)
        # Cataly modes never reach the MCP collector.
        self.assertEqual(self.rows("agent-mcp"), [])

    def test_unrelated_files_in_a_cataly_folder_are_not_claimed(self):
        self.write("Users/o/.config/cataly/config.toml", b"[tool]\nname = 'other'\n")
        self.write("Users/o/projects/cataly/logs/other.txt", b"x")
        self.write("Users/o/Library/LaunchAgents/dev.other.plist", plistlib.dumps({"Label": "x"}))
        rows = self.rows("cataly-hub")
        self.assertEqual([r.details["reason"] for r in rows], ["unrecognized-hub-config"])
