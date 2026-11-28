"""dori collector. Synthetic evidence only; layouts follow dori's public source (sisyphuslabs/dori-superagent)."""
from __future__ import annotations

import json
import os
import plistlib

from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import extract_artifact_events
from tests.test_ai_agents import AgentFixture

HOME = "Users/o/.dori"
STATE = f"{HOME}/state"
OPENED_MS, CLOSED_MS = 1_790_000_000_000, 1_790_000_600_000
OPENED, CLOSED = "2026-09-21T14:13:20.000Z", "2026-09-21T14:23:20.000Z"
OPENED_UTC, CLOSED_UTC = "2026-09-21T14:13:20+00:00", "2026-09-21T14:23:20+00:00"
TOKEN = "ghp_" + "A" * 36


def exported(rows):
    return json.dumps([row.details for row in rows], ensure_ascii=False)


def by_type(rows):
    out = {}
    for row in rows:
        out.setdefault(row.artifact_type, []).append(row.details)
    return out


class DoriStateTests(AgentFixture):
    def collect(self):
        rows = self.rows("dori-state")
        payload = run_artifact_collection(self.root, kind="dori-state", records_path=self.root.parent / "rows.jsonl",
                                          preview_limit=1)
        validate(payload, load_schema("artifacts.schema.json"))
        self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
        events = extract_artifact_events(payload, self.root.parent / "artifacts-dori-state.json")
        return rows, sorted((e["details"]["artifact_type"], e["timestamp_kind"]) for e in events)

    def test_skill_state_lanes_reports_worklog_lessons_and_messenger_ledgers(self):
        self.write(f"{STATE}/lanes/fix-login.json", {
            "key": "fix-login", "title": "로그인 고치기", "thread": "discord:1/9", "brief": "/w/briefs/fix-login.md",
            "done": "DONE-SIGNAL-NEVER-EXPORTED", "cwd": "/w/repo", "model": "anthropic/claude-opus",
            "worktrees": ["/w/repo-fix"], "session": "omo-s1", "sessionVia": "cwd",
            "sessionRef": {"runtime": "hc", "id": "t7"}, "status": "verified-done",
            "claim": {"at": OPENED, "evidence": "PR #12"}, "openedAt": OPENED, "closedAt": CLOSED,
            "lastPostedReport": "[REPORT] REPORT-LINE-NEVER-EXPORTED",
            "history": [{"at": OPENED, "status": "working", "note": "launched"},
                        {"at": CLOSED, "status": "closed", "note": "verified"}]})
        lane_dir = f"{STATE}/lanes/fix-login"
        self.lines(f"{lane_dir}/reports.jsonl",
                   {"type": "activity", "key": "fix-login", "at": OPENED, "state": "running", "text": "lane launched"},
                   {"type": "report", "key": "fix-login", "at": CLOSED, "kind": "done", "text": f"PR 올림 token={TOKEN}"})
        self.lines(f"{lane_dir}/checkpoints.jsonl", {
            "key": "fix-login", "at": CLOSED, "step": "push", "result": "pushed", "evidence": ["pr:12"],
            "remoteEffects": ["push:abc123"]})
        self.lines(f"{lane_dir}/cost.jsonl", {"key": "fix-login", "at": CLOSED, "tokens": 12000, "costUsd": 0.42,
                                              "final": True})
        self.write(f"{lane_dir}/supervision.json", {"at": OPENED_MS})
        torn = b'{"op":"note","id":"0a1b2c3d","at":"' + OPENED.encode()
        self.write(f"{STATE}/worklog.jsonl", b"\n".join([
            json.dumps({"op": "add", "id": "0a1b2c3d", "at": OPENED, "title": "도리 수집기", "source": "slack:D1/1.1"},
                       ensure_ascii=False).encode(),
            json.dumps({"op": "close", "id": "0a1b2c3d", "at": CLOSED, "result": "PR 열림"},
                       ensure_ascii=False).encode(), torn]) + b"\n")
        self.write(f"{STATE}/worklog.md", b"# Worklog\nRENDER-NEVER-READ\n")
        self.lines(f"{STATE}/lessons.jsonl", {
            "id": "4f1c9a7e-0000-4000-8000-000000000001", "at": CLOSED, "lane": "fix-login", "cwd": "/w/repo",
            "rule": "푸시 전에 테스트", "evidence": "slack:D1/1.1", "outcome": "pending"})
        self.write(f"{STATE}/slack-threads.json", [{"channel": "D1", "rootTs": "1790000000.000100",
                                                    "seenTs": "1790000600.123456"}])
        self.write(f"{STATE}/telegram-offset", b"596098530\n")

        rows, events = self.collect()
        found = by_type(rows)
        (lane,) = found["agent-lane"]
        self.assertEqual((lane["lane_key"], lane["state"], lane["thread"], lane["record_layout"]),
                         ("fix-login", "closed", "discord:1/9", "dori-mode"))
        self.assertEqual((lane["text"], lane["model"], lane["cwd"], lane["worktrees"]),
                         ("로그인 고치기", "anthropic/claude-opus", "/w/repo", ["/w/repo-fix"]))
        # The omo session ID joins the lane to its transcript in the omo session store.
        self.assertEqual((lane["session_id"], lane["session_ref"], lane["brief_path"]),
                         ("omo-s1", "hc:t7", "/w/briefs/fix-login.md"))
        self.assertEqual((lane["timestamp_utc"], lane["closed_utc"]), (OPENED_UTC, CLOSED_UTC))
        self.assertEqual([h["state"] for h in found["agent-lane-history"]], ["working", "closed"])
        activity, done = found["agent-lane-report"]
        self.assertEqual((activity["record_type"], activity["report_kind"]), ("activity", "running"))
        self.assertEqual((done["report_kind"], done["lane_key"]), ("done", "fix-login"))
        self.assertNotIn(TOKEN, done["text"])
        (checkpoint,) = found["agent-lane-checkpoint"]
        self.assertEqual((checkpoint["step"], checkpoint["text"], checkpoint["evidence"], checkpoint["remote_effects"]),
                         ("push", "pushed", ["pr:12"], ["push:abc123"]))
        (usage,) = found["agent-lane-usage"]
        self.assertEqual((usage["tokens"], usage["cost_usd"], usage["final"]), ("12000", "0.42", "true"))
        add, close = found["agent-worklog"]
        self.assertEqual((add["worklog_op"], add["text"], add["source_message"]), ("add", "도리 수집기", "slack:D1/1.1"))
        self.assertEqual((close["worklog_op"], close["text"], close["item_id"]), ("close", "PR 열림", "0a1b2c3d"))
        torn_note = next(n for n in found["agent-parse-note"] if n["source_path"].endswith("worklog.jsonl"))
        self.assertEqual((torn_note["reason"], torn_note["source_line"]), ("invalid-json-line", 3))
        (lesson,) = found["agent-lesson"]
        self.assertEqual((lesson["text"], lesson["lane_key"], lesson["cwd"], lesson["evidence"]),
                         ("푸시 전에 테스트", "fix-login", "/w/repo", ["slack:D1/1.1"]))
        (thread,) = found["agent-messenger-thread"]
        self.assertEqual((thread["channel_kind"], thread["channel"], thread["timestamp_raw"]),
                         ("slack", "D1", "1790000000.000100"))
        self.assertEqual((thread["timestamp_utc"], thread["seen_utc"]),
                         ("2026-09-21T14:13:20.000100+00:00", "2026-09-21T14:23:20.123456+00:00"))
        (offset,) = found["agent-messenger-offset"]
        self.assertEqual((offset["channel_kind"], offset["next_update_id"]), ("telegram", "596098530"))
        text = exported(rows)
        for hidden in ("DONE-SIGNAL-NEVER-EXPORTED", "REPORT-LINE-NEVER-EXPORTED", "RENDER-NEVER-READ"):
            self.assertNotIn(hidden, text)
        self.assertFalse(any(r.path.endswith(("supervision.json", "worklog.md")) for r in rows))
        self.assertEqual(events, [
            ("agent-lane", "closed"), ("agent-lane", "opened"), ("agent-lane-checkpoint", "checkpoint"),
            ("agent-lane-history", "status-changed"), ("agent-lane-history", "status-changed"),
            ("agent-lane-report", "reported"), ("agent-lane-report", "reported"),
            ("agent-lane-usage", "cost-recorded"), ("agent-lesson", "lesson"),
            ("agent-messenger-thread", "reply-seen"), ("agent-messenger-thread", "root-posted"),
            ("agent-worklog", "worklog"), ("agent-worklog", "worklog")])

    def test_harness_store_queues_receipts_backlog_loops_and_settings(self):
        self.write(f"{HOME}/lanes/old-lane.json", {
            "key": "old-lane", "paneId": "w1:p3", "tabId": "w1:t3", "brief": "/b.md", "cwd": "/w", "status": "done",
            "createdAt": OPENED_MS, "lastActivityAt": CLOSED_MS, "nudges": 1,
            "final": {"text": "끝냄", "evidence": ["https://github.com/o/r/pull/3"], "at": CLOSED_MS},
            "log": [{"at": OPENED_MS, "kind": "start", "text": "/b.md"},
                    {"at": CLOSED_MS, "kind": "done", "text": "closed"}]})
        self.write(f"{HOME}/briefs/old-lane.md", "앞말\n\n# 로그인 버그 고치기\n\nBRIEF-BODY-NEVER-EXPORTED\n".encode())
        self.write(f"{HOME}/briefs/old-lane.migrate-{CLOSED_MS}.md", b"no heading\nSCREEN-DUMP-NEVER-EXPORTED\n")
        self.lines(f"{HOME}/inbox/w1_p3.jsonl",
                   {"at": OPENED_MS, "from": "duty", "text": "리뷰 결과 확인",
                    "attempt": {"at": OPENED_MS + 1000, "state": "ambiguous", "detail": "timeout"}})
        self.lines(f"{HOME}/inbox/hc--t7.jsonl", {"at": CLOSED_MS, "from": "cli", "text": "plain"})
        self.write(f"{HOME}/inbox/w1_p3.jsonl.lock", {"pid": 1, "host": "h", "at": OPENED_MS})
        self.write(f"{HOME}/receipts/o__r_3@abc1234.json", {
            "pr": "o/r#3", "sha": "abc1234", "verdict": "CLEAR", "model": "default", "at": CLOSED_MS,
            "summary": "VERDICT: CLEAR"})
        self.write(f"{HOME}/receipts/o__r_4@def5678-0f8fad5b-d9cb-469f-a165-70867728950e.noverdict.txt",
                   b"REVIEWER-OUTPUT-NEVER-READ")
        self.write(f"{HOME}/backlog/b1.json", {
            "id": "b1", "title": "백로그 작업", "brief": "/x/b1.md", "cwd": "/w", "priority": 3, "status": "done",
            "attempts": 1, "source": "o/r#9", "createdAt": OPENED_MS, "updatedAt": CLOSED_MS,
            "log": [{"at": OPENED_MS, "kind": "add", "text": ""}, {"at": CLOSED_MS, "kind": "done", "text": ""}]})
        self.write(f"{HOME}/backlog/b1.md", b"BACKLOG-BRIEF-NEVER-READ")
        run = {"at": OPENED_MS, "status": {"lanes": 2, "maxLanes": 4, "adhoc": [], "items": {}, "host": {}},
               "synced": [], "findings": ["old-lane READY 3h ago, not closed: dori done old-lane"], "started": ["b1"],
               "held": [], "asked": []}
        self.write(f"{HOME}/loop/runs/2026-09-21T14-13-20.000Z.json", run)
        self.write(f"{HOME}/loop/stop", {"at": CLOSED_MS, "reason": "owner paused"})
        self.write(f"{HOME}/migrate/old-lane.json", {
            "name": "old-lane", "kind": "lane", "phase": "opened", "from": {"runtime": "herdr", "id": "w1:p3"},
            "to": "hc", "newRef": {"runtime": "hc", "id": "t9"}, "at": CLOSED_MS})
        self.write(f"{HOME}/roles.json", {"lead": "w1:p1", "duty": "hc:t2"})
        self.write(f"{HOME}/telemetry.json", {"installId": "a1b2", "key": "TELEMETRY-KEY-NEVER-EXPORTED",
                                              "lastActiveDay": "2026-09-21"})
        self.write(f"{HOME}/config.json", {
            "defaultModel": "anthropic/claude-opus", "stateDir": "~/.dori/state", "agentCommand": ["omo", f"--key={TOKEN}"],
            "hooks": {"threadReply": ["notify", "HOOK-ARGV-NEVER-EXPORTED"]},
            "repoIdentities": {"o/r": {"name": "IDENTITY-NAME", "email": "identity@example.invalid"}}})
        secret = self.write(f"{HOME}/secrets.env", b"DORI_TELEGRAM_TOKEN=SECRET-NEVER-READ\n")
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, 0o600)
        plist = {"Label": "com.o.dori-backup", "ProgramArguments": ["/bin/sh", "-c", f"backup --token {TOKEN}"],
                 "RunAtLoad": True, "EnvironmentVariables": {"DORI_HOME": "/Users/o/.dori"}}
        self.write("Users/o/Library/LaunchAgents/com.o.dori-backup.plist", plistlib.dumps(plist))
        self.write(f"{HOME}/disabled-launchd/com.o.dori-refresh.plist", plistlib.dumps({**plist, "Label": "refresh"}))
        self.write("Users/o/Library/LaunchAgents/com.adorise.helper.plist", plistlib.dumps(plist))
        # dori's own source checkout and its test fixtures live under ``~/.dori/src``.
        self.write(f"{HOME}/src/test/fixtures/lanes/x.json", {"key": "x", "createdAt": 1})

        rows, events = self.collect()
        found = by_type(rows)
        (lane,) = found["agent-lane"]
        self.assertEqual((lane["record_layout"], lane["session_ref"], lane["state"], lane["result"]),
                         ("dori-harness", "w1:p3", "done", "끝냄"))
        self.assertEqual((lane["timestamp_utc"], lane["closed_utc"], lane["evidence"]),
                         (OPENED_UTC, CLOSED_UTC, ["https://github.com/o/r/pull/3"]))
        self.assertEqual([h["state"] for h in found["agent-lane-history"]], ["start", "done"])
        briefs = {b["brief_kind"]: b for b in found["agent-brief"]}
        self.assertEqual((briefs["brief"]["lane_key"], briefs["brief"]["text"]), ("old-lane", "로그인 버그 고치기"))
        self.assertEqual((briefs["migrate"]["text"], briefs["migrate"]["timestamp_utc"]), ("", CLOSED_UTC))
        held, plain = sorted(found["agent-queued-message"], key=lambda m: m["timestamp_utc"])
        self.assertEqual((held["target_ref"], held["sender"], held["delivery_state"], held["text"]),
                         ("w1:p3", "duty", "ambiguous", "리뷰 결과 확인"))
        self.assertEqual(held["delivery_utc"], "2026-09-21T14:13:21+00:00")
        self.assertEqual((plain["target_ref"], plain["delivery_state"]), ("hc:t7", ""))
        clear, missing = sorted(found["agent-review-receipt"], key=lambda r: r["verdict"], reverse=True)
        self.assertEqual((clear["pr"], clear["sha"], clear["verdict"], clear["timestamp_utc"]),
                         ("o/r#3", "abc1234", "CLEAR", CLOSED_UTC))
        self.assertEqual((missing["pr_file_key"], missing["sha"], missing["verdict"]), ("o__r_4", "def5678", ""))
        (item,) = found["agent-backlog-item"]
        self.assertEqual((item["text"], item["state"], item["priority"], item["closed_utc"]),
                         ("백로그 작업", "done", "3", CLOSED_UTC))
        (loop,) = found["agent-loop-run"]
        self.assertEqual((loop["lanes"], loop["started"], len(loop["findings"])), ("2", ["b1"], 1))
        (stop,) = found["agent-pause"]
        self.assertEqual((stop["loop_name"], stop["text"]), ("loop", "owner paused"))
        (move,) = found["agent-migration"]
        self.assertEqual((move["from_ref"], move["new_ref"], move["phase"]), ("w1:p3", "hc:t9", "opened"))
        settings = {r["source_path"].rsplit("/", 1)[-1]: r for r in found["agent-settings"]}
        self.assertEqual(settings["roles.json"]["role_refs"], "lead=w1:p1; duty=hc:t2")
        self.assertEqual((settings["telemetry.json"]["telemetry_install_id"],
                          settings["telemetry.json"]["telemetry_key_stored"]), ("a1b2", "true"))
        config = settings["config.json"]
        self.assertEqual((config["model"], config["hook_names"], config["repo_identities"]),
                         ("anthropic/claude-opus", ["threadReply"], ["o/r"]))
        self.assertTrue(config["command_line"].startswith("omo --key="))
        (secret_row,) = found["agent-secret-file"]
        self.assertEqual(secret_row["file_name"], "secrets.env")
        services = sorted(found["agent-service"], key=lambda s: s["disabled"])
        self.assertEqual([(s["service_label"], s["disabled"]) for s in services],
                         [("com.o.dori-backup", "false"), ("refresh", "true")])
        self.assertEqual(services[0]["env_names"], ["DORI_HOME"])
        self.assertFalse([r.path for r in rows if "/src/" in r.path or "adorise" in r.path
                          or r.path.endswith((".lock", "b1.md"))])
        text = exported(rows)
        for hidden in ("BRIEF-BODY-NEVER-EXPORTED", "SCREEN-DUMP-NEVER-EXPORTED", "REVIEWER-OUTPUT-NEVER-READ",
                       "BACKLOG-BRIEF-NEVER-READ", "TELEMETRY-KEY-NEVER-EXPORTED", "HOOK-ARGV-NEVER-EXPORTED",
                       "IDENTITY-NAME", "identity@example.invalid", "SECRET-NEVER-READ", "/Users/o/.dori", TOKEN):
            self.assertNotIn(hidden, text)
        self.assertEqual(events, [
            ("agent-backlog-item", "closed"), ("agent-backlog-item", "opened"), ("agent-lane", "closed"),
            ("agent-lane", "opened"), ("agent-lane-history", "status-changed"),
            ("agent-lane-history", "status-changed"),
            ("agent-loop-run", "run"), ("agent-migration", "migrated"), ("agent-pause", "paused"),
            ("agent-queued-message", "delivery-attempted"), ("agent-queued-message", "queued"),
            ("agent-queued-message", "queued"), ("agent-review-receipt", "reviewed")])

    def test_foreign_or_damaged_documents_give_notes(self):
        self.write(f"{STATE}/lanes/odd.json", {"key": "odd", "openedAt": 5})
        self.write(f"{HOME}/receipts/x@1234567.json", {"verdict": "MAYBE"})
        self.write(f"{STATE}/telegram-offset", b"not-a-number")
        self.write(f"{STATE}/slack-threads.json", [{"channel": "C1", "rootTs": "yesterday", "seenTs": "x"}])
        self.lines(f"{STATE}/lanes/odd/reports.jsonl", {"type": "other", "key": "odd"})
        rows = self.rows("dori-state")
        reasons = sorted(r.details["reason"] for r in rows if r.artifact_type == "agent-parse-note")
        self.assertEqual(reasons, ["invalid-document", "unrecognized-lane-record", "unrecognized-report-record",
                                   "unrecognized-review-receipt"])
        (thread,) = [r.details for r in rows if r.artifact_type == "agent-messenger-thread"]
        self.assertIsNone(thread["timestamp_utc"])
        self.assertIn("timestamp-not-normalized", thread["flags"])
        self.assertNotIn("seen_utc", thread)
