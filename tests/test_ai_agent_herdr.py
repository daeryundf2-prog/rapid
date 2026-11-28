"""herdr collector. Synthetic evidence only; layouts follow herdr's public source (herdrdev/herdr, tag v0.9.5)."""
from __future__ import annotations

import json

from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import extract_artifact_events
from tests.test_ai_agents import AgentFixture

CONFIG = "Users/o/.config/herdr"
STATE = "Users/o/.local/state/herdr"
TOKEN = "ghp_" + "A" * 36
# 2026-09-21T14:13:20.123456789Z as herdr's 39-digit recovery-copy name.
SNAPSHOT_NAME = f"session-{1_790_000_000_123_456_789:039d}-2240-0.json"


def by_type(rows):
    out = {}
    for row in rows:
        out.setdefault(row.artifact_type, []).append(row.details)
    return out


def layout(workspaces):
    return {"version": 3, "workspaces": workspaces, "active": 0, "selected": 0}


WORKSPACE = {
    "id": "w1", "custom_name": "rapid", "identity_cwd": "/w/rapid",
    "worktree_space": {"key": "k", "label": "rapid · fix", "repo_root": "/w/rapid", "checkout_path": "/w/rapid-fix",
                       "is_linked_worktree": True},
    "public_pane_numbers": {"3": 3, "4": 33}, "next_public_pane_number": 34, "public_tab_numbers": [2],
    "next_public_tab_number": 3,
    "tabs": [{
        "custom_name": "agents", "layout": {"Split": {"direction": "Vertical", "ratio": 0.5, "first": {"Pane": 3},
                                                     "second": {"Pane": 4}}},
        "panes": {
            "3": {"cwd": "/w/rapid-fix", "label": "lead", "agent_name": "claude", "managed_agent_kind": "claude",
                  "agent_session": {"source": "herdr:claude", "agent": "claude", "kind": "id", "value": "claude-s1"},
                  "agent_resume": {"source": "herdr:claude", "agent": "claude",
                                   "argv": ["claude", "--resume", "claude-s1"]},
                  "launch_argv": ["claude", f"--api-key={TOKEN}"]},
            "4": {"cwd": "/w/rapid", "agent_name": "pi",
                  "agent_session": {"source": "herdr:pi", "agent": "pi", "kind": "path",
                                    "value": "/Users/o/.pi/agent/sessions/s2.jsonl"}},
        },
        "zoomed": False, "focused": 3, "root_pane": 3}],
    "active_tab": 0,
}


class HerdrSessionTests(AgentFixture):
    def collect(self):
        rows = self.rows("herdr-sessions")
        payload = run_artifact_collection(self.root, kind="herdr-sessions", records_path=self.root.parent / "rows.jsonl",
                                          preview_limit=1)
        validate(payload, load_schema("artifacts.schema.json"))
        self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
        events = extract_artifact_events(payload, self.root.parent / "artifacts-herdr-sessions.json")
        return rows, sorted((e["details"]["artifact_type"], e["timestamp_kind"]) for e in events)

    def test_layouts_link_panes_to_agent_sessions_and_snapshots_carry_their_time(self):
        self.write(f"{CONFIG}/session.json", layout([WORKSPACE]))
        self.write(f"{CONFIG}/session-snapshots/{SNAPSHOT_NAME}", layout([WORKSPACE]))
        # A pre-tab layout (version 2): the workspace holds its layout and panes itself.
        self.write(f"{CONFIG}/sessions/work/session-backups/{SNAPSHOT_NAME}", {
            "version": 2, "active": 0, "selected": 0,
            "workspaces": [{"custom_name": None, "layout": {"Pane": 1}, "panes": {"1": {"cwd": "/w/old"}},
                            "zoomed": False}]})
        # Not herdr: a folder that merely shares the name, the socket, the public rule catalog and a stray copy.
        self.write("Users/o/work/herdr/session.json", layout([WORKSPACE]))
        self.write(f"{CONFIG}/session-snapshots/session-latest.json", layout([WORKSPACE]))
        self.write(f"{STATE}/agent-detection/remote/claude.toml", b'version = "1"\n')

        rows, events = self.collect()
        found = by_type(rows)
        self.assertEqual({r["source_path"] for r in found["agent-terminal-pane"]}, {
            f"{CONFIG}/session.json", f"{CONFIG}/session-snapshots/{SNAPSHOT_NAME}",
            f"{CONFIG}/sessions/work/session-backups/{SNAPSHOT_NAME}"})
        current = [r for r in found["agent-terminal-pane"] if r["snapshot_kind"] == "current"]
        lead, pi = sorted(current, key=lambda r: r["pane_id"])
        # The agent session ID joins the pane to the Claude Code collector's rows.
        self.assertEqual((lead["session_id"], lead["agent_session_source"], lead["terminal_agent"]),
                         ("claude-s1", "herdr:claude", "claude"))
        self.assertEqual((lead["pane_ref"], lead["tab_ref"], lead["workspace_name"], lead["tab_name"]),
                         ("w1:p3", "w1:t2", "rapid", "agents"))
        self.assertEqual((lead["cwd"], lead["text"], lead["focused"], lead["schema_version"]),
                         ("/w/rapid-fix", "lead", "true", "3"))
        self.assertEqual((lead["worktree_repo"], lead["worktree_checkout"], lead["linked_worktree"]),
                         ("/w/rapid", "/w/rapid-fix", "true"))
        self.assertEqual((lead["resume_agent"], lead["resume_command"]), ("claude", "claude --resume claude-s1"))
        self.assertTrue(lead["command_line"].startswith("claude --api-key="))
        self.assertNotIn(TOKEN, json.dumps(lead))
        self.assertIsNone(lead["timestamp_utc"])
        # A pi pane reports its session file instead of an ID; public pane number 33 is "11" in herdr's alphabet.
        self.assertEqual((pi["session_id"], pi["agent_session_file"], pi["pane_ref"], pi["focused"]),
                         ("", "/Users/o/.pi/agent/sessions/s2.jsonl", "w1:p11", "false"))
        snapshot = next(r for r in found["agent-terminal-pane"] if r["snapshot_kind"] == "snapshot")
        self.assertEqual((snapshot["timestamp_utc"], snapshot["snapshot_pid"], snapshot["herdr_session"]),
                         ("2026-09-21T14:13:20.123456+00:00", "2240", "default"))
        (legacy,) = [r for r in found["agent-terminal-pane"] if r["snapshot_kind"] == "backup"]
        self.assertEqual((legacy["herdr_session"], legacy["cwd"], legacy["pane_id"], legacy["pane_ref"]),
                         ("work", "/w/old", "1", ""))
        self.assertEqual(events, [("agent-terminal-pane", "layout-saved")] * 3)

    def test_screen_history_logs_plugins_config_and_detection_status(self):
        self.write(f"{CONFIG}/session-history.json", {
            "version": 3, "layout_fingerprint": "ab" * 32,
            "workspaces": [{"tabs": [{"panes": {"3": {
                "ansi": f"\x1b[1;32m$\x1b[0m export GITHUB_TOKEN={TOKEN}\r\n\x1b]0;title\x07done\n", "lines": 2}}}]}]})
        self.write(f"{CONFIG}/herdr-server.log", "\n".join([
            '2026-09-21T14:13:20.000001Z  INFO herdr::logging: herdr starting event="app.startup" subsystem="server" '
            'outcome="started" pid=2240',
            '2026-09-21T14:13:21.000000Z  INFO herdr::logging: pane child spawned event="pane.spawned" '
            'subsystem="pane" outcome="ok" pane_id=3 pid=2301',
            '2026-09-21T14:13:22.000000Z DEBUG herdr::render: frame drawn',
            '2026-09-21T14:13:23.000000Z  INFO herdr::logging: session saved event="persist.save" subsystem="persist" '
            'outcome="ok" path=/Users/o/Library/Application Support/x/session.json workspaces=1',
            '2026-09-21T14:13:24.000000Z  WARN herdr::persist::io: failed to read session file err="denied \\"x\\""',
            '2026-09-21T14:23:20.000000Z  INFO herdr::logging: pane child exited event="pane.exit" subsystem="pane" '
            'outcome="completed" pane_id=3 status="exit status: 0"',
            "    continuation of a multi-line message",
        ]).encode() + b"\n")
        self.write(f"{CONFIG}/herdr.log.1", b"not a tracing line\n")
        self.write(f"{CONFIG}/plugins.json", [{
            "plugin_id": "devswha.herdr-web-ui", "name": "herdr web ui", "version": "0.3.0", "manifest_path": "/m",
            "plugin_root": "/p", "enabled": True, "description": "Browser view of panes",
            "source": {"kind": "github", "owner": "devswha", "repo": "herdr-web-ui", "resolved_commit": "210f619d6b7b",
                       "installed_unix_ms": 1_790_000_000_000}}])
        self.write(f"{CONFIG}/config.toml",
                   b'[session]\nresume_agents_on_restore = false\n[experimental]\npane_history = true\n'
                   b'[worktrees]\ndirectory = "~/.herdr/worktrees"\n[theme]\nname = "x"\n')
        self.write(f"{STATE}/agent-detection/status.toml",
                   b'last_check_unix = 1790000000\nlast_result = "updated"\n'
                   b'[agents.claude]\ncached_version = "7"\nlast_result = "ok"\n')

        rows, events = self.collect()
        found = by_type(rows)
        (screen,) = found["agent-terminal-history"]
        self.assertEqual((screen["pane_id"], screen["line_count"], screen["layout_fingerprint"]),
                         ("3", "2", "ab" * 32))
        self.assertTrue(screen["text"].startswith("$ export GITHUB_TOKEN="))
        self.assertTrue(screen["text"].endswith("done\n"))
        self.assertNotIn(TOKEN, screen["text"])
        self.assertNotIn("\x1b", screen["text"])
        (start,) = [r for r in found["agent-terminal-event"] if r["event"] == "app.startup"]
        self.assertEqual((start["text"], start["process_id"], start["log_role"], start["timestamp_utc"]),
                         ("herdr starting", "2240", "server", "2026-09-21T14:13:20.000001+00:00"))
        (saved,) = [r for r in found["agent-terminal-event"] if r["event"] == "persist.save"]
        self.assertNotIn("path", saved)
        (warning,) = [r for r in found["agent-terminal-event"] if not r["event"]]
        self.assertEqual((warning["log_level"], warning["log_target"], warning["error"]),
                         ("WARN", "herdr::persist::io", 'denied "x"'))
        (spawned,) = found["agent-pane-spawned"]
        (exited,) = found["agent-pane-exited"]
        self.assertEqual((spawned["pane_id"], spawned["process_id"], spawned["source_line"]), ("3", "2301", 2))
        self.assertEqual((exited["pane_id"], exited["exit_status"]), ("3", "exit status: 0"))
        (plugin,) = found["agent-terminal-plugin"]
        self.assertEqual((plugin["plugin_id"], plugin["plugin_repo"], plugin["enabled"], plugin["timestamp_utc"]),
                         ("devswha.herdr-web-ui", "devswha/herdr-web-ui", "true", "2026-09-21T14:13:20+00:00"))
        (settings,) = found["agent-settings"]
        self.assertEqual((settings["resume_agents_on_restore"], settings["pane_history"], settings["worktree_directory"]),
                         ("false", "true", "~/.herdr/worktrees"))
        self.assertEqual(settings["config_keys"], ["session", "experimental", "worktrees", "theme"])
        (check,) = found["agent-terminal-update-check"]
        self.assertEqual((check["text"], check["detection_agents"], check["timestamp_utc"]),
                         ("updated", ["claude 7"], "2026-09-21T14:13:20+00:00"))
        self.assertNotIn("agent-parse-note", found)
        self.assertEqual(events, [
            ("agent-pane-exited", "ended"), ("agent-pane-spawned", "started"), ("agent-terminal-event", "event"),
            ("agent-terminal-event", "event"), ("agent-terminal-event", "event"),
            ("agent-terminal-plugin", "installed"), ("agent-terminal-update-check", "detection-checked")])
