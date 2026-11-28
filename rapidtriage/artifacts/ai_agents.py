"""Collect coding-agent records strictly below the supplied evidence directory."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from ..core.ai_agent_kinds import AI_AGENT_LABELS
from ..core.models import ArtifactRecord
from ._walk import iter_evidence_paths
from .ai_agent_editor import editor, editor_value
from .ai_agent_orca import identify_orca, orca
from .ai_agent_records import Source, content, items, mapping
from .ai_agent_sessions import claude, claude_history, codex, gemini

LINE_BYTES = 1 << 20
STREAM_BYTES = 64 << 20
DOCUMENT_BYTES = 8 << 20
ROWS_PER_SOURCE = 20_000
EDITORS = {"cursor", "code", "code - insiders", "vscodium"}


def identify(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Match path components relative to the acquisition (including copied project settings)."""
    name = parts[-1]
    if name.endswith(".jsonl"):
        for index, part in enumerate(parts[:-1]):
            tail = parts[index + 1:]
            if part == ".claude" and tail[0] == "projects":
                return "claude-code", "session"
            if part == ".codex" and tail[0] == "sessions":
                return "codex-cli", "session"
        if parts[-2:] == (".codex", "history.jsonl"):
            return "codex-cli", "history"
        if parts[-2:] == (".claude", "history.jsonl"):
            return "claude-code", "history"
    if ".gemini" in parts:
        tail = parts[parts.index(".gemini") + 1:]
        if len(tail) == 4 and tail[0] == "tmp" and tail[2] == "chats" and name.endswith((".json", ".jsonl")):
            return "gemini-cli", "session"
        if len(tail) == 3 and tail[0] == "tmp" and name == "logs.json":
            return "gemini-cli", "session"
    if name == ".claude.json" or (parts[-2:-1] == (".claude",) and name in ("settings.json", "settings.local.json")):
        return "claude-code", "config"
    if parts[-2:] == (".codex", "config.toml"):
        return "codex-cli", "config"
    if parts[-2:] == (".gemini", "settings.json"):
        return "gemini-cli", "config"
    if name == ".mcp.json":
        return "claude-code", "mcp"
    if parts[-2:] in ((".cursor", "mcp.json"), (".vscode", "mcp.json")):
        return "editor-chat", "mcp"
    if len(parts) >= 3 and parts[-3] in EDITORS and parts[-2:] == ("user", "mcp.json"):
        return "editor-chat", "mcp"
    if len(parts) >= 4 and parts[-4] in EDITORS and parts[-3:] == ("user", "globalstorage", "state.vscdb"):
        return "editor-chat", "database"
    # Workspace stores hold the per-folder chat keys; chat session files are VS Code's JSON store.
    if len(parts) >= 5 and parts[-5] in EDITORS and parts[-4:-2] == ("user", "workspacestorage") and name == "state.vscdb":
        return "editor-chat", "database"
    if name.endswith(".json") and len(parts) >= 6 and parts[-6] in EDITORS and parts[-5:-3] == (
            "user", "workspacestorage") and parts[-2] == "chatsessions":
        return "editor-chat", "document"
    if name.endswith(".json") and len(parts) >= 5 and parts[-5] in EDITORS and parts[-4:-1] == (
            "user", "globalstorage", "emptywindowchatsessions"):
        return "editor-chat", "document"
    return identify_orca(parts)


def configuration(src, doc):
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    model = doc.get("model", "")
    if isinstance(model, dict):
        model = model.get("name", "")
    if src.kind != "agent-mcp":
        yield src.row(
            "settings", model=model, env_names=list(mapping(doc.get("env"))),
            permission_mode=mapping(doc.get("permissions")).get("defaultMode"),
            approval_policy=doc.get("approval_policy"), sandbox_mode=doc.get("sandbox_mode"),
        )
        return
    sections = [(None, doc)]
    if src.agent == "claude-code":
        sections.extend((key, mapping(value)) for key, value in mapping(doc.get("projects")).items())
    for project, section in sections:
        servers = section.get("mcp_servers" if src.agent == "codex-cli" else "mcpServers")
        if servers is None and src.agent == "editor-chat":
            servers = section.get("servers")
        if servers is not None and not isinstance(servers, dict):
            yield src.note("invalid-server-map")
        for name, server in mapping(servers).items():
            if not isinstance(server, dict):
                yield src.note("invalid-server-config", server_name=name)
                continue
            env = list(mapping(server.get("env")))
            env.extend(items(server.get("env_vars")))
            env.extend(mapping(server.get("env_http_headers")).values())
            if isinstance(server.get("bearer_token_env_var"), str):
                env.append(server["bearer_token_env_var"])
            # Arguments, headers and URLs may contain unlabelled credentials.
            # Only the configured executable and environment variable names are exported.
            yield src.row("mcp-server", server_name=name, command_line=server.get("command", ""),
                          env_names=env, project=project or "")


def parse_record(src, doc, mode):
    if isinstance(doc, dict):
        # VS Code chat session files declare their layout as ``version``.
        version = doc.get("schema_version", doc.get("schemaVersion", doc.get("version") if mode == "document" else None))
        if isinstance(version, (str, int)) and not isinstance(version, bool):
            src.version = str(version)
    if mode in ("mcp", "config"):
        yield from configuration(src, doc)
    elif mode == "document" and isinstance(doc, dict):
        yield from editor_value(src, "", doc)
    elif src.agent == "gemini-cli" and isinstance(doc, (list, dict)):
        yield from gemini(src, doc)
    elif not isinstance(doc, dict):
        yield src.note("invalid-record-shape", damaged_count=1)
    elif src.agent == "claude-code":
        yield from claude_history(src, doc) if mode == "history" else claude(src, doc)
    elif src.agent == "codex-cli":
        yield from codex(src, doc, mode == "history")


def line_records(path):
    with path.open("rb") as stream:
        size = path.stat().st_size
        limit = min(size, STREAM_BYTES)
        line = 0
        while stream.tell() < limit:
            start = stream.tell()
            raw = stream.readline(min(limit - start, LINE_BYTES + 1))
            if not raw:
                break
            line += 1
            location = {"source_line": line, "source_offset": start}
            if len(raw) > LINE_BYTES:
                while not raw.endswith(b"\n") and stream.tell() < limit:
                    raw = stream.readline(min(limit - stream.tell(), LINE_BYTES))
                    if not raw:
                        break
                yield location, None, "line-size-limit"
                continue
            if stream.tell() == limit and limit < size and not raw.endswith(b"\n"):
                break
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (ValueError, RecursionError):
                yield location, None, "invalid-json-line"
                continue
            yield location, doc, ""
        if size > limit:
            yield {"source_offset": limit}, None, "stream-byte-limit"


def message_key(role, text):
    return role, hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()


def next_turn(record, turn):
    """Codex persists a ``turn_context`` before each user turn's records. A recorded ``turn_id``
    names the turn (a context repeated after compaction keeps it); without one, each context
    starts a new turn. ``turn`` is ``(identity, contexts seen)``."""
    if record.get("type") != "turn_context":
        return turn
    count = turn[1] + 1
    ident = mapping(record.get("payload")).get("turn_id")
    return (("turn_id", ident) if isinstance(ident, str) and ident else ("turn_context", count)), count


def progress_message(record):
    payload = mapping(record.get("payload"))
    event = payload.get("type")
    text = payload.get("message")
    if record.get("type") == "event_msg" and event in ("user_message", "agent_message") and isinstance(text, str):
        return "user" if event == "user_message" else "assistant", text
    return None


def replay_counts(path):
    """Count replay and progress messages per turn so duplicate progress events do not double the
    transcript. A replay only stands in for a progress message of the same turn."""
    replays = Counter()
    progress = Counter()
    progress_seen = replays_seen = 0
    turn = (("turn_context", 0), 0)
    for _, obj, _reason in line_records(path):
        record = mapping(obj)
        turn = next_turn(record, turn)
        payload = mapping(record.get("payload"))
        role = payload.get("role")
        message = progress_message(record)
        if message is not None:
            if progress_seen < ROWS_PER_SOURCE:
                progress[turn[0], message_key(*message)] += 1
                progress_seen += 1
        elif record.get("type") == "response_item" and payload.get("type") == "message" and role in ("user", "assistant"):
            replays[turn[0], message_key(role, content(payload.get("content")))] += 1
            replays_seen += 1
            if replays_seen == ROWS_PER_SOURCE:
                break
    # More progress copies than replays in one turn: which copies the replays stand for is not recorded.
    ambiguous = {key for key, count in replays.items() if progress[key] > count}
    return replays, ambiguous


def json_lines(src, path, mode):
    replay = None
    turn = (("turn_context", 0), 0)
    for location, doc, reason in line_records(path):
        src.location = location
        if reason:
            yield src.note(reason, **({"damaged_count": 1} if reason != "stream-byte-limit" else {}))
            continue
        if src.agent == "codex-cli" and mode == "session":
            record = mapping(doc)
            turn = next_turn(record, turn)
            if record.get("type") == "event_msg":
                message = progress_message(record)
                if message is not None:
                    if replay is None:
                        replay = replay_counts(path)
                    counts, ambiguous = replay
                    key = turn[0], message_key(*message)
                    if counts[key]:
                        counts[key] -= 1
                    else:
                        row = src.row("message", role=message[0], timestamp=record.get("timestamp"), text=message[1],
                                      record_format="event_msg")
                        if key in ambiguous:
                            row.details["flags"].append("replay-pairing-ambiguous")
                        yield row
                continue
        yield from parse_record(src, doc, mode)


def read_source(src, path, mode):
    if src.agent == "orca-bots":
        yield from orca(src, path, mode)
    elif mode == "database":
        yield from editor(src, path)
    elif path.suffix.lower() == ".jsonl":
        yield from json_lines(src, path, mode)
    else:
        src.location = {"source_offset": 0}
        with path.open("rb") as stream:
            raw = stream.read(DOCUMENT_BYTES + 1)
        if len(raw) > DOCUMENT_BYTES:
            yield src.note("document-size-limit")
            return
        try:
            text = raw.decode("utf-8-sig")
            doc = tomllib.loads(text) if path.suffix.lower() == ".toml" else json.loads(text)
        except (ValueError, RecursionError):
            yield src.note("invalid-document")
            return
        yield from parse_record(src, doc, mode)


class AiAgentProvider:
    target_platform = "any"

    def __init__(self, kind: str):
        self.collector_kind = self.name = kind
        self.description = AI_AGENT_LABELS[kind]

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterator[ArtifactRecord]:
        for path in iter_evidence_paths(root):
            relative = path.relative_to(root)
            parts = tuple(p.casefold() for p in relative.parts)
            match = identify(parts)
            if not match:
                continue
            agent, mode = match
            if self.collector_kind == "agent-mcp":
                if mode not in ("config", "mcp"):
                    continue
            elif agent != self.collector_kind or mode == "mcp":
                continue
            src = Source(self.collector_kind, relative.as_posix(), agent)
            calls = {}
            try:
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
                    continue
                with closing(read_source(src, path, mode)) as rows:
                    for index, row in enumerate(rows):
                        if index == ROWS_PER_SOURCE:
                            yield src.note("row-limit")
                            break
                        # Results often store only a call ID. Correlate within this
                        # source and session, retaining a bounded set of names.
                        key = (row.details["session_id"], row.details.get("call_id"))
                        if key[1] and row.artifact_type == "agent-tool-call":
                            if len(calls) >= 1024:
                                calls.pop(next(iter(calls)))
                            calls[key] = row.details["tool_name"]
                        elif key[1] and row.artifact_type == "agent-tool-result" and not row.details["tool_name"]:
                            row.details["tool_name"] = calls.get(key, "")
                        yield row
            except (OSError, sqlite3.Error):
                yield src.note("source-unreadable")
