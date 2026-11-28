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
from .ai_agent_editor import editor, editor_value, prompt_history
from .ai_agent_records import Source, content, items, mapping
from .ai_agent_sessions import (
    claude,
    claude_history,
    codex,
    gemini,
    pi_entry,
    pi_header,
    pi_log,
)

LINE_BYTES = 1 << 20
STREAM_BYTES = 64 << 20
DOCUMENT_BYTES = 8 << 20
ROWS_PER_SOURCE = 20_000
EDITORS = {"cursor", "code", "code - insiders", "vscodium"}
HEADER_BYTES = 64 << 10
# oh-my-pi (omp) and pi keep their state in ``<home>/agent``; senpi and OmO are pi forks with the same session
# format (senpi docs/session-format.md; OmO runs senpi with agent directory ``~/.omo/agent``).
PI_HOMES = {".omp": "omp", ".pi": "pi", ".senpi": "senpi", ".omo": "omo"}
# ``pi-family``: a session found by its header outside these folders (``--session-dir``); the product is not recorded.
PI_AGENTS = {*PI_HOMES.values(), "pi-family"}
PI_AGENT_FILES = {"history.db": "history", "config.yml": "settings", "config.yaml": "settings",
                  "settings.json": "settings", "models.yml": "models", "models.yaml": "models",
                  "models.json": "models", "mcp.json": "mcp", ".mcp.json": "mcp"}


def collector_kind(agent: str) -> str:
    return "omp-pi" if agent in PI_AGENTS else agent


def identify_pi(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """``<home>/agent`` (or an omp profile's ``<home>/profiles/<name>/agent``), omp logs, project MCP files and the
    omp XDG data and state folders (``.local/share/omp``, ``.local/state/omp``)."""
    name = parts[-1]
    for index, part in enumerate(parts[:-1]):
        tail = parts[index + 1:]
        product = PI_HOMES.get(part)
        if product is None:
            if part == "omp" and parts[max(0, index - 2):index] in ((".local", "share"), (".local", "state")):
                if tail[0] == "sessions" and len(tail) > 2 and name.endswith(".jsonl"):
                    return "omp", "session"
                if tail == ("history.db",):
                    return "omp", "history"
                if len(tail) == 2 and tail[0] == "logs" and name.startswith("omp.") and name.endswith(".log"):
                    return "omp", "log"
            continue
        if len(tail) == 2 and tail[0] == "logs" and product == "omp" and name.startswith("omp.") and name.endswith(".log"):
            return product, "log"
        if len(tail) == 1 and name in ("mcp.json", ".mcp.json"):
            return product, "mcp"
        start = 1 if tail[0] == "agent" else 3 if tail[0] == "profiles" and tail[2:3] == ("agent",) else 0
        rest = tail[start:] if start else ()
        if rest[:1] == ("sessions",) and len(rest) > 2 and name.endswith(".jsonl"):
            return product, "session"
        if len(rest) == 1 and name in PI_AGENT_FILES:
            return product, PI_AGENT_FILES[name]
    return None


def pi_header_agent(path: Path) -> str | None:
    """A session saved outside the default folders is recognised by its first logical record: the ``session``
    header with a string ``id``, after omp's fixed-width ``title`` slot when present (the loaders' own check). As
    this runs on every unclaimed ``.jsonl``, the header must also carry the string ``cwd`` and ``timestamp`` that
    omp and pi always write, and it is decoded as strict UTF-8 like the reader (no BOM, no UTF-16)."""
    with path.open("rb") as stream:
        head = stream.read(HEADER_BYTES).split(b"\n", 2)
    agent = "pi-family"
    for index, raw in enumerate(head[:2]):
        try:
            doc = mapping(json.loads(raw.decode("utf-8")))
        except (ValueError, RecursionError):
            return None
        if index == 0 and doc.get("type") == "title" and doc.get("v") == 1:
            agent = "omp"
            continue
        header = doc.get("type") == "session" and all(isinstance(doc.get(key), str) for key in ("id", "cwd", "timestamp"))
        return agent if header else None
    return None


def identify(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Match path components relative to the acquisition (including copied project settings)."""
    pi = identify_pi(parts)
    if pi:
        return pi
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
    return None


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


def pi_settings(src, doc, mode):
    """Model names only. Provider base URLs, API keys, headers and authentication settings are never exported."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    if mode == "models":
        for name, provider in mapping(doc.get("providers")).items():
            models = [mapping(model).get("id") for model in items(mapping(provider).get("models"))]
            yield src.row("settings", provider=name, model_ids=models)
        return
    # omp ``config.yml`` assigns models to roles; pi-family ``settings.json`` names a default provider and model.
    roles = {k: v for k, v in mapping(doc.get("modelRoles")).items() if isinstance(k, str) and isinstance(v, str)}
    yield src.row("settings", model=roles.get("default", doc.get("defaultModel", "")),
                  provider=doc.get("defaultProvider", ""), model_roles="; ".join(f"{k}={v}" for k, v in roles.items()))


def parse_record(src, doc, mode):
    if isinstance(doc, dict):
        # VS Code chat session files declare their layout as ``version``.
        version = doc.get("schema_version", doc.get("schemaVersion", doc.get("version") if mode == "document" else None))
        if isinstance(version, (str, int)) and not isinstance(version, bool):
            src.version = str(version)
    if mode in ("mcp", "config"):
        yield from configuration(src, doc)
    elif mode in ("settings", "models"):
        yield from pi_settings(src, doc, mode)
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
    elif mode == "log":
        yield from pi_log(src, doc)


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


def line_note(src, reason):
    return src.note(reason, **({"damaged_count": 1} if reason != "stream-byte-limit" else {}))


def pi_active_entries(path):
    """The active branch as the pi-family loaders rebuild it on load: the last entry in the file is the leaf, and its
    ``parentId`` chain leads back to the root. ``None`` when the leaf is unknown (no tree ids, or the file is longer
    than the read prefix, so the last entry was never read)."""
    parents, leaf = {}, None
    for _, doc, reason in line_records(path):
        if reason == "stream-byte-limit":
            return None
        record = mapping(doc)
        ident = record.get("id")
        if record.get("type") == "session" or not isinstance(ident, str):
            continue
        parent = record.get("parentId")
        parents[ident] = parent if isinstance(parent, str) else None
        leaf = ident
    active = set()
    while leaf is not None and leaf not in active:
        active.add(leaf)
        leaf = parents.get(leaf)
    return active or None


def pi_session_lines(src, path):
    """omp's title slot, then the ``session`` header, then tree entries. As in the pi-family loaders, a file whose
    first logical record is not a header is not a session, and nothing more is read from it. Entries on abandoned
    branches really happened and are exported, flagged ``off-active-branch``."""
    header = False
    active = None
    models = {}
    for location, doc, reason in line_records(path):
        src.location = location
        if reason:
            yield line_note(src, reason)
            continue
        record = mapping(doc)
        if not header:
            if record.get("type") == "title" and location["source_line"] == 1:
                continue
            if record.get("type") != "session" or not isinstance(record.get("id"), str):
                yield src.note("session-header-missing")
                return
            pi_header(src, record)
            header = True
            active = pi_active_entries(path)
        elif not isinstance(doc, dict):
            yield src.note("invalid-record-shape", damaged_count=1)
        else:
            ident = record.get("id")
            off_branch = active is not None and isinstance(ident, str) and ident not in active
            for row in pi_entry(src, record, models):
                if off_branch:
                    row.details["flags"].append("off-active-branch")
                yield row


def json_lines(src, path, mode):
    replay = None
    turn = (("turn_context", 0), 0)
    for location, doc, reason in line_records(path):
        src.location = location
        if reason:
            yield line_note(src, reason)
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


def parse_document(suffix, text):
    if suffix == ".toml":
        return tomllib.loads(text)
    if suffix in (".yml", ".yaml"):
        import yaml

        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise ValueError(str(error)) from error
    return json.loads(text)


def read_source(src, path, mode):
    if mode == "database":
        yield from editor(src, path)
    elif mode == "history" and src.agent in PI_AGENTS:
        yield from prompt_history(src, path)
    elif mode == "session" and src.agent in PI_AGENTS:
        yield from pi_session_lines(src, path)
    elif path.suffix.lower() == ".jsonl" or mode == "log":
        yield from json_lines(src, path, mode)
    else:
        src.location = {"source_offset": 0}
        with path.open("rb") as stream:
            raw = stream.read(DOCUMENT_BYTES + 1)
        if len(raw) > DOCUMENT_BYTES:
            yield src.note("document-size-limit")
            return
        try:
            doc = parse_document(path.suffix.lower(), raw.decode("utf-8-sig"))
        except ModuleNotFoundError:
            # PyYAML is imported lazily (pyproject.toml); a trimmed install skips this document, not the whole run.
            yield src.note("parser-unavailable")
            return
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
            if match is None and self.collector_kind == "omp-pi" and parts[-1].endswith(".jsonl"):
                match = "pi-family", "header"
            if not match:
                continue
            agent, mode = match
            if self.collector_kind == "agent-mcp":
                if mode not in ("config", "mcp"):
                    continue
            elif collector_kind(agent) != self.collector_kind or mode == "mcp":
                continue
            src = Source(self.collector_kind, relative.as_posix(), agent)
            calls = {}
            try:
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
                    continue
                if mode == "header":
                    # An unreadable unclaimed ``.jsonl`` is not known to be a session; it is not an omp-pi source.
                    try:
                        src.agent = pi_header_agent(path)
                    except OSError:
                        continue
                    if src.agent is None:
                        continue
                    mode = "session"
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
