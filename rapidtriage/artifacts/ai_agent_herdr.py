"""herdr records (github.com/herdrdev/herdr): the terminal multiplexer that runs coding agents in workspaces, tabs and
panes. Formats follow herdr's public source at tag ``v0.9.5``: ``src/persist/snapshot.rs`` (``session.json`` and
``session-history.json``), ``src/persist/writer.rs`` (``session-snapshots/`` and ``session-backups/``),
``src/session.rs`` (named sessions under ``sessions/<name>``), ``src/logging.rs`` (``herdr*.log``),
``src/persist/plugin_registry.rs`` with ``src/api/schema/plugins.rs`` (``plugins.json``), ``src/config/model.rs``
(``config.toml``) and ``src/detect/manifest_update.rs`` (``agent-detection/status.toml``).

herdr records no transcript: a pane's conversation stays in its agent's own store. The pane's agent session ID (or
session file path) is the key that joins a pane to the rows of the Claude Code, Codex, pi and other collectors."""
from __future__ import annotations

import datetime as dt
import json
import re
import shlex
import sys
from dataclasses import replace
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from .ai_agent_records import clean, items, mapping

KIND = "herdr-sessions"
DOCUMENT_BYTES = 8 << 20
# Pane screen history is the whole scrollback of every pane in one document.
HISTORY_BYTES = 64 << 20
LOG_BYTES = 64 << 20
LINE_BYTES = 1 << 20
LIST_LIMIT = 64
# ``config/io.rs``: the release build uses ``herdr``, a debug build ``herdr-dev``.
APP_DIRS = {"herdr", "herdr-dev"}
# ``writer.rs``: ``session-<39-digit epoch ns>-<pid>-<sequence>.json``.
RECOVERY = re.compile(r"^session-(?P<ns>\d{39})-(?P<pid>\d+)-(?P<seq>\d+)\.json$")
# ``logging.rs``: ``herdr.log``, ``herdr-client.log`` and ``herdr-server.log``, rotated to ``<name>.<n>``.
LOG_NAME = re.compile(r"^herdr(?:-(?P<role>client|server))?\.log(?:\.\d{1,3})?$")
# tracing-subscriber's default line: RFC 3339 UTC time, level, target, message, then ``key=value`` fields.
LOG_LINE = re.compile(r"^(?P<at>\d{4}-\d\d-\d\dT\S+)\s+(?P<level>TRACE|DEBUG|INFO|WARN|ERROR)\s+(?P<target>.*?):\s(?P<rest>.*)$")
LOG_FIELD = re.compile(r"(?:^|\s)([a-z_][a-z0-9_]*)=")
# Log fields exported by name; anything else on the line (paths, sizes, request IDs) stays in the file.
LOG_FIELDS = {"event": "event", "subsystem": "subsystem", "outcome": "outcome", "pane_id": "pane_id",
              "pid": "process_id", "status": "exit_status", "workspace_id": "workspace_id", "tab_id": "tab_id",
              "method": "api_method", "err": "error", "version": "available_version"}
LOG_TYPES = {"pane.spawned": "pane-spawned", "pane.exit": "pane-exited"}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[@-Z\\-_]"
                  r"|[\x00-\x08\x0b-\x1f\x7f]")
# ``workspace.rs``: public workspace, tab and pane numbers in herdr's bijective base-32 alphabet (``w1:p3``).
PUBLIC_ALPHABET = "123456789ABCDEFGHJKMNPQRSTVWXYZ0"


def identify_herdr(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Files in herdr's config folder (``.config/herdr``, Windows ``AppData/Roaming/herdr``), in a named session
    below it (``sessions/<name>``) and the detection status in its state folder (``.local/state/herdr``, Windows
    ``AppData/Local/herdr``). An ``XDG_CONFIG_HOME`` or ``XDG_STATE_HOME`` moved elsewhere is not searched."""
    for index in range(1, len(parts) - 1):
        if parts[index] not in APP_DIRS:
            continue
        parent = parts[max(0, index - 2):index]
        tail = parts[index + 1:]
        if parent[-1:] == (".config",) or parent == ("appdata", "roaming"):
            mode = config_mode(tail)
        elif parent in ((".local", "state"), ("appdata", "local")):
            mode = "detection-status" if tail == ("agent-detection", "status.toml") else None
        else:
            mode = None
        if mode:
            return KIND, mode
    return None


def config_mode(tail: tuple[str, ...]) -> str | None:
    if tail == ("plugins.json",):
        return "plugins"
    if tail == ("config.toml",):
        return "herdr-config"
    if len(tail) > 2 and tail[0] == "sessions":
        tail = tail[2:]
    name = tail[-1]
    if tail in (("session.json",), ("session-history.json",)):
        return "layout" if name == "session.json" else "history"
    if len(tail) == 2 and tail[0] in ("session-snapshots", "session-backups") and RECOVERY.match(name):
        return "layout"
    return "log" if len(tail) == 1 and LOG_NAME.match(name) else None


def herdr_session(path: Path) -> str:
    """The named session a file belongs to: ``sessions/<name>/...`` below the config folder, else ``default``."""
    folder = path.parent.parent if path.parent.name.casefold() in ("session-snapshots", "session-backups") else path.parent
    if folder.parent.name.casefold() == "sessions" and folder.parent.parent.name.casefold() in APP_DIRS:
        return folder.name
    return "default"


def public_number(value) -> str:
    """``encode_public_number``: bijective base 32, so 1 is ``1``, 32 is ``0`` and 33 is ``11``."""
    if type(value) is not int or value < 0:
        return ""
    if value == 0:
        return "0"
    out = []
    while value:
        out.append(PUBLIC_ALPHABET[(value - 1) % 32])
        value = (value - 1) // 32
    return "".join(reversed(out))


def nanos_time(value: str) -> str:
    """Epoch nanoseconds as ISO UTC, to the microsecond."""
    seconds, nanos = divmod(int(value), 1_000_000_000)
    instant = dt.datetime.fromtimestamp(seconds, dt.timezone.utc).replace(microsecond=nanos // 1000)
    return instant.isoformat()


def flag(value) -> str:
    return str(value).lower() if isinstance(value, bool) else ""


def number(value) -> str:
    return str(value) if type(value) in (int, float) else ""


def text_of(value) -> str:
    return value if isinstance(value, str) else ""


def command(argv) -> str:
    return shlex.join([v for v in items(argv) if isinstance(v, str)][:LIST_LIMIT])


def listed(row, key, values):
    values = items(values)
    row.details[key] = [clean(v) for v in values[:LIST_LIMIT] if isinstance(v, str)]
    if len(values) > LIST_LIMIT:
        row.details["flags"].append("list-length-limit")
    return row


def herdr(src, path: Path, mode: str):
    session = herdr_session(path)
    if mode == "log":
        yield from log(src, path, session)
        return
    src.location = {"source_offset": 0}
    limit = HISTORY_BYTES if mode == "history" else DOCUMENT_BYTES
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        yield src.note("document-size-limit")
        return
    try:
        text = raw.decode("utf-8-sig")
        doc = tomllib.loads(text) if path.suffix.lower() == ".toml" else json.loads(text)
    except (ValueError, RecursionError):
        yield src.note("invalid-document")
        return
    if mode in ("layout", "history"):
        if not isinstance(doc, dict) or not isinstance(doc.get("workspaces"), list):
            yield src.note("invalid-config-shape")
            return
        if type(doc.get("version")) is int:
            src.version = str(doc["version"])
    yield from DOCUMENT_ROWS[mode](src, doc, path, session)


def layout(src, doc, path, session):
    """``SessionSnapshot``: one row per pane with its workspace, tab, working folder, detected agent, the agent
    session it reported and the command it was launched or resumed with. A recovery copy's time is the instant herdr
    preserved it (from its name); ``session.json`` itself records no time."""
    recovery = RECOVERY.match(path.name)
    kind = "current" if not recovery else "snapshot" if path.parent.name == "session-snapshots" else "backup"
    for w_index, workspace in enumerate(items(doc.get("workspaces"))):
        workspace = mapping(workspace)
        tabs = items(workspace.get("tabs"))
        if not tabs and "panes" in workspace:
            # Pre-tab layout (snapshot version 1-2): the workspace is its own single tab.
            tabs = [workspace]
        ws_id = text_of(workspace.get("id"))
        space = mapping(workspace.get("worktree_space"))
        numbers = mapping(workspace.get("public_pane_numbers"))
        tab_numbers = items(workspace.get("public_tab_numbers"))
        for t_index, tab in enumerate(tabs):
            tab = mapping(tab)
            panes = mapping(tab.get("panes"))
            tab_number = public_number(tab_numbers[t_index]) if t_index < len(tab_numbers) else ""
            for p_index, (pane_key, pane) in enumerate(panes.items()):
                pane = mapping(pane)
                agent_session = mapping(pane.get("agent_session"))
                resume = mapping(pane.get("agent_resume"))
                by_id = agent_session.get("kind") == "id"
                pane_number = public_number(numbers.get(pane_key))
                pane_src = replace(src, location={"source_offset": 0, "workspace_index": w_index, "tab_index": t_index,
                                                  "pane_index": p_index},
                                   session=agent_session.get("value") if by_id else "", cwd=text_of(pane.get("cwd")))
                out = pane_src.row(
                    "terminal-pane", text=pane.get("label"), snapshot_kind=kind, herdr_session=session,
                    workspace_id=ws_id, workspace_name=workspace.get("custom_name"),
                    workspace_cwd=workspace.get("identity_cwd"), worktree_label=space.get("label"),
                    worktree_repo=space.get("repo_root"), worktree_checkout=space.get("checkout_path"),
                    linked_worktree=flag(space.get("is_linked_worktree")),
                    tab_ref=f"{ws_id}:t{tab_number}" if ws_id and tab_number else "", tab_name=tab.get("custom_name"),
                    pane_id=pane_key, pane_ref=f"{ws_id}:p{pane_number}" if ws_id and pane_number else "",
                    focused=flag(str(tab.get("focused")) == pane_key) if "focused" in tab else "",
                    zoomed=flag(tab.get("zoomed")), terminal_agent=pane.get("agent_name"),
                    managed_agent=pane.get("managed_agent_kind"), agent_session_source=agent_session.get("source"),
                    agent_session_agent=agent_session.get("agent"),
                    agent_session_file=agent_session.get("value") if agent_session.get("kind") == "path" else "",
                    command_line=command(pane.get("launch_argv")), resume_agent=resume.get("agent"),
                    resume_command=command(resume.get("argv")))
                if recovery:
                    out.details["timestamp_raw"] = recovery["ns"]
                    out.details["timestamp_utc"] = nanos_time(recovery["ns"])
                    out.details["snapshot_pid"] = recovery["pid"]
                yield out


def history(src, doc, path, session):
    """``SessionHistorySnapshot`` (written only with ``experimental.pane_history``): each pane's screen and
    scrollback as ANSI text. Escape sequences are removed; the text passes the usual redaction and length limit.
    Workspaces and tabs are in the order of the ``session.json`` saved with it (``layout_fingerprint``)."""
    fingerprint = text_of(doc.get("layout_fingerprint"))
    for w_index, workspace in enumerate(items(doc.get("workspaces"))):
        for t_index, tab in enumerate(items(mapping(workspace).get("tabs"))):
            for pane_key, pane in mapping(mapping(tab).get("panes")).items():
                pane = mapping(pane)
                screen = ANSI.sub("", text_of(pane.get("ansi")))
                yield replace(src, location={"source_offset": 0, "workspace_index": w_index,
                                             "tab_index": t_index}).row(
                    "terminal-history", text=screen, herdr_session=session, pane_id=pane_key,
                    line_count=number(pane.get("lines")), layout_fingerprint=fingerprint)


def log_fields(rest: str) -> tuple[str, dict]:
    """Split a tracing line after the target into the message and its ``key=value`` fields. A quoted value is a
    Rust debug string; an unquoted one runs to the next field (a displayed path may contain spaces)."""
    match = LOG_FIELD.search(rest)
    if not match:
        return rest.strip(), {}
    message, fields = rest[:match.start()].strip(), {}
    while match:
        key, start = match[1], match.end()
        if rest.startswith('"', start):
            end = start + 1
            while end < len(rest) and rest[end] != '"':
                end += 2 if rest[end] == "\\" else 1
            try:
                value = json.loads(rest[start:end + 1])
            except ValueError:
                value = rest[start + 1:end]
            match = LOG_FIELD.search(rest, end + 1)
        else:
            match = LOG_FIELD.search(rest, start)
            value = rest[start:match.start() if match else len(rest)].strip()
        fields[key] = value
    return message, fields


def log(src, path, session):
    """``herdr*.log``: lines with a structured ``event`` (start and exit, pane spawn and exit, workspace and tab
    changes, session saves, API requests, update checks) and every warning or error. Other lines are not exported.
    A pane's ``pane_id`` is the key of the pane in the ``session.json`` of the same session."""
    role = LOG_NAME.match(path.name)["role"] or "main"
    size = path.stat().st_size
    with path.open("rb") as stream:
        offset, line = 0, 0
        limit = min(size, LOG_BYTES)
        while offset < limit:
            raw = stream.readline(min(limit - offset, LINE_BYTES + 1))
            if not raw:
                break
            line += 1
            start, offset = offset, offset + len(raw)
            src.location = {"source_line": line, "source_offset": start}
            if len(raw) > LINE_BYTES:
                while not raw.endswith(b"\n") and offset < limit:
                    raw = stream.readline(min(limit - offset, LINE_BYTES))
                    offset += len(raw)
                    if not raw:
                        break
                yield src.note("line-size-limit", damaged_count=1)
                continue
            match = LOG_LINE.match(raw.decode("utf-8", "replace").rstrip("\r\n"))
            if not match:
                continue
            message, fields = log_fields(match["rest"])
            event = fields.get("event", "")
            if not event and match["level"] not in ("WARN", "ERROR"):
                continue
            selected = {name: fields[key] for key, name in LOG_FIELDS.items() if key in fields}
            yield src.row(LOG_TYPES.get(event, "terminal-event"), timestamp=match["at"], text=message,
                          log_level=match["level"], log_target=match["target"], log_role=role, herdr_session=session,
                          **{"event": "", **selected})
    if size > LOG_BYTES:
        src.location = {"source_offset": LOG_BYTES}
        yield src.note("stream-byte-limit")


def plugins(src, doc, path, session):
    """``plugins.json``: installed plugins (``InstalledPluginInfo``) with their source repository, pinned commit and
    install time. Plugin manifests, configuration and state folders are not read."""
    if not isinstance(doc, list):
        yield src.note("invalid-config-shape")
        return
    for index, plugin in enumerate(doc):
        plugin = mapping(plugin)
        source = mapping(plugin.get("source"))
        repo = "/".join(v for v in (source.get("owner"), source.get("repo")) if isinstance(v, str))
        installed = source.get("installed_unix_ms")
        yield replace(src, location={"source_offset": 0, "entry_index": index}).row(
            "terminal-plugin", timestamp=installed if type(installed) is int else None, unit="ms",
            text=plugin.get("description"), plugin_id=plugin.get("plugin_id"), plugin_name=plugin.get("name"),
            plugin_version=plugin.get("version"), enabled=flag(plugin.get("enabled")),
            plugin_source_kind=source.get("kind"), plugin_repo=repo, requested_ref=source.get("requested_ref"),
            resolved_commit=source.get("resolved_commit"), plugin_root=plugin.get("plugin_root"))


def herdr_config(src, doc, path, session):
    """``config.toml``: the section names and the settings that decide what herdr keeps on disk: agent resume on
    restore, pane screen history and the worktree folder. Key bindings, themes and other values are not exported."""
    session_cfg = mapping(doc.get("session"))
    out = src.row("settings", resume_agents_on_restore=flag(session_cfg.get("resume_agents_on_restore")),
                  pane_history=flag(mapping(doc.get("experimental")).get("pane_history")),
                  worktree_directory=mapping(doc.get("worktrees")).get("directory"))
    yield listed(out, "config_keys", list(doc))


def detection_status(src, doc, path, session):
    """``agent-detection/status.toml``: the last check of herdr.dev for agent-detection rule updates (epoch seconds)
    and the agents with cached rules. The downloaded rules in ``remote/*.toml`` are herdr's public catalog."""
    checked = doc.get("last_check_unix")
    out = src.row("terminal-update-check", timestamp=checked if type(checked) is int else None, unit="s",
                  text=doc.get("last_result"))
    agents = mapping(doc.get("agents"))
    yield listed(out, "detection_agents",
                 [f"{name} {text_of(mapping(v).get('cached_version'))}".strip() for name, v in agents.items()])


DOCUMENT_ROWS = {"layout": layout, "history": history, "plugins": plugins, "herdr-config": herdr_config,
                 "detection-status": detection_status}
