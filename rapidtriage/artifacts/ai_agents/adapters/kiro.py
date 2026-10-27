"""Kiro IDE adapter (R7 AI plan §3.2; schema PC_SURVEY §4.8).

``~/.kiro/sessions/<workspaceHash>/sess_<uuid>/session.json`` is session metadata (model, mode,
workspace paths, times); message bodies were not found on the reference PC, so a ``history`` /
``messages`` list in ``session.json`` is parsed only if present (shape not validated).
``session-index/*.jsonl`` events are counted per session; ``logs/<ts>/mcp.log`` gives MCP server
rows (heuristic line parser; Kiro log lines carry no time zone -> ``timestamp_local``);
``steering/`` rules are instruction files; ``state.vscdb`` auth/token keys are existence-only.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import redact_str
from ._common import (
    COVERAGE_NOT_VALIDATED,
    RowContext,
    SessionAccumulator,
    app_dirs,
    content_text,
    credential_row,
    instruction_row,
    iter_jsonl,
    iter_profiles,
    make_found,
    open_sqlite_ro,
    parse_mcp_log,
    presence_row,
    profile_os,
    read_small_json,
    summary_row,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "kiro"
LABEL = "Kiro"


class KiroAdapter(AiAgentAdapter):
    name = "kiro"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".kiro") for profile in iter_profiles(roots, os_hint) if (profile.home / ".kiro").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home")]
        index_events: dict[str, int] = {}
        index_dir = base / "session-index"
        if index_dir.is_dir():
            for path in sorted(index_dir.glob("*.jsonl")):
                for record in iter_jsonl(path, ctx.budget):
                    key = str(record.get("sessionPath") or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                    if key:
                        index_events[key] = index_events.get(key, 0) + 1
        sessions_dir = base / "sessions"
        session_rows: list[AiRow] = []
        if sessions_dir.is_dir():
            for path in sorted(p for p in walk_files(sessions_dir, limit=20_000) if p.name == "session.json"):
                session_rows.extend(self._session(ctx, path, index_events))
        logs = base / "logs"
        if logs.is_dir():
            for path in sorted(walk_files(logs, limit=5000)):
                if path.name.lower().startswith("mcp") and path.suffix == ".log":
                    rows.extend(parse_mcp_log(ctx, path))
            rows.append(presence_row(ctx, logs, "logs", log_folders=sum(1 for p in logs.iterdir() if p.is_dir())))
        steering = base / "steering"
        if steering.is_dir():
            for path in walk_files(steering, limit=500):
                if path.suffix.lower() == ".md":
                    row = instruction_row(ctx, path, "steering")
                    if row:
                        rows.append(row)
        for roaming in app_dirs(found.profile.home if found.profile else base.parent, profile_os(found))["roaming"]:
            db = roaming / "Kiro" / "User" / "globalStorage" / "state.vscdb"
            if db.is_file():
                rows.extend(self._state(ctx, db))
        yield from session_rows
        yield from rows
        yield summary_row(ctx, base, sessions=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session"))

    def _session(self, ctx: RowContext, path: Path, index_events: Mapping[str, int]) -> list[AiRow]:
        data = read_small_json(path, ctx.budget, max_bytes=32 * 1024 * 1024)
        if not isinstance(data, Mapping):
            return []
        sid = str(data.get("id") or path.parent.name)
        acc = SessionAccumulator(ctx, sid, path)
        acc.see_time(to_iso(data.get("createdAt")))
        acc.see_time(to_iso(data.get("lastModifiedAt")))
        acc.note(acc.models, data.get("modelId"))
        roots = [str(p) for p in data.get("rootPaths") or [] if isinstance(p, str)]
        acc.meta.update(
            {
                "title": redact_str(data.get("title") or "")[:512],
                "agent_mode": str(data.get("agentMode") or ""),
                "autopilot": data.get("autopilot") if isinstance(data.get("autopilot"), bool) else None,
                "spec_workflow": data.get("specWorkflow") if isinstance(data.get("specWorkflow"), bool) else None,
                "cwd": redact_str(roots[0]) if roots else "",
                "workspaces": [redact_str(p) for p in (data.get("workspacePaths") or []) if isinstance(p, str)][:50],
                "workspace_hash": path.parent.parent.name,
                "schema_version": data.get("schemaVersion"),
                "index_events": index_events.get(path.parent.name, 0),
            }
        )
        history = data.get("history") if isinstance(data.get("history"), list) else data.get("messages")
        if isinstance(history, list):
            for item in history:
                if isinstance(item, Mapping) and item.get("role") and item.get("content"):
                    acc.message(str(item["role"]), to_iso(item.get("timestamp") or item.get("createdAt")), content_text(item["content"]), has_image=False, source="session.json history", coverage_note=COVERAGE_NOT_VALIDATED)
        return acc.finish()

    def _state(self, ctx: RowContext, path: Path) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, _ = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error:
            return rows
        try:
            keys = [(str(k), int(n or 0)) for k, n in conn.execute('SELECT key, length(value) FROM "ItemTable"')]
        except sqlite3.Error:
            keys = []
        finally:
            conn.close()
        agent_keys = []
        for key, length in keys:
            lowered = key.lower()
            if "token" in lowered or "secret" in lowered or "auth" in lowered.split(".")[-1] or "auth." in lowered:
                rows.append(credential_row(ctx, path, "auth-token", key_name=redact_str(key)[:256], value_bytes=length))
            elif "kiro" in lowered or "chat." in lowered:
                agent_keys.append(redact_str(key)[:200])
        rows.append(presence_row(ctx, path, "ide-state", agent_keys=agent_keys[:50]))
        return rows


register_adapter(KiroAdapter)
