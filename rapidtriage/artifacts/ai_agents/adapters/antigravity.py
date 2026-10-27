"""Google Antigravity adapter (R7 AI plan §3.2; schema PC_SURVEY §4.7).

The agent root is ``~/.gemini/antigravity`` (also the stray ``~/..gemini/antigravity``).
``conversation_summaries.db`` ``conversation_summaries`` is the session index
(``parent_conversation_id`` / ``nesting_depth`` -> ``parent_session_id``, ``workspace_uris`` ->
``workspace`` file touches); the FTS5 table is only counted. ``conversations/<uuid>.db`` ``steps``
are summarised by ``step_type`` / ``status`` with payload sizes from SQL ``length()`` - the
protobuf BLOBs are never decoded. Plain-text transcripts
``brain/<uuid>/.system_generated/logs/transcript*.jsonl`` (``transcript_full`` preferred) give
messages and ``tool_calls[].{name,args}``; ``messages/*.json`` are agent-to-agent messages.
``mcp/<server>/<tool>.json`` is the MCP tool cache, ``scratch/`` files are ``create`` touches
(listed, not read). The IDE ``state.vscdb`` ``antigravityAuthStatus`` key is existence-only.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..redact import redact_str
from ._common import (
    MAX_LIST_ITEMS,
    RowContext,
    SessionAccumulator,
    app_dirs,
    credential_row,
    decode_json_value,
    instruction_row,
    iter_jsonl,
    iter_profiles,
    make_found,
    mcp_row,
    open_sqlite_ro,
    presence_row,
    profile_os,
    read_small_json,
    select_rows,
    sqlite_over_cap,
    summary_row,
    table_columns,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "antigravity"
LABEL = "Antigravity"
KNOWN_TRANSCRIPT_TYPES = frozenset({"USER_INPUT", "PLANNER_RESPONSE", "TOOL_RESULT", "SYSTEM_MESSAGE", "MODEL_RESPONSE", "CHECKPOINT", "ERROR"})
SUMMARY_COLUMNS = (
    "conversation_id", "title", "preview", "step_count", "last_modified_time", "workspace_uris", "status", "source", "project_id",
    "agent_name", "parent_conversation_id", "nesting_depth", "killed", "last_user_input_time", "group_id",
)
_ROLE = {"user": "user", "user_explicit": "user", "user_implicit": "user", "model": "assistant", "agent": "assistant", "assistant": "assistant", "system": "system"}
MAX_SCRATCH_ROWS = 5_000


def _role(source: object) -> str:
    text = str(source or "").strip().lower()
    return _ROLE.get(text, text or "unknown")


def _uri_path(uri: str) -> str:
    if uri.startswith("file://"):
        path = unquote(urlparse(uri).path)
        return path[1:].replace("/", "\\") if len(path) > 2 and path[0] == "/" and path[2] == ":" else path
    return uri


def _workspace_uris(value: object) -> list[str]:
    parsed = decode_json_value(value) if isinstance(value, (str, bytes)) else value
    if isinstance(parsed, list):
        return [str(v) for v in parsed if isinstance(v, str)][:MAX_LIST_ITEMS]
    if isinstance(value, str) and value:
        return [part for part in value.replace(";", ",").split(",") if part][:MAX_LIST_ITEMS]
    return []


class AntigravityAdapter(AiAgentAdapter):
    name = "antigravity"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        found: list[Found] = []
        for profile in iter_profiles(roots, os_hint):
            for base in (profile.home / ".gemini" / "antigravity", profile.home / "..gemini" / "antigravity"):
                if base.is_dir():
                    found.append(make_found(self, profile, base))
        return found

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home", stray_double_dot_root=base.parent.name == "..gemini")]
        sessions: dict[str, SessionAccumulator] = {}
        order: list[str] = []

        def session(sid: str, path: Path) -> SessionAccumulator:
            acc = sessions.get(sid)
            if acc is None:
                acc = SessionAccumulator(ctx, sid, path)
                sessions[sid] = acc
                order.append(sid)
            return acc

        summaries = base / "conversation_summaries.db"
        if summaries.is_file():
            rows.extend(self._summaries(ctx, summaries, session))
        conv_dir = base / "conversations"
        if conv_dir.is_dir():
            for path in sorted(conv_dir.glob("*.db")):
                rows.extend(self._conversation_db(ctx, path, session(path.stem, path)))
        brain = base / "brain"
        if brain.is_dir():
            for conv in sorted(p for p in brain.iterdir() if p.is_dir()):
                self._brain(ctx, conv, session, rows)
        mcp = base / "mcp"
        if mcp.is_dir():
            for server in sorted(p for p in mcp.iterdir() if p.is_dir()):
                tools = sorted(p.stem for p in server.glob("*.json"))
                rows.append(mcp_row(ctx, server, server.name, status="cached", tools=tools, source="mcp-tool-cache"))
        scratch = base / "scratch"
        if scratch.is_dir():
            loose = SessionAccumulator(ctx, "", scratch)  # agent-level scratch: file rows, no session row
            self._scratch(loose, scratch)
            rows.extend(loose.rows)
        for user in app_dirs(found.profile.home if found.profile else base.parent.parent, profile_os(found))["roaming"]:
            db = user / "Antigravity" / "User" / "globalStorage" / "state.vscdb"
            if db.is_file():
                rows.extend(self._ide_state(ctx, db))
        session_rows: list[AiRow] = []
        for sid in order:
            session_rows.extend(sessions[sid].finish())
        rows = session_rows + rows
        rows.append(summary_row(ctx, base, sessions=len(order)))
        yield from rows

    def _summaries(self, ctx: RowContext, path: Path, session) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            return [presence_row(ctx, path, "database", open_error=type(exc).__name__)]
        try:
            tables = table_columns(conn)
            fts_chunks: dict[str, int] = {}
            fts = next((name for name in tables if name.startswith("conversations_fts") and "conversation_id" in tables[name]), "")
            if fts:
                try:
                    for conv, count in conn.execute(f'SELECT conversation_id, count(*) FROM "{fts}" GROUP BY conversation_id'):
                        fts_chunks[str(conv)] = int(count)
                except sqlite3.Error:
                    fts_chunks = {}
            rows.append(presence_row(ctx, path, "database", tables=sorted(tables)[:MAX_LIST_ITEMS], wal_included=with_wal, fts_conversations=len(fts_chunks), fts_text_collected=False))
            if "conversation_summaries" in tables:
                for item in select_rows(conn, "conversation_summaries", SUMMARY_COLUMNS, tables["conversation_summaries"]):
                    sid = str(item["conversation_id"] or "")
                    if not sid:
                        continue
                    acc = session(sid, path)
                    acc.parent_session_id = str(item["parent_conversation_id"] or "")
                    acc.see_time(to_iso(item["last_modified_time"]))
                    acc.see_time(to_iso(item["last_user_input_time"]))
                    workspaces = _workspace_uris(item["workspace_uris"])
                    acc.meta.update(
                        {
                            "title": redact_str(item["title"] or "")[:512],
                            "preview": ctx.text(item["preview"] or "")[0][:512],
                            "step_count": item["step_count"],
                            "status": str(item["status"] or ""),
                            "agent_name": redact_str(item["agent_name"] or ""),
                            "nesting_depth": item["nesting_depth"],
                            "project_label": redact_str(item["project_id"] or ""),
                            "cwd": redact_str(_uri_path(workspaces[0])) if workspaces else "",
                            "workspaces": [redact_str(_uri_path(w)) for w in workspaces],
                            "killed": bool(item["killed"]) if item["killed"] is not None else None,
                            "fts_chunks": fts_chunks.get(sid, 0),
                            "summary_last_modified": to_iso(item["last_modified_time"]),
                        }
                    )
                    for uri in workspaces:
                        acc.file_touch("workspace", _uri_path(uri), to_iso(item["last_modified_time"]), op_source="workspace_uris", source_path=path)
        except sqlite3.Error as exc:
            rows.append(presence_row(ctx, path, "database", read_error=type(exc).__name__))
        finally:
            conn.close()
        return rows

    def _conversation_db(self, ctx: RowContext, path: Path, acc: SessionAccumulator) -> list[AiRow]:
        """Per-conversation SQLite: step counts by type/status and payload byte totals only."""
        if sqlite_over_cap(path, ctx.limits):
            acc.meta["steps_db_meta_only_reason"] = "sqlite-over-size-cap"
            return []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            acc.meta["steps_db_error"] = type(exc).__name__
            return []
        try:
            tables = table_columns(conn)
            if "steps" in tables:
                cols = tables["steps"]
                payload = "sum(length(step_payload))" if "step_payload" in cols else "NULL"
                types: dict[str, int] = {}
                statuses: dict[str, int] = {}
                total = 0
                payload_bytes = 0
                for step_type, status, count, size in conn.execute(f'SELECT step_type, status, count(*), {payload} FROM "steps" GROUP BY step_type, status'):
                    types[str(step_type)] = types.get(str(step_type), 0) + int(count)
                    statuses[str(status)] = statuses.get(str(status), 0) + int(count)
                    total += int(count)
                    payload_bytes += int(size or 0)
                acc.meta.update({"steps_total": total, "step_type_counts": types, "step_status_counts": statuses, "step_payload_bytes": payload_bytes, "step_payload_decoded": False, "steps_wal_included": with_wal})
            if "trajectory_meta" in tables:
                for item in select_rows(conn, "trajectory_meta", ("trajectory_id", "cascade_id", "trajectory_type"), tables["trajectory_meta"]):
                    acc.meta["cascade_id"] = str(item["cascade_id"] or "")
                    acc.meta["trajectory_type"] = str(item["trajectory_type"] or "")
                    break
        except sqlite3.Error as exc:
            acc.meta["steps_db_error"] = type(exc).__name__
        finally:
            conn.close()
        return []

    def _brain(self, ctx: RowContext, conv: Path, session, rows: list[AiRow]) -> None:
        acc = session(conv.name, conv)
        generated = conv / ".system_generated"
        logs = generated / "logs"
        transcript = logs / "transcript_full.jsonl" if (logs / "transcript_full.jsonl").is_file() else logs / "transcript.jsonl"
        if transcript.is_file():
            acc.meta["transcript"] = transcript.name
            for record in iter_jsonl(transcript, ctx.budget):
                rtype = str(record.get("type") or "")
                ctx.count_type(rtype or "(none)", KNOWN_TRANSCRIPT_TYPES)
                stamp = to_iso(record.get("created_at"))
                acc.see_time(stamp)
                for key, attr in (("input_tokens", "tokens_in"), ("output_tokens", "tokens_out")):
                    value = record.get(key)
                    if isinstance(value, int):
                        setattr(acc, attr, getattr(acc, attr) + value)
                calls = record.get("tool_calls") if isinstance(record.get("tool_calls"), list) else []
                content = record.get("content")
                if isinstance(content, str) and content:
                    acc.message(_role(record.get("source")), stamp, content, source_path=transcript, step_index=record.get("step_index"), step_type=rtype, has_image=False, tool_use_count=len(calls), source="transcript")
                for call in calls:
                    if isinstance(call, Mapping) and call.get("name"):
                        acc.tool_call(str(call["name"]), stamp, call.get("args"), call_id=str(call.get("id") or ""), source_path=transcript, source="transcript")
        messages = generated / "messages"
        if messages.is_dir():
            for path in sorted(messages.glob("*.json")):
                data = read_small_json(path, ctx.budget, max_bytes=4 * 1024 * 1024)
                if not isinstance(data, Mapping):
                    continue
                stamp = to_iso(data.get("timestamp"))
                if data.get("content"):
                    acc.message("agent", stamp, data.get("content"), source_path=path, sender=redact_str(data.get("sender") or ""), recipient=redact_str(data.get("recipient") or ""), has_image=False, source="agent-message")
                tool = data.get("sourceMetadata", {}).get("tool") if isinstance(data.get("sourceMetadata"), Mapping) else None
                call = tool.get("toolCall") if isinstance(tool, Mapping) else None
                if isinstance(call, Mapping) and call.get("name"):
                    acc.tool_call(str(call["name"]), stamp, call.get("argumentsJson") or call.get("arguments"), call_id=str(call.get("id") or ""), source_path=path, source="agent-message")
        subagents = generated / "subagents"
        if subagents.is_dir():
            acc.meta["subagent_dirs"] = sum(1 for p in subagents.iterdir() if p.is_dir())
        scratch = conv / "scratch"
        if scratch.is_dir():
            self._scratch(acc, scratch)
        for path in sorted(conv.glob("*.md")):
            row = instruction_row(ctx, path, "agent-artifact", extra={"session_id": conv.name})
            if row:
                rows.append(row)

    def _scratch(self, acc: SessionAccumulator, scratch: Path) -> None:
        count = 0
        for path in walk_files(scratch, limit=MAX_SCRATCH_ROWS + 1):
            count += 1
            if count > MAX_SCRATCH_ROWS:
                acc.meta["scratch_rows_capped"] = True
                break
            try:
                size = path.stat().st_size
            except OSError:
                size = None
            acc.file_touch("create", str(path), "", op_source="scratch-listing", source_path=path, exists_in_evidence=True, file_locator=str(path), size=size, content_collected=False)

    def _ide_state(self, ctx: RowContext, path: Path) -> list[AiRow]:
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
        ai_keys = 0
        for key, length in keys:
            lowered = key.lower()
            if "auth" in lowered or "token" in lowered or key.startswith("secret:"):
                rows.append(credential_row(ctx, path, "auth-status", key_name=redact_str(key)[:256], value_bytes=length))
            elif "antigravity" in lowered:
                ai_keys += 1
        rows.append(presence_row(ctx, path, "ide-state", antigravity_keys=ai_keys, conversations_here=False))
        return rows


register_adapter(AntigravityAdapter)
