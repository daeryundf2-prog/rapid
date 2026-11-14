"""ZCode (``~/.zcode``) adapter (R7 AI plan §3.2; schema PC_SURVEY §4.9, cli_agents.json).

``cli/db/db.sqlite`` (opencode-style): ``session`` (``parent_id`` + ``session_task_link`` ->
``parent_session_id``), ``message`` (``data`` JSON: role, model, tokens) with text from ``part``
rows (``type=text``), ``tool_usage`` rows are the tool calls (``destructive``,
``approval_status``, ``exit_code``, output bytes) joined to the ``part`` tool input by
``tool_call_id``/``callID`` for the command / path; ``input_history`` prompts are user messages;
``model_usage`` is summed per (day, model) into ``ai-usage-stat``. ``cli/rollout/*.jsonl`` (raw
model I/O with request headers) is counted, never read. ``v2/config.json`` gives provider ids,
models and the base URL host only; ``v2/credentials.json``, ``certs/*.key|*.pem`` are
existence-only.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from urllib.parse import urlparse

from ..redact import redact_str
from ._common import (
    MAX_LIST_ITEMS,
    RowContext,
    SessionAccumulator,
    credential_row,
    decode_json_value,
    iter_profiles,
    make_found,
    open_sqlite_ro,
    presence_row,
    read_small_json,
    select_rows,
    sqlite_over_cap,
    summary_row,
    table_columns,
    to_iso,
    walk_files,
)
from ._iface import (
    AiAgentAdapter,
    AiLimits,
    AiRow,
    Found,
    is_credential_name,
    register_adapter,
)

TOOL = "zcode"
LABEL = "ZCode"
KNOWN_PART_TYPES = frozenset({"text", "tool", "reasoning", "file", "step-start", "step-finish", "snapshot", "patch", "agent", "compaction"})


def _config_summary(data: object) -> dict[str, object]:
    """Provider ids, models and base-URL hosts of ``v2/config.json`` (no key fields)."""
    providers: list[str] = []
    models: list[str] = []
    hosts: list[str] = []

    def walk(node: object, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in ("baseurl", "base_url") and isinstance(value, str):
                    host = urlparse(value).hostname or ""
                    if host and host not in hosts:
                        hosts.append(host)
                elif lowered in ("id", "provider", "providerid") and isinstance(value, str) and depth <= 3 and value not in providers:
                    providers.append(value)
                elif lowered in ("model", "models", "modelid"):
                    for item in value if isinstance(value, list) else [value]:
                        if isinstance(item, str) and item not in models:
                            models.append(item)
                else:
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:200]:
                walk(item, depth + 1)

    walk(data)
    return {"providers": providers[:MAX_LIST_ITEMS], "models": models[:MAX_LIST_ITEMS], "base_url_hosts": hosts[:MAX_LIST_ITEMS]}


class ZcodeAdapter(AiAgentAdapter):
    name = "zcode"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".zcode") for profile in iter_profiles(roots, os_hint) if (profile.home / ".zcode").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home")]
        session_rows: list[AiRow] = []
        db = base / "cli" / "db" / "db.sqlite"
        if db.is_file():
            session_rows, extra = self._db(ctx, db)
            rows.extend(extra)
        config = base / "v2" / "config.json"
        if config.is_file():
            rows.append(presence_row(ctx, config, "settings", **_config_summary(read_small_json(config, ctx.budget, max_bytes=4 * 1024 * 1024))))
        rollout = base / "cli" / "rollout"
        if rollout.is_dir():
            files = [p for p in walk_files(rollout, limit=5000) if p.suffix == ".jsonl"]
            rows.append(presence_row(ctx, rollout, "raw-model-io", file_count=len(files), total_bytes=sum(p.stat().st_size for p in files), content_collected=False))
        v2 = base / "v2"
        if v2.is_dir():
            for path in walk_files(v2, limit=5000):
                if path.name == "credentials.json" or path.suffix in (".key", ".pem") or (is_credential_name(path.name) and path.suffix != ".sqlite"):
                    rows.append(credential_row(ctx, path, "credential-file"))
        yield from session_rows
        yield from rows
        yield summary_row(ctx, base, sessions=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session"))

    def _db(self, ctx: RowContext, path: Path) -> tuple[list[AiRow], list[AiRow]]:
        extra: list[AiRow] = []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            return [], [presence_row(ctx, path, "database", open_error=type(exc).__name__)]
        sessions: dict[str, SessionAccumulator] = {}
        order: list[str] = []

        def session(sid: str) -> SessionAccumulator:
            acc = sessions.get(sid)
            if acc is None:
                acc = SessionAccumulator(ctx, sid, path)
                sessions[sid] = acc
                order.append(sid)
            return acc

        over = sqlite_over_cap(path, ctx.limits)
        try:
            tables = table_columns(conn)
            extra.append(presence_row(ctx, path, "database", tables=sorted(tables)[:MAX_LIST_ITEMS], wal_included=with_wal, meta_only=over, meta_only_reason="sqlite-over-size-cap" if over else ""))
            if "session" in tables:
                cols = ("id", "parent_id", "slug", "directory", "path", "title", "version", "time_created", "time_updated", "time_archived", "task_type", "summary_additions", "summary_deletions", "summary_files")
                for item in select_rows(conn, "session", cols, tables["session"]):
                    acc = session(str(item["id"] or ""))
                    acc.parent_session_id = str(item["parent_id"] or "")
                    acc.see_time(to_iso(item["time_created"]))
                    acc.see_time(to_iso(item["time_updated"]))
                    acc.note(acc.versions, item["version"])
                    acc.meta.update(
                        {
                            "title": redact_str(item["title"] or "")[:512],
                            "cwd": redact_str(item["directory"] or item["path"] or ""),
                            "task_type": str(item["task_type"] or ""),
                            "archived_at": to_iso(item["time_archived"]),
                            "lines_added": item["summary_additions"],
                            "lines_deleted": item["summary_deletions"],
                            "files_changed": item["summary_files"],
                        }
                    )
            if "session_task_link" in tables:
                for link in select_rows(conn, "session_task_link", ("parent_session_id", "child_session_id", "agent_type", "depth"), tables["session_task_link"]):
                    acc = session(str(link["child_session_id"] or ""))
                    acc.parent_session_id = acc.parent_session_id or str(link["parent_session_id"] or "")
                    acc.meta["agent_type"] = str(link["agent_type"] or "")
                    acc.meta["nesting_depth"] = link["depth"]
            tool_inputs: dict[str, Mapping[str, object]] = {}
            if not over and "message" in tables:
                texts: dict[str, list[str]] = {}
                if "part" in tables:
                    for part in select_rows(conn, "part", ("message_id", "data", "sequence"), tables["part"], order="message_id, sequence"):
                        data = decode_json_value(part["data"])
                        if not isinstance(data, Mapping):
                            continue
                        ptype = str(data.get("type") or "")
                        ctx.count_type(f"part:{ptype}", frozenset(f"part:{t}" for t in KNOWN_PART_TYPES))
                        if ptype == "text" and isinstance(data.get("text"), str):
                            texts.setdefault(str(part["message_id"]), []).append(str(data["text"]))
                        elif ptype == "tool" and data.get("callID"):
                            state = data.get("state")
                            tool_inputs[str(data["callID"])] = state.get("input") if isinstance(state, Mapping) and isinstance(state.get("input"), Mapping) else {}
                for item in select_rows(conn, "message", ("id", "session_id", "time_created", "data", "sequence"), tables["message"], order="session_id, time_created"):
                    data = decode_json_value(item["data"])
                    data = data if isinstance(data, Mapping) else {}
                    acc = session(str(item["session_id"] or ""))
                    acc.note(acc.models, data.get("modelID"))
                    tokens = data.get("tokens")
                    if isinstance(tokens, Mapping):
                        acc.tokens_in += int(tokens.get("input") or 0) if isinstance(tokens.get("input"), int) else 0
                        acc.tokens_out += int(tokens.get("output") or 0) if isinstance(tokens.get("output"), int) else 0
                    text = "\n".join(texts.get(str(item["id"]), []))
                    if text:
                        acc.message(str(data.get("role") or "unknown"), to_iso(item["time_created"]), text, has_image=False, message_id=str(item["id"] or ""), model=str(data.get("modelID") or ""), source="message+part")
            if not over and "input_history" in tables:
                for item in select_rows(conn, "input_history", ("session_id", "text", "kind", "time_created"), tables["input_history"]):
                    if item["text"]:
                        session(str(item["session_id"] or "")).message("user", to_iso(item["time_created"]), item["text"], has_image=False, source="input_history", input_kind=str(item["kind"] or ""))
            if "tool_usage" in tables:
                cols = ("session_id", "tool_call_id", "tool_name", "side_effect_scope", "read_only", "destructive", "approval_status", "status", "started_at", "completed_at", "exit_code", "output_bytes")
                for item in select_rows(conn, "tool_usage", cols, tables["tool_usage"], order="started_at"):
                    acc = session(str(item["session_id"] or ""))
                    acc.tool_call(
                        str(item["tool_name"] or ""),
                        to_iso(item["started_at"]),
                        tool_inputs.get(str(item["tool_call_id"] or ""), {}),
                        call_id=str(item["tool_call_id"] or ""),
                        destructive=bool(item["destructive"]) if item["destructive"] is not None else None,
                        approval=str(item["approval_status"] or ""),
                        status=str(item["status"] or ""),
                        read_only=bool(item["read_only"]) if item["read_only"] is not None else None,
                        side_effect_scope=str(item["side_effect_scope"] or ""),
                        exit_code=item["exit_code"],
                        result_bytes=item["output_bytes"],
                        completed_at=to_iso(item["completed_at"]),
                        source="tool_usage",
                    )
            if "todo" in tables:
                for sid, count in conn.execute('SELECT session_id, count(*) FROM "todo" GROUP BY session_id'):
                    session(str(sid or "")).meta["todos"] = int(count)
            if "model_usage" in tables:
                usage: dict[tuple[str, str], dict[str, int]] = {}
                cols = ("model_id", "provider_id", "started_at", "input_tokens", "output_tokens", "reasoning_tokens")
                for item in select_rows(conn, "model_usage", cols, tables["model_usage"]):
                    key = (to_iso(item["started_at"])[:10], str(item["model_id"] or ""))
                    stat = usage.setdefault(key, {"tokens_in": 0, "tokens_out": 0, "reasoning": 0, "requests": 0})
                    stat["tokens_in"] += int(item["input_tokens"] or 0)
                    stat["tokens_out"] += int(item["output_tokens"] or 0)
                    stat["reasoning"] += int(item["reasoning_tokens"] or 0)
                    stat["requests"] += 1
                for (day, model), stat in sorted(usage.items()):
                    extra.append(ctx.row("ai-usage-stat", path, period=day, model=model, tokens=stat["tokens_in"] + stat["tokens_out"], tokens_in=stat["tokens_in"], tokens_out=stat["tokens_out"], reasoning_tokens=stat["reasoning"], requests=stat["requests"], source="model_usage"))
        except sqlite3.Error as exc:
            extra.append(presence_row(ctx, path, "database", read_error=type(exc).__name__))
        finally:
            conn.close()
        session_rows: list[AiRow] = []
        for sid in order:
            if sid:
                session_rows.extend(sessions[sid].finish())
        return session_rows, extra


register_adapter(ZcodeAdapter)
