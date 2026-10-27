"""OpenAI Codex (``~/.codex``) adapter (R7 AI plan §3.2; schema PC_SURVEY §4.2).

The verified store is SQLite, not rollout JSONL: ``sqlite/state_*.sqlite`` ``threads`` (+
``thread_spawn_edges`` parent/child, ``thread_dynamic_tools``), ``codex-dev.db``
``local_thread_catalog`` / ``thread_timeline_ledger(payload_json)`` / ``automation_runs``,
``logs_*.sqlite`` (meta only: row count, body bytes, first/last time - bodies are never read),
``memories_*.sqlite`` ``stage1_outputs`` and ``goals_*.sqlite`` ``thread_goals``. Databases are
recognised by their tables, not their file names. Every database is in WAL mode on the
reference PC, so a database with a ``-wal`` sidecar is opened ``mode=ro`` (WAL included, see
``_common.open_sqlite_ro``). Rollout JSONL under ``sessions/`` / ``archived_sessions/`` is
parsed when present. ``auth.json``, ``.sandbox-secrets`` and ``mcp-oauth-locks`` are
existence-only.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ...url_redaction import redact_url
from ..redact import redact_str
from ._common import (
    MAX_LIST_ITEMS,
    RowContext,
    SessionAccumulator,
    credential_row,
    decode_json_value,
    instruction_row,
    is_sqlite,
    iter_jsonl,
    iter_profiles,
    make_found,
    mcp_rows_from_config,
    open_sqlite_ro,
    presence_row,
    select_rows,
    sqlite_over_cap,
    summary_row,
    table_columns,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "codex"
LABEL = "OpenAI Codex"
KNOWN_ITEM_TYPES = frozenset(
    {
        "message",
        "function_call",
        "function_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
        "local_shell_call",
        "local_shell_call_output",
        "reasoning",
        "web_search_call",
        "session_meta",
        "response_item",
        "event_msg",
        "turn_context",
        "compacted",
        "token_count",
    }
)
THREAD_COLUMNS = (
    "id", "rollout_path", "created_at", "updated_at", "created_at_ms", "updated_at_ms", "source", "model_provider", "cwd", "title",
    "sandbox_policy", "approval_mode", "tokens_used", "archived", "git_sha", "git_branch", "git_origin_url", "cli_version",
    "first_user_message", "agent_nickname", "agent_role", "model", "reasoning_effort", "preview", "thread_source",
)


def _toml_mcp_servers(text: str) -> dict[str, dict[str, object]]:
    """``[mcp_servers.<name>]`` tables of a Codex ``config.toml`` (``tomllib`` when available,
    else a minimal key = value reader for those tables only)."""
    try:
        import tomllib  # type: ignore[import-not-found]

        data = tomllib.loads(text)
        servers = data.get("mcp_servers")
        return servers if isinstance(servers, dict) else {}
    except ModuleNotFoundError:  # pragma: no cover - py310
        pass
    except Exception:
        return {}
    servers: dict[str, dict[str, object]] = {}  # pragma: no cover - py310 fallback
    current: dict[str, object] | None = None  # pragma: no cover
    for line in text.splitlines():  # pragma: no cover
        stripped = line.strip()
        header = re.match(r"^\[mcp_servers\.([^\].]+)\]$", stripped)
        if header:
            current = servers.setdefault(header.group(1).strip('"'), {})
            continue
        if stripped.startswith("["):
            current = None
            continue
        if current is not None and "=" in stripped:
            key, _, value = stripped.partition("=")
            current[key.strip()] = value.strip().strip('"')
    return servers


def _content_text(content: object) -> str:
    if isinstance(content, str):
        return content
    parts: list[str] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, Mapping) and isinstance(item.get("text"), str):
                parts.append(str(item["text"]))
    return "\n".join(parts)


def _unwrap(item: Mapping[str, object]) -> Mapping[str, object]:
    for key in ("payload", "item", "response_item"):
        inner = item.get(key)
        if isinstance(inner, Mapping) and inner.get("type"):
            return inner
    return item


class _Sessions:
    def __init__(self, ctx: RowContext) -> None:
        self.ctx = ctx
        self.by_id: dict[str, SessionAccumulator] = {}
        self.order: list[str] = []

    def get(self, thread_id: str, path: Path) -> SessionAccumulator:
        acc = self.by_id.get(thread_id)
        if acc is None:
            acc = SessionAccumulator(self.ctx, thread_id, path)
            acc.meta["sources"] = []
            self.by_id[thread_id] = acc
            self.order.append(thread_id)
        return acc


def _item(acc: SessionAccumulator, item: Mapping[str, object], stamp: str, path: Path, source: str) -> None:
    """One Codex response item (rollout line payload or ledger payload)."""
    item = _unwrap(item)
    itype = str(item.get("type") or "")
    acc.ctx.count_type(itype or "(none)", KNOWN_ITEM_TYPES)
    if itype == "message":
        role = str(item.get("role") or "")
        text = _content_text(item.get("content"))
        if role and text:
            acc.message(role, stamp, text, source_path=path, source=source, has_image=False)
    elif itype in ("function_call", "custom_tool_call", "local_shell_call"):
        name = str(item.get("name") or ("shell" if itype == "local_shell_call" else ""))
        arguments = item.get("arguments") if "arguments" in item else item.get("input") or item.get("action")
        acc.tool_call(name, stamp, arguments, call_id=str(item.get("call_id") or item.get("id") or ""), source_path=path, source=source)
    elif itype in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
        output = item.get("output")
        parsed = decode_json_value(output) if isinstance(output, str) else output
        exit_code = None
        if isinstance(parsed, Mapping):
            meta = parsed.get("metadata")
            if isinstance(meta, Mapping):
                exit_code = meta.get("exit_code")
        size = len(output.encode("utf-8", "replace")) if isinstance(output, str) else None
        acc.tool_result(str(item.get("call_id") or ""), result_bytes=size, exit_code=exit_code)


class CodexAdapter(AiAgentAdapter):
    name = "codex"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".codex") for profile in iter_profiles(roots, os_hint) if (profile.home / ".codex").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home")]
        sessions = _Sessions(ctx)
        extra: list[AiRow] = []
        for name, kind in (("auth.json", "auth-token"), (".sandbox-secrets", "sandbox-secrets"), ("mcp-oauth-locks", "mcp-oauth"), (".credentials.json", "oauth-credentials")):
            path = base / name
            if path.exists():
                extra.append(credential_row(ctx, path, kind))
        for name, kind in (("AGENTS.md", "AGENTS.md"), ("instructions.md", "instructions")):
            path = base / name
            if path.is_file():
                row = instruction_row(ctx, path, kind)
                if row:
                    extra.append(row)
        config = base / "config.toml"
        if config.is_file():
            size = config.stat().st_size
            if size <= 1024 * 1024 and ctx.budget.take(size, str(config)):
                servers = _toml_mcp_servers(config.read_text(encoding="utf-8", errors="replace"))
                extra.extend(mcp_rows_from_config(ctx, config, servers, scope="config.toml"))
            extra.append(presence_row(ctx, config, "settings"))
        db_dir = base / "sqlite"
        dbs = sorted(p for p in walk_files(db_dir, limit=500) if not p.name.endswith(("-wal", "-shm", "-journal")) and is_sqlite(p)) if db_dir.is_dir() else []
        for top in sorted(base.glob("*.sqlite")) + sorted(base.glob("*.db")):
            if is_sqlite(top) and top not in dbs:
                dbs.append(top)
        usage: dict[tuple[str, str], dict[str, object]] = {}
        for path in dbs:
            extra.extend(self._database(ctx, path, sessions, usage))
        for folder in ("sessions", "archived_sessions"):
            root = base / folder
            if root.is_dir():
                for path in walk_files(root, limit=50_000):
                    if path.suffix == ".jsonl":
                        self._rollout(ctx, path, sessions, archived=folder == "archived_sessions")
        memories = base / "memories"
        if memories.is_dir():
            extra.append(presence_row(ctx, memories, "memory-store", is_git_repo=(memories / ".git").exists()))
            for path in walk_files(memories, limit=2000):
                if ".git" in path.relative_to(memories).parts or path.suffix.lower() != ".md":
                    continue
                kind = "rollout-summary" if "rollout_summaries" in path.parts else "MEMORY.md"
                row = instruction_row(ctx, path, kind)
                if row:
                    extra.append(row)
        attachments = base / "attachments"
        if attachments.is_dir():
            for path in walk_files(attachments, limit=2000):
                if path.name.lower().startswith("pasted-text"):
                    row = instruction_row(ctx, path, "pasted-text")
                    if row:
                        extra.append(row)
        for thread_id in sessions.order:
            acc = sessions.by_id[thread_id]
            rows.extend(acc.finish())
        for (day, model), stat in sorted(usage.items()):
            rows.append(ctx.row("ai-usage-stat", stat["path"], period=day, model=model, tokens=stat["tokens"], requests=None, threads=stat["threads"], source="threads.tokens_used"))  # type: ignore[arg-type]
        rows.extend(extra)
        rows.append(summary_row(ctx, base, databases=len(dbs), sessions=len(sessions.order)))
        yield from rows

    # --- SQLite --------------------------------------------------------------------------

    def _database(self, ctx: RowContext, path: Path, sessions: _Sessions, usage: dict) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            return [presence_row(ctx, path, "database", open_error=type(exc).__name__)]
        try:
            tables = table_columns(conn)
            over = sqlite_over_cap(path, ctx.limits)
            rows.append(presence_row(ctx, path, "database", tables=sorted(tables)[:MAX_LIST_ITEMS], wal_included=with_wal, meta_only=over, meta_only_reason="sqlite-over-size-cap" if over else ""))
            if "threads" in tables:
                self._threads(ctx, conn, path, tables, sessions, usage)
            if "thread_spawn_edges" in tables:
                for edge in select_rows(conn, "thread_spawn_edges", ("parent_thread_id", "child_thread_id", "status"), tables["thread_spawn_edges"]):
                    child = str(edge["child_thread_id"] or "")
                    if child:
                        acc = sessions.get(child, path)
                        acc.parent_session_id = str(edge["parent_thread_id"] or "")
                        acc.meta["spawn_status"] = str(edge["status"] or "")
            if "thread_dynamic_tools" in tables:
                for tool in select_rows(conn, "thread_dynamic_tools", ("thread_id", "name"), tables["thread_dynamic_tools"]):
                    acc = sessions.get(str(tool["thread_id"] or ""), path)
                    acc.meta.setdefault("dynamic_tools", [])
                    acc.note(acc.meta["dynamic_tools"], redact_str(tool["name"]))  # type: ignore[arg-type]
            if "local_thread_catalog" in tables:
                cols = ("thread_id", "display_title", "source_created_at", "source_updated_at", "cwd", "source_kind", "model_provider", "git_branch", "project_id")
                for item in select_rows(conn, "local_thread_catalog", cols, tables["local_thread_catalog"]):
                    acc = sessions.get(str(item["thread_id"] or ""), path)
                    acc.note(acc.meta["sources"], "local_thread_catalog")  # type: ignore[arg-type]
                    acc.see_time(to_iso(item["source_created_at"]))
                    acc.see_time(to_iso(item["source_updated_at"]))
                    for key, meta in (("display_title", "title"), ("cwd", "cwd"), ("git_branch", "git_branch"), ("model_provider", "model_provider"), ("source_kind", "source_kind")):
                        if item[key] and not acc.meta.get(meta):
                            acc.meta[meta] = redact_str(item[key])
            if "thread_timeline_ledger" in tables and not over:
                for item in select_rows(conn, "thread_timeline_ledger", ("thread_id", "sequence", "payload_json"), tables["thread_timeline_ledger"], order="thread_id, sequence"):
                    payload = decode_json_value(item["payload_json"])
                    if not isinstance(payload, Mapping):
                        continue
                    acc = sessions.get(str(item["thread_id"] or ""), path)
                    acc.note(acc.meta["sources"], "thread_timeline_ledger")  # type: ignore[arg-type]
                    stamp = to_iso(payload.get("timestamp") or payload.get("created_at"))
                    _item(acc, payload, stamp, path, "thread_timeline_ledger")
            if "automation_runs" in tables and not over:
                cols = ("thread_id", "thread_title", "source_cwd", "archived_user_message", "archived_assistant_message", "created_at")
                for item in select_rows(conn, "automation_runs", cols, tables["automation_runs"]):
                    acc = sessions.get(str(item["thread_id"] or ""), path)
                    acc.note(acc.meta["sources"], "automation_runs")  # type: ignore[arg-type]
                    stamp = to_iso(item["created_at"])
                    if item["thread_title"] and not acc.meta.get("title"):
                        acc.meta["title"] = redact_str(item["thread_title"])
                    if item["source_cwd"] and not acc.meta.get("cwd"):
                        acc.meta["cwd"] = redact_str(item["source_cwd"])
                    for role, key in (("user", "archived_user_message"), ("assistant", "archived_assistant_message")):
                        if item[key]:
                            acc.message(role, stamp, item[key], source_path=path, source="automation_runs", has_image=False)
            if "logs" in tables:
                rows.append(self._logs_meta(ctx, conn, path, tables["logs"]))
            if "stage1_outputs" in tables and not over:
                for item in select_rows(conn, "stage1_outputs", ("thread_id", "raw_memory", "rollout_summary", "generated_at"), tables["stage1_outputs"]):
                    text, truncated, original = ctx.text(item["raw_memory"] or item["rollout_summary"] or "")
                    rows.append(
                        ctx.row(
                            "ai-instruction-file",
                            path,
                            instruction_kind="memory-db",
                            session_id=str(item["thread_id"] or ""),
                            size=original,
                            head_text=text[:512],
                            truncated=truncated or len(text) > 512,
                            generated_at=to_iso(item["generated_at"]),
                            sha256="",
                        )
                    )
            if "thread_goals" in tables:
                for goal in select_rows(conn, "thread_goals", ("thread_id", "objective", "status", "tokens_used"), tables["thread_goals"]):
                    acc = sessions.get(str(goal["thread_id"] or ""), path)
                    acc.meta["goal_objective"] = ctx.text(goal["objective"] or "")[0][:512]
                    acc.meta["goal_status"] = str(goal["status"] or "")
        except sqlite3.Error as exc:
            rows.append(presence_row(ctx, path, "database", read_error=type(exc).__name__))
        finally:
            conn.close()
        return rows

    def _threads(self, ctx: RowContext, conn: sqlite3.Connection, path: Path, tables: Mapping[str, list[str]], sessions: _Sessions, usage: dict) -> None:
        for item in select_rows(conn, "threads", THREAD_COLUMNS, tables["threads"]):
            thread_id = str(item["id"] or "")
            if not thread_id:
                continue
            acc = sessions.get(thread_id, path)
            acc.path = path
            acc.note(acc.meta["sources"], "threads")  # type: ignore[arg-type]
            created = to_iso(item["created_at_ms"] or item["created_at"])
            updated = to_iso(item["updated_at_ms"] or item["updated_at"])
            acc.see_time(created)
            acc.see_time(updated)
            model = str(item["model"] or "")
            acc.note(acc.models, model)
            acc.note(acc.versions, item["cli_version"])
            tokens = item["tokens_used"] if isinstance(item["tokens_used"], int) else None
            acc.meta.update(
                {
                    "title": redact_str(item["title"] or "")[:512],
                    "cwd": redact_str(item["cwd"] or ""),
                    "git_branch": redact_str(item["git_branch"] or ""),
                    "git_origin": redact_url(redact_str(item["git_origin_url"] or "")),
                    "git_sha": str(item["git_sha"] or ""),
                    "sandbox_mode": redact_str(item["sandbox_policy"] or "")[:256],
                    "permission_mode": str(item["approval_mode"] or ""),
                    "model_provider": str(item["model_provider"] or ""),
                    "reasoning_effort": str(item["reasoning_effort"] or ""),
                    "archived": bool(item["archived"]) if item["archived"] is not None else None,
                    "tokens_total": tokens,
                    "agent_role": str(item["agent_role"] or ""),
                    "agent_nickname": redact_str(item["agent_nickname"] or ""),
                    "preview": ctx.text(item["preview"] or "")[0][:512],
                    "rollout_path_recorded": redact_str(item["rollout_path"] or ""),
                }
            )
            if item["first_user_message"]:
                acc.message("user", created, item["first_user_message"], source_path=path, source="threads.first_user_message", has_image=False)
            if tokens:
                key = ((updated or created)[:10], model)
                stat = usage.setdefault(key, {"tokens": 0, "threads": 0, "path": path})
                stat["tokens"] = int(stat["tokens"]) + tokens
                stat["threads"] = int(stat["threads"]) + 1

    def _logs_meta(self, ctx: RowContext, conn: sqlite3.Connection, path: Path, cols: Sequence[str]) -> AiRow:
        """``logs`` table: counts and time range only; ``feedback_log_body`` is measured, not read."""
        fields: dict[str, object] = {"log_rows": None, "body_bytes": None, "first_ts": "", "last_ts": "", "bodies_collected": False}
        try:
            body = "sum(length(feedback_log_body))" if "feedback_log_body" in cols else "NULL"
            ts = "ts" if "ts" in cols else "NULL"
            count, size, first, last = conn.execute(f'SELECT count(*), {body}, min({ts}), max({ts}) FROM "logs"').fetchone()
            fields.update(log_rows=count, body_bytes=size, first_ts=to_iso(first), last_ts=to_iso(last))
        except sqlite3.Error as exc:
            fields["read_error"] = type(exc).__name__
        return presence_row(ctx, path, "log-db", **fields)

    def _rollout(self, ctx: RowContext, path: Path, sessions: _Sessions, *, archived: bool) -> None:
        acc: SessionAccumulator | None = None
        for record in iter_jsonl(path, ctx.budget):
            rtype = str(record.get("type") or "")
            payload = record.get("payload")
            stamp = to_iso(record.get("timestamp"))
            if rtype == "session_meta" and isinstance(payload, Mapping):
                ctx.count_type(rtype, KNOWN_ITEM_TYPES)
                thread_id = str(payload.get("id") or path.stem)
                acc = sessions.get(thread_id, path)
                acc.note(acc.meta["sources"], "rollout-jsonl")  # type: ignore[arg-type]
                acc.meta["cwd"] = redact_str(payload.get("cwd") or acc.meta.get("cwd") or "")
                acc.note(acc.versions, payload.get("cli_version"))
                acc.meta["archived"] = archived
                acc.see_time(to_iso(payload.get("timestamp")) or stamp)
                git = payload.get("git")
                if isinstance(git, Mapping):
                    acc.meta["git_branch"] = redact_str(git.get("branch") or "")
                    acc.meta["git_origin"] = redact_url(redact_str(git.get("repository_url") or ""))
                continue
            if acc is None:
                acc = sessions.get(path.stem, path)
                acc.note(acc.meta["sources"], "rollout-jsonl")  # type: ignore[arg-type]
            if rtype == "response_item" and isinstance(payload, Mapping):
                _item(acc, payload, stamp, path, "rollout-jsonl")
            elif rtype == "turn_context" and isinstance(payload, Mapping):
                ctx.count_type(rtype, KNOWN_ITEM_TYPES)
                acc.note(acc.models, payload.get("model"))
                acc.see_time(stamp)
            else:
                ctx.count_type(rtype or "(none)", KNOWN_ITEM_TYPES)
                acc.see_time(stamp)
                if rtype == "event_msg" and isinstance(payload, Mapping) and payload.get("type") == "token_count":
                    info = payload.get("info")
                    total = info.get("total_token_usage") if isinstance(info, Mapping) else None
                    if isinstance(total, Mapping):
                        acc.tokens_in = int(total.get("input_tokens") or 0)
                        acc.tokens_out = int(total.get("output_tokens") or 0)


register_adapter(CodexAdapter)
