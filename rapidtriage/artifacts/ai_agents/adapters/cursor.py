"""Cursor adapter (R7 AI plan §3.2; schema PC_SURVEY §4.3, §4.10).

Conversations live in the GLOBAL ``User/globalStorage/state.vscdb``: ``composerHeaders`` (one
row per composer = session, ``isSubagent``) and ``cursorDiskKV`` (``composerData:<composerId>``
conversation objects, ``bubbleId:<composerId>:<bubbleId>`` message bubbles whose
``toolFormerData`` is a tool call, ``codeBlockDiff:<composerId>:<id>`` edited files). Values are
JSON in TEXT or BLOB cells; a value that is not UTF-8 JSON is counted (``undecoded_values``) and
never guessed at. ``ItemTable`` gives ``aiCodeTracking.dailyStats.*`` (usage),
``browserAutomation.history`` (browser tool calls) and ``cloudAgentRepository.*`` (presence);
``secret:*`` and token/auth keys are existence-only (key name + value length via SQL
``length()``). ``~/.cursor/ai-tracking/ai-code-tracking.db`` yields ``ai-code-attribution`` rows
(per file from ``ai_code_hashes``, per commit from ``scored_commits``). A global database over
``AiLimits.max_sqlite_bytes`` is read for ``ItemTable`` and ``composerHeaders`` only.

Bubble ``type`` 1 = user, 2 = assistant (community-documented; the reference PC's values were
not opened) - the mapping is recorded on every message as ``role_source``.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from urllib.parse import unquote, urlparse

from ...url_redaction import redact_url
from ..redact import mask_email, redact_str
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
    mcp_rows_from_config,
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
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "cursor"
LABEL = "Cursor"
BUBBLE_ROLES = {1: "user", 2: "assistant"}
KNOWN_KV_PREFIXES = frozenset(
    {
        "agentKv",
        "bubbleId",
        "checkpointId",
        "codeBlockPartialInlineDiffFates",
        "ofsContent",
        "codeBlockDiff",
        "composerData",
        "inlineDiff",
        "messageRequestContext",
        "composer.content",
        "inlineDiffs",
    }
)
_SENSITIVE_KEY_RE = re.compile(r"(?i)(^secret:|token|password|apikey|api_key|cookie|refresh|credential)")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _kv_prefix(key: str) -> str:
    if key.startswith("composer.content."):
        return "composer.content"
    if key.startswith("inlineDiffs-"):
        return "inlineDiffs"
    return key.split(":", 1)[0]


def _folder_of(workspace_json: object) -> str:
    if not isinstance(workspace_json, Mapping):
        return ""
    uri = workspace_json.get("folder") or workspace_json.get("workspace") or ""
    if not isinstance(uri, str) or not uri:
        return ""
    if uri.startswith("file://"):
        path = unquote(urlparse(uri).path)
        if re.match(r"^/[A-Za-z]:", path):
            path = path[1:].replace("/", "\\")
        return path
    return uri


def _diff_path(value: Mapping[str, object]) -> str:
    uri = value.get("uri")
    if isinstance(uri, Mapping):
        for key in ("fsPath", "path", "external"):
            if isinstance(uri.get(key), str) and uri[key]:
                return str(uri[key])
    for key in ("filePath", "fsPath", "fileName", "relativeWorkspacePath", "uri"):
        if isinstance(value.get(key), str) and value[key]:
            return str(value[key])
    return ""


class CursorAdapter(AiAgentAdapter):
    name = "cursor"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        found: list[Found] = []
        for profile in iter_profiles(roots, os_hint):
            home = profile.home
            os_name = profile.os if profile.os != "unknown" else (os_hint or "auto")
            users = [d / "Cursor" / "User" for d in app_dirs(home, os_name)["roaming"] if (d / "Cursor" / "User").is_dir()]
            dot = home / ".cursor"
            if users or dot.is_dir():
                found.append(make_found(self, profile, dot if dot.is_dir() else users[0], users=users, dot=dot if dot.is_dir() else None))
        return found

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        home = found.profile.home if found.profile is not None else found.path.parent
        users = list(found.extra.get("users") or [])  # type: ignore[call-overload]
        dot = found.extra.get("dot")
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = []
        sessions: dict[str, SessionAccumulator] = {}
        order: list[str] = []
        workspaces: dict[str, str] = {}
        for user in users:
            rows.append(presence_row(ctx, user, "app-data"))
            ws_root = user / "workspaceStorage"
            if ws_root.is_dir():
                for ws in sorted(p for p in ws_root.iterdir() if p.is_dir()):
                    folder = _folder_of(read_small_json(ws / "workspace.json", ctx.budget, max_bytes=64 * 1024))
                    if folder:
                        workspaces[ws.name] = folder
            global_db = user / "globalStorage" / "state.vscdb"
            if global_db.is_file():
                rows.extend(self._global_db(ctx, global_db, sessions, order, workspaces))
            if ws_root.is_dir():
                for ws in sorted(p for p in ws_root.iterdir() if p.is_dir()):
                    db = ws / "state.vscdb"
                    if db.is_file():
                        rows.extend(self._workspace_db(ctx, db, ws.name, workspaces.get(ws.name, ""), sessions, order))
        if dot is not None:
            rows.append(presence_row(ctx, dot, "tool-home"))
            mcp = dot / "mcp.json"
            if mcp.is_file():
                data = read_small_json(mcp, ctx.budget)
                rows.extend(mcp_rows_from_config(ctx, mcp, data.get("mcpServers") if isinstance(data, Mapping) else None, scope="~/.cursor/mcp.json"))
            tracking = dot / "ai-tracking" / "ai-code-tracking.db"
            if tracking.is_file():
                rows.extend(self._tracking_db(ctx, tracking))
            projects = dot / "projects"
            if projects.is_dir():
                for path in walk_files(projects, limit=50_000):
                    if path.suffix == ".jsonl" and "agent-transcripts" in path.parts:
                        self._transcript(ctx, path, projects, sessions, order)
            for sub in ("rules",):
                folder = dot / sub
                if folder.is_dir():
                    for path in walk_files(folder, limit=500):
                        row = instruction_row(ctx, path, "rules")
                        if row:
                            rows.append(row)
        for path in (home / ".cursorrules",):
            if path.is_file():
                row = instruction_row(ctx, path, ".cursorrules")
                if row:
                    rows.append(row)
        session_rows: list[AiRow] = []
        for sid in order:
            session_rows.extend(sessions[sid].finish())
        rows = session_rows + rows
        rows.append(summary_row(ctx, dot or (users[0] if users else home), sessions=len(order), workspaces=len(workspaces)))
        yield from rows

    # --- global state.vscdb ----------------------------------------------------------------

    def _session(self, ctx: RowContext, sessions: dict, order: list, sid: str, path: Path) -> SessionAccumulator:
        acc = sessions.get(sid)
        if acc is None:
            acc = SessionAccumulator(ctx, sid, path)
            sessions[sid] = acc
            order.append(sid)
        return acc

    def _global_db(self, ctx: RowContext, path: Path, sessions: dict, order: list, workspaces: Mapping[str, str]) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            return [presence_row(ctx, path, "database", open_error=type(exc).__name__)]
        over = sqlite_over_cap(path, ctx.limits)
        kv_counts: dict[str, int] = {}
        undecoded = 0
        try:
            tables = table_columns(conn)
            if "ItemTable" in tables:
                rows.extend(self._item_table(ctx, conn, path, scope="global"))
            if "composerHeaders" in tables:
                cols = ("composerId", "workspaceId", "createdAt", "lastUpdatedAt", "isArchived", "isSubagent", "value", "subagentTypeName")
                for item in select_rows(conn, "composerHeaders", cols, tables["composerHeaders"]):
                    sid = str(item["composerId"] or "")
                    if not sid:
                        continue
                    acc = self._session(ctx, sessions, order, sid, path)
                    acc.see_time(to_iso(item["createdAt"]))
                    acc.see_time(to_iso(item["lastUpdatedAt"]))
                    value = decode_json_value(item["value"])
                    parent = ""
                    if isinstance(value, Mapping):
                        parent = str(value.get("parentComposerId") or value.get("parentId") or "")
                        if isinstance(value.get("name"), str):
                            acc.meta["title"] = redact_str(value["name"])[:512]
                    acc.parent_session_id = parent
                    workspace = str(item["workspaceId"] or "")
                    acc.meta.update(
                        {
                            "workspace_id": workspace,
                            "cwd": redact_str(workspaces.get(workspace, "")),
                            "archived": bool(item["isArchived"]) if item["isArchived"] is not None else None,
                            "is_subagent": bool(item["isSubagent"]),
                            "subagent_type": str(item["subagentTypeName"] or ""),
                            "source_kind": "composerHeaders",
                        }
                    )
            if "cursorDiskKV" in tables and not over:
                kv_counts, undecoded = self._disk_kv(ctx, conn, path, sessions, order, rows)
            rows.append(
                presence_row(
                    ctx,
                    path,
                    "database",
                    tables=sorted(tables)[:MAX_LIST_ITEMS],
                    wal_included=with_wal,
                    meta_only=over,
                    meta_only_reason="sqlite-over-size-cap: cursorDiskKV (messages, tool calls) not read" if over else "",
                    kv_prefix_counts=dict(sorted(kv_counts.items())),
                    undecoded_values=undecoded,
                )
            )
        except sqlite3.Error as exc:
            rows.append(presence_row(ctx, path, "database", read_error=type(exc).__name__))
        finally:
            conn.close()
        return rows

    def _item_table(self, ctx: RowContext, conn: sqlite3.Connection, path: Path, *, scope: str) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            keys = [(str(k), int(n or 0)) for k, n in conn.execute('SELECT key, length(value) FROM "ItemTable"')]
        except sqlite3.Error:
            return rows
        cloud_agents = 0
        for key, length in keys:
            if key == "cursorAuth/cachedEmail":
                value = self._item_value(conn, key)
                domain, local_hash = mask_email(value if isinstance(value, str) else "")
                rows.append(ctx.row("ai-account", path, tool_account_key=f"cursor-{local_hash}" if local_hash else "", org_label="", email_domain=domain, email_local_hash=local_hash, active=True, source=f"ItemTable {key}"))
            elif _SENSITIVE_KEY_RE.search(key) and not key.startswith(("aiCodeTracking", "browserAutomation")):
                rows.append(credential_row(ctx, path, "secret-storage" if key.startswith("secret:") else "auth-token", key_name=redact_str(key)[:256], value_bytes=length))
            elif key.startswith("aiCodeTracking.dailyStats"):
                value = decode_json_value(self._item_value(conn, key))
                if isinstance(value, Mapping):
                    date = _DATE_RE.search(key)
                    metrics = {str(k): v for k, v in value.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
                    rows.append(ctx.row("ai-usage-stat", path, period=(date.group(0) if date else str(value.get("date") or "")), model="", tokens=None, requests=None, metrics=metrics, source=f"ItemTable {key}"))
            elif key == "browserAutomation.history":
                value = decode_json_value(self._item_value(conn, key))
                entries = value if isinstance(value, list) else value.get("history") if isinstance(value, Mapping) else []
                for entry in (entries or [])[:5000]:
                    if not isinstance(entry, Mapping):
                        continue
                    stamp = to_iso(entry.get("timestamp") or entry.get("time"))
                    rows.append(
                        ctx.row(
                            "ai-agent-tool-call",
                            path,
                            timestamp=stamp,
                            kind="run",
                            session_id=str(entry.get("composerId") or ""),
                            ts=stamp,
                            tool_name="browserAutomation",
                            tool_kind="browser",
                            target_url=redact_url(redact_str(entry.get("url") or ""))[:1024],
                            command="",
                            target_path="",
                            destructive=None,
                            source="ItemTable browserAutomation.history",
                        )
                    )
            elif key.startswith("cloudAgentRepository.agents"):
                cloud_agents += 1
        if cloud_agents:
            rows.append(presence_row(ctx, path, "cloud-agents", cloud_agent_keys=cloud_agents, scope=scope))
        return rows

    def _item_value(self, conn: sqlite3.Connection, key: str) -> object:
        row = conn.execute('SELECT value FROM "ItemTable" WHERE key = ?', (key,)).fetchone()
        if row is None:
            return None
        value = row[0]
        if isinstance(value, (bytes, bytearray)):
            try:
                return bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                return None
        return value

    def _disk_kv(self, ctx: RowContext, conn: sqlite3.Connection, path: Path, sessions: dict, order: list, rows: list[AiRow]) -> tuple[dict[str, int], int]:
        counts: dict[str, int] = {}
        undecoded = 0
        bubbles: dict[str, dict[str, Mapping[str, object] | None]] = {}
        headers: dict[str, list[str]] = {}
        diffs: list[tuple[str, Mapping[str, object]]] = []
        for key, length in conn.execute('SELECT key, length(value) FROM "cursorDiskKV"'):
            prefix = _kv_prefix(str(key))
            counts[prefix] = counts.get(prefix, 0) + 1
            ctx.count_type(f"kv:{prefix}", frozenset(f"kv:{p}" for p in KNOWN_KV_PREFIXES))
        wanted = ("composerData:%", "bubbleId:%", "codeBlockDiff:%")
        for pattern in wanted:
            for key, value in conn.execute('SELECT key, value FROM "cursorDiskKV" WHERE key LIKE ?', (pattern,)):
                key = str(key)
                size = len(value) if isinstance(value, (bytes, str)) else 0
                if not ctx.budget.take(size, f"{path}#{key}"):
                    continue
                parsed = decode_json_value(value)
                parts = key.split(":")
                if parsed is None or not isinstance(parsed, Mapping):
                    undecoded += 1
                    if parts[0] == "bubbleId" and len(parts) >= 3:
                        bubbles.setdefault(parts[1], {})[parts[2]] = None
                    continue
                if parts[0] == "composerData" and len(parts) >= 2:
                    sid = parts[1]
                    acc = self._session(ctx, sessions, order, sid, path)
                    if isinstance(parsed.get("name"), str) and not acc.meta.get("title"):
                        acc.meta["title"] = redact_str(parsed["name"])[:512]
                    acc.see_time(to_iso(parsed.get("createdAt")))
                    acc.see_time(to_iso(parsed.get("lastUpdatedAt")))
                    model = parsed.get("modelConfig")
                    if isinstance(model, Mapping):
                        acc.note(acc.models, model.get("modelName"))
                    head = parsed.get("fullConversationHeadersOnly") or parsed.get("conversation")
                    if isinstance(head, list):
                        headers[sid] = [str(h.get("bubbleId")) for h in head if isinstance(h, Mapping) and h.get("bubbleId")]
                elif parts[0] == "bubbleId" and len(parts) >= 3:
                    bubbles.setdefault(parts[1], {})[parts[2]] = parsed
                elif parts[0] == "codeBlockDiff" and len(parts) >= 2:
                    diffs.append((parts[1], parsed))
        for sid, by_id in bubbles.items():
            acc = self._session(ctx, sessions, order, sid, path)
            ordered = [b for b in headers.get(sid, []) if b in by_id] + sorted(b for b in by_id if b not in headers.get(sid, []))
            for bubble_id in ordered:
                bubble = by_id[bubble_id]
                if bubble is None:
                    acc.meta["undecoded_bubbles"] = int(acc.meta.get("undecoded_bubbles") or 0) + 1  # type: ignore[call-overload]
                    continue
                self._bubble(acc, bubble, bubble_id, path)
        for sid, diff in diffs:
            acc = self._session(ctx, sessions, order, sid, path)
            target = _diff_path(diff)
            if target:
                acc.file_touch("edit", target, to_iso(diff.get("createdAt")), tool_name="codeBlockDiff", op_source="codeBlockDiff")
        return counts, undecoded

    def _bubble(self, acc: SessionAccumulator, bubble: Mapping[str, object], bubble_id: str, path: Path) -> None:
        btype = bubble.get("type")
        role = BUBBLE_ROLES.get(btype, str(btype)) if isinstance(btype, int) else str(btype or "")
        timing = bubble.get("timingInfo")
        stamp = to_iso(bubble.get("createdAt")) or (to_iso(timing.get("clientStartTime")) if isinstance(timing, Mapping) else "")
        tool = bubble.get("toolFormerData")
        text = bubble.get("text") or ""
        images = bubble.get("images")
        if text or images:
            acc.message(role, stamp, text, has_image=bool(images), bubble_id=bubble_id, role_source="bubble.type 1=user 2=assistant", tool_use_count=1 if isinstance(tool, Mapping) else 0)
        if isinstance(tool, Mapping) and tool.get("name"):
            params = tool.get("params") if tool.get("params") is not None else tool.get("rawArgs")
            row = acc.tool_call(str(tool["name"]), stamp, params, call_id=str(tool.get("toolCallId") or bubble_id), status=str(tool.get("status") or ""))
            result = tool.get("result")
            if row is not None and isinstance(result, str):
                row.payload["result_bytes"] = len(result.encode("utf-8", "replace"))

    # --- workspace / tracking / transcripts -------------------------------------------------

    def _workspace_db(self, ctx: RowContext, path: Path, workspace: str, folder: str, sessions: dict, order: list) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, _ = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error:
            return rows
        try:
            tables = table_columns(conn)
            if "ItemTable" not in tables:
                return rows
            rows.extend(self._item_table(ctx, conn, path, scope=f"workspace:{workspace}"))
            prompts = decode_json_value(self._item_value(conn, "aiService.prompts"))
            if isinstance(prompts, list) and prompts:
                acc = self._session(ctx, sessions, order, f"workspace:{workspace}", path)
                acc.meta.update({"workspace_id": workspace, "cwd": redact_str(folder), "source_kind": "workspace aiService.prompts"})
                for prompt in prompts:
                    if isinstance(prompt, Mapping) and prompt.get("text"):
                        acc.message("user", "", prompt["text"], has_image=False, source="aiService.prompts")
        except sqlite3.Error:
            pass
        finally:
            conn.close()
        return rows

    def _tracking_db(self, ctx: RowContext, path: Path) -> list[AiRow]:
        rows: list[AiRow] = []
        try:
            conn, with_wal = open_sqlite_ro(path, ctx.limits)
        except sqlite3.Error as exc:
            return [presence_row(ctx, path, "database", open_error=type(exc).__name__)]
        try:
            tables = table_columns(conn)
            rows.append(presence_row(ctx, path, "database", tables=sorted(tables)[:MAX_LIST_ITEMS], wal_included=with_wal))
            if "ai_code_hashes" in tables:
                per_file: dict[str, dict[str, object]] = {}
                for item in select_rows(conn, "ai_code_hashes", ("fileName", "conversationId", "timestamp", "model", "source", "createdAt"), tables["ai_code_hashes"]):
                    name = str(item["fileName"] or "")
                    entry = per_file.setdefault(name, {"lines": 0, "models": [], "conversations": [], "sources": [], "first": "", "last": ""})
                    entry["lines"] = int(entry["lines"]) + 1  # type: ignore[call-overload]
                    for key, value in (("models", item["model"]), ("conversations", item["conversationId"]), ("sources", item["source"])):
                        bucket = entry[key]
                        if isinstance(value, str) and value and value not in bucket and len(bucket) < MAX_LIST_ITEMS:  # type: ignore[operator]
                            bucket.append(value)  # type: ignore[union-attr]
                    stamp = to_iso(item["timestamp"] or item["createdAt"])
                    if stamp:
                        entry["first"] = min(filter(None, [str(entry["first"]), stamp]))
                        entry["last"] = max(str(entry["last"]), stamp)
                for name, entry in sorted(per_file.items()):
                    rows.append(
                        ctx.row(
                            "ai-code-attribution",
                            path,
                            timestamp=str(entry["last"]),
                            kind="last-modified",
                            file=redact_str(name),
                            commit="",
                            ai_lines=entry["lines"],
                            human_lines=None,
                            ai_percent=None,
                            model=(entry["models"] or [""])[0],  # type: ignore[index]
                            models=entry["models"],
                            conversation_ids=entry["conversations"],
                            hash_sources=entry["sources"],
                            first_ts=entry["first"],
                            ts=entry["last"],
                            source="ai_code_hashes",
                        )
                    )
            if "scored_commits" in tables:
                cols = ("commitHash", "branchName", "scoredAt", "linesAdded", "linesDeleted", "tabLinesAdded", "composerLinesAdded", "humanLinesAdded", "commitMessage", "commitDate", "v1AiPercentage", "v2AiPercentage")
                for item in select_rows(conn, "scored_commits", cols, tables["scored_commits"]):
                    ai_lines = sum(int(item[k] or 0) for k in ("tabLinesAdded", "composerLinesAdded") if isinstance(item[k], (int, float)))
                    percent = item["v2AiPercentage"] if item["v2AiPercentage"] is not None else item["v1AiPercentage"]
                    stamp = to_iso(item["commitDate"])
                    rows.append(
                        ctx.row(
                            "ai-code-attribution",
                            path,
                            timestamp=stamp,
                            kind="committed",
                            file="",
                            commit=str(item["commitHash"] or ""),
                            branch=redact_str(item["branchName"] or ""),
                            ai_lines=ai_lines,
                            human_lines=item["humanLinesAdded"],
                            lines_added=item["linesAdded"],
                            lines_deleted=item["linesDeleted"],
                            ai_percent=float(percent) if isinstance(percent, (int, float, str)) and str(percent).replace(".", "", 1).isdigit() else None,
                            ai_percent_v1=item["v1AiPercentage"],
                            commit_message=ctx.text(item["commitMessage"] or "")[0][:512],
                            scored_at=to_iso(item["scoredAt"]),
                            ts=stamp,
                            model="",
                            source="scored_commits",
                        )
                    )
        except sqlite3.Error as exc:
            rows.append(presence_row(ctx, path, "database", read_error=type(exc).__name__))
        finally:
            conn.close()
        return rows

    def _transcript(self, ctx: RowContext, path: Path, projects: Path, sessions: dict, order: list) -> None:
        """``~/.cursor/projects/<slug>/agent-transcripts/**.jsonl`` - format not validated on real
        data: lines with ``role`` + ``content``/``text`` become messages, the rest are counted."""
        sid = f"transcript:{path.stem}"
        acc = self._session(ctx, sessions, order, sid, path)
        acc.meta.update({"project_label": path.relative_to(projects).parts[0], "source_kind": "agent-transcript", "coverage_note": "schema-not-validated"})
        for record in iter_jsonl(path, ctx.budget):
            message = record.get("message") if isinstance(record.get("message"), Mapping) else {}
            role = record.get("role") or message.get("role")
            content = record.get("content", record.get("text"))
            if content is None:
                content = message.get("content")
            if isinstance(content, list):
                text = "\n".join(str(c.get("text")) for c in content if isinstance(c, Mapping) and c.get("text"))
            else:
                text = content if isinstance(content, str) else ""
            stamp = to_iso(record.get("timestamp") or record.get("createdAt"))
            if isinstance(role, str) and role and text:
                acc.message(role, stamp, text, has_image=False, source="agent-transcripts")
            else:
                ctx.count_type("transcript-line-without-role", frozenset())


register_adapter(CursorAdapter)
