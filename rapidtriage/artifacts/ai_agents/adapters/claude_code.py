"""Claude Code (``~/.claude``) session adapter (R7 AI plan §3.2; schema PC_SURVEY §4.1).

Sessions are ``projects/<cwd-slug>/<sessionId>.jsonl``; sub-agents are
``projects/<cwd-slug>/<sessionId>/subagents/agent-<agentId>.jsonl`` (and deeper
``…/subagents/agent-a/subagents/agent-b.jsonl``). A sub-agent session id is
``<sessionId>:<agentId>``; its ``parent_session_id`` is the enclosing session (or agent).
Record ``type`` values outside :data:`KNOWN_TYPES` are tolerated and counted. Text blocks become
messages; ``tool_use`` blocks become tool calls (+ file touches); ``tool_result`` blocks set the
call's result size / error; base64 ``image`` blocks are size-only. ``attachment`` records that
carry MCP server state lists, ``attributionMcpServer`` fields and ``mcp__server__tool`` calls
become ``ai-mcp-server`` rows. ``.credentials.json`` and ``sessions/*.key`` are existence-only.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import mask_email, redact_str
from ._common import (
    MAX_LIST_ITEMS,
    RowContext,
    SessionAccumulator,
    credential_row,
    instruction_row,
    iter_jsonl,
    iter_profiles,
    make_found,
    mcp_row,
    mcp_rows_from_config,
    presence_row,
    read_small_json,
    retention_row,
    summary_row,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "claude-code"
LABEL = "Claude Code"
KNOWN_TYPES = frozenset(
    {
        "assistant",
        "user",
        "attachment",
        "queue-operation",
        "last-prompt",
        "custom-title",
        "agent-name",
        "mode",
        "system",
        "file-history-snapshot",
        "api-request",
        "api-request-blob",
        "atis-latch",
        "summary",
    }
)
_MCP_STATUS_KEYS = {
    "failed": "failed",
    "failedmcpservers": "failed",
    "pending": "pending",
    "pendingmcpservers": "pending",
    "needsauth": "needs-auth",
    "needsauthmcpservers": "needs-auth",
    "connected": "connected",
    "connectedmcpservers": "connected",
}


def _image_bytes(block: Mapping[str, object]) -> int:
    source = block.get("source")
    data = source.get("data") if isinstance(source, Mapping) else None
    return (len(data) * 3) // 4 if isinstance(data, str) else 0


def _result_size(content: object) -> tuple[int, int]:
    """``(text bytes, image count)`` of a ``tool_result`` content value."""
    if isinstance(content, str):
        return len(content.encode("utf-8", "replace")), 0
    total, images = 0, 0
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, Mapping):
                continue
            if item.get("type") == "image":
                images += 1
                total += _image_bytes(item)
            elif isinstance(item.get("text"), str):
                total += len(str(item["text"]).encode("utf-8", "replace"))
    return total, images


def _exit_code(result: object) -> object:
    if isinstance(result, Mapping):
        for key in ("exitCode", "exit_code", "returnCode", "code"):
            value = result.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
    return None


def _mcp_status_lists(attachment: Mapping[str, object]) -> list[tuple[str, str]]:
    """``(server, status)`` from an MCP-state attachment (lists under failed/pending/needsAuth…)."""
    kind = str(attachment.get("type") or "").lower()
    out: list[tuple[str, str]] = []
    for key, value in attachment.items():
        lowered = str(key).lower()
        status = _MCP_STATUS_KEYS.get(lowered)
        if status is None or ("mcp" not in kind and "mcp" not in lowered):
            continue
        if isinstance(value, list):
            for item in value:
                name = item.get("name") if isinstance(item, Mapping) else item
                if isinstance(name, str) and name:
                    out.append((name, status))
    return out


class _SessionFile:
    def __init__(self, path: Path, projects: Path) -> None:
        self.path = path
        rel = path.relative_to(projects).parts
        self.slug = rel[0] if len(rel) > 1 else ""
        self.is_subagent = "subagents" in rel
        self.root_session = rel[1] if self.is_subagent and len(rel) > 2 else path.stem
        parent_agent = ""
        if self.is_subagent:
            # nearest enclosing agent folder: …/agent-a/subagents/agent-b.jsonl
            enclosing = rel[-3] if len(rel) >= 4 else ""
            if enclosing.startswith("agent-") and rel[-2] == "subagents" and len(rel) > 4:
                parent_agent = enclosing[len("agent-") :]
        self.parent_agent = parent_agent


class ClaudeCodeAdapter(AiAgentAdapter):
    name = "claude_code"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".claude") for profile in iter_profiles(roots, os_hint) if (profile.home / ".claude").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        home = base.parent
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = []
        rows.append(presence_row(ctx, base, "tool-home"))
        settings_retention = None
        for name in ("settings.json", "settings.local.json"):
            path = base / name
            if path.is_file():
                data = read_small_json(path, ctx.budget)
                fields: dict[str, object] = {}
                if isinstance(data, Mapping):
                    if isinstance(data.get("cleanupPeriodDays"), int):
                        settings_retention = data["cleanupPeriodDays"]
                        fields["retention_days"] = settings_retention
                    if isinstance(data.get("model"), str):
                        fields["configured_model"] = redact_str(data["model"])
                    env = data.get("env")
                    if isinstance(env, Mapping):
                        fields["env_var_names"] = sorted(str(k) for k in env)[:MAX_LIST_ITEMS]
                    if isinstance(data.get("permissions"), Mapping):
                        fields["permission_rules"] = sum(len(v) for v in data["permissions"].values() if isinstance(v, list))
                    rows.extend(mcp_rows_from_config(ctx, path, data.get("mcpServers"), scope="settings"))
                rows.append(presence_row(ctx, path, "settings", **fields))
        cleanup = base / ".last-cleanup"
        if cleanup.is_file():
            rows.append(retention_row(ctx, cleanup, retention_days=settings_retention))
        cred = base / ".credentials.json"
        if cred.exists():
            rows.append(credential_row(ctx, cred, "oauth-credentials"))
        rows.extend(self._home_config(ctx, home))
        for path in (base / "CLAUDE.md",):
            if path.is_file():
                row = instruction_row(ctx, path, "CLAUDE.md")
                if row:
                    rows.append(row)
        for sub, kind in (("skills", "skill"), ("agents", "agent-definition"), ("commands", "command"), ("rules", "rules")):
            folder = base / sub
            if folder.is_dir():
                for path in walk_files(folder, limit=500):
                    if path.suffix.lower() == ".md":
                        row = instruction_row(ctx, path, kind)
                        if row:
                            rows.append(row)
        plugins = base / "plugins"
        if plugins.is_dir():
            rows.append(presence_row(ctx, plugins, "plugins", file_count=sum(1 for _ in walk_files(plugins, limit=5000))))
        snapshots = base / "shell-snapshots"
        if snapshots.is_dir():
            # Shell environment snapshots may hold exported secrets: counted, never read.
            rows.append(presence_row(ctx, snapshots, "shell-snapshots", file_count=sum(1 for _ in walk_files(snapshots, limit=5000)), content_collected=False))
        sessions_dir = base / "sessions"
        if sessions_dir.is_dir():
            for path in walk_files(sessions_dir, limit=2000):
                if path.suffix.lower() == ".key":
                    rows.append(credential_row(ctx, path, "session-key"))
                elif path.suffix.lower() == ".json":
                    data = read_small_json(path, ctx.budget, max_bytes=256 * 1024)
                    fields = {}
                    if isinstance(data, Mapping):
                        fields = {
                            "session_id": redact_str(data.get("sessionId") or ""),
                            "pid": data.get("pid") if isinstance(data.get("pid"), int) else None,
                            "cwd": redact_str(data.get("cwd") or ""),
                            "started_at": to_iso(data.get("startedAt") or data.get("startTime")),
                        }
                    rows.append(presence_row(ctx, path, "live-session-marker", **fields))
        file_history = self._file_history(base / "file-history")
        history_rows = self._history(ctx, base / "history.jsonl")
        projects = base / "projects"
        session_rows: list[AiRow] = []
        if projects.is_dir():
            files = [p for p in walk_files(projects, limit=200_000) if p.suffix == ".jsonl"]
            for path in sorted(files, key=lambda p: (len(p.parts), str(p))):
                session_rows.extend(self._session(ctx, path, projects, file_history))
        rows.extend(session_rows)
        rows.extend(history_rows)
        rows.append(summary_row(ctx, base, session_files=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session")))
        yield from rows

    # --- sidecars ------------------------------------------------------------------------

    def _home_config(self, ctx: RowContext, home: Path) -> list[AiRow]:
        """``~/.claude.json``: MCP servers (global + per project) and the OAuth account's org /
        email domain. Only these keys are read; tokens or API keys in the file are never emitted."""
        path = home / ".claude.json"
        if not path.is_file():
            return []
        data = read_small_json(path, ctx.budget, max_bytes=32 * 1024 * 1024)
        rows: list[AiRow] = [presence_row(ctx, path, "user-config")]
        if not isinstance(data, Mapping):
            return rows
        rows.extend(mcp_rows_from_config(ctx, path, data.get("mcpServers"), scope="user"))
        projects = data.get("projects")
        if isinstance(projects, Mapping):
            for project, spec in projects.items():
                if isinstance(spec, Mapping):
                    rows.extend(mcp_rows_from_config(ctx, path, spec.get("mcpServers"), scope=f"project:{redact_str(project)}"))
        account = data.get("oauthAccount")
        if isinstance(account, Mapping):
            domain, local_hash = mask_email(account.get("emailAddress"))
            rows.append(
                ctx.row(
                    "ai-account",
                    path,
                    account_key=ctx.account_key,
                    tool_account_key=f"claude-{local_hash}" if local_hash else "",
                    org_label=redact_str(account.get("organizationName") or ""),
                    email_domain=domain,
                    email_local_hash=local_hash,
                    active=True,
                    source="~/.claude.json oauthAccount",
                )
            )
        return rows

    def _file_history(self, folder: Path) -> dict[str, int]:
        counts: dict[str, int] = {}
        if not folder.is_dir():
            return counts
        try:
            children = list(folder.iterdir())
        except OSError:
            return counts
        for child in children:
            if child.is_dir():
                counts[child.name] = sum(1 for _ in walk_files(child, limit=5000))
        return counts

    def _history(self, ctx: RowContext, path: Path) -> list[AiRow]:
        """``history.jsonl`` prompt history (pasted content inline): one ``ai-agent-message`` per
        entry, role ``user``, ``source=history.jsonl``."""
        if not path.is_file():
            return []
        rows: list[AiRow] = []
        stats: dict[str, int] = {}
        for seq, record in enumerate(iter_jsonl(path, ctx.budget, stats), start=1):
            stamp = to_iso(record.get("timestamp"))
            text, truncated, original = ctx.text(record.get("display")) if ctx.limits.include_bodies else ("", False, 0)
            pasted = record.get("pastedContents")
            pasted_parts: list[str] = []
            if isinstance(pasted, Mapping):
                for item in pasted.values():
                    content = item.get("content") if isinstance(item, Mapping) else item
                    if isinstance(content, str):
                        pasted_parts.append(content)
            pasted_text, pasted_truncated, pasted_bytes = ctx.text("\n---\n".join(pasted_parts)) if pasted_parts and ctx.limits.include_bodies else ("", False, 0)
            rows.append(
                ctx.row(
                    "ai-agent-message",
                    path,
                    timestamp=stamp,
                    kind="message",
                    session_id=redact_str(record.get("sessionId") or ""),
                    seq=seq,
                    role="user",
                    ts=stamp,
                    text=text,
                    text_bytes=original,
                    truncated=truncated or pasted_truncated,
                    has_pasted=bool(pasted_parts),
                    pasted_text=pasted_text,
                    pasted_bytes=pasted_bytes,
                    has_image=False,
                    project=redact_str(record.get("project") or ""),
                    source="history.jsonl",
                )
            )
        return rows

    # --- sessions ------------------------------------------------------------------------

    def _session(self, ctx: RowContext, path: Path, projects: Path, file_history: Mapping[str, int]) -> list[AiRow]:
        info = _SessionFile(path, projects)
        records = iter_jsonl(path, ctx.budget, stats := {})
        acc: SessionAccumulator | None = None
        mcp_seen: dict[tuple[str, str], AiRow] = {}
        title = ""
        agent_name = ""
        for record in records:
            rtype = str(record.get("type") or "")
            ctx.count_type(rtype or "(none)", KNOWN_TYPES)
            if acc is None:
                session_id = str(record.get("sessionId") or info.root_session)
                agent_id = str(record.get("agentId") or "")
                if info.is_subagent:
                    if not agent_id:
                        agent_id = path.stem.removeprefix("agent-")
                    sid = f"{session_id}:{agent_id}"
                    parent = f"{session_id}:{info.parent_agent}" if info.parent_agent else session_id
                else:
                    sid, parent = session_id, ""
                acc = SessionAccumulator(ctx, sid, path, parent_session_id=parent)
                acc.meta.update(
                    {
                        "project_label": info.slug,
                        "is_subagent": info.is_subagent,
                        "agent_id": agent_id if info.is_subagent else "",
                    }
                )
            stamp = to_iso(record.get("timestamp"))
            acc.see_time(stamp)
            for key, meta_key in (("cwd", "cwd"), ("gitBranch", "git_branch"), ("permissionMode", "permission_mode"), ("entrypoint", "entrypoint"), ("slug", "slug")):
                value = record.get(key)
                if isinstance(value, str) and value and meta_key not in acc.meta:
                    acc.meta[meta_key] = redact_str(value)
            acc.note(acc.versions, record.get("version"))
            if rtype in ("custom-title", "summary"):
                title = str(record.get("customTitle") or record.get("title") or record.get("summary") or title)
            elif rtype == "agent-name":
                agent_name = str(record.get("agentName") or record.get("name") or agent_name)
            elif rtype == "attachment":
                attachment = record.get("attachment")
                if isinstance(attachment, Mapping):
                    for server, status in _mcp_status_lists(attachment):
                        key = (server, status)
                        if key not in mcp_seen:
                            mcp_seen[key] = mcp_row(ctx, path, server, status=status, stamp=stamp, session_id=acc.session_id, source="attachment")
            server = record.get("attributionMcpServer")
            if isinstance(server, str) and server:
                key = (server, "used")
                tool = record.get("attributionMcpTool")
                row = mcp_seen.get(key) or mcp_row(ctx, path, server, status="used", stamp=stamp, session_id=acc.session_id, source="attribution")
                if isinstance(tool, str) and tool and tool not in row.payload["tools"]:  # type: ignore[operator]
                    row.payload["tools"].append(redact_str(tool))  # type: ignore[union-attr]
                    row.payload["tool_count"] = len(row.payload["tools"])  # type: ignore[arg-type]
                mcp_seen[key] = row
            if rtype in ("user", "assistant"):
                self._message(acc, record, rtype, stamp, path, mcp_seen)
        if acc is None:
            return []
        for row in mcp_seen.values():
            acc.rows.append(row)
        sid_root = acc.session_id.split(":", 1)[0]
        return acc.finish(
            title=redact_str(title)[:512],
            agent_name=redact_str(agent_name)[:200],
            file_history_files=file_history.get(sid_root) if not acc.meta.get("is_subagent") else None,
            bad_lines=stats.get("bad_lines", 0),
            source_kind="subagent-jsonl" if acc.meta.get("is_subagent") else "session-jsonl",
        )

    def _message(self, acc: SessionAccumulator, record: Mapping[str, object], rtype: str, stamp: str, path: Path, mcp_seen: dict[tuple[str, str], AiRow]) -> None:
        message = record.get("message")
        if not isinstance(message, Mapping):
            return
        role = str(message.get("role") or rtype)
        model = message.get("model")
        if isinstance(model, str) and model and not model.startswith("<"):
            acc.note(acc.models, model)
        usage = message.get("usage")
        if isinstance(usage, Mapping):
            acc.tokens_in += sum(int(usage.get(k) or 0) for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens") if isinstance(usage.get(k), int))
            if isinstance(usage.get("output_tokens"), int):
                acc.tokens_out += int(usage["output_tokens"])  # type: ignore[arg-type]
        content = message.get("content")
        texts: list[str] = []
        images = 0
        image_bytes = 0
        thinking = 0
        tool_uses: list[Mapping[str, object]] = []
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, Mapping):
                    continue
                btype = block.get("type")
                if btype == "text" and isinstance(block.get("text"), str):
                    texts.append(str(block["text"]))
                elif btype == "image":
                    images += 1
                    image_bytes += _image_bytes(block)
                elif btype == "thinking":
                    thinking += 1
                elif btype == "tool_use":
                    tool_uses.append(block)
                elif btype == "tool_result":
                    size, result_images = _result_size(block.get("content"))
                    images += result_images
                    acc.tool_result(
                        str(block.get("tool_use_id") or ""),
                        result_bytes=size,
                        exit_code=_exit_code(record.get("toolUseResult")),
                        is_error=block.get("is_error") if isinstance(block.get("is_error"), bool) else None,
                    )
        if texts or images:
            acc.message(
                role,
                stamp,
                "\n".join(texts),
                has_image=images > 0,
                image_count=images,
                image_bytes=image_bytes,
                thinking_blocks=thinking,
                tool_use_count=len(tool_uses),
                is_meta=bool(record.get("isMeta")),
                is_sidechain=bool(record.get("isSidechain")),
                record_uuid=str(record.get("uuid") or ""),
                parent_uuid=str(record.get("parentUuid") or ""),
                model=str(model or "") if role == "assistant" else "",
            )
        for block in tool_uses:
            name = str(block.get("name") or "")
            acc.tool_call(name, stamp, block.get("input"), call_id=str(block.get("id") or ""))
            if name.startswith("mcp__"):
                server, tool = name[5:].split("__", 1) if "__" in name[5:] else (name[5:], "")
                key = (server, "used")
                row = mcp_seen.get(key) or mcp_row(acc.ctx, path, server, status="used", stamp=stamp, session_id=acc.session_id, source="tool_use")
                if tool and tool not in row.payload["tools"]:  # type: ignore[operator]
                    row.payload["tools"].append(redact_str(tool))  # type: ignore[union-attr]
                    row.payload["tool_count"] = len(row.payload["tools"])  # type: ignore[arg-type]
                mcp_seen[key] = row


register_adapter(ClaudeCodeAdapter)
