"""Claude desktop app adapter (R7 AI plan §3.2; layout PC_SURVEY §4.6, chatbots.json).

The live data folder is ``%LOCALAPPDATA%/Claude-Data/<package>/`` (MSIX); ``Claude-3p`` and
``%APPDATA%/Claude`` are read the same way when they hold data. ``claude-code-sessions/<account>/
local_*.json`` are Code-tab sessions (``cliSessionId`` links to the Claude Code JSONL session,
emitted as ``linked_session_id``); every ``<account>`` folder becomes an ``ai-account`` row with a
pseudonymous ``tool_account_key`` (the folder uuid is hashed). ``local-agent-mode-sessions/*/
local_*.json`` are cowork sessions. ``plan-usage-history.json`` samples become per-day
``ai-usage-stat`` rows; ``claude_desktop_config.json`` ``mcpServers`` and ``logs/mcp*.log`` give
MCP rows; ``main*.log`` is reduced to MCP / session line counts. ``buddy-tokens.json``,
``ssh-remote-server-state.json`` and ``Network/Cookies`` are existence-only; the native
messaging host and the MSIX ``Packages/Claude_*`` stub are presence rows.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import redact_str, short_hash
from ._common import (
    RowContext,
    SessionAccumulator,
    credential_row,
    iter_profiles,
    iter_text_lines,
    log_line_time,
    make_found,
    mcp_rows_from_config,
    parse_mcp_log,
    presence_row,
    read_small_json,
    summary_row,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "claude-desktop"
LABEL = "Claude (desktop)"
SENSITIVE_FILES = {"buddy-tokens.json": "session-tokens", "ssh-remote-server-state.json": "ssh-tokens", "Cookies": "browser-cookies"}
_MCP_LINE = re.compile(r"(?i)\bmcp\b")
_SESSION_LINE = re.compile(r"(?i)\bsession\b")


def _data_dirs(home: Path) -> list[Path]:
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    mac = home / "Library" / "Application Support"
    dirs: list[Path] = []
    data = local / "Claude-Data"
    if data.is_dir():
        dirs.extend(sorted(p for p in data.iterdir() if p.is_dir()))
    for candidate in (local / "Claude-3p", roaming / "Claude-3p", roaming / "Claude", mac / "Claude", home / ".config" / "Claude"):
        if candidate.is_dir():
            dirs.append(candidate)
    return dirs


class ClaudeDesktopAdapter(AiAgentAdapter):
    name = "claude_desktop"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        found: list[Found] = []
        for profile in iter_profiles(roots, os_hint):
            home = profile.home
            dirs = _data_dirs(home)
            logs = [p for p in (home / "AppData" / "Local" / "Claude" / "logs", home / "Library" / "Logs" / "Claude") if p.is_dir()]
            native = home / "AppData" / "Roaming" / "Claude-NativeHost"
            packages = sorted((home / "AppData" / "Local" / "Packages").glob("Claude_*")) if (home / "AppData" / "Local" / "Packages").is_dir() else []
            if dirs or logs or native.is_dir() or packages:
                found.append(make_found(self, profile, dirs[0] if dirs else home, data_dirs=dirs, log_dirs=logs, native_host=native if native.is_dir() else None, packages=packages))
        return found

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = []
        session_rows: list[AiRow] = []
        for data in found.extra.get("data_dirs") or []:  # type: ignore[union-attr]
            rows.append(presence_row(ctx, data, "app-data"))
            session_rows.extend(self._code_sessions(ctx, data / "claude-code-sessions", rows))
            session_rows.extend(self._agent_mode(ctx, data / "local-agent-mode-sessions"))
            config = data / "claude_desktop_config.json"
            if config.is_file():
                parsed = read_small_json(config, ctx.budget)
                rows.extend(mcp_rows_from_config(ctx, config, parsed.get("mcpServers") if isinstance(parsed, Mapping) else None, scope="claude_desktop_config.json"))
            usage = data / "plan-usage-history.json"
            if usage.is_file():
                rows.extend(self._plan_usage(ctx, usage))
            worktrees = data / "git-worktrees.json"
            if worktrees.is_file():
                parsed = read_small_json(worktrees, ctx.budget)
                rows.append(presence_row(ctx, worktrees, "git-worktrees", entries=len(parsed) if isinstance(parsed, (dict, list)) else None, content_collected=False))
            for name, kind in SENSITIVE_FILES.items():
                for path in (data / name, data / "Network" / name):
                    if path.is_file():
                        rows.append(credential_row(ctx, path, kind))
            bundled = data / "claude-code"
            if bundled.is_dir():
                rows.append(presence_row(ctx, bundled, "bundled-cli", versions=sorted(p.name for p in bundled.iterdir() if p.is_dir())[:50]))
        for logs in found.extra.get("log_dirs") or []:  # type: ignore[union-attr]
            for path in sorted(walk_files(logs, limit=500)):
                if path.suffix != ".log":
                    continue
                if path.name.lower().startswith("mcp"):
                    rows.extend(parse_mcp_log(ctx, path))
                elif path.name.lower().startswith("main"):
                    rows.append(self._main_log(ctx, path))
        native = found.extra.get("native_host")
        if native is not None:
            rows.append(presence_row(ctx, native, "browser-extension-native-host", manifests=sorted(p.name for p in native.glob("*.json"))[:20]))  # type: ignore[union-attr]
        for package in found.extra.get("packages") or []:  # type: ignore[union-attr]
            rows.append(presence_row(ctx, package, "msix-package"))
        yield from session_rows
        yield from rows
        yield summary_row(ctx, found.path, sessions=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session"))

    def _code_sessions(self, ctx: RowContext, folder: Path, rows: list[AiRow]) -> list[AiRow]:
        out: list[AiRow] = []
        if not folder.is_dir():
            return out
        for account in sorted(p for p in folder.iterdir() if p.is_dir()):
            account_key = f"claude-acct-{short_hash(account.name)}"
            first, last, count = "", "", 0
            for path in sorted(account.glob("local_*.json")):
                data = read_small_json(path, ctx.budget, max_bytes=4 * 1024 * 1024)
                if not isinstance(data, Mapping):
                    continue
                count += 1
                acc = SessionAccumulator(ctx, path.stem, path)
                created, last_activity = to_iso(data.get("createdAt")), to_iso(data.get("lastActivityAt"))
                acc.see_time(created)
                acc.see_time(last_activity)
                acc.note(acc.models, data.get("model"))
                pin = data.get("cliBinaryPin")
                acc.note(acc.versions, pin.get("version") if isinstance(pin, Mapping) else None)
                acc.meta.update(
                    {
                        "linked_session_id": redact_str(data.get("cliSessionId") or ""),
                        "linked_tool": "claude-code",
                        "tool_account_key": account_key,
                        "cwd": redact_str(data.get("cwd") or ""),
                        "origin_cwd": redact_str(data.get("originCwd") or ""),
                        "effort": str(data.get("effort") or ""),
                        "permission_mode": str(data.get("permissionMode") or ""),
                        "turns": data.get("completedTurns"),
                        "archived": data.get("isArchived") if isinstance(data.get("isArchived"), bool) else None,
                        "source_kind": "claude-code-sessions",
                    }
                )
                out.extend(acc.finish())
                first = min(filter(None, [first, created])) if created else first
                last = max(last, last_activity or created)
            rows.append(ctx.row("ai-account", account, tool_account_key=account_key, org_label="", email_domain="", email_local_hash="", active=None, first_seen=first, last_seen=last, sessions=count, source="claude-code-sessions/<account>"))
        return out

    def _agent_mode(self, ctx: RowContext, folder: Path) -> list[AiRow]:
        out: list[AiRow] = []
        if not folder.is_dir():
            return out
        for path in sorted(p for p in walk_files(folder, limit=5000) if p.name.startswith("local_") and p.suffix == ".json"):
            data = read_small_json(path, ctx.budget, max_bytes=4 * 1024 * 1024)
            if not isinstance(data, Mapping):
                continue
            acc = SessionAccumulator(ctx, str(data.get("sessionId") or path.stem), path)
            acc.see_time(to_iso(data.get("createdAt")))
            acc.see_time(to_iso(data.get("lastActivityAt")))
            acc.note(acc.models, data.get("model"))
            audit = path.parent / "audit.jsonl"
            acc.meta.update({"title": redact_str(data.get("title") or "")[:512], "source_kind": "local-agent-mode-sessions", "audit_lines": sum(1 for _ in iter_text_lines(audit, ctx.budget)) if audit.is_file() else None})
            out.extend(acc.finish())
        return out

    def _plan_usage(self, ctx: RowContext, path: Path) -> list[AiRow]:
        data = read_small_json(path, ctx.budget)
        samples = data.get("samples") if isinstance(data, Mapping) else None
        days: dict[str, dict[str, object]] = {}
        for sample in samples or []:
            if not isinstance(sample, Mapping):
                continue
            day = to_iso(sample.get("t"))[:10]
            usage = sample.get("u")
            value = usage.get("fh") if isinstance(usage, Mapping) else None
            entry = days.setdefault(day, {"samples": 0, "max": None})
            entry["samples"] = int(entry["samples"]) + 1  # type: ignore[call-overload]
            if isinstance(value, (int, float)):
                entry["max"] = max(float(entry["max"]), float(value)) if entry["max"] is not None else float(value)  # type: ignore[arg-type]
        return [ctx.row("ai-usage-stat", path, period=day, model="", tokens=None, requests=None, samples=entry["samples"], max_plan_utilization=entry["max"], source="plan-usage-history.json") for day, entry in sorted(days.items()) if day]

    def _main_log(self, ctx: RowContext, path: Path) -> AiRow:
        counts = {"lines": 0, "mcp_lines": 0, "session_lines": 0}
        first, last = "", ""
        for line in iter_text_lines(path, ctx.budget):
            counts["lines"] += 1
            if _MCP_LINE.search(line):
                counts["mcp_lines"] += 1
            if _SESSION_LINE.search(line):
                counts["session_lines"] += 1
            stamp = log_line_time(line)
            if stamp:
                first = first or stamp
                last = stamp
        return presence_row(ctx, path, "app-log", first_line_time=first, last_line_time=last, content_collected=False, **counts)


register_adapter(ClaudeDesktopAdapter)
