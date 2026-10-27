"""Gemini CLI (``~/.gemini``) adapter (R7 AI plan §3.2).

``~/.gemini`` is shared with Antigravity: the ``antigravity*`` sub-folders belong to the
antigravity adapter and are skipped here. ``GEMINI.md`` is an instruction file,
``settings.json`` ``mcpServers`` MCP rows, ``google_accounts.json`` an ``ai-account`` row (email
domain + hash). Chat checkpoints ``tmp/<projectHash>/chats/*.json`` (``messages[].{type,content,
toolCalls}``) and ``tmp/<projectHash>/logs.json`` prompt logs are parsed when present - their
layout follows the public Gemini CLI source and was NOT seen on the reference PC, so those rows
carry ``coverage_status=schema-not-validated``. ``oauth_creds.json``,
``jetski-standalone-oauth-token`` and other credential names are existence-only.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import mask_email
from ._common import (
    COVERAGE_LOCAL_VERIFIED,
    COVERAGE_NOT_VALIDATED,
    RowContext,
    SessionAccumulator,
    content_text,
    credential_row,
    instruction_row,
    iter_profiles,
    make_found,
    mcp_rows_from_config,
    presence_row,
    read_small_json,
    summary_row,
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

TOOL = "gemini-cli"
LABEL = "Gemini CLI"
_ROLE = {"user": "user", "gemini": "assistant", "model": "assistant", "info": "system", "error": "system"}


class GeminiCliAdapter(AiAgentAdapter):
    name = "gemini_cli"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".gemini") for profile in iter_profiles(roots, os_hint) if (profile.home / ".gemini").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home", shared_with=sorted(p.name for p in base.glob("antigravity*") if p.is_dir()))]
        gemini_md = base / "GEMINI.md"
        if gemini_md.is_file():
            row = instruction_row(ctx, gemini_md, "GEMINI.md")
            if row:
                rows.append(row)
        settings = base / "settings.json"
        if settings.is_file():
            data = read_small_json(settings, ctx.budget)
            if isinstance(data, Mapping):
                rows.extend(mcp_rows_from_config(ctx, settings, data.get("mcpServers"), scope="settings.json"))
                auth = data.get("selectedAuthType") or ""
                rows.append(presence_row(ctx, settings, "settings", auth_type=str(auth or "")))
        accounts = base / "google_accounts.json"
        if accounts.is_file():
            data = read_small_json(accounts, ctx.budget, max_bytes=256 * 1024)
            if isinstance(data, Mapping):
                domain, local_hash = mask_email(data.get("active"))
                old = data.get("old") if isinstance(data.get("old"), list) else []
                rows.append(ctx.row("ai-account", accounts, tool_account_key=f"google-{local_hash}" if local_hash else "", org_label="", email_domain=domain, email_local_hash=local_hash, active=True, previous_accounts=len(old), source="google_accounts.json"))
        for path in sorted(base.iterdir()) if base.is_dir() else []:
            if path.is_file() and path.name not in ("google_accounts.json",) and (is_credential_name(path.name) or path.name == "oauth_creds.json"):
                rows.append(credential_row(ctx, path, "oauth-token"))
        session_rows: list[AiRow] = []
        tmp = base / "tmp"
        if tmp.is_dir():
            ctx.coverage = COVERAGE_NOT_VALIDATED  # chat/log layout taken from public source, not the reference PC
            for project in sorted(p for p in tmp.iterdir() if p.is_dir()):
                session_rows.extend(self._project(ctx, project))
            ctx.coverage = COVERAGE_LOCAL_VERIFIED
        yield from session_rows
        yield from rows
        yield summary_row(ctx, base, sessions=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session"))

    def _project(self, ctx: RowContext, project: Path) -> list[AiRow]:
        sessions: dict[str, SessionAccumulator] = {}
        order: list[str] = []

        def session(sid: str, path: Path) -> SessionAccumulator:
            acc = sessions.get(sid)
            if acc is None:
                acc = SessionAccumulator(ctx, sid, path)
                acc.meta.update({"project_label": project.name, "coverage_note": COVERAGE_NOT_VALIDATED})
                sessions[sid] = acc
                order.append(sid)
            return acc

        chats = project / "chats"
        if chats.is_dir():
            for path in sorted(walk_files(chats, limit=5000)):
                if path.suffix != ".json":
                    continue
                data = read_small_json(path, ctx.budget, max_bytes=64 * 1024 * 1024)
                if not isinstance(data, Mapping):
                    continue
                acc = session(str(data.get("sessionId") or path.stem), path)
                acc.see_time(to_iso(data.get("startTime")))
                acc.see_time(to_iso(data.get("lastUpdated")))
                for message in data.get("messages") or []:
                    if not isinstance(message, Mapping):
                        continue
                    stamp = to_iso(message.get("timestamp"))
                    acc.note(acc.models, message.get("model"))
                    tokens = message.get("tokens")
                    if isinstance(tokens, Mapping):
                        acc.tokens_in += int(tokens.get("input") or 0) if isinstance(tokens.get("input"), int) else 0
                        acc.tokens_out += int(tokens.get("output") or 0) if isinstance(tokens.get("output"), int) else 0
                    calls = [c for c in message.get("toolCalls") or [] if isinstance(c, Mapping)]
                    text = content_text(message.get("content"))
                    if text:
                        acc.message(_ROLE.get(str(message.get("type") or ""), str(message.get("type") or "")), stamp, text, source_path=path, has_image=False, tool_use_count=len(calls), source="chats")
                    for call in calls:
                        acc.tool_call(str(call.get("name") or ""), to_iso(call.get("timestamp")) or stamp, call.get("args"), call_id=str(call.get("id") or ""), source_path=path, status=str(call.get("status") or ""))
        logs = project / "logs.json"
        if logs.is_file():
            data = read_small_json(logs, ctx.budget, max_bytes=64 * 1024 * 1024)
            for entry in data if isinstance(data, list) else []:
                if isinstance(entry, Mapping) and entry.get("message"):
                    acc = session(str(entry.get("sessionId") or project.name), logs)
                    acc.message(_ROLE.get(str(entry.get("type") or ""), str(entry.get("type") or "")), to_iso(entry.get("timestamp")), entry.get("message"), source_path=logs, has_image=False, source="logs.json")
        out: list[AiRow] = []
        for sid in order:
            out.extend(sessions[sid].finish())
        return out


register_adapter(GeminiCliAdapter)
