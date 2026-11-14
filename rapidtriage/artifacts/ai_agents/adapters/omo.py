"""OmO / oh-my-opencode adapter (R7 AI plan §3.2; layout PC_SURVEY §4.10, harnesses.json).

Root ``~/.omo`` (not the temp folder of older versions). ``agent/sessions/<cwd-slug>/<ts>_<uuid>
.jsonl`` are Pi-style typed session logs: ``message.{role, content[]}`` entries become messages,
``toolCall`` / ``tool_use`` content blocks tool calls (+ file touches); other entry types are
counted. The folder slug names the project without opening anything. ``ulw-loop/<run>/``
(``goals.json`` + ``ledger.jsonl``) becomes one session per run with ledger lines as
``ledger`` messages; ``brief.md``, ``memory/**.md`` and ``plans/*.md`` are instruction files.
``omo.jsonc`` holds provider keys, so it is listed (presence) and never parsed;
``agent/auth.json`` and ``*.auth`` are existence-only.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import redact_str
from ._common import (
    RowContext,
    SessionAccumulator,
    content_text,
    credential_row,
    instruction_row,
    iter_jsonl,
    iter_profiles,
    make_found,
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

TOOL = "omo"
LABEL = "OmO (oh-my-opencode)"
KNOWN_ENTRY_TYPES = frozenset({"session", "message", "custom", "model_change", "thinking_level_change", "compaction", "branch_summary", "label"})
_TS_NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})(?:-(\d{1,6}))?Z?_(.+)$")
TOOL_BLOCK_TYPES = frozenset({"toolCall", "tool_use", "tool_call", "toolUse"})


def _name_time_and_id(stem: str) -> tuple[str, str]:
    match = _TS_NAME_RE.match(stem)
    if not match:
        return "", stem
    date, hh, mm, ss, frac, rest = match.groups()
    stamp = f"{date}T{hh}:{mm}:{ss}{'.' + frac if frac else ''}Z"
    return to_iso(stamp), rest


class OmoAdapter(AiAgentAdapter):
    name = "omo"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".omo") for profile in iter_profiles(roots, os_hint) if (profile.home / ".omo").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        install = read_small_json(base / "install.json", ctx.budget, max_bytes=64 * 1024) if (base / "install.json").is_file() else None
        version = str(install.get("version") or "") if isinstance(install, Mapping) else ""
        backups = sorted(p.name for p in base.glob("omo.jsonc*") if p.name != "omo.jsonc")
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home", version=version)]
        if (base / "omo.jsonc").is_file():
            # provider keys live here: listed, never parsed
            rows.append(presence_row(ctx, base / "omo.jsonc", "settings", content_collected=False, backup_copies=len(backups)))
        for migration in sorted(base.glob("migration-backup-*")):
            rows.append(presence_row(ctx, migration, "migration-backup", migrated_from="opencode" if "opencode" in migration.name else ""))
        for path in walk_files(base, limit=20_000):
            rel = path.relative_to(base).parts
            if rel[0] in ("binary-runtime", "codegraph", "ulw-loop") and not path.name.endswith((".auth", ".key")):
                continue
            if is_credential_name(path.name) or path.suffix == ".auth":
                rows.append(credential_row(ctx, path, "auth-file"))
        session_rows: list[AiRow] = []
        sessions = base / "agent" / "sessions"
        if sessions.is_dir():
            for path in sorted(p for p in walk_files(sessions, limit=50_000) if p.suffix == ".jsonl"):
                session_rows.extend(self._session(ctx, path, sessions))
        loops = base / "ulw-loop"
        if loops.is_dir():
            for run in sorted(p for p in loops.iterdir() if p.is_dir()):
                session_rows.extend(self._ulw(ctx, run, rows))
        for folder, kind in (("memory", "MEMORY.md"), ("plans", "plan")):
            root = base / folder
            if root.is_dir():
                for path in walk_files(root, limit=2000):
                    if path.suffix.lower() == ".md":
                        row = instruction_row(ctx, path, kind)
                        if row:
                            rows.append(row)
        yield from session_rows
        yield from rows
        yield summary_row(ctx, base, sessions=sum(1 for r in session_rows if r.artifact_type == "ai-agent-session"))

    def _session(self, ctx: RowContext, path: Path, sessions: Path) -> list[AiRow]:
        started, sid = _name_time_and_id(path.stem)
        acc = SessionAccumulator(ctx, sid, path)
        acc.see_time(started)
        acc.meta.update({"project_label": path.relative_to(sessions).parts[0], "source_kind": "omo-agent-session"})
        for record in iter_jsonl(path, ctx.budget):
            etype = str(record.get("type") or record.get("customType") or "")
            ctx.count_type(etype or "(none)", KNOWN_ENTRY_TYPES)
            stamp = to_iso(record.get("timestamp"))
            acc.see_time(stamp)
            details = record.get("details") if isinstance(record.get("details"), Mapping) else {}
            cwd = record.get("cwd") or details.get("cwd")
            if isinstance(cwd, str) and cwd and not acc.meta.get("cwd"):
                acc.meta["cwd"] = redact_str(cwd)
            message = record.get("message")
            if not isinstance(message, Mapping):
                continue
            role = str(message.get("role") or "")
            content = message.get("content")
            text = content_text(content)
            model = message.get("model")
            acc.note(acc.models, model)
            blocks = [b for b in content if isinstance(b, Mapping) and b.get("type") in TOOL_BLOCK_TYPES] if isinstance(content, list) else []
            if role and text:
                acc.message(role, stamp, text, has_image=False, tool_use_count=len(blocks))
            for block in blocks:
                acc.tool_call(str(block.get("name") or ""), stamp, block.get("arguments") or block.get("input") or block.get("args"), call_id=str(block.get("id") or ""))
        return acc.finish()

    def _ulw(self, ctx: RowContext, run: Path, rows: list[AiRow]) -> list[AiRow]:
        acc = SessionAccumulator(ctx, f"ulw:{run.name}", run)
        goals = read_small_json(run / "goals.json", ctx.budget, max_bytes=1024 * 1024) if (run / "goals.json").is_file() else None
        if isinstance(goals, Mapping):
            items = [g for g in goals.get("goals") or [] if isinstance(g, Mapping)]
            active = next((g for g in items if g.get("id") == goals.get("activeGoalId")), items[0] if items else None)
            if active is not None:
                acc.meta["title"] = ctx.text(active.get("objective") or "")[0][:512]
                acc.meta["goal_status"] = str(active.get("status") or "")
                acc.see_time(to_iso(active.get("startedAt")))
            acc.meta["goals"] = len(items)
        ledger = run / "ledger.jsonl"
        if ledger.is_file():
            for record in iter_jsonl(ledger, ctx.budget):
                stamp = to_iso(record.get("at"))
                acc.message("ledger", stamp, record.get("message") or "", source_path=ledger, has_image=False, ledger_kind=str(record.get("kind") or ""), goal_id=str(record.get("goalId") or ""), status=str(record.get("status") or ""))
        brief = run / "brief.md"
        if brief.is_file():
            row = instruction_row(ctx, brief, "brief", extra={"session_id": acc.session_id})
            if row:
                rows.append(row)
        acc.meta["source_kind"] = "ulw-loop"
        return acc.finish()


register_adapter(OmoAdapter)
