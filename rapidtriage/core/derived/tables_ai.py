"""통합 보기 AI tables (R7 stage 3.5 §3.4, lane C): ``ai_usage`` and ``ai_projects``.

Unlike the value tables of :mod:`engine` (one row per distinct column value), these two aggregate
the ``ai-agent`` kind's session rows:

``ai_usage``     one row per *tool × account × UTC day* (day of the session start): sessions,
                 sub-agent sessions, turns, messages, tool calls, tokens in/out, distinct projects.
``ai_projects``  one row per project (the session ``cwd``, else its ``project_label``): sessions,
                 file touches, tool calls, first / last activity, sessions per tool, accounts.

Rows keep the engine's row shape so the console pages and pivots them like ``people`` /
``devices``: ``value`` (display), ``normalized`` (key), ``semantic`` / ``semantics``, ``count``
(= sessions), ``kinds``, ``families``, ``first_seen`` / ``last_seen`` and ``samples`` (≤ 20
``{kind, record_index, field, family, artifact_type, time}`` pointing at the session rows -- and for
``ai_projects`` also file-touch rows -- spread round-robin over the families) plus the table's own
fields listed above.

Counting rules: ``turns`` is the session row's own ``turns`` when the tool records it, else the
number of ``role = user`` message rows read for that session (capped sessions under-count -- the
row carries ``messages_capped_sessions``). ``tool_calls`` / ``messages`` / ``file_touches`` /
``tokens_*`` are the session row's own counters (they count past the row caps). A session without
a start time is counted under day ``""`` (날짜 미상); one without ``cwd`` and ``project_label`` is in
no project (``sessions_without_project`` in the summary).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..triage_rules.base import parse_time

__all__ = [
    "AI_TABLES",
    "AI_TABLE_LABELS",
    "FILE_TOUCH_FAMILY",
    "SESSION_FAMILY",
    "AiTablesCollector",
    "project_key",
]

AI_TABLES: tuple[str, ...] = ("ai_usage", "ai_projects")
AI_TABLE_LABELS: dict[str, str] = {"ai_usage": "AI 사용량(도구·계정·일)", "ai_projects": "AI 프로젝트"}
SESSION_TYPE = "ai-agent-session"
MESSAGE_TYPE = "ai-agent-message"
FILE_TOUCH_TYPE = "ai-agent-file-touch"
# Catalogue family ids (core/triage_rules/catalog/ai.yaml) of the rows the samples point at.
SESSION_FAMILY = "ai-session"
FILE_TOUCH_FAMILY = "ai-file-touch"
MAX_SAMPLES = 20
MAX_LISTED = 10
UNKNOWN_ACCOUNT = "(계정 미상)"
UNKNOWN_DAY = "(날짜 미상)"


def _text(value: object) -> str:
    if value is None or isinstance(value, (Mapping, list, tuple, bool)):
        return ""
    return str(value).strip()


def _int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def project_key(cwd: str, label: str) -> tuple[str, str]:
    """``(key, display)`` of a session's project: the normalised ``cwd`` (``/`` separators, case-folded,
    no trailing separator), else ``label:<project_label>``; ``("", "")`` when neither is known."""
    if cwd:
        normalized = cwd.replace("\\", "/").rstrip("/").casefold()
        if normalized:
            return normalized, cwd
    if label:
        return f"label:{label.casefold()}", label
    return "", ""


@dataclass
class _Session:
    tool: str
    tool_label: str
    account: str
    day: str
    project: str
    project_display: str
    cwd: str
    label: str
    record_index: int
    kind: str
    started: dt.datetime | None
    ended: dt.datetime | None
    turns: int | None
    messages: int
    tool_calls: int
    file_touches: int
    tokens_in: int
    tokens_out: int
    model: str
    subagent: bool
    messages_capped: bool


@dataclass
class _Sample:
    kind: str
    record_index: int
    field: str
    family: str
    artifact_type: str
    time: str | None


@dataclass
class _Group:
    key: str
    value: str
    count: int = 0
    first: dt.datetime | None = None
    last: dt.datetime | None = None
    kinds: dict[str, int] = field(default_factory=dict)
    families: dict[str, int] = field(default_factory=dict)
    samples: dict[str, list[_Sample]] = field(default_factory=dict)
    extra: dict[str, object] = field(default_factory=dict)

    def see(self, moment: dt.datetime | None) -> None:
        if moment is None:
            return
        if self.first is None or moment < self.first:
            self.first = moment
        if self.last is None or moment > self.last:
            self.last = moment

    def sample(self, sample: _Sample) -> None:
        self.kinds[sample.kind] = self.kinds.get(sample.kind, 0) + 1
        self.families[sample.family] = self.families.get(sample.family, 0) + 1
        bucket = self.samples.setdefault(sample.family, [])
        if len(bucket) < MAX_SAMPLES:
            bucket.append(sample)

    def row(self, semantic: str) -> dict[str, object]:
        queues = [list(items) for items in self.samples.values()]
        picked: list[dict[str, object]] = []
        position = 0
        while len(picked) < MAX_SAMPLES and any(queues):
            queue = queues[position % len(queues)]
            if queue:
                item = queue.pop(0)
                picked.append(
                    {
                        "kind": item.kind,
                        "record_index": item.record_index,
                        "field": item.field,
                        "family": item.family,
                        "artifact_type": item.artifact_type,
                        "time": item.time,
                    }
                )
            position += 1
        return {
            "value": self.value,
            "normalized": self.key,
            "semantic": semantic,
            "semantics": {semantic: self.count},
            "count": self.count,
            "kinds": dict(sorted(self.kinds.items(), key=lambda item: (-item[1], item[0]))),
            "families": dict(sorted(self.families.items(), key=lambda item: (-item[1], item[0]))),
            "first_seen": self.first.isoformat() if self.first else None,
            "last_seen": self.last.isoformat() if self.last else None,
            "samples": picked,
            **self.extra,
        }


class AiTablesCollector:
    """Gathers the ai-agent rows of one derived pass (:meth:`observe`), then builds both tables."""

    def __init__(self) -> None:
        self.sessions: dict[tuple[str, str], _Session] = {}
        self.anonymous_sessions: list[_Session] = []
        self.user_messages: dict[tuple[str, str], int] = {}
        self.touches: dict[tuple[str, str], list[_Sample]] = {}
        self.touch_counts: dict[tuple[str, str], int] = {}
        self.occurrences: dict[str, int] = {table: 0 for table in AI_TABLES}
        self._built: dict[str, list[dict[str, object]]] | None = None
        self.sessions_without_project = 0

    def observe(self, details: Mapping[str, object], *, kind: str, record_index: int, artifact_type: str) -> None:
        """One artifact row of the pass (rows of other types are ignored)."""
        if artifact_type == SESSION_TYPE:
            self._session(details, kind=kind, record_index=record_index)
        elif artifact_type == MESSAGE_TYPE:
            if _text(details.get("role")).lower() == "user":
                key = (_text(details.get("tool")), _text(details.get("session_id")))
                self.user_messages[key] = self.user_messages.get(key, 0) + 1
        elif artifact_type == FILE_TOUCH_TYPE:
            key = (_text(details.get("tool")), _text(details.get("session_id")))
            self.touch_counts[key] = self.touch_counts.get(key, 0) + 1
            bucket = self.touches.setdefault(key, [])
            if len(bucket) < MAX_SAMPLES:
                moment = parse_time(details.get("timestamp") or details.get("ts"))
                bucket.append(_Sample(kind, record_index, "touched_path", FILE_TOUCH_FAMILY, artifact_type, moment.isoformat() if moment else None))

    def _session(self, details: Mapping[str, object], *, kind: str, record_index: int) -> None:
        tool = _text(details.get("tool"))
        session_id = _text(details.get("session_id"))
        started = parse_time(details.get("started_at") or details.get("timestamp"))
        ended = parse_time(details.get("ended_at")) or started
        cwd = _text(details.get("cwd"))
        label = _text(details.get("project_label"))
        project, display = project_key(cwd, label)
        account = _text(details.get("account_key")) or _text(details.get("tool_account_key")) or _text(details.get("user"))
        session = _Session(
            tool=tool,
            tool_label=_text(details.get("tool_label")) or tool,
            account=account,
            day=started.date().isoformat() if started else "",
            project=project,
            project_display=display,
            cwd=cwd,
            label=label,
            record_index=record_index,
            kind=kind,
            started=started,
            ended=ended,
            turns=_int(details.get("turns")),
            messages=_int(details.get("messages")) or 0,
            tool_calls=_int(details.get("tool_calls")) or 0,
            file_touches=_int(details.get("file_touches")) or 0,
            tokens_in=_int(details.get("tokens_in")) or 0,
            tokens_out=_int(details.get("tokens_out")) or 0,
            model=_text(details.get("model")),
            subagent=bool(_text(details.get("parent_session_id"))),
            messages_capped=details.get("messages_capped") is True,
        )
        if session_id and (tool, session_id) not in self.sessions:
            self.sessions[(tool, session_id)] = session
        else:
            self.anonymous_sessions.append(session)

    def _all_sessions(self) -> list[tuple[tuple[str, str] | None, _Session]]:
        return [*self.sessions.items(), *((None, session) for session in self.anonymous_sessions)]

    def _turns(self, key: tuple[str, str] | None, session: _Session) -> int:
        if session.turns is not None:
            return session.turns
        return self.user_messages.get(key, 0) if key is not None else 0

    def build(self) -> dict[str, list[dict[str, object]]]:
        if self._built is not None:
            return self._built
        usage: dict[str, _Group] = {}
        projects: dict[str, _Group] = {}
        self.sessions_without_project = 0
        for key, session in sorted(self._all_sessions(), key=lambda item: (item[1].kind, item[1].record_index)):
            moment = session.started.isoformat() if session.started else None
            sample = _Sample(session.kind, session.record_index, "session_id", SESSION_FAMILY, SESSION_TYPE, moment)
            usage_key = "|".join((session.tool, session.account.casefold(), session.day))
            group = usage.get(usage_key)
            if group is None:
                value = " · ".join((session.tool_label or session.tool or "?", session.account or UNKNOWN_ACCOUNT, session.day or UNKNOWN_DAY))
                group = usage[usage_key] = _Group(
                    usage_key,
                    value,
                    extra={
                        "tool": session.tool,
                        "tool_label": session.tool_label,
                        "account": session.account,
                        "day": session.day,
                        "sessions": 0,
                        "subagent_sessions": 0,
                        "turns": 0,
                        "messages": 0,
                        "tool_calls": 0,
                        "tokens_in": 0,
                        "tokens_out": 0,
                        "projects": 0,
                        "project_list": [],
                        "models": [],
                        "messages_capped_sessions": 0,
                        "_projects": set(),
                    },
                )
            self._add(group, session, sample, self._turns(key, session))
            if session.project:
                group.extra["_projects"].add(session.project)  # type: ignore[union-attr]
                names = group.extra["project_list"]
                if session.project_display not in names and len(names) < MAX_LISTED:  # type: ignore[operator, arg-type]
                    names.append(session.project_display)  # type: ignore[union-attr]
            if not session.project:
                self.sessions_without_project += 1
                continue
            project = projects.get(session.project)
            if project is None:
                project = projects[session.project] = _Group(
                    session.project,
                    session.project_display,
                    extra={
                        "project": session.project_display,
                        "cwd": session.cwd,
                        "project_label": session.label,
                        "sessions": 0,
                        "subagent_sessions": 0,
                        "turns": 0,
                        "messages": 0,
                        "tool_calls": 0,
                        "tokens_in": 0,
                        "tokens_out": 0,
                        "file_touches": 0,
                        "file_touch_rows": 0,
                        "tools": {},
                        "accounts": [],
                        "models": [],
                        "messages_capped_sessions": 0,
                        "first_activity": None,
                        "last_activity": None,
                    },
                )
            self._add(project, session, sample, self._turns(key, session))
            extra = project.extra
            if not extra["cwd"] and session.cwd:
                extra["cwd"] = session.cwd
            if not extra["project_label"] and session.label:
                extra["project_label"] = session.label
            tools = extra["tools"]
            tools[session.tool] = tools.get(session.tool, 0) + 1  # type: ignore[union-attr, index]
            accounts = extra["accounts"]
            if session.account and session.account not in accounts and len(accounts) < MAX_LISTED:  # type: ignore[operator, arg-type]
                accounts.append(session.account)  # type: ignore[union-attr]
            extra["file_touches"] = int(extra["file_touches"]) + session.file_touches  # type: ignore[call-overload]
            if key is not None:
                extra["file_touch_rows"] = int(extra["file_touch_rows"]) + self.touch_counts.get(key, 0)  # type: ignore[call-overload]
                for touch in self.touches.get(key, ()):
                    project.sample(touch)
        usage_rows = []
        for group in usage.values():
            group.extra["projects"] = len(group.extra.pop("_projects"))  # type: ignore[arg-type]
            usage_rows.append(group.row("ai_usage"))
        project_rows = []
        for group in projects.values():
            group.extra["first_activity"] = group.first.isoformat() if group.first else None
            group.extra["last_activity"] = group.last.isoformat() if group.last else None
            group.extra["tools"] = dict(sorted(group.extra["tools"].items(), key=lambda item: (-item[1], item[0])))  # type: ignore[union-attr]
            project_rows.append(group.row("ai_project"))
        usage_rows.sort(key=lambda row: (-int(row["count"]), str(row["normalized"])))  # type: ignore[call-overload]
        project_rows.sort(key=lambda row: (-int(row["count"]), str(row["normalized"])))  # type: ignore[call-overload]
        self.occurrences = {"ai_usage": sum(int(row["count"]) for row in usage_rows), "ai_projects": sum(int(row["count"]) for row in project_rows)}  # type: ignore[call-overload]
        self._built = {"ai_usage": usage_rows, "ai_projects": project_rows}
        return self._built

    @staticmethod
    def _add(group: _Group, session: _Session, sample: _Sample, turns: int) -> None:
        group.count += 1
        group.see(session.started)
        group.see(session.ended)
        group.sample(sample)
        extra = group.extra
        extra["sessions"] = int(extra["sessions"]) + 1  # type: ignore[call-overload]
        extra["subagent_sessions"] = int(extra["subagent_sessions"]) + int(session.subagent)  # type: ignore[call-overload]
        extra["turns"] = int(extra["turns"]) + turns  # type: ignore[call-overload]
        extra["messages"] = int(extra["messages"]) + session.messages  # type: ignore[call-overload]
        extra["tool_calls"] = int(extra["tool_calls"]) + session.tool_calls  # type: ignore[call-overload]
        extra["tokens_in"] = int(extra["tokens_in"]) + session.tokens_in  # type: ignore[call-overload]
        extra["tokens_out"] = int(extra["tokens_out"]) + session.tokens_out  # type: ignore[call-overload]
        extra["messages_capped_sessions"] = int(extra["messages_capped_sessions"]) + int(session.messages_capped)  # type: ignore[call-overload]
        models = extra["models"]
        if session.model and session.model not in models and len(models) < MAX_LISTED:  # type: ignore[operator, arg-type]
            models.append(session.model)  # type: ignore[union-attr]

    def rows(self, table: str) -> list[dict[str, object]]:
        return list(self.build().get(table, []))
