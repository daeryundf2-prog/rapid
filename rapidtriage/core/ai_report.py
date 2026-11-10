"""보고서 절 "AI 사용" (R7 stage 3.5 §3.4, lane C).

:func:`ai_usage_summary` reads a finished run's ``ai-agent`` output (read only) and
:func:`ai_usage_section_lines` renders the case-report section (Markdown): tools, accounts, period,
sessions, top projects, top called tools, AI code share, and the **gap table** -- for every catalog
tool category, whether this run found local evidence and which server-side records would be needed
("로컬 증거 없음 ≠ 미사용"). Collection-scope and consent lines are placeholders for the examiner;
no legal wording is generated (legal review item, plan §3.4).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from .ai_catalog.catalog import load_catalog
from .ai_catalog.labels import CATEGORY_LABELS_KO

__all__ = [
    "AI_SECTION_HEADING",
    "AI_SECTION_ID",
    "SERVER_EVIDENCE_KO",
    "ai_usage_gaps",
    "ai_usage_section_lines",
    "ai_usage_summary",
    "server_evidence_list",
]

AI_SECTION_ID = "ai-usage"
AI_SECTION_HEADING = "## AI 사용"
AI_KIND = "ai-agent"
CATEGORY_ORDER = ("chatbot", "cli_agent", "ide_agent", "cloud_agent", "harness", "local_llm")
# Server-side records an examiner would request per tool category (no legal wording).
SERVER_EVIDENCE_KO: dict[str, str] = {
    "chatbot": "벤더 계정 데이터 내보내기(대화 기록), 조직 관리자 감사 로그(팀·기업 플랜), OAuth·SSO 승인 기록",
    "cli_agent": "벤더 API·콘솔 사용 기록(키·계정별 사용량), 조직 관리자 감사 로그·내보내기, OAuth 승인 기록",
    "ide_agent": "벤더 계정·팀 대시보드 사용 기록, 조직 관리자 내보내기, 확장·편집기 OAuth 승인 기록",
    "cloud_agent": "벤더 작업(태스크) 로그·감사 로그, 저장소 연동(GitHub 앱 등) 승인 기록, 조직 관리자 내보내기",
    "harness": "하니스가 호출한 기반 도구(CLI·IDE 에이전트)의 서버 측 기록 — 하니스 자체 서버 기록은 대개 없음",
    "local_llm": "서버 측 대화 기록 없음(로컬 실행) — 모델 내려받기 계정 기록(Hugging Face·Ollama 등)만 해당",
}
EVIDENCE_LABELS_KO: dict[str, str] = {
    "session": "세션",
    "install": "설치",
    "execution": "실행 흔적",
    "path": "경로",
    "credential": "자격 증명 파일",
    "account": "계정",
    "code": "코드 기여",
    "mcp": "MCP",
    "usage": "사용량",
}
_INSTALL_KINDS = frozenset({"npm-global", "pip", "winget", "msix", "vscode-extension"})
_SUMMARY_PRESENCE = frozenset({"adapter-summary", "git-repo-scan"})
TOP = 5


def _details(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    return details if isinstance(details, Mapping) else {}


def _int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except ValueError:
        return None


def _evidence_kind(artifact_type: str, details: Mapping[str, object]) -> str:
    if artifact_type in ("ai-agent-session", "ai-agent-message", "ai-agent-tool-call", "ai-agent-file-touch"):
        return "session"
    if artifact_type == "ai-credential-presence":
        return "credential"
    if artifact_type in ("ai-account", "ai-account-switch"):
        return "account"
    if artifact_type == "ai-code-attribution":
        return "code"
    if artifact_type == "ai-mcp-server":
        return "mcp"
    if artifact_type == "ai-usage-stat":
        return "usage"
    if artifact_type == "ai-tool-presence":
        if str(details.get("presence_kind") or "") in _SUMMARY_PRESENCE:
            return ""
        install = str(details.get("install_kind") or "")
        if install == "execution":
            return "execution"
        if install in _INSTALL_KINDS:
            return "install"
        return "path"
    return ""


def _payload(output_dir: Path) -> tuple[Mapping[str, object] | None, Path]:
    path = Path(output_dir) / "artifacts" / f"rapidtriage-artifacts-{AI_KIND}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, path
    return (payload if isinstance(payload, Mapping) else None), path


def ai_usage_summary(output_dir: Path | str | None) -> dict[str, object]:
    """Counts of a run's ``ai-agent`` output (``collected = False`` when the kind did not run)."""
    summary: dict[str, object] = {"collected": False, "rows": 0}
    if not output_dir:
        return summary
    payload, path = _payload(Path(output_dir))
    if payload is None:
        return summary
    from .artifact_profiles import iter_payload_records

    catalog = load_catalog()
    tools: dict[str, dict[str, object]] = {}
    accounts: set[tuple[str, str]] = set()
    projects: Counter[str] = Counter()
    project_names: dict[str, str] = {}
    called: Counter[str] = Counter()
    sessions = subagents = tool_calls = destructive = credentials = 0
    first = last = ""
    ai_lines = human_lines = 0
    scored_rows = 0
    trailer_commits = commits_read = repos = 0
    retention_markers = 0
    rows = 0
    read_error = ""

    def records():
        nonlocal read_error
        try:
            yield from iter_payload_records(payload, payload_path=path)
        except (OSError, ValueError) as exc:  # a truncated stream: count what was read
            read_error = f"{type(exc).__name__}: {exc}"[:200]

    for row in records():
        rows += 1
        details = _details(row)
        artifact_type = str(row.get("artifact_type") or "")
        tool_id = str(details.get("tool") or "")
        kind = _evidence_kind(artifact_type, details)
        if kind and tool_id:
            entry = tools.setdefault(tool_id, {"label": str(details.get("tool_label") or tool_id), "evidence": set()})
            entry["evidence"].add(kind)  # type: ignore[union-attr]
        if artifact_type == "ai-agent-session":
            sessions += 1
            if str(details.get("parent_session_id") or ""):
                subagents += 1
            for stamp in (str(details.get("started_at") or details.get("timestamp") or ""), str(details.get("ended_at") or "")):
                if len(stamp) >= 10:
                    first = stamp if not first or stamp < first else first
                    last = stamp if not last or stamp > last else last
            cwd = str(details.get("cwd") or "") or str(details.get("project_label") or "")
            if cwd:
                key = cwd.replace("\\", "/").rstrip("/").casefold()
                projects[key] += 1
                project_names.setdefault(key, cwd)
        elif artifact_type == "ai-agent-tool-call":
            tool_calls += 1
            name = str(details.get("tool_name") or "").casefold()
            if name:
                called[name] += 1
            if details.get("destructive") is True:
                destructive += 1
        elif artifact_type == "ai-account":
            key = str(details.get("tool_account_key") or details.get("account_number") or details.get("email_local_hash") or "")
            accounts.add((tool_id, key))
        elif artifact_type == "ai-credential-presence":
            credentials += 1
        elif artifact_type == "ai-retention-cleanup":
            retention_markers += 1
        elif artifact_type == "ai-code-attribution":
            if details.get("source") == "git-trailer":
                trailer_commits += 1
            else:
                ai, human = _int(details.get("ai_lines")), _int(details.get("human_lines"))
                if ai is not None and human is not None and ai + human > 0:
                    ai_lines += ai
                    human_lines += human
                    scored_rows += 1
        elif artifact_type == "ai-tool-presence" and details.get("presence_kind") == "git-repo-scan":
            repos += 1
            commits_read += _int(details.get("commits_read")) or 0
    categories: dict[str, list[str]] = {category: [] for category in CATEGORY_ORDER}
    evidence_by_category: dict[str, set[str]] = {category: set() for category in CATEGORY_ORDER}
    for tool_id, entry in sorted(tools.items()):
        tool = catalog.tool(tool_id)
        category = tool.category if tool is not None else ""
        if category in categories:
            categories[category].append(str(entry["label"]))
            evidence_by_category[category].update(entry["evidence"])  # type: ignore[arg-type]
    options = payload.get("collector_options") if isinstance(payload.get("collector_options"), Mapping) else {}
    summary.update(
        {
            "collected": True,
            "rows": rows,
            "read_error": read_error,
            "tools": {tool_id: {"label": entry["label"], "evidence": sorted(entry["evidence"])} for tool_id, entry in sorted(tools.items())},  # type: ignore[arg-type]
            "accounts": len(accounts),
            "sessions": sessions,
            "subagent_sessions": subagents,
            "first_activity": first,
            "last_activity": last,
            "top_projects": [{"project": project_names[key], "sessions": count} for key, count in projects.most_common(TOP)],
            "tool_calls": tool_calls,
            "destructive_tool_calls": destructive,
            "top_called_tools": [{"tool_name": name, "calls": count} for name, count in called.most_common(TOP)],
            "credential_files": credentials,
            "retention_markers": retention_markers,
            "code": {
                "scored_rows": scored_rows,
                "ai_lines": ai_lines,
                "human_lines": human_lines,
                "ai_percent": round(100.0 * ai_lines / (ai_lines + human_lines), 1) if ai_lines + human_lines else None,
                "git_repositories": repos,
                "git_commits_read": commits_read,
                "git_ai_trailer_commits": trailer_commits,
                "git_ai_commit_percent": round(100.0 * trailer_commits / commits_read, 1) if commits_read else None,
            },
            "categories": {
                category: {"tools": sorted(names), "evidence": sorted(evidence_by_category[category])} for category, names in categories.items()
            },
            "options": {"ai_bodies": options.get("ai_bodies"), "ai_hash_dbs": options.get("ai_hash_dbs")},
        }
    )
    return summary


def _cell(text: str) -> str:
    return text.replace("|", "/").replace("\n", " ")


def ai_usage_section_lines(summary: Mapping[str, object], *, metadata: Mapping[str, object] | None = None) -> list[str]:
    """Markdown lines of the "AI 사용" section (heading :data:`AI_SECTION_HEADING`)."""
    metadata = metadata or {}
    lines = [AI_SECTION_HEADING, ""]
    if not summary.get("collected"):
        lines.extend(
            [
                "- 이 런에는 AI 사용 기록 종류(ai-agent)가 포함되지 않았거나 그 산출물을 읽을 수 없음. 아래 갭 표는 모든 분류를 '로컬 증거 없음'으로 표시함.",
                "",
            ]
        )
    else:
        tools = summary.get("tools") if isinstance(summary.get("tools"), Mapping) else {}
        tool_text = ", ".join(
            f"{entry.get('label')}({'·'.join(EVIDENCE_LABELS_KO.get(item, item) for item in entry.get('evidence') or [])})"
            for entry in tools.values()  # type: ignore[union-attr]
            if isinstance(entry, Mapping)
        )
        code = summary.get("code") if isinstance(summary.get("code"), Mapping) else {}
        period = (
            f"`{summary.get('first_activity')}` ~ `{summary.get('last_activity')}` (UTC)"
            if summary.get("first_activity")
            else "세션 시각 없음"
        )
        lines.extend(
            [
                f"- 확인된 AI 도구: {len(tools)}개 — {tool_text or '없음'}",  # type: ignore[arg-type]
                f"- 계정: {summary.get('accounts', 0)}개 (도구별 계정 기록 기준, 이메일은 도메인·해시만)",
                f"- 기간(세션 시작~마지막 활동): {period}",
                f"- 세션: {summary.get('sessions', 0)}건 (하위 에이전트 세션 {summary.get('subagent_sessions', 0)}건)",
                f"- 도구 호출: {summary.get('tool_calls', 0)}건 (파괴적 표시 {summary.get('destructive_tool_calls', 0)}건)",
                f"- 자격 증명 파일 존재: {summary.get('credential_files', 0)}건 (값은 수집하지 않음)",
                f"- 보존 정리 표식: {summary.get('retention_markers', 0)}건 — 정리 이전 기록은 남아 있지 않을 수 있음",
                "",
            ]
        )
        if summary.get("read_error"):
            lines.extend([f"- 주의: AI 기록 산출물을 끝까지 읽지 못함({summary.get('read_error')}) — 위 수치는 읽은 행까지", ""])
        lines.extend(["### 주요 프로젝트", ""])
        projects = [item for item in summary.get("top_projects") or [] if isinstance(item, Mapping)]  # type: ignore[union-attr]
        lines.extend([f"- `{item.get('project')}`: 세션 {item.get('sessions')}건" for item in projects] or ["- 작업 폴더가 기록된 세션 없음"])
        lines.extend(["", "### 도구 호출 상위", ""])
        called = [item for item in summary.get("top_called_tools") or [] if isinstance(item, Mapping)]  # type: ignore[union-attr]
        lines.extend([f"- `{item.get('tool_name')}`: {item.get('calls')}건" for item in called] or ["- 도구 호출 기록 없음"])
        lines.extend(["", "### AI 생성 코드 비율", ""])
        if code.get("ai_percent") is not None:  # type: ignore[union-attr]
            lines.append(
                f"- 편집기 기록(Cursor 점수 커밋 등) {code.get('scored_rows')}건: AI {code.get('ai_lines')}줄 / 사람 {code.get('human_lines')}줄"  # type: ignore[union-attr]
                f" → AI {code.get('ai_percent')}%"  # type: ignore[union-attr]
            )
        else:
            lines.append("- 편집기 AI 라인 기록 없음")
        if code.get("git_repositories"):  # type: ignore[union-attr]
            lines.append(
                f"- git 트레일러: 저장소 {code.get('git_repositories')}개에서 읽은 커밋 {code.get('git_commits_read')}건 중 "  # type: ignore[union-attr]
                f"AI 트레일러 커밋 {code.get('git_ai_trailer_commits')}건({code.get('git_ai_commit_percent')}%) — 트레일러 없는 AI 사용은 셀 수 없음"  # type: ignore[union-attr]
            )
        else:
            lines.append("- git 저장소 없음(파일 목록 기준)")
        lines.append("")
    lines.extend(
        [
            "### 서버 측 증거 갭",
            "",
            "로컬 증거가 없다는 것은 사용하지 않았다는 뜻이 아님(부재 ≠ 미사용). 분류별로 필요한 서버 측 기록:",
            "",
            "| 도구 분류 | 로컬 증거 | 확인된 도구 | 필요한 서버 측 증거 |",
            "| --- | --- | --- | --- |",
        ]
    )
    categories = summary.get("categories") if isinstance(summary.get("categories"), Mapping) else {}
    for category in CATEGORY_ORDER:
        entry = categories.get(category) if isinstance(categories.get(category), Mapping) else {}  # type: ignore[union-attr]
        names = [str(name) for name in entry.get("tools") or []]  # type: ignore[union-attr]
        evidence = [EVIDENCE_LABELS_KO.get(str(item), str(item)) for item in entry.get("evidence") or []]  # type: ignore[union-attr]
        local = f"있음({'·'.join(evidence)})" if names else "없음"
        lines.append(
            f"| {CATEGORY_LABELS_KO.get(category, category)} | {_cell(local)} | {_cell(', '.join(names) or '—')} | {_cell(SERVER_EVIDENCE_KO[category])} |"
        )
    options = summary.get("options") if isinstance(summary.get("options"), Mapping) else {}
    bodies = options.get("ai_bodies")  # type: ignore[union-attr]
    scope = str(metadata.get("ai_collection_scope") or metadata.get("scope") or "").strip()
    lines.extend(
        [
            "",
            "### 수집 범위·동의",
            "",
            f"- 수집 범위: {scope or '미기재 (검사관 기재)'}",
            f"- AI 대화 본문 수집: {'메타만' if bodies is False else '포함(비밀값 가림)'}",
            f"- 동의·근거 문서: {str(metadata.get('ai_consent_basis') or '').strip() or '미기재 (검사관 기재 — 법률 검토 항목)'}",
            "",
        ]
    )
    return lines


def server_evidence_list(category: str) -> list[str]:
    """The server-side records of a category as a list (``SERVER_EVIDENCE_KO`` split on ``, ``)."""
    return [part.strip() for part in SERVER_EVIDENCE_KO.get(category, "").split(", ") if part.strip()]


def ai_usage_gaps(summary: Mapping[str, object]) -> dict[str, object]:
    """``GET /api/runs/{id}/ai-usage/gaps`` body: per detected tool whether the run holds local *content*
    evidence (session records — presence, installs or credentials alone are not) and which server-side
    records would show what it was used for, plus the per-category gap table of the report section."""
    catalog = load_catalog()
    tools_out: list[dict[str, object]] = []
    tools = summary.get("tools") if isinstance(summary.get("tools"), Mapping) else {}
    for tool_id, entry in tools.items():  # type: ignore[union-attr]
        if not isinstance(entry, Mapping):
            continue
        tool = catalog.tool(str(tool_id))
        category = tool.category if tool is not None else ""
        evidence = [str(item) for item in entry.get("evidence") or []]
        tools_out.append(
            {
                "tool": str(tool_id),
                "tool_label": str(entry.get("label") or tool_id),
                "category": category,
                "category_label": CATEGORY_LABELS_KO.get(category, category),
                "evidence": evidence,
                "evidence_labels": [EVIDENCE_LABELS_KO.get(item, item) for item in evidence],
                "local_evidence": "session" in evidence,
                "server_evidence_needed": server_evidence_list(category),
            }
        )
    categories = summary.get("categories") if isinstance(summary.get("categories"), Mapping) else {}
    category_rows: list[dict[str, object]] = []
    for category in CATEGORY_ORDER:
        entry = categories.get(category) if isinstance(categories.get(category), Mapping) else {}  # type: ignore[union-attr]
        names = [str(name) for name in entry.get("tools") or []]  # type: ignore[union-attr]
        category_rows.append(
            {
                "category": category,
                "category_label": CATEGORY_LABELS_KO.get(category, category),
                "local_evidence": bool(names),
                "tools": names,
                "evidence": [str(item) for item in entry.get("evidence") or []],  # type: ignore[union-attr]
                "server_evidence_needed": server_evidence_list(category),
            }
        )
    return {
        "collected": bool(summary.get("collected")),
        "tools": tools_out,
        "categories": category_rows,
        "note": "로컬 증거가 없다는 것은 사용하지 않았다는 뜻이 아님(부재 ≠ 미사용)",
    }
