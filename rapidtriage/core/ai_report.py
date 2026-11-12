"""보고서 절 "AI 사용" (R7 stage 3.5 §3.4, lane C).

:func:`ai_usage_summary` reads a finished run's ``ai-agent`` output (read only) and
:func:`ai_usage_section_lines` renders the case-report section (Markdown): tools, accounts, period,
sessions, top projects, top called tools, AI code share, and the **gap table** -- for every catalog
tool category, whether this run found local evidence and which server-side records would be needed
("로컬 증거 없음 ≠ 미사용"). Collection-scope and consent lines are placeholders for the examiner;
no legal wording is generated (legal review item, plan §3.4).

Honesty (R8 T-189): browser AI-service visits (``browser-ai-usage`` rows of the browser kinds) count as
local chatbot evidence ("방문 기록"); the read-budget skipped files (the ``rapidtriage-ai-agent-skipped.json``
sidecar), per-session message/tool-call caps and cut messages are stated on a "수집 한계" line; periods carry
the time zone their stamps actually hold; and a metadata-only run says what was still collected.
"""

from __future__ import annotations

import json
import re
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
    "visit": "방문 기록",
}
# Browser kinds whose rows of the given type summarize AI-service visits from browser history.
BROWSER_AI_SOURCES: tuple[tuple[str, str], ...] = (("browser", "browser-ai-usage"), ("macos-system", "macos-browser-ai-usage"))
# Written by the ai-agent provider next to its payload when the read budget left files unread.
AI_SKIPPED_SIDECAR = "rapidtriage-ai-agent-skipped.json"
BODIES_EXCLUDED_KO = "본문 제외(명령·제목·지침 머리는 수집됨)"
_OFFSET = re.compile(r"([+-])(\d{2}):?(\d{2})$")
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


def _zone(stamp: str) -> str:
    """The time zone an ISO stamp states: ``UTC``, ``UTC+09:00`` or ``""`` (no zone written)."""
    text = stamp.strip()
    if len(text) < 11:
        return ""
    if text.endswith(("Z", "z")):
        return "UTC"
    match = _OFFSET.search(text[10:])
    if match is None:
        return ""
    sign, hours, minutes = match.groups()
    return "UTC" if hours == minutes == "00" else f"UTC{sign}{hours}:{minutes}"


def period_text(first: str, last: str) -> str:
    """```first` ~ `last` (시간대: …)`` naming the zone(s) the two stamps hold -- never assumed."""
    zones = sorted({_zone(first) or "표기 없음", _zone(last) or "표기 없음"})
    return f"`{first}` ~ `{last}` (시간대: {' / '.join(zones)})"


def _browser_ai_visits(output_dir: Path) -> dict[str, object]:
    """AI-service visits recorded in browser history (``browser-ai-usage`` rows), read only."""
    from .artifact_profiles import iter_payload_records

    profiles = urls = visits = 0
    services: Counter[str] = Counter()
    first = last = ""
    for kind, artifact_type in BROWSER_AI_SOURCES:
        payload, path = _payload(output_dir, kind)
        if payload is None:
            continue
        try:
            for row in iter_payload_records(payload, payload_path=path):
                if str(row.get("artifact_type") or "") != artifact_type:
                    continue
                details = _details(row)
                profiles += 1
                for item in details.get("ai_usage") or []:  # type: ignore[union-attr]
                    if not isinstance(item, Mapping):
                        continue
                    urls += 1
                    visits += max(1, _int(item.get("visit_count")) or 0)
                    service = str(item.get("ai_service") or "").strip()
                    if service:
                        services[service] += 1
                    stamp = str(item.get("last_visited_at") or "")
                    if len(stamp) >= 10:
                        first = stamp if not first or stamp < first else first
                        last = stamp if not last or stamp > last else last
        except (OSError, ValueError):  # a truncated stream: count what was read
            continue
    return {
        "profiles": profiles,
        "urls": urls,
        "visits": visits,
        "services": dict(sorted(services.items())),
        "first_visit": first,
        "last_visit": last,
    }


def _skipped_sidecar(output_dir: Path) -> int | None:
    """Files left unread for the read budget per the sidecar (``None`` = no readable sidecar)."""
    try:
        payload = json.loads((Path(output_dir) / "artifacts" / AI_SKIPPED_SIDECAR).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, Mapping):
        return None
    count = _int(payload.get("skipped_count"))
    if count is None:
        entries = payload.get("entries")
        count = len(entries) if isinstance(entries, list) else None
    return count


def _payload(output_dir: Path, kind: str = AI_KIND) -> tuple[Mapping[str, object] | None, Path]:
    path = Path(output_dir) / "artifacts" / f"rapidtriage-artifacts-{kind}.json"
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
    browser = _browser_ai_visits(Path(output_dir))
    summary["browser_ai"] = browser
    summary["categories"] = _categories({}, {}, browser)
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
    capped_sessions = tool_capped_sessions = messages_cut = truncated_rows = 0
    commands = titles = instruction_heads = 0
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
        if details.get("truncated") is True:
            truncated_rows += 1
        if artifact_type == "ai-agent-session":
            sessions += 1
            capped_sessions += details.get("messages_capped") is True
            tool_capped_sessions += details.get("tool_calls_capped") is True
            messages_cut += _int(details.get("messages_truncated")) or 0
            titles += bool(str(details.get("title") or "").strip())
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
            commands += bool(str(details.get("command") or "").strip())
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
        elif artifact_type == "ai-instruction-file":
            instruction_heads += bool(str(details.get("head_text") or "").strip())
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
            "categories": _categories(categories, evidence_by_category, browser),
            "options": {"ai_bodies": options.get("ai_bodies"), "ai_hash_dbs": options.get("ai_hash_dbs")},
            "limits": {
                "skipped_files": _skipped_sidecar(Path(output_dir)),
                "messages_capped_sessions": capped_sessions,
                "tool_calls_capped_sessions": tool_capped_sessions,
                "messages_truncated": messages_cut,
                "truncated_rows": truncated_rows,
            },
            "metadata_collected": {"commands": commands, "titles": titles, "instruction_heads": instruction_heads},
        }
    )
    return summary


def _categories(
    names: Mapping[str, list[str]], evidence: Mapping[str, set[str]], browser: Mapping[str, object]
) -> dict[str, dict[str, object]]:
    """Per-category tools / evidence kinds; browser AI-service visits are chatbot evidence ("visit")."""
    out: dict[str, dict[str, object]] = {}
    for category in CATEGORY_ORDER:
        kinds = set(evidence.get(category) or ())
        visit_services: list[str] = []
        if category == "chatbot" and (_int(browser.get("urls")) or 0) > 0:
            kinds.add("visit")
            services = browser.get("services") if isinstance(browser.get("services"), Mapping) else {}
            visit_services = sorted(str(name) for name in services)  # type: ignore[union-attr]
        out[category] = {"tools": sorted(names.get(category) or []), "evidence": sorted(kinds), "visit_services": visit_services}
    return out


def _local_text(entry: Mapping[str, object]) -> str:
    evidence = [EVIDENCE_LABELS_KO.get(str(item), str(item)) for item in entry.get("evidence") or []]  # type: ignore[union-attr]
    return f"있음({'·'.join(evidence)})" if evidence else "없음"


def _limits_line(summary: Mapping[str, object]) -> str:
    limits = summary.get("limits") if isinstance(summary.get("limits"), Mapping) else {}
    skipped = limits.get("skipped_files")  # type: ignore[union-attr]
    parts: list[str] = []
    if isinstance(skipped, int) and skipped > 0:
        parts.append(f"읽기 예산으로 미수집 파일 {skipped}개(목록 {AI_SKIPPED_SIDECAR})")
    capped = _int(limits.get("messages_capped_sessions")) or 0  # type: ignore[union-attr]
    if capped:
        parts.append(f"메시지 상한에 걸린 세션 {capped}건(상한 이후 메시지는 행 없음)")
    tool_capped = _int(limits.get("tool_calls_capped_sessions")) or 0  # type: ignore[union-attr]
    if tool_capped:
        parts.append(f"도구 호출 상한에 걸린 세션 {tool_capped}건")
    cut = _int(limits.get("messages_truncated")) or 0  # type: ignore[union-attr]
    if cut:
        parts.append(f"길이 상한으로 잘린 메시지 {cut}건")
    rows = _int(limits.get("truncated_rows")) or 0  # type: ignore[union-attr]
    if rows:
        parts.append(f"절단 표시 행 {rows}건")
    if summary.get("read_error"):
        parts.append("산출물을 끝까지 읽지 못함")
    if not parts:
        return "- 수집 한계: 확인된 한계 없음(읽기 예산 미수집·메시지 상한·절단 기록 0건)"
    return f"- 수집 한계: {' · '.join(parts)} — 위 수치는 수집된 범위까지"


def _bodies_text(summary: Mapping[str, object]) -> str:
    options = summary.get("options") if isinstance(summary.get("options"), Mapping) else {}
    bodies = options.get("ai_bodies")  # type: ignore[union-attr]
    if bodies is False:
        meta = summary.get("metadata_collected") if isinstance(summary.get("metadata_collected"), Mapping) else {}
        counts = (
            f"명령 {_int(meta.get('commands')) or 0}건 · 제목 {_int(meta.get('titles')) or 0}건 · "  # type: ignore[union-attr]
            f"지침 머리 {_int(meta.get('instruction_heads')) or 0}건"  # type: ignore[union-attr]
        )
        return f"{BODIES_EXCLUDED_KO} — 이 런: {counts}"
    if bodies is True:
        return "포함(비밀값 가림, 긴 메시지는 잘림)"
    if not summary.get("collected"):
        return "해당 없음(AI 사용 기록 종류를 수집하지 않음)"
    return "실행 옵션 기록 없음 — 기본값은 포함(비밀값 가림, 긴 메시지는 잘림)"


def _entry(categories: Mapping[str, object], category: str) -> Mapping[str, object]:
    entry = categories.get(category)
    return entry if isinstance(entry, Mapping) else {}


def _cell(text: str) -> str:
    return text.replace("|", "/").replace("\n", " ")


def ai_usage_section_lines(summary: Mapping[str, object], *, metadata: Mapping[str, object] | None = None) -> list[str]:
    """Markdown lines of the "AI 사용" section (heading :data:`AI_SECTION_HEADING`)."""
    metadata = metadata or {}
    lines = [AI_SECTION_HEADING, ""]
    browser = summary.get("browser_ai") if isinstance(summary.get("browser_ai"), Mapping) else {}
    browser_urls = _int(browser.get("urls")) or 0  # type: ignore[union-attr]
    if not summary.get("collected"):
        lines.append(
            "- 이 런에는 AI 사용 기록 종류(ai-agent)가 포함되지 않았거나 그 산출물을 읽을 수 없음 — 도구 설치·세션 기록은 확인하지 않음."
            + ("" if browser_urls else " 아래 갭 표는 모든 분류를 '로컬 증거 없음'으로 표시함.")
        )
    if browser_urls:
        services = browser.get("services") if isinstance(browser.get("services"), Mapping) else {}  # type: ignore[union-attr]
        service_text = ", ".join(f"{name} {count}건" for name, count in services.items())  # type: ignore[union-attr]
        first, last = str(browser.get("first_visit") or ""), str(browser.get("last_visit") or "")  # type: ignore[union-attr]
        lines.append(
            f"- 브라우저 AI 서비스 방문: 프로필 {browser.get('profiles')}개, 주소 {browser_urls}건(방문 {browser.get('visits')}회)"  # type: ignore[union-attr]
            f" — {service_text or '서비스 미상'}; 마지막 방문 시각 범위 {period_text(first, last) if first else '시각 없음'}"
            " — 방문 기록만으로는 대화 내용·입력값을 알 수 없음"
        )
    if not summary.get("collected"):
        lines.append("")
    else:
        tools = summary.get("tools") if isinstance(summary.get("tools"), Mapping) else {}
        tool_text = ", ".join(
            f"{entry.get('label')}({'·'.join(EVIDENCE_LABELS_KO.get(item, item) for item in entry.get('evidence') or [])})"
            for entry in tools.values()  # type: ignore[union-attr]
            if isinstance(entry, Mapping)
        )
        code = summary.get("code") if isinstance(summary.get("code"), Mapping) else {}
        period = (
            period_text(str(summary.get("first_activity")), str(summary.get("last_activity") or ""))
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
                _limits_line(summary),
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
    categories = summary.get("categories") if isinstance(summary.get("categories"), Mapping) else {}
    lines.extend(
        [
            "### 서버 측 증거 갭",
            "",
            "로컬 증거가 없다는 것은 사용하지 않았다는 뜻이 아님(부재 ≠ 미사용). 분류별로 필요한 서버 측 기록:",
            "",
            "- 분류별 로컬 증거: "
            + ", ".join(
                f"{CATEGORY_LABELS_KO.get(category, category)}: {_local_text(_entry(categories, category))}"  # type: ignore[arg-type]
                for category in CATEGORY_ORDER
            ),
            "",
            "| 도구 분류 | 로컬 증거 | 확인된 도구 | 필요한 서버 측 증거 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for category in CATEGORY_ORDER:
        entry = _entry(categories, category)  # type: ignore[arg-type]
        names = [str(name) for name in entry.get("tools") or []]  # type: ignore[union-attr]
        names += [f"{name}(브라우저 방문)" for name in entry.get("visit_services") or []]  # type: ignore[union-attr]
        lines.append(
            f"| {CATEGORY_LABELS_KO.get(category, category)} | {_cell(_local_text(entry))} | {_cell(', '.join(names) or '—')} | {_cell(SERVER_EVIDENCE_KO[category])} |"
        )
    scope = str(metadata.get("ai_collection_scope") or metadata.get("scope") or "").strip()
    lines.extend(
        [
            "",
            "### 수집 범위·동의",
            "",
            f"- 수집 범위: {scope or '미기재 (검사관 기재)'}",
            f"- AI 대화 본문 수집: {_bodies_text(summary)}",
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
        evidence = [str(item) for item in entry.get("evidence") or []]  # type: ignore[union-attr]
        category_rows.append(
            {
                "category": category,
                "category_label": CATEGORY_LABELS_KO.get(category, category),
                "local_evidence": bool(names) or bool(evidence),
                "tools": names,
                "visit_services": [str(name) for name in entry.get("visit_services") or []],  # type: ignore[union-attr]
                "evidence": evidence,
                "server_evidence_needed": server_evidence_list(category),
            }
        )
    return {
        "collected": bool(summary.get("collected")),
        "tools": tools_out,
        "categories": category_rows,
        "note": "로컬 증거가 없다는 것은 사용하지 않았다는 뜻이 아님(부재 ≠ 미사용)",
    }
