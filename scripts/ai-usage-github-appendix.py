#!/usr/bin/env python3
"""Build the GitHub appendix of docs/ai-usage-coverage-matrix.md.

Two steps, so the slow GitHub search runs once and the list can be re-rendered:

    python scripts/ai-usage-github-appendix.py collect --out qc-runs/ai-usage-github
    python scripts/ai-usage-github-appendix.py render --out qc-runs/ai-usage-github \
        --survey-date 2026-11-28 --docs docs

``collect`` runs ``gh search repos`` (authenticated ``gh`` CLI required) for every
topic and keyword below with stars >= 500, splits a search that hits GitHub's
1,000-result cap into star ranges, drops forks, and adds the owner-named
repositories from ``ai-usage-github-matrix-links.json`` with ``gh repo view``.
It writes ``repos.json``.

``render`` applies the AI-relevance filter and the classification rules, writes
the full list (``ai-usage-github-full.json`` / ``.csv``, descriptions included)
to ``--out``, and with ``--docs`` writes the committed appendix: summary counts,
then per category only the repositories the matrix links to plus the non-X
repositories with at least ``--min-stars`` stars, without descriptions (they are
the repository owners' text). The full list stays out of Git.
"""

from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")

import argparse
import csv
import json
import re
import shutil
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LINKS_PATH = Path(__file__).with_name("ai-usage-github-matrix-links.json")
DOCS_INDEX_NAME = "ai-usage-coverage-github.md"
DOCS_DIR_NAME = "ai-usage-coverage-github"
SEARCH_FIELDS = "fullName,stargazersCount,description,isFork,isArchived,pushedAt,url"
SEARCH_LIMIT = 1000
MIN_STARS = 500
STAR_RANGES = (
    "500..599", "600..699", "700..849", "850..999", "1000..1249", "1250..1499",
    "1500..1999", "2000..2999", "3000..4999", "5000..9999", ">=10000",
)
TOPICS = (
    "agent-framework", "agentic-ai", "agents", "ai-agent", "ai-agents", "ai-assistant", "ai-chatbot", "ai-coding",
    "ai-tools", "anthropic", "autonomous-agents", "browser-automation", "browser-use", "chatbot", "chatgpt",
    "chatgpt-api", "claude", "claude-code", "codex", "coding-agent", "comfyui", "computer-use", "copilot", "cursor",
    "deepseek", "discord-bot", "gemini", "gemini-cli", "generative-ai", "gpt-4", "llama", "llamacpp", "llm",
    "llm-agent", "llm-inference", "llm-ui", "local-llm", "mcp", "mcp-server", "multi-agent", "ollama", "openai",
    "opencode", "personal-assistant", "qwen", "stable-diffusion", "telegram-bot", "text-to-speech", "vibe-coding",
    "voice-assistant", "workflow-automation",
)
KEYWORDS = (
    "agent", "ai assistant", "anthropic", "chatbot", "chatgpt", "claude", "codex", "coding assistant", "comfyui",
    "copilot", "cursor", "deepseek", "gemini", "gpt", "llm", "local llm", "mcp", "ollama", "openai", "qwen",
    "stable diffusion", "telegram bot", "text to speech", "whisper",
)
KEYWORD_TAG = "kw:"
NAMED_TAG = "named"

# A keyword search also returns repositories that are not about AI (mouse
# cursors, monitoring agents): keep one only with an AI topic or an AI term.
AI_TOPICS = {
    "ai-agent", "ai-agents", "coding-agent", "claude-code", "llm", "local-llm", "agent-framework", "mcp", "mcp-server",
    "chatgpt", "ai-assistant", "llm-agent", "multi-agent", "autonomous-agents", "ollama", "agentic-ai", "ai-coding",
    "vibe-coding", "gemini-cli", "llamacpp", "llama", "comfyui", "stable-diffusion", "computer-use", "browser-use",
    "ai-chatbot", "llm-ui", "openai", "anthropic", "claude", "gemini", "gpt-4", "chatgpt-api", "generative-ai",
    "deepseek", "qwen", "opencode", "llm-inference", "ai-tools",
}
AI_TERMS = re.compile(
    r"(\bai\b|\ba\.i\.|\bllms?\b|gpt|openai|claude|anthropic|gemini|\bmcp\b|model context protocol|ollama|llama|deepseek|"
    r"qwen|mistral|language model|stable.?diffusion|comfyui|\bwhisper\b|\btts\b|text.to.speech|speech.to.text|\brag\b|chatbot|"
    r"agentic|ai.agent|coding agent|kimi|grok|copilot|생성형|인공지능|大模型|智能体|人工智能)",
    re.IGNORECASE,
)
# X: probably not a tool someone installs (lists, courses, papers, examples, datasets).
EXCLUDE_TERMS = re.compile(
    r"(\bawesome\b|curated list|a list of|collection of|\btutorials?\b|\bcourses?\b|\bbooks?\b|handbook|\bguides?\b|"
    r"cookbook|roadmap|interview|\bpapers?\b|\bsurvey\b|learning resources|\bexamples?\b|\bdemos?\b|leaked|system prompts|"
    r"prompt engineering|\blessons?\b|for beginners|from scratch|\bcurso\b|\blearn\b|cheat ?sheet|\bbenchmarks?\b|\bdatasets?\b|study notes|学习|教程|面试|论文|资源|合集|精选|指南)",
    re.IGNORECASE,
)
# First match on "<repo name> <description>" wins.
NAME_RULES = (
    ("N", r"\bmcp\b|model context protocol"),
    ("H", r"telegram|discord|slack bot|wechat|whatsapp|qq ?bot|feishu|lark|dingtalk|line bot|kakao|messenger|微信|飞书"),
    ("G", r"orchestrat|multi-?agent|swarm|parallel (claude|agents|coding|sessions)|worktree|kanban|tmux|agent (hub|manager|multiplexer)|manage multiple|多智能体"),
    ("F", r"claude code (plugin|skill|hook|config|setup|framework|subagent|command|statusline|template|memory)|\bskills?\b|plugins? for (claude|codex|opencode|cursor)|subagents|slash commands|\bhooks?\b|\.claude|cursor rules|spec[- ]driven|memory (layer|plugin|for (claude|ai|agents))"),
    ("D", r"vs ?code|visual studio code|jetbrains|intellij|neovim|nvim|\bvim\b|emacs|\bide\b|editor|xcode"),
    ("E", r"coding agent|code agent|terminal|\bcli\b|command[- ]line|\bshell\b|software engineering agent|pair programm"),
    ("C", r"browser extension|chrome extension|firefox|userscript|browser agent|browser automation|browser-use|web agent|computer[- ]use|desktop automation|gui agent|浏览器"),
    ("L", r"stable diffusion|comfyui|text-to-image|image generation|video generation|text-to-speech|\btts\b|speech|voice|whisper|music|audio|avatar|diffusion|语音"),
    ("J", r"ollama|llama\.?cpp|gguf|local llm|run (llms|models) locally|locally|on-device|offline|inference|self-hosted|serving|webui|web ui|quantiz|本地"),
    ("B", r"chat client|desktop (app|client)|ai chat|chat ui|chatbot ui|electron|tauri|chat interface|assistant app|chatgpt (client|app)|聊天"),
    ("M", r"\bandroid\b|\bios\b|iphone|mobile app"),
    ("I", r"autonomous|cloud agent|background agent|research agent|deep research"),
)
TOPIC_RULES = (
    ({"mcp", "mcp-server", "kw:mcp"}, "N"),
    ({"ollama", "local-llm", "llamacpp", "llama", "llm-inference", "kw:ollama", "kw:local llm"}, "J"),
    ({"comfyui", "stable-diffusion", "text-to-speech", "voice-assistant", "kw:comfyui", "kw:stable diffusion", "kw:whisper", "kw:text to speech"}, "L"),
    ({"claude-code"}, "F"),
    ({"coding-agent", "codex", "gemini-cli", "opencode", "ai-coding", "vibe-coding", "kw:coding assistant"}, "E"),
    ({"chatbot", "chatgpt", "ai-chatbot", "llm-ui", "ai-assistant", "personal-assistant", "kw:chatbot", "kw:ai assistant"}, "B"),
)
CATEGORY_NAMES = {
    "A": "A 웹 채팅 서비스", "B": "B 데스크톱·웹 챗 클라이언트", "C": "C 브라우저·컴퓨터 사용 에이전트",
    "D": "D IDE·에디터 어시스턴트", "E": "E CLI 코딩 에이전트", "F": "F 하네스·플러그인·스킬·메모리 묶음",
    "G": "G 오케스트레이터·멀티에이전트", "H": "H 메신저 봇", "I": "I 자율·리서치 에이전트",
    "J": "J 로컬 LLM 런타임·UI", "K": "K API·SDK·프레임워크·RAG·자동화", "L": "L 이미지·음성·영상 생성",
    "M": "M 모바일 앱", "N": "N MCP 서버·도구 연결", "X": "X 제외 후보(목록·교재·논문·예제·데이터셋)",
}
EXCLUDED_CATEGORY = "X"
FULL_COLUMNS = ("name", "url", "stars", "category", "rule", "matrix_ref", "rapid_status", "archived", "owner_named", "description")


def load_links(path: Path = LINKS_PATH) -> dict[str, dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


# --- collect -------------------------------------------------------------------


def gh_json(args: Sequence[str], *, attempts: int = 5, backoff: float = 40.0) -> object:
    error = ""
    for attempt in range(attempts):
        result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return json.loads(result.stdout)
        error = result.stderr.strip()[:300]
        if attempt + 1 < attempts:
            time.sleep(backoff)
    raise RuntimeError(f"gh {' '.join(args)}: {error}")


def search(query: tuple[str, str], stars: str) -> list[dict[str, object]]:
    kind, term = query
    args = ["search", "repos"] + (["--topic", term] if kind == "topic" else [term])
    items = gh_json([*args, "--stars", stars, "--limit", str(SEARCH_LIMIT), "--json", SEARCH_FIELDS])
    return list(items) if isinstance(items, list) else []


def search_all(query: tuple[str, str]) -> list[dict[str, object]]:
    items = search(query, f">={MIN_STARS}")
    if len(items) < SEARCH_LIMIT:
        return items
    split: list[dict[str, object]] = []
    for stars in STAR_RANGES:
        part = search(query, stars)
        if len(part) >= SEARCH_LIMIT:
            print(f"warning: {query[1]!r} stars {stars} still hits the {SEARCH_LIMIT} cap", file=_sys.stderr)
        split.extend(part)
    return split


def collect(out_dir: Path, *, workers: int) -> dict[str, dict[str, object]]:
    queries = [("topic", topic) for topic in TOPICS] + [("keyword", keyword) for keyword in KEYWORDS]
    repos: dict[str, dict[str, object]] = {}
    with ThreadPoolExecutor(workers) as pool:
        for (kind, term), items in zip(queries, pool.map(search_all, queries)):
            tag = term if kind == "topic" else KEYWORD_TAG + term
            print(f"{kind} {term}: {len(items)}", file=_sys.stderr)
            for item in items:
                if item.get("isFork"):
                    continue
                entry = repos.setdefault(str(item["fullName"]).lower(), dict(item, topics_hit=[]))
                if tag not in entry["topics_hit"]:
                    entry["topics_hit"].append(tag)
    for key, link in sorted(load_links().items()):
        if not link.get("owner_named") or key in repos:
            continue
        view = gh_json(
            ["repo", "view", key, "--json", "nameWithOwner,stargazerCount,description,isFork,isArchived,pushedAt,url"],
            attempts=2,
            backoff=5.0,
        )
        assert isinstance(view, dict)
        repos[key] = {
            "fullName": view["nameWithOwner"],
            "stargazersCount": view["stargazerCount"],
            "description": view.get("description") or "",
            "isFork": view.get("isFork", False),
            "isArchived": view.get("isArchived", False),
            "pushedAt": view.get("pushedAt", ""),
            "url": view["url"],
            "topics_hit": [NAMED_TAG],
        }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repos.json").write_text(json.dumps(repos, ensure_ascii=False), encoding="utf-8")
    return repos


# --- classify ------------------------------------------------------------------


def is_relevant(key: str, repo: Mapping[str, object], links: Mapping[str, object]) -> bool:
    if key in links:
        return True
    topics = {str(topic) for topic in repo.get("topics_hit") or [] if not str(topic).startswith(KEYWORD_TAG)}
    return bool(topics & AI_TOPICS) or bool(AI_TERMS.search(f"{repo['fullName']} {repo.get('description') or ''}"))


def classify(key: str, repo: Mapping[str, object], links: Mapping[str, Mapping[str, object]]) -> tuple[str, str]:
    """Return (category, rule) where rule is 수동 / 규칙 / 토픽 / 기본값."""
    if key in links:
        return str(links[key]["category"]), "수동"
    text = f"{str(repo['fullName']).split('/')[-1]} {repo.get('description') or ''}"
    if EXCLUDE_TERMS.search(text):
        return EXCLUDED_CATEGORY, "규칙"
    for category, pattern in NAME_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            return category, "규칙"
    topics = {str(topic) for topic in repo.get("topics_hit") or []}
    for rule_topics, category in TOPIC_RULES:
        if topics & rule_topics:
            return category, "토픽"
    return "K", "기본값"


def build_rows(
    repos: Mapping[str, Mapping[str, object]], links: Mapping[str, Mapping[str, object]]
) -> tuple[list[dict[str, object]], int]:
    rows: list[dict[str, object]] = []
    dropped = 0
    for key, repo in repos.items():
        if repo.get("isFork"):
            continue
        stars = int(repo["stargazersCount"])
        if stars < MIN_STARS and key not in links:
            continue
        if not is_relevant(key, repo, links):
            dropped += 1
            continue
        category, rule = classify(key, repo, links)
        link = links.get(key, {})
        rows.append(
            {
                "name": str(repo["fullName"]),
                "url": str(repo["url"]),
                "stars": stars,
                "category": category,
                "rule": rule,
                "matrix_ref": str(link.get("matrix_ref") or ""),
                "rapid_status": str(link.get("rapid") or ""),
                "archived": bool(repo.get("isArchived")),
                "owner_named": bool(link.get("owner_named")),
                "description": " ".join(str(repo.get("description") or "").split()),
            }
        )
    rows.sort(key=lambda row: (row["category"], -int(row["stars"]), str(row["name"]).lower()))
    return rows, dropped


def count_by_category(rows: Iterable[Mapping[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["category"])] = counts.get(str(row["category"]), 0) + 1
    return dict(sorted(counts.items()))


# --- render --------------------------------------------------------------------


def write_full(out_dir: Path, rows: Sequence[Mapping[str, object]], summary: Mapping[str, object]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ai-usage-github-full.json").write_text(
        json.dumps({"summary": summary, "rows": list(rows)}, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    with (out_dir / "ai-usage-github-full.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FULL_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def kept_in_docs(row: Mapping[str, object], min_stars: int) -> bool:
    if row["matrix_ref"]:
        return True
    return row["category"] != EXCLUDED_CATEGORY and int(row["stars"]) >= min_stars


def doc_row(row: Mapping[str, object]) -> str:
    flags = (" (보관됨)" if row["archived"] else "") + (
        " (주인 지정)" if row["owner_named"] and int(row["stars"]) < MIN_STARS else ""
    )
    ref = str(row["matrix_ref"])
    rapid = str(row["rapid_status"]) or ("없음" if ref else "—")
    return f"| [{row['name']}]({row['url']}){flags} | {int(row['stars']):,} | {row['rule']} | {ref or '—'} | {rapid} |"


def write_docs(docs_dir: Path, rows: Sequence[Mapping[str, object]], summary: Mapping[str, object], min_stars: int) -> None:
    survey_date = summary["survey_date"]
    kept = [row for row in rows if kept_in_docs(row, min_stars)]
    total_counts = count_by_category(rows)
    kept_counts = count_by_category(kept)
    linked_counts = count_by_category(row for row in rows if row["matrix_ref"])
    category_dir = docs_dir / DOCS_DIR_NAME
    shutil.rmtree(category_dir, ignore_errors=True)
    category_dir.mkdir(parents=True)
    for category, count in kept_counts.items():
        lines = [
            f"# {CATEGORY_NAMES[category]}",
            "",
            f"[부록 목차](../{DOCS_INDEX_NAME})로 돌아가기. 조사일 {survey_date}. 이 분류의 별 {MIN_STARS}개 이상 저장소 "
            f"{total_counts[category]:,}개 중 본문 표와 연결된 것과 별 {min_stars:,}개 이상인 것 {count:,}개만 싣는다. "
            "전체 목록은 목차의 스크립트로 다시 만든다.",
            "",
            "| 저장소 | 별 | 분류 근거 | 본문 | Rapid 현재 |",
            "|---|---|---|---|---|",
        ]
        lines += [doc_row(row) for row in kept if row["category"] == category]
        (category_dir / f"{category.lower()}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    index = [
        "# AI 사용 흔적 매트릭스 부록: GitHub 별 500개 이상 프로젝트",
        "",
        f"조사일 {survey_date}. [AI 사용 흔적 커버리지 매트릭스](ai-usage-coverage-matrix.md)의 부록이다. 별 수는 조사일 값이다.",
        "",
        f"- **싣는 범위.** 조사한 {summary['total']:,}개 중 본문 표와 연결된 저장소 {summary['matrix_linked']:,}개와, "
        f"X(제외 후보)를 뺀 별 {min_stars:,}개 이상 저장소를 합쳐 {len(kept):,}개만 싣는다. 설명문은 각 저장소 소유자의 글이라 싣지 않는다. "
        "전체 목록(설명문 포함)은 `scripts/ai-usage-github-appendix.py`로 다시 만들며 Git에 넣지 않는다: "
        "`collect --out qc-runs/ai-usage-github`(GitHub 검색, `gh` 로그인 필요) 다음 "
        f"`render --out qc-runs/ai-usage-github --survey-date {survey_date} --docs docs`가 "
        "`qc-runs/ai-usage-github/ai-usage-github-full.{json,csv}`과 이 부록을 쓴다.",
        "- **흔적.** 본문 표에 행이 있는 저장소는 `본문` 열에 절과 행 이름을, `Rapid 현재` 열에 지원 상태를 적었다. 나머지(`본문` 열이 —)는 이름·별 수·분류만 있고, 어디에 무슨 흔적이 남는지는 아직 1차 출처로 확인하지 않았으므로 모두 [미확인]이다. 라이브러리·프레임워크는 그 자체로는 사용 흔적을 남기지 않고 그것으로 만든 앱이 남긴다.",
        f"- **수집.** 아래 토픽·키워드마다 `gh search repos`(별 {MIN_STARS}개 이상, 한 번에 {SEARCH_LIMIT:,}개). "
        f"{SEARCH_LIMIT:,}개에서 잘리는 검색은 별 수 구간으로 나눠 다시 조회한다. 포크는 뺀다. 본문에서 다룬 제품 중 주인이 이름을 댄 저장소"
        f"(`scripts/ai-usage-github-matrix-links.json`의 `owner_named`)는 검색에 걸리지 않아도 넣고, 별이 {MIN_STARS}개 미만이면 `(주인 지정)`을 붙인다.",
        "- **AI 관련성.** 키워드 검색은 AI와 무관한 저장소(마우스 커서, 모니터링 에이전트 등)도 걸러 오므로, AI 토픽이 있거나 이름·설명에 AI 용어가 있는 저장소만 남긴다. "
        f"이렇게 뺀 저장소: {summary['dropped_not_ai']:,}개.",
        "- **분류.** `수동` = 본문 조사로 정함(`scripts/ai-usage-github-matrix-links.json`), `규칙` = 이름·설명 키워드 규칙, `토픽` = GitHub 토픽, `기본값` = 어느 규칙에도 걸리지 않아 K로 둠. 규칙은 스크립트에 있고 검토 전이라 틀린 칸이 있을 수 있다. X는 설치해서 쓰는 도구가 아닐 가능성이 큰 것(목록·교재·논문·예제·데이터셋)이며 이 부록에는 싣지 않는다.",
        "- **토픽:** " + ", ".join(f"`{topic}`" for topic in TOPICS) + ".",
        "- **키워드:** " + ", ".join(f"`{keyword}`" for keyword in KEYWORDS) + ".",
        "",
        "| 분류 | 조사한 저장소 | 본문 연결 | 이 부록에 실음 |",
        "|---|---|---|---|",
    ]
    for category, count in total_counts.items():
        name = CATEGORY_NAMES[category]
        label = f"[{name}]({DOCS_DIR_NAME}/{category.lower()}.md)" if category in kept_counts else name
        index.append(f"| {label} | {count:,} | {linked_counts.get(category, 0):,} | {kept_counts.get(category, 0):,} |")
    index.append(f"| 합계 | {summary['total']:,} | {summary['matrix_linked']:,} | {len(kept):,} |")
    (docs_dir / DOCS_INDEX_NAME).write_text("\n".join(index) + "\n", encoding="utf-8")


def render(out_dir: Path, *, survey_date: str, docs_dir: Path | None, min_stars: int) -> dict[str, object]:
    repos = json.loads((out_dir / "repos.json").read_text(encoding="utf-8"))
    rows, dropped = build_rows(repos, load_links())
    summary: dict[str, object] = {
        "survey_date": survey_date,
        "total": len(rows),
        "dropped_not_ai": dropped,
        "matrix_linked": sum(1 for row in rows if row["matrix_ref"]),
        "docs_min_stars": min_stars,
        "docs_rows": sum(1 for row in rows if kept_in_docs(row, min_stars)),
        "by_category": count_by_category(rows),
    }
    write_full(out_dir, rows, summary)
    if docs_dir is not None:
        write_docs(docs_dir, rows, summary, min_stars)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect", help="run the GitHub searches into <out>/repos.json")
    collect_parser.add_argument("--out", type=Path, required=True)
    collect_parser.add_argument("--workers", type=int, default=2)
    render_parser = sub.add_parser("render", help="classify <out>/repos.json; write the full list and the docs")
    render_parser.add_argument("--out", type=Path, required=True)
    render_parser.add_argument("--survey-date", required=True, help="date of the collect run, YYYY-MM-DD")
    render_parser.add_argument("--docs", type=Path, help="docs directory to write the committed appendix into")
    render_parser.add_argument("--min-stars", type=int, default=5000, help="stars needed for an unlinked row in the docs")
    args = parser.parse_args(argv)
    if args.command == "collect":
        repos = collect(args.out, workers=args.workers)
        print(json.dumps({"repos": len(repos), "out": str(args.out / "repos.json")}))
        return 0
    summary = render(args.out, survey_date=args.survey_date, docs_dir=args.docs, min_stars=args.min_stars)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
