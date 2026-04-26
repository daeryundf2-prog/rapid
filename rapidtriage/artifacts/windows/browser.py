from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse

from ...core.models import ArtifactRecord
from .common import (
    isoformat_from_unix_micros,
    isoformat_from_webkit_micros,
    iter_windows_user_homes,
    open_sqlite_snapshot,
)

CHROMIUM_BROWSER_ROOTS: Tuple[Tuple[str, Sequence[str]], ...] = (
    ("chrome", ("AppData", "Local", "Google", "Chrome", "User Data")),
    ("edge", ("AppData", "Local", "Microsoft", "Edge", "User Data")),
    ("brave", ("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")),
)
FIREFOX_PROFILE_ROOT = ("AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
PARSER_VERSION = "windows-browser-v2"
MAX_USAGE_ROWS = 500
MAX_AI_STORAGE_FILES = 80
MAX_AI_STORAGE_FILE_BYTES = 5 * 1024 * 1024
MAX_AI_CONVERSATION_ROWS = 200

AI_SERVICE_DOMAINS: Tuple[Tuple[str, str], ...] = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("openai.com", "OpenAI"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("aistudio.google.com", "Google AI Studio"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("bing.com", "Microsoft Copilot/Bing Chat"),
    ("poe.com", "Poe"),
    ("huggingface.co", "Hugging Face"),
    ("grok.com", "Grok"),
    ("x.ai", "Grok"),
    ("you.com", "You.com"),
    ("phind.com", "Phind"),
    ("chat.mistral.ai", "Mistral Le Chat"),
    ("deepseek.com", "DeepSeek"),
    ("meta.ai", "Meta AI"),
    ("character.ai", "Character.AI"),
    ("notion.so", "Notion AI"),
)
QUERY_HINT_KEYS = ("q", "query", "prompt", "text", "message", "ask", "p")
SEARCH_HOST_HINTS = ("google.", "bing.com", "duckduckgo.com", "naver.com", "daum.net", "yahoo.")
EMAIL_HOST_HINTS = ("mail.google.com", "outlook.live.com", "outlook.office.com", "mail.naver.com", "mail.daum.net")
SOCIAL_HOST_HINTS = ("facebook.com", "instagram.com", "x.com", "twitter.com", "threads.net", "linkedin.com")
CLOUD_HOST_HINTS = ("drive.google.com", "onedrive.live.com", "dropbox.com", "icloud.com", "box.com")
AI_STORAGE_DIRS: Tuple[Tuple[str, ...], ...] = (
    ("Local Storage", "leveldb"),
    ("Session Storage",),
    ("IndexedDB",),
    ("Cache", "Cache_Data"),
    ("Cache",),
)
AI_STORAGE_SUFFIXES = {".log", ".ldb", ".sqlite", ".sqlite3", ".db", ".json", ".txt"}


class WindowsBrowserArtifactsProvider:
    collector_kind = "browser"
    name = "windows-browser-artifacts"
    description = "Windows browser history/download collectors backed by real profile files"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for user_root in iter_windows_user_homes(root):
            user_name = user_root.name
            for browser_name, relative_parts in CHROMIUM_BROWSER_ROOTS:
                user_data_root = user_root.joinpath(*relative_parts)
                if not user_data_root.is_dir():
                    continue
                for profile_dir in sorted(user_data_root.iterdir(), key=lambda item: item.name.lower()):
                    if not profile_dir.is_dir():
                        continue
                    history_path = profile_dir / "History"
                    if not history_path.is_file():
                        yield from build_browser_storage_only_artifacts(
                            provider=self.name,
                            user=user_name,
                            browser=browser_name,
                            profile=profile_dir.name,
                            profile_dir=profile_dir,
                        )
                        continue
                    history_rows, download_rows = extract_chromium_history_and_downloads(history_path)
                    if not history_rows and not download_rows:
                        continue
                    yield from build_browser_artifacts(
                        provider=self.name,
                        artifact_type="browser-history-downloads",
                        user=user_name,
                        browser=browser_name,
                        profile=profile_dir.name,
                        source_path=history_path,
                        history_rows=history_rows,
                        download_rows=download_rows,
                    )

            firefox_root = user_root.joinpath(*FIREFOX_PROFILE_ROOT)
            if not firefox_root.is_dir():
                continue
            for profile_dir in sorted(firefox_root.iterdir(), key=lambda item: item.name.lower()):
                if not profile_dir.is_dir():
                    continue
                places_path = profile_dir / "places.sqlite"
                if not places_path.is_file():
                    continue
                history_rows = extract_firefox_history(places_path)
                if not history_rows:
                    continue
                yield from build_browser_artifacts(
                    provider=self.name,
                    artifact_type="browser-history",
                    user=user_name,
                    browser="firefox",
                    profile=profile_dir.name,
                    source_path=places_path,
                    history_rows=history_rows,
                    download_rows=[],
                )


def build_browser_storage_only_artifacts(
    *,
    provider: str,
    user: str,
    browser: str,
    profile: str,
    profile_dir: Path,
    parser_version: str = PARSER_VERSION,
    ai_conversation_artifact_type: str = "browser-ai-conversation",
) -> List[ArtifactRecord]:
    conversation_rows = extract_ai_conversation_candidates(profile_dir)
    if not conversation_rows:
        return []
    return [
        build_ai_conversation_record(
            provider=provider,
            artifact_type=ai_conversation_artifact_type,
            user=user,
            browser=browser,
            profile=profile,
            profile_dir=profile_dir,
            conversation_rows=conversation_rows,
            parser_version=parser_version,
        )
    ]


def build_browser_artifacts(
    *,
    provider: str,
    artifact_type: str,
    user: str,
    browser: str,
    profile: str,
    source_path: Path,
    history_rows: List[Dict[str, object]],
    download_rows: List[Dict[str, object]],
    parser: str | None = None,
    parser_version: str = PARSER_VERSION,
    ai_artifact_type: str = "browser-ai-usage",
    ai_conversation_artifact_type: str = "browser-ai-conversation",
) -> List[ArtifactRecord]:
    usage_rows = summarize_internet_usage(history_rows)
    ai_rows = extract_ai_usage(history_rows)
    profile_dir = source_path.parent
    conversation_rows = extract_ai_conversation_candidates(profile_dir)
    source_hashes = file_hashes(source_path)
    base_details = {
        "parser": parser or "browser-history",
        "parser_version": parser_version,
        "coverage_status": "parsed",
        "reportability": "triage",
        "source_path": str(source_path.resolve()),
        "source_hashes": source_hashes,
        "user": user,
        "browser": browser,
        "profile": profile,
        "history_count": len(history_rows),
        "download_count": len(download_rows),
        "internet_usage_count": len(usage_rows),
        "ai_usage_count": len(ai_rows),
        "ai_conversation_candidate_count": len(conversation_rows),
        "internet_category_counts": count_field(usage_rows, "category"),
        "top_domains": count_field(usage_rows, "domain", limit=20),
        "history": history_rows,
        "downloads": download_rows,
        "internet_usage": usage_rows,
        "ai_usage": ai_rows,
        "ai_conversation_candidates": conversation_rows[:25],
    }
    records = [
        ArtifactRecord(
            provider=provider,
            artifact_type=artifact_type,
            path=str(source_path.resolve()),
            supported=True,
            details=base_details,
        )
    ]
    if ai_rows:
        seen = sorted([str(row.get("last_visited_at")) for row in ai_rows if row.get("last_visited_at")])
        records.append(
            ArtifactRecord(
                provider=provider,
                artifact_type=ai_artifact_type,
                path=str(source_path.resolve()),
                supported=True,
                details={
                    "parser": "browser-ai-usage",
                    "parser_version": parser_version,
                    "coverage_status": "detected",
                    "reportability": "review",
                    "source_path": str(source_path.resolve()),
                    "source_hashes": source_hashes,
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "ai_usage_count": len(ai_rows),
                    "ai_conversation_candidate_count": len(conversation_rows),
                    "ai_service_counts": count_field(ai_rows, "ai_service"),
                    "first_seen_at": seen[0] if seen else None,
                    "last_seen_at": seen[-1] if seen else None,
                    "ai_usage": ai_rows,
                    "ai_conversation_candidates": conversation_rows[:25],
                    "risk_flags": ["ai-service-usage"],
                    "triage_recommendation": (
                        "Browser history proves visits to AI services only. Review page titles, URL query hints, "
                        "browser cache, downloads, synced cloud exports, and app logs before claiming prompt content."
                    ),
                },
            )
        )
    if conversation_rows:
        records.append(
            build_ai_conversation_record(
                provider=provider,
                artifact_type=ai_conversation_artifact_type,
                user=user,
                browser=browser,
                profile=profile,
                profile_dir=profile_dir,
                conversation_rows=conversation_rows,
                parser_version=parser_version,
            )
        )
    return records


def build_ai_conversation_record(
    *,
    provider: str,
    artifact_type: str,
    user: str,
    browser: str,
    profile: str,
    profile_dir: Path,
    conversation_rows: List[Dict[str, object]],
    parser_version: str,
) -> ArtifactRecord:
    return ArtifactRecord(
        provider=provider,
        artifact_type=artifact_type,
        path=str(profile_dir.resolve()),
        supported=True,
        details={
            "parser": "browser-ai-conversation-storage",
            "parser_version": parser_version,
            "coverage_status": "candidate",
            "reportability": "review",
            "source_path": str(profile_dir.resolve()),
            "user": user,
            "browser": browser,
            "profile": profile,
            "ai_conversation_candidate_count": len(conversation_rows),
            "question_count": sum(1 for row in conversation_rows if row.get("direction") == "question"),
            "answer_count": sum(1 for row in conversation_rows if row.get("direction") == "answer"),
            "ai_service_counts": count_field(conversation_rows, "ai_service"),
            "conversation_candidates": conversation_rows,
            "risk_flags": ["ai-conversation-storage-candidate"],
            "triage_recommendation": (
                "Review these recovered browser-storage snippets against the raw source files. "
                "They are conversation candidates, not a guaranteed complete AI transcript."
            ),
        },
    )


def extract_ai_conversation_candidates(profile_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for source in iter_ai_storage_files(profile_dir):
        if len(rows) >= MAX_AI_CONVERSATION_ROWS:
            break
        try:
            data = source.read_bytes()[:MAX_AI_STORAGE_FILE_BYTES]
        except OSError:
            continue
        text = decode_storage_blob(data)
        if not text:
            continue
        service = detect_ai_service(text, "")
        if not service and not likely_ai_storage_text(text):
            continue
        service = service or infer_ai_service_from_path(source)
        fragments = extract_ai_text_fragments(text)
        if not fragments:
            continue
        source_hash = hashlib.sha256(data).hexdigest()
        for fragment in fragments:
            if len(rows) >= MAX_AI_CONVERSATION_ROWS:
                break
            rows.append(
                {
                    "ai_service": service or "AI service",
                    "direction": fragment["direction"],
                    "role": fragment["role"],
                    "text": fragment["text"],
                    "confidence": fragment["confidence"],
                    "storage_area": storage_area(profile_dir, source),
                    "source_path": str(source.resolve()),
                    "source_sha256": source_hash,
                    "evidence_note": "Recovered from browser storage; verify with the raw storage file before reporting as a transcript.",
                }
            )
    return deduplicate_conversation_rows(rows)


def iter_ai_storage_files(profile_dir: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    yielded = 0
    for relative in AI_STORAGE_DIRS:
        root = profile_dir.joinpath(*relative)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*"), key=lambda item: str(item).lower())
        for candidate in candidates:
            if yielded >= MAX_AI_STORAGE_FILES:
                return
            if not candidate.is_file() or candidate in seen:
                continue
            if candidate.suffix.lower() not in AI_STORAGE_SUFFIXES and candidate.name.lower() not in {"data_0", "data_1", "index"}:
                continue
            try:
                if candidate.stat().st_size <= 0:
                    continue
            except OSError:
                continue
            seen.add(candidate)
            yielded += 1
            yield candidate


def decode_storage_blob(data: bytes) -> str:
    if not data:
        return ""
    decoded = data.decode("utf-8", errors="ignore")
    printable = re.sub(r"[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]+", " ", decoded)
    return printable[:MAX_AI_STORAGE_FILE_BYTES]


def likely_ai_storage_text(text: str) -> bool:
    lowered = text.lower()
    if any(domain in lowered for domain, _service in AI_SERVICE_DOMAINS):
        return True
    return any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "assistant", '"role"', '"content"'))


def infer_ai_service_from_path(path: Path) -> str:
    lowered = str(path).lower()
    for domain, service in AI_SERVICE_DOMAINS:
        if domain in lowered:
            return service
    return ""


def extract_ai_text_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    fragments.extend(extract_json_role_content_fragments(text))
    fragments.extend(extract_named_prompt_answer_fragments(text))
    return fragments


def extract_json_role_content_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    patterns = (
        r'"role"\s*:\s*"(?P<role>user|assistant|system)"[\s\S]{0,800}?"content"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"',
        r'"content"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"[\s\S]{0,800}?"role"\s*:\s*"(?P<role>user|assistant|system)"',
        r'"author"\s*:\s*\{[\s\S]{0,400}?"role"\s*:\s*"(?P<role>user|assistant|system)"[\s\S]{0,1200}?"text"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"',
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            role = match.group("role").lower()
            content = clean_recovered_text(match.group("content"))
            if not useful_conversation_text(content):
                continue
            fragments.append(
                {
                    "role": role,
                    "direction": role_to_direction(role),
                    "text": content,
                    "confidence": 0.82 if role in {"user", "assistant"} else 0.65,
                }
            )
    return fragments


def extract_named_prompt_answer_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    key_roles = {
        "prompt": ("user", "question"),
        "question": ("user", "question"),
        "query": ("user", "question"),
        "answer": ("assistant", "answer"),
        "response": ("assistant", "answer"),
        "completion": ("assistant", "answer"),
    }
    pattern = r'"(?P<key>prompt|question|query|answer|response|completion)"\s*:\s*"(?P<content>(?:\\.|[^"\\]){4,3000})"'
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        key = match.group("key").lower()
        role, direction = key_roles[key]
        content = clean_recovered_text(match.group("content"))
        if not useful_conversation_text(content):
            continue
        fragments.append({"role": role, "direction": direction, "text": content, "confidence": 0.72})
    return fragments


def role_to_direction(role: str) -> str:
    if role == "user":
        return "question"
    if role == "assistant":
        return "answer"
    return "context"


def clean_recovered_text(value: str) -> str:
    try:
        decoded = json.loads(f'"{value}"')
    except json.JSONDecodeError:
        decoded = value
    normalized = re.sub(r"\s+", " ", str(decoded)).strip()
    return normalized[:1500]


def useful_conversation_text(value: str) -> bool:
    if len(value) < 4:
        return False
    lowered = value.lower()
    if lowered in {"null", "true", "false", "undefined"}:
        return False
    return any(character.isalpha() for character in value)


def storage_area(profile_dir: Path, source: Path) -> str:
    try:
        relative = source.relative_to(profile_dir)
    except ValueError:
        return source.parent.name
    parts = relative.parts
    if len(parts) >= 2 and parts[0] in {"Local Storage", "Cache"}:
        return "/".join(parts[:2])
    return parts[0] if parts else source.parent.name


def deduplicate_conversation_rows(rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    deduped: List[Dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (str(row.get("ai_service") or ""), str(row.get("direction") or ""), str(row.get("text") or "")[:240])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(row))
    return deduped


def summarize_internet_usage(history_rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    usage_rows: List[Dict[str, object]] = []
    for index, row in enumerate(history_rows[:MAX_USAGE_ROWS]):
        url = str(row.get("url") or "")
        parsed = safe_parse_url(url)
        if not parsed.scheme.startswith("http") or not parsed.netloc:
            continue
        title = str(row.get("title") or "")
        service = detect_ai_service(url, title)
        usage_rows.append(
            {
                "source_index": index,
                "url": url,
                "title": title,
                "domain": normalize_host(parsed.netloc),
                "category": classify_url(parsed, title, service),
                "visit_count": int(row.get("visit_count") or 0),
                "last_visited_at": row.get("last_visited_at"),
                "ai_service": service,
                "query_hint": extract_query_hint(url),
            }
        )
    return usage_rows


def extract_ai_usage(history_rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    ai_rows: List[Dict[str, object]] = []
    for index, row in enumerate(history_rows[:MAX_USAGE_ROWS]):
        url = str(row.get("url") or "")
        title = str(row.get("title") or "")
        service = detect_ai_service(url, title)
        if not service:
            continue
        parsed = safe_parse_url(url)
        query_hint = extract_query_hint(url)
        ai_rows.append(
            {
                "source_index": index,
                "ai_service": service,
                "url": url,
                "domain": normalize_host(parsed.netloc),
                "title": title,
                "visit_count": int(row.get("visit_count") or 0),
                "last_visited_at": row.get("last_visited_at"),
                "query_hint": query_hint,
                "prompt_hint": query_hint,
                "confidence": ai_usage_confidence(service, url, title, query_hint),
                "evidence_note": "AI service visit detected from browser history; prompt contents may be absent from history.",
            }
        )
    return ai_rows


def detect_ai_service(url: str, title: str = "") -> str:
    parsed = safe_parse_url(url)
    host = normalize_host(parsed.netloc)
    lowered = f"{url} {title}".lower()
    for domain, service in AI_SERVICE_DOMAINS:
        if not host_matches(host, domain):
            continue
        if domain == "bing.com" and not any(token in lowered for token in ("copilot", "bing chat", "chat")):
            continue
        if domain == "notion.so" and "ai" not in lowered:
            continue
        return service
    if "chatgpt" in lowered:
        return "ChatGPT"
    if "claude" in lowered:
        return "Claude"
    if "perplexity" in lowered:
        return "Perplexity"
    if "copilot" in lowered or "bing chat" in lowered:
        return "Microsoft Copilot"
    return ""


def classify_url(parsed, title: str, ai_service: str) -> str:
    host = normalize_host(parsed.netloc)
    lowered = f"{host} {parsed.path} {parsed.query} {title}".lower()
    if ai_service:
        return "ai"
    if any(token in host for token in SEARCH_HOST_HINTS):
        return "search"
    if any(host_matches(host, token) for token in EMAIL_HOST_HINTS):
        return "email"
    if any(host_matches(host, token) for token in SOCIAL_HOST_HINTS):
        return "social"
    if any(host_matches(host, token) for token in CLOUD_HOST_HINTS):
        return "cloud"
    if any(token in lowered for token in ("download", ".zip", ".exe", ".dmg", ".pkg", ".msi")):
        return "download"
    return "web"


def extract_query_hint(url: str) -> str:
    query = parse_qs(safe_parse_url(url).query, keep_blank_values=False)
    for key in QUERY_HINT_KEYS:
        values = query.get(key)
        if not values:
            continue
        value = unquote_plus(str(values[0])).strip()
        if value:
            return value[:240]
    return ""


def ai_usage_confidence(service: str, url: str, title: str, query_hint: str) -> float:
    if query_hint:
        return 0.9
    lowered = f"{url} {title}".lower()
    if service and service.lower().split()[0] in lowered:
        return 0.85
    return 0.75


def safe_parse_url(url: str):
    try:
        return urlparse(url)
    except ValueError:
        return urlparse("")


def normalize_host(host: str) -> str:
    return host.lower().split("@")[-1].split(":")[0].strip(".")


def host_matches(host: str, domain: str) -> bool:
    domain = domain.lower()
    return host == domain or host.endswith(f".{domain}")


def count_field(rows: Sequence[Mapping[str, object]], key: str, *, limit: int = 10) -> List[Dict[str, object]]:
    counts: Dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "")
        if value:
            counts[value] = counts.get(value, 0) + 1
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def file_hashes(path: Path) -> dict[str, str]:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def extract_chromium_history_and_downloads(history_db: Path) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    try:
        with open_sqlite_snapshot(history_db) as connection:
            if not sqlite_table_exists(connection, "urls"):
                return [], []

            history_rows = [
                {
                    "url": row["url"],
                    "title": row["title"] or "",
                    "visit_count": int(row["visit_count"] or 0),
                    "last_visited_at": isoformat_from_webkit_micros(row["last_visit_time"]),
                }
                for row in connection.execute(
                    """
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    WHERE url IS NOT NULL AND url != ''
                    ORDER BY last_visit_time DESC, url ASC
                    """
                )
            ]

            download_rows: List[Dict[str, object]] = []
            if sqlite_table_exists(connection, "downloads"):
                download_rows = extract_chromium_downloads(connection)
            return history_rows, download_rows
    except (sqlite3.DatabaseError, OSError):
        return [], []


def extract_chromium_downloads(connection: sqlite3.Connection) -> List[Dict[str, object]]:
    columns = sqlite_table_columns(connection, "downloads")
    if "id" not in columns:
        return []

    chain_urls: Dict[int, str] = {}
    if sqlite_table_exists(connection, "downloads_url_chains"):
        for row in connection.execute(
            """
            SELECT id, url
            FROM downloads_url_chains
            WHERE url IS NOT NULL AND url != ''
            ORDER BY id ASC, chain_index ASC
            """
        ):
            chain_urls.setdefault(int(row["id"]), str(row["url"]))

    select_columns = [
        "id",
        column_or_null(columns, "target_path"),
        column_or_null(columns, "current_path"),
        column_or_null(columns, "tab_url"),
        column_or_null(columns, "total_bytes"),
        column_or_null(columns, "state"),
        column_or_null(columns, "start_time"),
        column_or_null(columns, "end_time"),
    ]
    order_column = "start_time" if "start_time" in columns else "id"
    query = f"SELECT {', '.join(select_columns)} FROM downloads ORDER BY {order_column} DESC, id ASC"

    rows: List[Dict[str, object]] = []
    for row in connection.execute(query):
        download_id = int(row["id"])
        target_path = row["target_path"] or row["current_path"] or ""
        rows.append(
            {
                "source_url": chain_urls.get(download_id) or row["tab_url"] or "",
                "target_path": str(target_path),
                "tab_url": row["tab_url"] or "",
                "total_bytes": int(row["total_bytes"] or 0),
                "state": int(row["state"] or 0),
                "started_at": isoformat_from_webkit_micros(row["start_time"]),
                "ended_at": isoformat_from_webkit_micros(row["end_time"]),
            }
        )
    return rows


def extract_firefox_history(places_db: Path) -> List[Dict[str, object]]:
    try:
        with open_sqlite_snapshot(places_db) as connection:
            if not sqlite_table_exists(connection, "moz_places"):
                return []
            history_rows = []
            for row in connection.execute(
                """
                SELECT
                    moz_places.url AS url,
                    moz_places.title AS title,
                    moz_places.visit_count AS visit_count,
                    MAX(moz_historyvisits.visit_date) AS last_visit_date
                FROM moz_places
                LEFT JOIN moz_historyvisits ON moz_historyvisits.place_id = moz_places.id
                WHERE moz_places.url IS NOT NULL AND moz_places.url != ''
                GROUP BY moz_places.id, moz_places.url, moz_places.title, moz_places.visit_count
                ORDER BY last_visit_date DESC, moz_places.url ASC
                """
            ):
                history_rows.append(
                    {
                        "url": row["url"],
                        "title": row["title"] or "",
                        "visit_count": int(row["visit_count"] or 0),
                        "last_visited_at": isoformat_from_unix_micros(row["last_visit_date"]),
                    }
                )
            return history_rows
    except (sqlite3.DatabaseError, OSError):
        return []


def sqlite_table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table_name})")}


def column_or_null(columns: set[str], name: str) -> str:
    if name in columns:
        return name
    return f"NULL AS {name}"
