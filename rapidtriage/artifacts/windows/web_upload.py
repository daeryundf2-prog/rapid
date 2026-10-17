"""Webmail / web-hard / file-sharing upload candidates from browser rows (plan r2-communication §3.3 M3).

:class:`WebUploadScanner` watches the rows the browser provider emits
(``browser-cache-entry``, ``browser-history``, ``browser-visit``) and turns every URL that
matches a pattern of ``web_upload_patterns.yaml`` into one ``web-upload-candidate`` row
(service, category, strength, time, size, file-name candidate, the source row's type /
path / offset). The candidate is a lead, not a finding: a URL pattern says a page or
endpoint of an upload flow was requested, not which file left the machine.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from ...core.models import ArtifactRecord
from .browser_cache import file_name_from_url

UPLOAD_PATTERNS_PATH = Path(__file__).with_name("web_upload_patterns.yaml")
UPLOAD_PARSER = "web-upload-candidate"
UPLOAD_PARSER_VERSION = "web-upload-candidate-v1"
SOURCE_TYPES = frozenset({"browser-cache-entry", "browser-history", "browser-visit"})
CATEGORIES = ("webmail", "filesharing", "cloud")
STRENGTHS = ("weak", "medium", "strong")
CATEGORY_LABELS = {"webmail": "웹메일", "filesharing": "파일 공유·웹하드", "cloud": "클라우드 저장소"}
STRENGTH_LABELS = {"weak": "약함(첨부 참조)", "medium": "중간(업로드 경로)", "strong": "강함(업로드 엔드포인트·POST)"}
MAX_UPLOAD_CANDIDATES = 50_000
HOST_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


class UploadPatternError(ValueError):
    """``web_upload_patterns.yaml`` is malformed (Korean message)."""


@dataclass(frozen=True)
class UploadPattern:
    id: str
    service: str
    label_ko: str
    category: str
    hosts: tuple[str, ...]
    host_contains: tuple[str, ...]
    path_regex: re.Pattern[str] | None
    query_keys: frozenset[str]
    post_only: bool
    strength: str
    basis: str
    sources: tuple[str, ...]

    def host_matches(self, host: str) -> bool:
        if any(host == item or host.endswith("." + item) for item in self.hosts):
            return True
        return any(token in host for token in self.host_contains)


def parse_upload_patterns(data: bytes) -> tuple[UploadPattern, ...]:
    import yaml

    try:
        document = yaml.safe_load(data.decode("utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise UploadPatternError(f"업로드 패턴 YAML을 읽을 수 없습니다: {exc}") from exc
    entries = document.get("patterns") if isinstance(document, Mapping) else None
    if not isinstance(entries, list) or not entries:
        raise UploadPatternError("업로드 패턴에 patterns 목록이 없습니다")
    patterns: list[UploadPattern] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise UploadPatternError("업로드 패턴 항목이 매핑이 아닙니다")
        pattern_id = str(entry.get("id") or "")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", pattern_id) or pattern_id in seen:
            raise UploadPatternError(f"업로드 패턴 id가 올바르지 않거나 중복됩니다: {pattern_id!r}")
        seen.add(pattern_id)
        category = str(entry.get("category") or "")
        strength = str(entry.get("strength") or "")
        if category not in CATEGORIES or strength not in STRENGTHS:
            raise UploadPatternError(f"업로드 패턴 {pattern_id}의 category/strength가 올바르지 않습니다")
        hosts = tuple(str(item) for item in entry.get("hosts") or ())
        if not hosts or not all(HOST_RE.fullmatch(host) for host in hosts):
            raise UploadPatternError(f"업로드 패턴 {pattern_id}의 hosts 형식이 올바르지 않습니다")
        sources = tuple(str(item) for item in entry.get("sources") or ())
        if not sources or not all(item.startswith("https://") for item in sources):
            raise UploadPatternError(f"업로드 패턴 {pattern_id}의 sources는 https URL 목록이어야 합니다")
        regex_text = entry.get("path_regex")
        query_keys = frozenset(str(item).lower() for item in entry.get("query_keys") or ())
        post_only = bool(entry.get("post_only"))
        if not regex_text and not query_keys and not post_only:
            raise UploadPatternError(f"업로드 패턴 {pattern_id}에 path_regex·query_keys·post_only 중 하나가 필요합니다")
        try:
            compiled = re.compile(str(regex_text)) if regex_text else None
        except re.error as exc:
            raise UploadPatternError(f"업로드 패턴 {pattern_id}의 path_regex가 올바르지 않습니다: {exc}") from exc
        patterns.append(
            UploadPattern(
                id=pattern_id,
                service=str(entry.get("service") or pattern_id),
                label_ko=str(entry.get("label_ko") or pattern_id),
                category=category,
                hosts=hosts,
                host_contains=tuple(str(item).lower() for item in entry.get("host_contains") or ()),
                path_regex=compiled,
                query_keys=query_keys,
                post_only=post_only,
                strength=strength,
                basis=str(entry.get("basis") or "heuristic"),
                sources=sources,
            )
        )
    return tuple(patterns)


_CACHE: dict[tuple[str, int, int], tuple[UploadPattern, ...]] = {}


def load_upload_patterns(path: Path | None = None) -> tuple[UploadPattern, ...]:
    target = Path(path) if path is not None else UPLOAD_PATTERNS_PATH
    stat = target.stat()
    key = (str(target), stat.st_size, stat.st_mtime_ns)
    if key not in _CACHE:
        patterns = parse_upload_patterns(target.read_bytes())
        _CACHE.clear()
        _CACHE[key] = patterns
    return _CACHE[key]


def match_upload_url(
    url: str, method: str, patterns: Iterable[UploadPattern]
) -> tuple[UploadPattern, str] | None:
    """The strongest pattern matching ``url`` and the resulting strength (POST raises it one step)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host or parts.scheme.lower() not in {"http", "https"}:
        return None
    is_post = method.upper() in {"POST", "PUT"}
    target = parts.path + ("?" + parts.query if parts.query else "")
    query = {name.lower() for name, _value in parse_qsl(parts.query, keep_blank_values=True)}
    best: tuple[UploadPattern, str] | None = None
    for pattern in patterns:
        if not pattern.host_matches(host):
            continue
        if pattern.post_only:
            if not is_post:
                continue
        else:
            if pattern.path_regex is not None and not pattern.path_regex.search(target):
                continue
            if pattern.query_keys and not pattern.query_keys & query:
                continue
        strength = pattern.strength
        # A POST/PUT raises the pattern's strength one step, except for post-only patterns (the POST is their signal).
        if is_post and not pattern.post_only and strength != "strong":
            strength = STRENGTHS[STRENGTHS.index(strength) + 1]
        if best is None or STRENGTHS.index(strength) > STRENGTHS.index(best[1]):
            best = (pattern, strength)
    return best


class WebUploadScanner:
    """Collects ``web-upload-candidate`` rows while the browser provider streams its rows."""

    def __init__(self, patterns: tuple[UploadPattern, ...] | None = None) -> None:
        self.error = ""
        if patterns is None:
            try:
                patterns = load_upload_patterns()
            except (UploadPatternError, OSError, ModuleNotFoundError) as exc:
                self.error = f"{type(exc).__name__}: {exc}"[:300]
                patterns = ()
        self.patterns = patterns
        self.hosts = tuple({host for pattern in patterns for host in pattern.hosts})
        self.tokens = tuple({token for pattern in patterns for token in pattern.host_contains})
        self.candidates: list[ArtifactRecord] = []
        self.seen: set[tuple[str, str, str, str]] = set()
        self.capped = False

    def _maybe_relevant(self, url: str) -> bool:
        lowered = url[:300].lower()
        return any(host in lowered for host in self.hosts) or any(token in lowered for token in self.tokens)

    def observe(self, record: ArtifactRecord) -> None:
        if record.artifact_type not in SOURCE_TYPES or not self.patterns:
            return
        details = record.details
        url = str(details.get("url") or "")
        if not url or not self._maybe_relevant(url):
            return
        method = str(details.get("method") or "GET")
        matched = match_upload_url(url, method, self.patterns)
        if matched is None:
            return
        pattern, strength = matched
        timestamp = details.get("timestamp")
        key = (str(details.get("browser") or ""), str(details.get("profile") or ""), url, str(timestamp or ""))
        if key in self.seen:
            return
        if len(self.candidates) >= MAX_UPLOAD_CANDIDATES:
            self.capped = True
            return
        self.seen.add(key)
        self.candidates.append(build_upload_candidate(record, pattern, strength, method))


def build_upload_candidate(record: ArtifactRecord, pattern: UploadPattern, strength: str, method: str) -> ArtifactRecord:
    details = record.details
    url = str(details.get("url") or "")
    size = details.get("body_size")
    if not size:
        size = details.get("content_length")
    file_name = str(details.get("file_name_candidate") or "") or file_name_from_url(url)
    signals = []
    if method.upper() in {"POST", "PUT"}:
        signals.append(f"{method.upper()} 요청(캐시 키 업로드 id)" if details.get("method_basis") == "cache-key-upload-id" else f"{method.upper()} 요청")
    signals.append(f"URL 패턴 {pattern.id}")
    fields: dict[str, object] = {
        "parser": UPLOAD_PARSER,
        "parser_version": UPLOAD_PARSER_VERSION,
        "coverage_status": "derived-candidate",
        "recovery_method": "derived",
        "user": details.get("user", ""),
        "browser": details.get("browser", ""),
        "profile": details.get("profile", ""),
        "timestamp": details.get("timestamp"),
        "timestamp_kind": details.get("timestamp_kind", ""),
        "timestamp_timezone": details.get("timestamp_timezone", ""),
        "url": url,
        "host": (urlsplit(url).hostname or "").lower(),
        "service": pattern.service,
        "service_label": pattern.label_ko,
        "category": pattern.category,
        "category_label": CATEGORY_LABELS[pattern.category],
        "strength": strength,
        "strength_label": STRENGTH_LABELS[strength],
        "method": method.upper(),
        "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
        "file_name_candidate": file_name,
        "match_pattern_id": pattern.id,
        "match_basis": pattern.basis,
        "match_sources": list(pattern.sources),
        "signals": signals,
        "source_artifact_type": record.artifact_type,
        "source_path": details.get("source_path") or record.path,
        "source_offset": details.get("source_offset"),
        "source_table": details.get("source_table", ""),
        "source_row_id": details.get("source_row_id"),
        "cache_format": details.get("cache_format", ""),
        "http_status": details.get("http_status"),
        "content_type": details.get("content_type", ""),
        "interpretation_ko": "업로드 흐름의 페이지·엔드포인트가 요청된 흔적(후보). 어떤 파일이 나갔는지는 원본 행·다른 증거로 확인 필요",
    }
    return ArtifactRecord(provider=record.provider, artifact_type="web-upload-candidate", path=record.path, supported=True, details=fields)
