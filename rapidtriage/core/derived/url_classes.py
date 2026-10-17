"""URL classes of the 통합 보기 › URL 분류 table (``url_classes.yaml``, plan axiom-adoption §3.2)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

URL_CLASSES_PATH = Path(__file__).with_name("url_classes.yaml")
CLASS_ID = re.compile(r"^[a-z][a-z0-9_-]*$")
DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


class UrlClassError(ValueError):
    """``url_classes.yaml`` is malformed (Korean message)."""


@dataclass(frozen=True)
class UrlClasses:
    version: str
    labels: Mapping[str, str]
    sources: Mapping[str, tuple[str, ...]]
    # domain -> class id
    domains: Mapping[str, str] = field(default_factory=dict)

    def classify(self, host: str) -> str | None:
        """Class of ``host``: the longest listed domain equal to it or a parent of it."""
        parts = host.lower().strip(".").split(".")
        for start in range(len(parts) - 1):
            found = self.domains.get(".".join(parts[start:]))
            if found is not None:
                return found
        return None


def parse_url_classes(data: bytes) -> UrlClasses:
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
        raise UrlClassError("URL 분류 규칙을 읽으려면 PyYAML이 필요합니다 (pip install pyyaml)") from exc
    try:
        document = yaml.safe_load(data.decode("utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise UrlClassError(f"URL 분류 규칙 YAML을 읽을 수 없습니다: {exc}") from exc
    classes = document.get("classes") if isinstance(document, Mapping) else None
    if not isinstance(classes, list) or not classes:
        raise UrlClassError("URL 분류 규칙에 classes 목록이 없습니다")
    labels: dict[str, str] = {}
    sources: dict[str, tuple[str, ...]] = {}
    domains: dict[str, str] = {}
    for entry in classes:
        class_id = str(entry.get("id") or "") if isinstance(entry, Mapping) else ""
        if not CLASS_ID.fullmatch(class_id) or class_id in labels:
            raise UrlClassError(f"URL 분류 id가 올바르지 않거나 중복됩니다: {class_id!r}")
        label = entry.get("label_ko")
        urls = entry.get("sources")
        listed = entry.get("domains")
        if not isinstance(label, str) or not label:
            raise UrlClassError(f"URL 분류 {class_id}에 label_ko가 없습니다")
        if not isinstance(urls, list) or not urls or not all(isinstance(url, str) and url.startswith("https://") for url in urls):
            raise UrlClassError(f"URL 분류 {class_id}의 sources는 https URL 목록이어야 합니다")
        if not isinstance(listed, list) or not listed:
            raise UrlClassError(f"URL 분류 {class_id}에 domains 목록이 없습니다")
        for domain in listed:
            if not isinstance(domain, str) or not DOMAIN.fullmatch(domain):
                raise UrlClassError(f"URL 분류 {class_id}의 도메인 형식이 아닙니다: {domain!r}")
            if domain in domains:
                raise UrlClassError(f"도메인 {domain}이(가) 두 분류에 있습니다")
            domains[domain] = class_id
        labels[class_id] = label
        sources[class_id] = tuple(urls)
    return UrlClasses(version=hashlib.sha256(data).hexdigest()[:16], labels=labels, sources=sources, domains=domains)


_CACHE: dict[tuple[str, int, int], UrlClasses] = {}


def load_url_classes(path: Path | None = None) -> UrlClasses:
    target = Path(path) if path is not None else URL_CLASSES_PATH
    stat = target.stat()
    key = (str(target), stat.st_size, stat.st_mtime_ns)
    cached = _CACHE.get(key)
    if cached is None:
        cached = parse_url_classes(target.read_bytes())
        _CACHE.clear()
        _CACHE[key] = cached
    return cached
