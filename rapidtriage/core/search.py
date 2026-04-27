from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from .docs import build_preview, extract_text
from .files import CATEGORY_RULES

IMAGE_EXTS = set(CATEGORY_RULES["images"]["extensions"])


class SearchError(ValueError):
    """Raised when unified search cannot load a completed run."""


def run_unified_search(
    run_summary: Mapping[str, object] | Path,
    keywords: Sequence[str],
    *,
    include_ocr: bool = True,
    limit: int = 500,
    sources: Sequence[str] | None = None,
    extensions: Sequence[str] | None = None,
    path_contains: str | None = None,
) -> Dict[str, object]:
    summary = load_run_summary(run_summary)
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise SearchError("at least one keyword is required")
    normalized_sources = {item.strip().lower() for item in (sources or []) if item.strip()}
    normalized_extensions = normalize_extensions(extensions or [])
    normalized_path_fragment = (path_contains or "").strip().lower()

    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise SearchError("run summary does not include outputs")

    matches: list[dict[str, object]] = []
    ocr_errors: list[dict[str, str]] = []
    matches.extend(search_docs(outputs, normalized, limit=limit))
    matches.extend(search_files(outputs, normalized, limit=limit))
    matches.extend(search_artifacts(outputs, normalized, limit=limit))
    matches.extend(search_indicators(outputs, normalized, limit=limit))
    matches.extend(search_timeline(outputs, normalized, limit=limit))
    if include_ocr:
        ocr_matches, ocr_errors = search_ocr(outputs, normalized, limit=limit)
        matches.extend(ocr_matches)
    matches = filter_matches(
        matches,
        sources=normalized_sources,
        extensions=normalized_extensions,
        path_fragment=normalized_path_fragment,
    )

    if limit:
        matches = matches[:limit]
    source_counts: dict[str, int] = {}
    keyword_counts: dict[str, int] = {keyword: 0 for keyword in normalized}
    for match in matches:
        source = str(match.get("source", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
        for keyword in match.get("matched_keywords", []):
            keyword_counts[str(keyword)] = keyword_counts.get(str(keyword), 0) + 1

    return {
        "command": "search",
        "generated_at": dt.datetime.now().isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary", "")),
        "keywords": normalized,
        "options": {
            "include_ocr": include_ocr,
            "limit": limit,
            "sources": sorted(normalized_sources),
            "extensions": sorted(normalized_extensions),
            "path_contains": normalized_path_fragment,
        },
        "summary": {
            "match_count": len(matches),
            "source_counts": source_counts,
            "keyword_counts": keyword_counts,
            "ocr_error_count": len(ocr_errors),
        },
        "matches": matches,
        "ocr": {
            "enabled": include_ocr,
            "errors": ocr_errors,
        },
    }


def load_run_summary(run_summary: Mapping[str, object] | Path) -> Mapping[str, object]:
    if isinstance(run_summary, Mapping):
        return run_summary
    path = Path(run_summary).expanduser().resolve()
    if path.is_dir():
        path = path / "rapidtriage-run-summary.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SearchError(f"run summary not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SearchError(f"invalid run summary JSON: {path}") from exc


def search_docs(outputs: Mapping[str, object], keywords: Sequence[str], *, limit: int) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "docs")
    if not payload:
        return []
    matches = []
    result_index_by_path = {
        str(item.get("path")): index
        for index, item in enumerate(payload.get("results", []))
        if isinstance(item, Mapping) and item.get("path")
    }
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        path = Path(str(candidate.get("path", "")))
        kind = str(candidate.get("kind", ""))
        try:
            text = extract_text(path, kind)
        except Exception:
            text = ""
        matched = match_keywords(text, keywords)
        if not matched:
            continue
        matches.append(
            {
                "source": "documents",
                "kind": kind,
                "path": str(path),
                "title": path.name,
                "matched_keywords": matched,
                "preview": build_preview(text, matched[0]),
                "pointer": f"/results/{result_index_by_path[str(path)]}" if str(path) in result_index_by_path else "",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_files(outputs: Mapping[str, object], keywords: Sequence[str], *, limit: int) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return []
    matches = []
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        haystack = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords)
        if not matched:
            continue
        path = str(candidate.get("path", ""))
        matches.append(
            {
                "source": "files",
                "kind": ",".join(str(item) for item in candidate.get("categories", [])),
                "path": path,
                "title": str(candidate.get("name") or Path(path).name),
                "matched_keywords": matched,
                "preview": path,
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_artifacts(outputs: Mapping[str, object], keywords: Sequence[str], *, limit: int) -> list[dict[str, object]]:
    matches = []
    for output_name, raw_path in sorted(outputs.items()):
        name = str(output_name)
        if not name.startswith("artifacts_"):
            continue
        payload = read_json_path(Path(str(raw_path)))
        if not payload:
            continue
        artifact_kind = name.removeprefix("artifacts_")
        source = "web" if artifact_kind == "browser" else "artifacts"
        for index, artifact in enumerate(payload.get("artifacts", [])):
            if not isinstance(artifact, Mapping):
                continue
            haystack = json.dumps(artifact, ensure_ascii=False, sort_keys=True)
            matched = match_keywords(haystack, keywords)
            if not matched:
                continue
            path = str(artifact.get("path", ""))
            title = str(artifact.get("artifact_type") or artifact_kind)
            matches.append(
                {
                    "source": source,
                    "kind": artifact_kind,
                    "path": path,
                    "title": title,
                    "matched_keywords": matched,
                    "preview": compact_json_preview(artifact),
                    "pointer": f"/artifacts/{index}",
                    "metadata": dict(artifact),
                }
            )
            if limit and len(matches) >= limit:
                return matches
    return matches


def search_timeline(outputs: Mapping[str, object], keywords: Sequence[str], *, limit: int) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "timeline")
    if not payload:
        return []
    matches = []
    for index, event in enumerate(payload.get("events", [])):
        if not isinstance(event, Mapping):
            continue
        haystack = json.dumps(event, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords)
        if not matched:
            continue
        matches.append(
            {
                "source": "timeline",
                "kind": str(event.get("event_type", "")),
                "path": str(event.get("path", "")),
                "title": str(event.get("summary", "timeline event")),
                "matched_keywords": matched,
                "preview": compact_json_preview(event),
                "pointer": f"/events/{index}",
                "metadata": dict(event),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_indicators(outputs: Mapping[str, object], keywords: Sequence[str], *, limit: int) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "indicators")
    if not payload:
        return []
    matches = []
    for index, indicator in enumerate(payload.get("indicators", [])):
        if not isinstance(indicator, Mapping):
            continue
        haystack = json.dumps(indicator, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords)
        if not matched:
            continue
        sources = indicator.get("sources")
        first_source = sources[0] if isinstance(sources, list) and sources and isinstance(sources[0], Mapping) else {}
        path = str(first_source.get("path") or first_source.get("source_path") or "")
        indicator_type = str(indicator.get("type") or "indicator")
        indicator_value = str(indicator.get("value") or "")
        matches.append(
            {
                "source": "indicators",
                "kind": indicator_type,
                "path": path,
                "title": f"{indicator_type}: {indicator_value}" if indicator_value else indicator_type,
                "matched_keywords": matched,
                "preview": compact_json_preview(indicator),
                "pointer": f"/indicators/{index}",
                "metadata": dict(indicator),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_ocr(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return [], []
    try:
        import cv2
        import pytesseract
    except ImportError as exc:
        return [], [{"path": "", "error": f"OCR dependencies unavailable: {exc}"}]

    matches = []
    errors: list[dict[str, str]] = []
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        path = Path(str(candidate.get("path", "")))
        if path.suffix.lower() not in IMAGE_EXTS:
            continue
        try:
            image = cv2.imread(str(path))
            if image is None:
                raise OSError("image could not be decoded")
            text = pytesseract.image_to_string(image)
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        matched = match_keywords(text, keywords)
        if not matched:
            continue
        matches.append(
            {
                "source": "ocr",
                "kind": path.suffix.lower().lstrip("."),
                "path": str(path),
                "title": path.name,
                "matched_keywords": matched,
                "preview": build_preview(text, matched[0]),
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches, errors


def match_keywords(text: str, keywords: Sequence[str]) -> list[str]:
    lower = text.lower()
    return [keyword for keyword in keywords if keyword in lower]


def normalize_extensions(values: Sequence[str]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        item = value.strip().lower()
        if not item:
            continue
        normalized.add(item if item.startswith(".") else f".{item}")
    return normalized


def filter_matches(
    matches: Sequence[Mapping[str, object]],
    *,
    sources: set[str],
    extensions: set[str],
    path_fragment: str,
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for match in matches:
        source = str(match.get("source") or "").lower()
        path = str(match.get("path") or "")
        suffix = Path(path).suffix.lower()
        if sources and source not in sources:
            continue
        if extensions and suffix not in extensions:
            continue
        if path_fragment and path_fragment not in path.lower():
            continue
        filtered.append(dict(match))
    return filtered


def read_json_output(outputs: Mapping[str, object], name: str) -> Mapping[str, object] | None:
    raw_path = outputs.get(name)
    if not raw_path:
        return None
    return read_json_path(Path(str(raw_path)))


def read_json_path(path: Path) -> Mapping[str, object] | None:
    try:
        payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def compact_json_preview(value: Any, *, limit: int = 240) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text[:limit] + ("..." if len(text) > limit else "")
