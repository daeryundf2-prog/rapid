from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from .analysis import build_search_analysis
from .docs import build_preview, extract_text
from .files import CATEGORY_RULES
from .forensic_accuracy import build_accuracy_gate

IMAGE_EXTS = set(CATEGORY_RULES["images"]["extensions"])
SEARCH_FEATURE_GAP_ID = "#61"
SEARCH_NATIVE_CAPABILITIES = {
    "exact_search": True,
    "regex_search": True,
    "fuzzy_levenshtein_search": True,
    "simple_suffix_stemming": True,
    "proximity_window_summary": True,
    "full_linguistic_stemming": False,
    "semantic_near_duplicate_search": False,
}
SEARCH_REPORT_GRADE_BLOCKERS = [
    "fuzzy-and-stemmed-search-are-triage-aids-not-exact-source-proof",
    "regex-pattern-quality-is-analyst-controlled-and-must-be-documented",
    "proximity-window-results-require-source-row-verification-before-reporting",
    "trusted-advanced-search-query-hit-diff-is-required-before-commercial-claim",
]
SEARCH_TRUSTED_DIFF_BLOCKER_61 = "trusted-advanced-search-query-hit-diff-missing"


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
    include_analysis: bool = True,
    search_mode: str = "exact",
    fuzzy_distance: int = 1,
    proximity_window: int = 0,
) -> Dict[str, object]:
    summary = load_run_summary(run_summary)
    normalized = normalize_keywords(keywords, search_mode=search_mode)
    if not normalized:
        raise SearchError("at least one keyword is required")
    normalized_search_mode = normalize_search_mode(search_mode)
    normalized_fuzzy_distance = max(0, min(int(fuzzy_distance or 0), 2))
    normalized_proximity_window = max(0, min(int(proximity_window or 0), 100))
    normalized_sources = {item.strip().lower() for item in (sources or []) if item.strip()}
    normalized_extensions = normalize_extensions(extensions or [])
    normalized_path_fragment = (path_contains or "").strip().lower()

    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise SearchError("run summary does not include outputs")

    matches: list[dict[str, object]] = []
    ocr_errors: list[dict[str, str]] = []
    search_options = {
        "search_mode": normalized_search_mode,
        "fuzzy_distance": normalized_fuzzy_distance,
        "proximity_window": normalized_proximity_window,
    }
    matches.extend(search_docs(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_files(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_artifacts(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_indicators(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_timeline(outputs, normalized, limit=limit, search_options=search_options))
    if include_ocr:
        ocr_matches, ocr_errors = search_ocr(outputs, normalized, limit=limit, search_options=search_options)
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

    core_accuracy_gates = search_core_accuracy_gates(matches=matches, options=search_options)
    report_grade = search_report_grade_assessment()
    payload: Dict[str, object] = {
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
            **search_options,
        },
        "summary": {
            "match_count": len(matches),
            "source_counts": source_counts,
            "keyword_counts": keyword_counts,
            "ocr_error_count": len(ocr_errors),
            "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
            "commercial_grade_ready": False,
        },
        "matches": matches,
        "ocr": {
            "enabled": include_ocr,
            "errors": ocr_errors,
        },
        "search_native_capabilities": dict(SEARCH_NATIVE_CAPABILITIES),
        "search_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": search_commercial_uplift_evidence(
            matches=matches,
            options=search_options,
            core_accuracy_gates=core_accuracy_gates,
            report_grade=report_grade,
            limit=limit,
        ),
    }
    if include_analysis:
        payload["analysis"] = build_search_analysis(matches, normalized)
    return payload


def search_commercial_uplift_evidence(
    *,
    matches: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    core_accuracy_gates: Sequence[Mapping[str, object]],
    report_grade: Mapping[str, object],
    limit: int,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == SEARCH_FEATURE_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [61],
        "implementation_track": "advanced-search-query-gate",
        "source_refs": [
            f"match_count:{len(matches)}",
            f"search_mode:{options.get('search_mode', '')}",
            f"proximity_window:{options.get('proximity_window', 0)}",
        ],
        "reportability_decision": search_reportability_decision(
            failed_validation_check_ids=[
                "multilingual-relevance-corpus",
                "query-builder-ux-validation",
                "tuned-false-positive-false-negative-metrics",
                SEARCH_TRUSTED_DIFF_BLOCKER_61,
            ],
            commercial_blockers=list(report_grade.get("blockers") or []),
            options=options,
            match_count=len(matches),
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "multilingual-relevance-corpus",
            "query-builder-ux-validation",
            "tuned-false-positive-false-negative-metrics",
            SEARCH_TRUSTED_DIFF_BLOCKER_61,
        ],
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "result_limit": limit,
            "match_count": len(matches),
            "search_mode": str(options.get("search_mode") or ""),
            "fuzzy_distance": int(options.get("fuzzy_distance") or 0),
            "proximity_window": int(options.get("proximity_window") or 0),
            "full_linguistic_stemming": False,
            "semantic_near_duplicate_search": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def search_reportability_decision(
    *,
    failed_validation_check_ids: Sequence[str],
    commercial_blockers: Sequence[str],
    options: Mapping[str, object],
    match_count: int,
) -> dict[str, object]:
    blockers = {str(item) for item in commercial_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "advanced-search-reportability-decision-v1",
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "decision": "do-not-report-advanced-search-hit-as-source-proof",
        "allowed_use": "advanced-search-triage-pivot",
        "blockers": sorted(blockers),
        "search_mode": str(options.get("search_mode") or ""),
        "match_count": match_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "open and hash-verify source rows for every report candidate",
            "document regex/fuzzy/proximity query rationale and false-positive review",
            "attach language/domain corpus validation before claiming search completeness",
        ],
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


def search_docs(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
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
        matched = match_keywords(text, keywords, search_options=search_options)
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
                "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                "pointer": f"/results/{result_index_by_path[str(path)]}" if str(path) in result_index_by_path else "",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_files(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return []
    matches = []
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        haystack = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
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
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_artifacts(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
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
            matched = match_keywords(haystack, keywords, search_options=search_options)
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
                    "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                    "pointer": f"/artifacts/{index}",
                    "metadata": dict(artifact),
                }
            )
            if limit and len(matches) >= limit:
                return matches
    return matches


def search_timeline(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "timeline")
    if not payload:
        return []
    matches = []
    for index, event in enumerate(payload.get("events", [])):
        if not isinstance(event, Mapping):
            continue
        haystack = json.dumps(event, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
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
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/events/{index}",
                "metadata": dict(event),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_indicators(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "indicators")
    if not payload:
        return []
    matches = []
    for index, indicator in enumerate(payload.get("indicators", [])):
        if not isinstance(indicator, Mapping):
            continue
        haystack = json.dumps(indicator, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
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
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
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
    search_options: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return [], []
    matches = []
    errors: list[dict[str, str]] = []
    sidecar_matched_candidate_indices: set[int] = set()
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        path = Path(str(candidate.get("path", "")))
        if path.suffix.lower() not in IMAGE_EXTS:
            continue
        for sidecar in find_ocr_sidecars(path):
            try:
                text = sidecar.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append({"path": str(sidecar), "error": str(exc)})
                continue
            matched = match_keywords(text, keywords, search_options=search_options)
            if not matched:
                continue
            matches.append(
                {
                    "source": "ocr",
                    "kind": f"{path.suffix.lower().lstrip('.')}-sidecar",
                    "path": str(path),
                    "title": f"{path.name} OCR sidecar",
                    "matched_keywords": matched,
                    "preview": build_preview(text, matched[0]),
                    "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                    "pointer": f"/candidates/{index}",
                    "metadata": {
                        **dict(candidate),
                        "ocr_source": "sidecar",
                        "ocr_sidecar_path": str(sidecar),
                    },
                }
            )
            sidecar_matched_candidate_indices.add(index)
            if limit and len(matches) >= limit:
                return matches, errors
    try:
        import cv2
        import pytesseract
    except ImportError as exc:
        if matches:
            errors.append({"path": "", "error": f"OCR engine dependencies unavailable after sidecar search: {exc}"})
            return matches, errors
        return [], [{"path": "", "error": f"OCR dependencies unavailable: {exc}"}]

    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        if index in sidecar_matched_candidate_indices:
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
        matched = match_keywords(text, keywords, search_options=search_options)
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
                "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches, errors


def find_ocr_sidecars(path: Path) -> list[Path]:
    candidates = [
        path.with_suffix(path.suffix + ".ocr.txt"),
        path.with_suffix(path.suffix + ".txt"),
        path.with_suffix(".ocr.txt"),
        path.with_suffix(".txt"),
        path.with_suffix(".srt"),
        path.with_suffix(".vtt"),
    ]
    output = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        output.append(candidate)
    return output


def normalize_search_mode(value: str) -> str:
    normalized = str(value or "exact").strip().lower()
    supported = {"exact", "fuzzy", "regex"}
    if normalized not in supported:
        raise SearchError(f"unsupported search mode: {value!r}; expected one of: {', '.join(sorted(supported))}")
    return normalized


def normalize_keywords(keywords: Sequence[str], *, search_mode: str) -> list[str]:
    mode = normalize_search_mode(search_mode)
    output = []
    seen = set()
    for item in keywords:
        keyword = str(item or "").strip()
        if not keyword:
            continue
        normalized = keyword if mode == "regex" else keyword.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def match_keywords(
    text: str,
    keywords: Sequence[str],
    *,
    search_options: Mapping[str, object] | None = None,
) -> list[str]:
    options = search_options or {}
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    if mode == "regex":
        return [keyword for keyword in keywords if regex_keyword_matches(text, keyword)]
    if mode == "fuzzy":
        max_distance = max(0, min(int(options.get("fuzzy_distance") or 1), 2))
        return [keyword for keyword in keywords if fuzzy_keyword_matches(text, keyword, max_distance=max_distance)]
    lower = text.lower()
    return [keyword for keyword in keywords if exact_or_stem_matches(lower, keyword)]


def regex_keyword_matches(text: str, pattern: str) -> bool:
    try:
        return re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        return False


def exact_or_stem_matches(lower_text: str, keyword: str) -> bool:
    if keyword in lower_text:
        return True
    if not is_simple_word(keyword):
        return False
    tokens = set(tokenize_words(lower_text))
    return any(stem in tokens for stem in keyword_stems(keyword))


def fuzzy_keyword_matches(text: str, keyword: str, *, max_distance: int) -> bool:
    lower = text.lower()
    if exact_or_stem_matches(lower, keyword):
        return True
    if not is_simple_word(keyword):
        return False
    keyword_variants = keyword_stems(keyword)
    for token in tokenize_words(lower):
        if abs(len(token) - len(keyword)) > max_distance + 1:
            continue
        if any(levenshtein_distance(token, variant, max_distance=max_distance) <= max_distance for variant in keyword_variants):
            return True
    return False


def build_search_match_metadata(
    text: str,
    keywords: Sequence[str],
    *,
    search_options: Mapping[str, object] | None = None,
) -> dict[str, object]:
    options = search_options or {}
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    proximity_window = max(0, min(int(options.get("proximity_window") or 0), 100))
    metadata: dict[str, object] = {
        "mode": mode,
        "matched_by": mode,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "ready_for_court_report": False,
    }
    if mode == "fuzzy":
        metadata["fuzzy_distance"] = max(0, min(int(options.get("fuzzy_distance") or 1), 2))
        metadata["matched_by"] = "fuzzy-or-stem"
    if proximity_window and len(keywords) >= 2:
        proximity = proximity_summary(text, keywords, window=proximity_window)
        metadata["proximity"] = proximity
        if proximity.get("matched"):
            metadata["matched_by"] = f"{metadata['matched_by']}+proximity"
    return metadata


def build_advanced_search_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "query-hit-manifest",
) -> dict[str, object]:
    rapid_index = {advanced_search_diff_key(row): advanced_search_diff_value(row) for row in rapid_rows}
    trusted_index = {advanced_search_diff_key(row): advanced_search_diff_value(row) for row in trusted_rows}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "advanced-search-trusted-query-hit-diff-v1",
        "item_number": 61,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def advanced_search_diff_key(row: Mapping[str, object]) -> str:
    return "|".join(
        [
            str(row.get("source") or ""),
            str(row.get("path") or row.get("title") or ""),
            str(row.get("pointer") or row.get("offset") or ""),
            ",".join(str(item) for item in row.get("matched_keywords") or row.get("keywords") or []),
        ]
    )


def advanced_search_diff_value(row: Mapping[str, object]) -> dict[str, object]:
    search_match = row.get("search_match")
    search_match_map = search_match if isinstance(search_match, Mapping) else {}
    proximity = search_match_map.get("proximity")
    return {
        "mode": str(search_match_map.get("mode") or row.get("mode") or ""),
        "matched_by": str(search_match_map.get("matched_by") or row.get("matched_by") or ""),
        "proximity_matched": bool(proximity.get("matched")) if isinstance(proximity, Mapping) else bool(row.get("proximity_matched")),
        "preview": str(row.get("preview") or "")[:160],
    }


def search_report_grade_assessment(*, trusted_diff: Mapping[str, object] | None = None) -> dict[str, object]:
    blockers = list(SEARCH_REPORT_GRADE_BLOCKERS)
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(SEARCH_TRUSTED_DIFF_BLOCKER_61)
    return {
        "component": "fuzzy-regex-stemming-proximity-search",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Record the exact query mode/options with any cited hit.",
            "Open the source viewer and verify the row, offset, hash, and parser limitations before report inclusion.",
        ],
        "trusted_diff": trusted_diff or {
            "status": "missing",
            "blocker": SEARCH_TRUSTED_DIFF_BLOCKER_61,
        },
    }


def search_core_accuracy_gates(
    *,
    matches: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["query mode and options recorded", "source verification limitation warning"]
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    if mode in {"exact", "fuzzy", "regex"} and SEARCH_NATIVE_CAPABILITIES["fuzzy_levenshtein_search"]:
        satisfied.append("fuzzy/stemming/regex matching available")
    if int(options.get("proximity_window") or 0) > 0:
        satisfied.append("proximity metadata preserved")
    if any(match.get("pointer") for match in matches):
        satisfied.append("matched hit source pointers")
    evidence_refs = [
        f"search_mode:{mode}",
        f"match_count:{len(matches)}",
        f"proximity_window:{int(options.get('proximity_window') or 0)}",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted advanced-search query-hit diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            61,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def proximity_summary(text: str, keywords: Sequence[str], *, window: int) -> dict[str, object]:
    tokens = tokenize_words(text.lower())
    if not tokens:
        return {"matched": False, "window": window}
    positions: dict[str, list[int]] = {}
    for keyword in keywords:
        if not is_simple_word(keyword):
            continue
        stems = set(keyword_stems(keyword))
        hits = [index for index, token in enumerate(tokens) if token == keyword or token in stems]
        if hits:
            positions[keyword] = hits
    if len(positions) < 2:
        return {"matched": False, "window": window, "matched_keyword_count": len(positions)}
    nearest: tuple[int, str, str] | None = None
    items = list(positions.items())
    for left_index, (left_keyword, left_positions) in enumerate(items):
        for right_keyword, right_positions in items[left_index + 1 :]:
            for left_pos in left_positions:
                for right_pos in right_positions:
                    distance = abs(left_pos - right_pos)
                    if nearest is None or distance < nearest[0]:
                        nearest = (distance, left_keyword, right_keyword)
    matched = nearest is not None and nearest[0] <= window
    return {
        "matched": matched,
        "window": window,
        "nearest_distance": nearest[0] if nearest else None,
        "nearest_keywords": [nearest[1], nearest[2]] if nearest else [],
        "matched_keyword_count": len(positions),
    }


def tokenize_words(text: str) -> list[str]:
    return re.findall(r"[\w가-힣]{2,}", text.lower())


def is_simple_word(value: str) -> bool:
    return re.fullmatch(r"[\w가-힣]{2,}", value.lower()) is not None


def keyword_stems(keyword: str) -> set[str]:
    lower = keyword.lower()
    stems = {lower}
    for suffix in ("ing", "edly", "edly", "ed", "es", "s"):
        if len(lower) > len(suffix) + 3 and lower.endswith(suffix):
            stems.add(lower[: -len(suffix)])
    return stems


def levenshtein_distance(left: str, right: str, *, max_distance: int) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_min = current[0]
        for right_index, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            value = min(
                current[right_index - 1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + cost,
            )
            current.append(value)
            row_min = min(row_min, value)
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


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
