from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence
from urllib.parse import urlparse
from xml.etree import ElementTree as ET


class RuleConfigError(ValueError):
    """Raised when a rapidtriage rule file is invalid."""


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    ext: tuple[str, ...] = ()
    path_terms: tuple[str, ...] = ()
    artifact_types: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    date_after: str | None = None
    date_before: str | None = None
    date_on: str | None = None


@dataclass(frozen=True)
class RuleSet:
    path: str
    format: str
    rules: tuple[Rule, ...]

    @property
    def rule_count(self) -> int:
        return len(self.rules)


@dataclass
class RecordContext:
    path: str = ""
    extension: str = ""
    artifact_type: str = ""
    timestamp: str | None = None
    text_values: tuple[str, ...] = ()
    url_values: tuple[str, ...] = ()
    domain_values: tuple[str, ...] = ()
    hash_path: str | None = None


HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"https?://[^\s\]\[\)\(\}\{\"'<>]+", re.IGNORECASE)
DOMAIN_LITERAL_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{", re.IGNORECASE)
YARA_SECTION_RE = re.compile(r"(?m)^\s*(meta|strings|condition)\s*:", re.IGNORECASE)
YARA_STRING_RE = re.compile(
    r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<literal>\"(?:\\.|[^\"\\])*\")(?P<modifiers>[^\r\n]*)",
    re.IGNORECASE,
)
YARA_META_TEXT_RE = re.compile(
    r"(?m)^\s*(?:description|desc)\s*=\s*(?P<literal>\"(?:\\.|[^\"\\])*\")",
    re.IGNORECASE,
)
TEXT_EXTS = {".txt", ".md", ".log", ".json", ".csv", ".tsv", ".xml"}
DOC_EXTS = {".docx", ".pdf"}
YARA_RULE_EXTS = {".yar", ".yara"}
MAX_YARA_STRING_LITERAL_LENGTH = 1024


class _RuleEvaluator:
    def __init__(self, rule_set: RuleSet) -> None:
        self.rule_set = rule_set
        self._hash_cache: Dict[str, str | None] = {}

    def annotate_items(self, items: Sequence[MutableMapping[str, object]], contexts: Sequence[RecordContext]) -> Dict[str, object]:
        for item, context in zip(items, contexts):
            matched_rules, ioc_hits = self.evaluate_context(context)
            if matched_rules:
                item["matched_rules"] = matched_rules
            if ioc_hits:
                item["ioc_hits"] = ioc_hits
        return summarize_annotated_items(items)

    def evaluate_context(self, context: RecordContext) -> tuple[list[str], list[Dict[str, object]]]:
        matched_rules: list[str] = []
        ioc_hits: list[Dict[str, object]] = []
        for rule in self.rule_set.rules:
            rule_hits = self._evaluate_rule(rule, context)
            if rule_hits is None:
                continue
            matched_rules.append(rule.id)
            ioc_hits.extend(rule_hits)
        return matched_rules, dedupe_ioc_hits(ioc_hits)

    def _evaluate_rule(self, rule: Rule, context: RecordContext) -> list[Dict[str, object]] | None:
        path_lower = context.path.lower()
        extension = context.extension.lower()
        artifact_type = context.artifact_type.lower()
        normalized_text = [value.lower() for value in context.text_values if value]
        normalized_urls = [value.lower() for value in context.url_values if value]
        normalized_domains = [value.lower() for value in context.domain_values if value]

        if rule.ext and extension not in rule.ext:
            return None
        if rule.path_terms and not any(term in path_lower for term in rule.path_terms):
            return None
        if rule.artifact_types and artifact_type not in rule.artifact_types:
            return None
        if not matches_timestamp(context.timestamp, rule):
            return None

        rule_hits: list[Dict[str, object]] = []

        keyword_hits = match_substrings(rule.keywords, normalized_text)
        if rule.keywords and not keyword_hits:
            return None
        rule_hits.extend(build_ioc_hits(rule.id, "keyword", keyword_hits))

        hash_hits = match_hashes(rule.hashes, self._resolve_hash(context.hash_path))
        if rule.hashes and not hash_hits:
            return None
        rule_hits.extend(build_ioc_hits(rule.id, "hash", hash_hits))

        domain_hits = match_domains(rule.domains, normalized_domains, normalized_urls, normalized_text)
        if rule.domains and not domain_hits:
            return None
        rule_hits.extend(build_ioc_hits(rule.id, "domain", domain_hits))

        url_hits = match_urls(rule.urls, normalized_urls, normalized_text)
        if rule.urls and not url_hits:
            return None
        rule_hits.extend(build_ioc_hits(rule.id, "url", url_hits))

        return rule_hits

    def _resolve_hash(self, path: str | None) -> str | None:
        if not path:
            return None
        if path not in self._hash_cache:
            self._hash_cache[path] = compute_sha256(path)
        return self._hash_cache[path]


def load_rule_set(path: Path | str) -> RuleSet:
    rule_path = Path(path).expanduser().resolve()
    text = rule_path.read_text(encoding="utf-8")
    format_name = detect_rule_format(rule_path, text)
    if format_name == "yara-lite":
        rules = parse_yara_lite_rules(text, rule_path)
        if not rules:
            raise RuleConfigError(f"YARA rule file did not contain supported string IOC rules: {rule_path}")
        return RuleSet(path=str(rule_path), format=format_name, rules=tuple(rules))
    if format_name == "json":
        data = json.loads(text)
    else:
        data = parse_simple_yaml(text)
    raw_rules = normalize_rule_root(data)
    rules = tuple(normalize_rule(index, raw_rule) for index, raw_rule in enumerate(raw_rules, start=1))
    if not rules:
        raise RuleConfigError(f"rule file must contain at least one rule: {rule_path}")
    return RuleSet(path=str(rule_path), format=format_name, rules=rules)


def detect_rule_format(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    stripped = text.lstrip()
    if suffix in YARA_RULE_EXTS or YARA_RULE_RE.search(stripped):
        return "yara-lite"
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"}:
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        return "yaml"
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    return "yaml"


@dataclass(frozen=True)
class YaraStringDefinition:
    name: str
    value: str
    modifiers: tuple[str, ...] = ()


def parse_yara_lite_rules(text: str, path: Path) -> list[Rule]:
    """Import a safe YARA subset as local IOC string rules.

    This is intentionally not a native YARA engine. It extracts literal strings
    from standard ``strings:`` sections and maps them into the existing bounded
    rule matcher so analysts can reuse simple IOC-focused .yar files without
    implying full grammar or malware-engine parity.
    """

    rules: list[Rule] = []
    stripped = strip_yara_comments(text)
    for rule_name, body in iter_yara_rule_blocks(stripped):
        strings_section = yara_section(body, "strings")
        string_defs = parse_yara_string_definitions(strings_section)
        if not string_defs:
            continue
        condition = yara_section(body, "condition")
        selected = select_yara_strings_for_condition(string_defs, condition)
        if not selected:
            selected = string_defs
        description = parse_yara_description(yara_section(body, "meta")) or f"Imported YARA string rule from {path.name}"
        if yara_condition_requires_all(condition):
            rule = build_rule_from_yara_strings(rule_name, description, selected)
            if rule_has_terms(rule):
                rules.append(rule)
            continue
        for string_def in selected:
            rule = build_rule_from_yara_strings(rule_name, description, [string_def])
            if rule_has_terms(rule):
                rules.append(rule)
    return dedupe_rules(rules)


def strip_yara_comments(text: str) -> str:
    result: list[str] = []
    index = 0
    in_string = False
    escape = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            result.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            newline = text.find("\n", index)
            if newline == -1:
                break
            result.append("\n")
            index = newline + 1
            continue
        if char == "/" and next_char == "*":
            end = text.find("*/", index + 2)
            comment = text[index + 2 : end if end != -1 else len(text)]
            result.extend("\n" for _ in range(comment.count("\n")))
            index = len(text) if end == -1 else end + 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def iter_yara_rule_blocks(text: str) -> Iterable[tuple[str, str]]:
    search_pos = 0
    while True:
        match = YARA_RULE_RE.search(text, search_pos)
        if match is None:
            return
        open_brace = text.find("{", match.end() - 1)
        close_brace = find_matching_yara_brace(text, open_brace)
        if open_brace == -1 or close_brace is None:
            raise RuleConfigError(f"invalid YARA rule block near {match.group(1)!r}")
        yield match.group(1), text[open_brace + 1 : close_brace]
        search_pos = close_brace + 1


def find_matching_yara_brace(text: str, open_brace: int) -> int | None:
    depth = 0
    in_string = False
    escape = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def yara_section(body: str, section_name: str) -> str:
    matches = list(YARA_SECTION_RE.finditer(body))
    for index, match in enumerate(matches):
        if match.group(1).lower() != section_name.lower():
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        return body[match.end() : end].strip()
    return ""


def parse_yara_string_definitions(section: str) -> list[YaraStringDefinition]:
    definitions: list[YaraStringDefinition] = []
    for match in YARA_STRING_RE.finditer(section):
        value = decode_yara_string_literal(match.group("literal"))
        if not value or len(value) > MAX_YARA_STRING_LITERAL_LENGTH:
            continue
        modifiers = tuple(item.lower() for item in match.group("modifiers").split() if item.strip())
        definitions.append(YaraStringDefinition(name=match.group("name"), value=value, modifiers=modifiers))
    return definitions


def decode_yara_string_literal(literal: str) -> str:
    inner = literal[1:-1]
    result: list[str] = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        if index + 1 >= len(inner):
            result.append("\\")
            break
        escape = inner[index + 1]
        if escape == "x" and index + 3 < len(inner):
            hex_value = inner[index + 2 : index + 4]
            try:
                result.append(chr(int(hex_value, 16)))
                index += 4
                continue
            except ValueError:
                pass
        result.append({"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}.get(escape, escape))
        index += 2
    return "".join(result).strip()


def parse_yara_description(meta_section: str) -> str | None:
    match = YARA_META_TEXT_RE.search(meta_section)
    if match is None:
        return None
    return decode_yara_string_literal(match.group("literal")) or None


def select_yara_strings_for_condition(
    string_defs: Sequence[YaraStringDefinition],
    condition: str,
) -> list[YaraStringDefinition]:
    referenced_names = {match.lower() for match in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", condition)}
    if not referenced_names:
        return list(string_defs)
    return [item for item in string_defs if item.name.lower() in referenced_names]


def yara_condition_requires_all(condition: str) -> bool:
    lowered = f" {condition.lower()} "
    if " all of " in lowered:
        return True
    if " and " in lowered and " or " not in lowered:
        return True
    return False


def build_rule_from_yara_strings(
    rule_name: str,
    description: str,
    string_defs: Sequence[YaraStringDefinition],
) -> Rule:
    keywords: set[str] = set()
    hashes: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()
    for string_def in string_defs:
        value = string_def.value.strip().lower()
        if not value:
            continue
        if HASH_RE.fullmatch(value):
            hashes.add(value)
        elif URL_RE.fullmatch(value):
            urls.add(value)
        elif is_domain_literal(value):
            domains.add(value)
        else:
            keywords.add(value)
    return Rule(
        id=rule_name,
        description=description,
        keywords=tuple(sorted(keywords)),
        hashes=tuple(sorted(hashes)),
        domains=tuple(sorted(domains)),
        urls=tuple(sorted(urls)),
    )


def is_domain_literal(value: str) -> bool:
    return bool(DOMAIN_LITERAL_RE.fullmatch(value)) and " " not in value and "/" not in value


def rule_has_terms(rule: Rule) -> bool:
    return any((rule.keywords, rule.hashes, rule.domains, rule.urls))


def dedupe_rules(rules: Sequence[Rule]) -> list[Rule]:
    deduped: list[Rule] = []
    seen: set[tuple[object, ...]] = set()
    for rule in rules:
        key = (rule.id, rule.keywords, rule.hashes, rule.domains, rule.urls)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rule)
    return deduped


def normalize_rule_root(data: object) -> list[Mapping[str, object]]:
    if isinstance(data, dict):
        rules = data.get("rules", [])
    else:
        rules = data
    if not isinstance(rules, list):
        raise RuleConfigError("rule file must contain a top-level list or a 'rules' list")
    normalized: list[Mapping[str, object]] = []
    for index, item in enumerate(rules, start=1):
        if not isinstance(item, dict):
            raise RuleConfigError(f"rule #{index} must be an object")
        normalized.append(item)
    return normalized


def normalize_rule(index: int, raw_rule: Mapping[str, object]) -> Rule:
    raw_conditions = raw_rule.get("conditions")
    merged: Dict[str, object] = dict(raw_conditions) if isinstance(raw_conditions, dict) else {}
    merged.update(raw_rule)

    rule_id = str(merged.get("id") or merged.get("name") or f"rule-{index}").strip()
    if not rule_id:
        raise RuleConfigError(f"rule #{index} must define a non-empty id")

    date_config = merged.get("date") if isinstance(merged.get("date"), dict) else {}
    return Rule(
        id=rule_id,
        description=str(merged.get("description") or merged.get("title") or rule_id),
        ext=tuple(normalize_extensions(merged.get("ext") or merged.get("extensions"))),
        path_terms=tuple(normalize_text_list(merged.get("path") or merged.get("path_contains"))),
        artifact_types=tuple(normalize_text_list(merged.get("artifact") or merged.get("artifact_type") or merged.get("artifacts"))),
        keywords=tuple(normalize_text_list(merged.get("keyword") or merged.get("keywords"))),
        hashes=tuple(normalize_hashes(merged.get("hash") or merged.get("hashes") or merged.get("sha256"))),
        domains=tuple(normalize_text_list(merged.get("domain") or merged.get("domains"))),
        urls=tuple(normalize_text_list(merged.get("url") or merged.get("urls"))),
        date_after=normalize_optional_text(merged.get("date_after") or date_config.get("after")),
        date_before=normalize_optional_text(merged.get("date_before") or date_config.get("before")),
        date_on=normalize_optional_text(merged.get("date_on") or date_config.get("on")),
    )


def annotate_files_payload(payload: MutableMapping[str, object], rule_set: RuleSet) -> MutableMapping[str, object]:
    candidates = [item for item in payload.get("candidates", []) if isinstance(item, dict)]
    evaluator = _RuleEvaluator(rule_set)
    contexts = [context_from_file_candidate(item) for item in candidates]
    apply_annotation_summary(payload, evaluator.annotate_items(candidates, contexts), rule_set)
    return payload


def annotate_docs_payload(
    payload: MutableMapping[str, object],
    rule_set: RuleSet,
    *,
    text_by_path: Mapping[str, str] | None = None,
) -> MutableMapping[str, object]:
    results = [item for item in payload.get("results", []) if isinstance(item, dict)]
    candidates_by_path = {
        str(item.get("path")): item
        for item in payload.get("candidates", [])
        if isinstance(item, dict) and item.get("path")
    }
    evaluator = _RuleEvaluator(rule_set)
    contexts = [
        context_from_doc_result(item, candidates_by_path.get(str(item.get("path")), {}), text_by_path=text_by_path)
        for item in results
    ]
    apply_annotation_summary(payload, evaluator.annotate_items(results, contexts), rule_set)
    return payload


def annotate_artifacts_payload(payload: MutableMapping[str, object], rule_set: RuleSet) -> MutableMapping[str, object]:
    artifacts = [item for item in payload.get("artifacts", []) if isinstance(item, dict)]
    evaluator = _RuleEvaluator(rule_set)
    contexts = [context_from_artifact(item) for item in artifacts]
    apply_annotation_summary(payload, evaluator.annotate_items(artifacts, contexts), rule_set)
    return payload


def annotate_timeline_payload(payload: MutableMapping[str, object], rule_set: RuleSet) -> MutableMapping[str, object]:
    events = [item for item in payload.get("events", []) if isinstance(item, dict)]
    evaluator = _RuleEvaluator(rule_set)
    contexts = [context_from_timeline_event(item) for item in events]
    apply_annotation_summary(payload, evaluator.annotate_items(events, contexts), rule_set)
    return payload


def apply_annotation_summary(payload: MutableMapping[str, object], annotation_summary: Mapping[str, object], rule_set: RuleSet) -> None:
    payload["rule_set"] = {
        "path": rule_set.path,
        "format": rule_set.format,
        "rule_count": rule_set.rule_count,
    }
    if annotation_summary["matched_rules"]:
        payload["matched_rules"] = annotation_summary["matched_rules"]
    if annotation_summary["ioc_hits"]:
        payload["ioc_hits"] = annotation_summary["ioc_hits"]
    summary = payload.get("summary")
    if isinstance(summary, dict):
        summary["matched_rule_count"] = int(annotation_summary["matched_rule_count"])
        summary["ioc_hit_count"] = int(annotation_summary["ioc_hit_count"])


def summarize_annotated_items(items: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    matched_rules: set[str] = set()
    hit_counts: Counter[tuple[str, str, str]] = Counter()
    for item in items:
        for rule_id in item.get("matched_rules", []):
            matched_rules.add(str(rule_id))
        for hit in item.get("ioc_hits", []):
            if not isinstance(hit, dict):
                continue
            hit_counts[(str(hit.get("rule_id", "")), str(hit.get("type", "")), str(hit.get("value", "")))] += 1
    return {
        "matched_rules": sorted(matched_rules),
        "matched_rule_count": len(matched_rules),
        "ioc_hits": [
            {
                "rule_id": rule_id,
                "type": hit_type,
                "value": value,
                "count": count,
            }
            for (rule_id, hit_type, value), count in sorted(hit_counts.items())
            if rule_id and hit_type and value
        ],
        "ioc_hit_count": int(sum(hit_counts.values())),
    }


def summarize_payload_annotations(*payloads: Mapping[str, object]) -> Dict[str, object]:
    matched_rules: set[str] = set()
    hit_counts: Counter[tuple[str, str, str]] = Counter()
    for payload in payloads:
        for rule_id in payload.get("matched_rules", []):
            matched_rules.add(str(rule_id))
        for hit in payload.get("ioc_hits", []):
            if not isinstance(hit, dict):
                continue
            hit_counts[(str(hit.get("rule_id", "")), str(hit.get("type", "")), str(hit.get("value", "")))] += int(hit.get("count", 1))
    return {
        "matched_rules": sorted(matched_rules),
        "matched_rule_count": len(matched_rules),
        "ioc_hits": [
            {
                "rule_id": rule_id,
                "type": hit_type,
                "value": value,
                "count": count,
            }
            for (rule_id, hit_type, value), count in sorted(hit_counts.items())
            if rule_id and hit_type and value
        ],
        "ioc_hit_count": int(sum(hit_counts.values())),
    }


def context_from_file_candidate(candidate: Mapping[str, object]) -> RecordContext:
    path = str(candidate.get("path", ""))
    extension = str(candidate.get("extension") or Path(path).suffix)
    text_values = [
        path,
        str(candidate.get("name", "")),
        json.dumps(candidate.get("categories", []), ensure_ascii=False),
        json.dumps(candidate.get("reasons", {}), ensure_ascii=False),
    ]
    text_values.extend(extract_text_for_rule_matching(Path(path)))
    return build_context(
        path=path,
        extension=extension,
        timestamp=string_or_none(candidate.get("modified_at")),
        text_values=text_values,
        hash_path=path,
    )


def context_from_doc_result(
    result: Mapping[str, object],
    candidate: Mapping[str, object],
    *,
    text_by_path: Mapping[str, str] | None = None,
) -> RecordContext:
    path = str(result.get("path", ""))
    text_values = [
        path,
        str(result.get("preview", "")),
        json.dumps(result.get("matched_keywords", []), ensure_ascii=False),
    ]
    text_blob = ""
    if text_by_path is not None:
        text_blob = str(text_by_path.get(path, ""))
    elif path:
        text_blob = "\n".join(extract_text_for_rule_matching(Path(path)))
    if text_blob:
        text_values.append(text_blob)
    return build_context(
        path=path,
        extension=f".{str(result.get('kind', candidate.get('kind', ''))).lstrip('.')}" if (result.get("kind") or candidate.get("kind")) else Path(path).suffix,
        timestamp=string_or_none(candidate.get("modified_at")),
        text_values=text_values,
        hash_path=path,
    )


def context_from_artifact(artifact: Mapping[str, object]) -> RecordContext:
    path = str(artifact.get("path", ""))
    details = artifact.get("details", {})
    strings = [path, str(artifact.get("provider", "")), str(artifact.get("artifact_type", ""))]
    strings.extend(iter_scalar_strings(details))
    return build_context(
        path=path,
        extension=Path(path).suffix,
        artifact_type=str(artifact.get("artifact_type", "")),
        timestamp=find_primary_timestamp(details),
        text_values=strings,
        hash_path=path,
    )


def context_from_timeline_event(event: Mapping[str, object]) -> RecordContext:
    path = str(event.get("path", ""))
    details = event.get("details", {})
    strings = [path, str(event.get("summary", "")), str(event.get("event_type", "")), str(event.get("source", ""))]
    strings.extend(iter_scalar_strings(details))
    return build_context(
        path=path,
        extension=Path(path).suffix,
        artifact_type=str(details.get("artifact_type", "")) if isinstance(details, dict) else "",
        timestamp=string_or_none(event.get("timestamp")),
        text_values=strings,
        hash_path=path,
    )


def build_context(
    *,
    path: str,
    extension: str,
    artifact_type: str = "",
    timestamp: str | None = None,
    text_values: Sequence[str] = (),
    hash_path: str | None = None,
) -> RecordContext:
    normalized_text_values = tuple(value for value in text_values if value)
    urls = extract_urls(normalized_text_values)
    domains = extract_domains(normalized_text_values, urls)
    return RecordContext(
        path=path,
        extension=extension.lower(),
        artifact_type=artifact_type,
        timestamp=timestamp,
        text_values=normalized_text_values,
        url_values=tuple(urls),
        domain_values=tuple(domains),
        hash_path=hash_path,
    )


def build_ioc_hits(rule_id: str, hit_type: str, values: Sequence[str]) -> list[Dict[str, object]]:
    return [{"rule_id": rule_id, "type": hit_type, "value": value} for value in values]


def dedupe_ioc_hits(hits: Sequence[Mapping[str, object]]) -> list[Dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Dict[str, object]] = []
    for hit in hits:
        key = (str(hit.get("rule_id", "")), str(hit.get("type", "")), str(hit.get("value", "")))
        if not all(key) or key in seen:
            continue
        seen.add(key)
        deduped.append({"rule_id": key[0], "type": key[1], "value": key[2]})
    return deduped


def match_substrings(needles: Sequence[str], haystacks: Sequence[str]) -> list[str]:
    matched = []
    for needle in needles:
        if any(needle in haystack for haystack in haystacks):
            matched.append(needle)
    return matched


def match_hashes(needles: Sequence[str], file_hash: str | None) -> list[str]:
    if not file_hash:
        return []
    return [needle for needle in needles if needle == file_hash]


def match_domains(needles: Sequence[str], domains: Sequence[str], urls: Sequence[str], texts: Sequence[str]) -> list[str]:
    matched: list[str] = []
    for needle in needles:
        if any(domain == needle or domain.endswith(f".{needle}") for domain in domains):
            matched.append(needle)
            continue
        if any(needle in url for url in urls):
            matched.append(needle)
            continue
        if any(needle in text for text in texts):
            matched.append(needle)
    return matched


def match_urls(needles: Sequence[str], urls: Sequence[str], texts: Sequence[str]) -> list[str]:
    matched: list[str] = []
    for needle in needles:
        if any(needle in url for url in urls):
            matched.append(needle)
            continue
        if any(needle in text for text in texts):
            matched.append(needle)
    return matched


def matches_timestamp(timestamp: str | None, rule: Rule) -> bool:
    if not any((rule.date_after, rule.date_before, rule.date_on)):
        return True
    if not timestamp:
        return False
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return False
    if rule.date_after:
        after_value = parse_timestamp(rule.date_after)
        if after_value is None or parsed < after_value:
            return False
    if rule.date_before:
        before_value = parse_timestamp(rule.date_before)
        if before_value is None or parsed > before_value:
            return False
    if rule.date_on:
        on_value = parse_timestamp(rule.date_on)
        if on_value is None or parsed.date() != on_value.date():
            return False
    return True


def parse_timestamp(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        try:
            parsed = dt.datetime.fromisoformat(f"{value}T00:00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def compute_sha256(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def normalize_extensions(value: object) -> list[str]:
    normalized: list[str] = []
    for item in ensure_list(value):
        text = str(item).strip().lower()
        if not text:
            continue
        normalized.append(text if text.startswith(".") else f".{text}")
    return normalized


def normalize_hashes(value: object) -> list[str]:
    hashes: list[str] = []
    for item in ensure_list(value):
        text = str(item).strip().lower()
        if not text:
            continue
        if not HASH_RE.fullmatch(text):
            raise RuleConfigError(f"invalid SHA256 IOC value: {item!r}")
        hashes.append(text)
    return hashes


def normalize_text_list(value: object) -> list[str]:
    normalized: list[str] = []
    for item in ensure_list(value):
        text = str(item).strip().lower()
        if text:
            normalized.append(text)
    return normalized


def normalize_optional_text(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def ensure_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def iter_scalar_strings(value: object) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key:
                yield str(key)
            yield from iter_scalar_strings(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from iter_scalar_strings(item)
        return
    if value is None:
        return
    yield str(value)


def find_primary_timestamp(details: object) -> str | None:
    if isinstance(details, dict):
        for key in ("modified_at", "last_visited_at", "started_at", "ended_at", "timestamp"):
            value = details.get(key)
            if isinstance(value, str) and value:
                return value
        for item in details.values():
            nested = find_primary_timestamp(item)
            if nested:
                return nested
        return None
    if isinstance(details, list):
        for item in details:
            nested = find_primary_timestamp(item)
            if nested:
                return nested
    return None


def extract_urls(text_values: Sequence[str]) -> list[str]:
    urls: set[str] = set()
    for value in text_values:
        for match in URL_RE.findall(value):
            urls.add(match.strip())
    return sorted(urls)


def extract_domains(text_values: Sequence[str], urls: Sequence[str]) -> list[str]:
    domains: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname.lower())
    for value in text_values:
        for match in URL_RE.findall(value):
            parsed = urlparse(match)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
    return sorted(domains)


def string_or_none(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def extract_text_for_rule_matching(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTS:
        try:
            return [path.read_text(encoding="utf-8", errors="ignore")]
        except (FileNotFoundError, PermissionError, OSError):
            return []
    if suffix == ".docx":
        return [_extract_docx_text(path)]
    if suffix == ".pdf":
        return [_extract_pdf_text(path)]
    return []


def _extract_docx_text(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            with archive.open("word/document.xml") as handle:
                xml_data = handle.read()
    except (FileNotFoundError, PermissionError, OSError, zipfile.BadZipFile, KeyError):
        return ""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return ""
    texts = []
    for node in root.iter():
        if node.tag.endswith("}t") and node.text:
            texts.append(node.text)
    return " ".join(texts)


def _extract_pdf_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        return ""
    snippets: List[str] = []
    for stream in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        candidates = [stream]
        try:
            candidates.append(zlib.decompress(stream))
        except zlib.error:
            pass
        for item in candidates:
            snippets.extend(_extract_pdf_literal_strings(item))
    if not snippets:
        snippets.extend(_extract_pdf_literal_strings(data))
    return " ".join(snippets)


def _extract_pdf_literal_strings(blob: bytes) -> List[str]:
    found = []
    for raw in re.findall(rb"\((.*?)(?<!\\)\)", blob, re.S):
        text = (
            raw.replace(b"\\n", b"\n")
            .replace(b"\\r", b"\r")
            .replace(b"\\t", b"\t")
            .replace(b"\\(", b"(")
            .replace(b"\\)", b")")
            .replace(b"\\\\", b"\\")
        )
        cleaned = text.decode("latin-1", errors="ignore").strip()
        if cleaned:
            found.append(cleaned)
    return found


def parse_simple_yaml(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    lines = tokenize_yaml(text)
    if not lines:
        return {}
    value, index = parse_yaml_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise RuleConfigError("unexpected trailing YAML content")
    return value


def tokenize_yaml(text: str) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        stripped = strip_yaml_comment(raw_line)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        tokens.append((indent, stripped.strip()))
    return tokens


def strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            if index == 0 or line[index - 1].isspace():
                return line[:index]
    return line


def parse_yaml_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[object, int]:
    if index >= len(lines):
        return {}, index
    _, content = lines[index]
    if content.startswith("- "):
        return parse_yaml_list(lines, index, indent)
    return parse_yaml_mapping(lines, index, indent)


def parse_yaml_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[object], int]:
    items: list[object] = []
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent:
            raise RuleConfigError("invalid YAML indentation in list")
        if not content.startswith("- "):
            break
        rest = content[2:].strip()
        index += 1
        if not rest:
            child, index = parse_yaml_block(lines, index, indent + 2)
            items.append(child)
            continue
        if looks_like_mapping_pair(rest):
            key, value_text = split_mapping_pair(rest)
            item: Dict[str, object] = {}
            if value_text:
                item[key] = parse_yaml_scalar(value_text)
            else:
                child, index = parse_yaml_block(lines, index, indent + 4)
                item[key] = child
            extra, index = parse_yaml_mapping(lines, index, indent + 2)
            item.update(extra)
            items.append(item)
            continue
        items.append(parse_yaml_scalar(rest))
    return items, index


def parse_yaml_mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, object], int]:
    mapping: dict[str, object] = {}
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent:
            break
        if content.startswith("- "):
            break
        key, value_text = split_mapping_pair(content)
        index += 1
        if value_text:
            mapping[key] = parse_yaml_scalar(value_text)
            continue
        child, index = parse_yaml_block(lines, index, indent + 2)
        mapping[key] = child
    return mapping, index


def looks_like_mapping_pair(value: str) -> bool:
    separator_index = find_mapping_separator(value)
    if separator_index is None:
        return False
    key = value[:separator_index].strip()
    return bool(key)


def split_mapping_pair(value: str) -> tuple[str, str]:
    separator_index = find_mapping_separator(value)
    if separator_index is None:
        raise RuleConfigError(f"invalid YAML mapping entry: {value!r}")
    key = value[:separator_index]
    remainder = value[separator_index + 1 :]
    return key.strip(), remainder.strip()


def find_mapping_separator(value: str) -> int | None:
    for index, char in enumerate(value):
        if char != ":":
            continue
        next_index = index + 1
        if next_index >= len(value) or value[next_index].isspace():
            return index
    return None


def parse_yaml_scalar(value: str) -> object:
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_yaml_scalar(item.strip()) for item in inner.split(",") if item.strip()]
    if value.startswith("{") and value.endswith("}"):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuleConfigError(f"invalid inline YAML object: {value!r}") from exc
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
