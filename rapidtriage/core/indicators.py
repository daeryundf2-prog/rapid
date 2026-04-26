from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence
from urllib.parse import urlparse

from .rules import RuleSet

URL_RE = re.compile(r"https?://[^\s\]\[\)\(\}\{\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
MAX_SCALAR_LENGTH = 4096
DEFAULT_MAX_INDICATORS = 1000
DEFAULT_MAX_SOURCES_PER_INDICATOR = 10


class IndicatorSummaryError(ValueError):
    """Raised when indicator summary input cannot be loaded."""


def build_indicator_summary(
    run_output: Path | Mapping[str, object],
    *,
    rule_set: RuleSet | None = None,
    max_indicators: int = DEFAULT_MAX_INDICATORS,
    max_sources_per_indicator: int = DEFAULT_MAX_SOURCES_PER_INDICATOR,
) -> dict[str, object]:
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise IndicatorSummaryError("run summary does not include outputs")

    accumulator: dict[tuple[str, str], dict[str, object]] = {}
    source_counts: Counter[str] = Counter()
    for output_name, output_path in iter_run_json_outputs(outputs):
        payload = read_json_path(output_path)
        if not payload:
            continue
        source_counts[output_name] += 1
        for pointer, value, context in iter_scalar_contexts(payload):
            collect_indicators_from_text(
                value,
                accumulator,
                source={
                    "output": output_name,
                    "output_path": str(output_path),
                    "pointer": pointer,
                    **context,
                },
                max_sources_per_indicator=max_sources_per_indicator,
            )

    indicators = [finalize_indicator(record, rule_set=rule_set) for record in accumulator.values()]
    indicators.sort(key=lambda item: (-int(item["count"]), str(item["type"]), str(item["value"])))
    if max_indicators:
        indicators = indicators[:max_indicators]

    type_counts = Counter(str(item["type"]) for item in indicators)
    rule_counts = Counter(rule for item in indicators for rule in item.get("matched_rules", []))
    return {
        "command": "indicators",
        "generated_at": dt.datetime.now().isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary", "")),
        "options": {
            "max_indicators": max_indicators,
            "max_sources_per_indicator": max_sources_per_indicator,
            "rule_set": rule_set.path if rule_set else "",
        },
        "summary": {
            "indicator_count": len(indicators),
            "type_counts": dict(type_counts),
            "source_output_counts": dict(source_counts),
            "matched_rule_counts": dict(rule_counts),
            "matched_indicator_count": sum(1 for item in indicators if item.get("matched_rules")),
        },
        "indicators": indicators,
    }


def load_run_summary(run_output: Path | Mapping[str, object]) -> Mapping[str, object]:
    if isinstance(run_output, Mapping):
        return run_output
    path = Path(run_output).expanduser().resolve()
    if path.is_dir():
        path = path / "rapidtriage-run-summary.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IndicatorSummaryError(f"run summary not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IndicatorSummaryError(f"invalid run summary JSON: {path}") from exc
    if not isinstance(payload, Mapping):
        raise IndicatorSummaryError(f"run summary must be a JSON object: {path}")
    return payload


def iter_run_json_outputs(outputs: Mapping[str, object]) -> Iterable[tuple[str, Path]]:
    for name, raw_path in sorted(outputs.items()):
        output_name = str(name)
        if not output_name.startswith("artifacts_") and output_name not in {"docs", "files", "timeline"}:
            continue
        path = Path(str(raw_path)).expanduser().resolve()
        if path.is_file():
            yield output_name, path


def read_json_path(path: Path) -> Mapping[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def iter_scalar_contexts(value: object, pointer: str = "") -> Iterable[tuple[str, str, dict[str, str]]]:
    if isinstance(value, Mapping):
        context = context_from_mapping(value)
        for key, item in value.items():
            child_pointer = f"{pointer}/{escape_pointer(str(key))}"
            if isinstance(item, (Mapping, list)):
                yield from iter_scalar_contexts(item, child_pointer)
                continue
            if item is None:
                continue
            text = str(item)
            if text and len(text) <= MAX_SCALAR_LENGTH:
                yield child_pointer, text, context
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_scalar_contexts(item, f"{pointer}/{index}")


def context_from_mapping(value: Mapping[str, object]) -> dict[str, str]:
    context: dict[str, str] = {}
    for key in ("path", "source_path", "artifact_type", "kind", "event_type", "source", "parser"):
        item = value.get(key)
        if item not in (None, ""):
            context[key] = str(item)
    return context


def escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def collect_indicators_from_text(
    text: str,
    accumulator: MutableMapping[tuple[str, str], dict[str, object]],
    *,
    source: Mapping[str, str],
    max_sources_per_indicator: int,
) -> None:
    for raw_url in URL_RE.findall(text):
        url = normalize_url(raw_url)
        if not url:
            continue
        add_indicator(accumulator, "url", url, source, max_sources_per_indicator=max_sources_per_indicator)
        host = urlparse(url).hostname
        if host:
            add_indicator(accumulator, "domain", host.lower(), source, max_sources_per_indicator=max_sources_per_indicator)
    for raw_ip in IP_RE.findall(text):
        if not valid_ipv4(raw_ip):
            continue
        add_indicator(accumulator, "ip", raw_ip, source, max_sources_per_indicator=max_sources_per_indicator)
    for raw_hash in HASH_RE.findall(text):
        add_indicator(
            accumulator,
            hash_type(raw_hash),
            raw_hash.lower(),
            source,
            max_sources_per_indicator=max_sources_per_indicator,
        )


def add_indicator(
    accumulator: MutableMapping[tuple[str, str], dict[str, object]],
    indicator_type: str,
    value: str,
    source: Mapping[str, str],
    *,
    max_sources_per_indicator: int,
) -> None:
    key = (indicator_type, value)
    if key not in accumulator:
        accumulator[key] = {"type": indicator_type, "value": value, "count": 0, "sources": []}
    record = accumulator[key]
    record["count"] = int(record["count"]) + 1
    sources = record["sources"]
    if isinstance(sources, list) and len(sources) < max_sources_per_indicator:
        compact_source = {key: val for key, val in source.items() if val}
        if compact_source not in sources:
            sources.append(compact_source)


def finalize_indicator(record: Mapping[str, object], *, rule_set: RuleSet | None) -> dict[str, object]:
    indicator = {
        "type": str(record.get("type", "")),
        "value": str(record.get("value", "")),
        "count": int(record.get("count", 0)),
        "classification": classify_indicator(str(record.get("type", "")), str(record.get("value", ""))),
        "risk_flags": indicator_risk_flags(str(record.get("type", "")), str(record.get("value", ""))),
        "sources": list(record.get("sources", [])) if isinstance(record.get("sources"), list) else [],
    }
    matched_rules = match_indicator_rules(indicator, rule_set)
    if matched_rules:
        indicator["matched_rules"] = matched_rules
    return indicator


def classify_indicator(indicator_type: str, value: str) -> str:
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return "invalid"
        if address.is_private:
            return "private"
        if address.is_loopback:
            return "loopback"
        if address.is_reserved:
            return "reserved"
        if address.is_global:
            return "global"
        return "non-global"
    if indicator_type in {"md5", "sha1", "sha256"}:
        return "hash"
    if indicator_type == "url":
        return "network"
    if indicator_type == "domain":
        return "network"
    return "unknown"


def indicator_risk_flags(indicator_type: str, value: str) -> list[str]:
    flags: list[str] = []
    if indicator_type in {"url", "domain", "ip"}:
        flags.append("network-indicator")
    if indicator_type == "ip" and classify_indicator(indicator_type, value) == "global":
        flags.append("global-ip")
    if indicator_type == "url":
        parsed = urlparse(value)
        if parsed.hostname and valid_ipv4(parsed.hostname):
            flags.append("url-ip-host")
        if parsed.scheme == "http":
            flags.append("cleartext-url")
    if indicator_type in {"md5", "sha1", "sha256"}:
        flags.append("hash-indicator")
    return flags


def match_indicator_rules(indicator: Mapping[str, object], rule_set: RuleSet | None) -> list[str]:
    if rule_set is None:
        return []
    indicator_type = str(indicator.get("type", ""))
    value = str(indicator.get("value", "")).lower()
    matched: list[str] = []
    for rule in rule_set.rules:
        if indicator_type == "domain" and any(value == item or value.endswith(f".{item}") for item in rule.domains):
            matched.append(rule.id)
        elif indicator_type == "url" and any(item in value for item in rule.urls):
            matched.append(rule.id)
        elif indicator_type in {"md5", "sha1", "sha256"} and indicator_type == "sha256" and value in rule.hashes:
            matched.append(rule.id)
    return sorted(set(matched))


def normalize_url(value: str) -> str:
    return value.strip().rstrip(".,);]").lower()


def valid_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4


def hash_type(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    return "sha256"
