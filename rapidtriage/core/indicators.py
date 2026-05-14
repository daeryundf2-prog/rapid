from __future__ import annotations

import datetime as dt
import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence
from urllib.parse import urlparse

from .forensic_accuracy import build_accuracy_gate
from .rules import RuleSet

URL_RE = re.compile(r"https?://[^\s\]\[\)\(\}\{\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
MAX_SCALAR_LENGTH = 4096
DEFAULT_MAX_INDICATORS = 1000
DEFAULT_MAX_SOURCES_PER_INDICATOR = 10
IOC_TI_GAP_ID = "#63"
INDICATOR_NATIVE_CAPABILITIES = {
    "url_domain_ip_hash_extraction": True,
    "local_rule_matching": True,
    "rule_based_ioc_scanner": True,
    "bounded_file_content_keyword_scanning": True,
    "offline_ti_feed_enrichment": True,
    "yara_compatible_full_grammar": False,
    "native_yara_engine_integration": False,
    "external_ti_api_calls": False,
    "malware_sandbox_enrichment": False,
}
IOC_TI_REPORT_GRADE_BLOCKERS = [
    "local-ti-feed-quality-and-timestamp-must-be-documented",
    "indicator-presence-is-a-pivot-not-proof-of-malicious-activity",
    "external-ti-api-enrichment-is-disabled-in-local-only-core",
    "trusted-ioc-ti-enrichment-diff-is-required-before-commercial-claim",
]
IOC_TI_TRUSTED_DIFF_BLOCKER_63 = "trusted-ioc-ti-enrichment-diff-missing"


class IndicatorSummaryError(ValueError):
    """Raised when indicator summary input cannot be loaded."""


def stable_ioc_ti_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_indicator_summary(
    run_output: Path | Mapping[str, object],
    *,
    rule_set: RuleSet | None = None,
    ti_feeds: Sequence[Path] | None = None,
    max_indicators: int = DEFAULT_MAX_INDICATORS,
    max_sources_per_indicator: int = DEFAULT_MAX_SOURCES_PER_INDICATOR,
) -> dict[str, object]:
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise IndicatorSummaryError("run summary does not include outputs")

    accumulator: dict[tuple[str, str], dict[str, object]] = {}
    scanner_accumulator: dict[tuple[str, str, str], dict[str, object]] = {}
    source_counts: Counter[str] = Counter()
    for output_name, output_path in iter_run_json_outputs(outputs):
        payload = read_json_path(output_path)
        if not payload:
            continue
        source_counts[output_name] += 1
        collect_ioc_scanner_hits_from_payload(
            payload,
            scanner_accumulator,
            source={
                "output": output_name,
                "output_path": str(output_path),
            },
            max_sources_per_hit=max_sources_per_indicator,
        )
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

    enrichment, ti_feed_sources = load_ti_feeds(ti_feeds or [])
    indicators = [
        finalize_indicator(record, rule_set=rule_set, enrichment=enrichment)
        for record in accumulator.values()
    ]
    indicators.sort(key=lambda item: (-int(item["count"]), str(item["type"]), str(item["value"])))
    if max_indicators:
        indicators = indicators[:max_indicators]
    indicators = attach_ioc_ti_indicator_manifests(indicators)
    ioc_scanner_hits = finalize_ioc_scanner_hits(scanner_accumulator, limit=max_indicators)
    ioc_scanner_manifest = build_ioc_scanner_manifest(
        hits=ioc_scanner_hits,
        source_output_counts=source_counts,
        rule_set=rule_set,
    )
    enrichment_manifest = build_ioc_ti_enrichment_manifest(
        indicators=indicators,
        ti_feed_sources=ti_feed_sources,
        max_indicators=max_indicators,
        max_sources_per_indicator=max_sources_per_indicator,
    )

    type_counts = Counter(str(item["type"]) for item in indicators)
    rule_counts = Counter(rule for item in indicators for rule in item.get("matched_rules", []))
    scanner_rule_counts = Counter(str(item.get("rule_id") or "") for item in ioc_scanner_hits if item.get("rule_id"))
    core_accuracy_gates = ioc_ti_core_accuracy_gates(
        indicators=indicators,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
    )
    assessment = ti_enrichment_assessment(ti_feed_sources=ti_feed_sources, enrichment_manifest=enrichment_manifest)
    return {
        "command": "indicators",
        "generated_at": dt.datetime.now().isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary", "")),
        "options": {
            "max_indicators": max_indicators,
            "max_sources_per_indicator": max_sources_per_indicator,
            "rule_set": rule_set.path if rule_set else "",
            "ti_feeds": [str(path) for path in (ti_feeds or [])],
        },
        "summary": {
            "indicator_count": len(indicators),
            "type_counts": dict(type_counts),
            "source_output_counts": dict(source_counts),
            "matched_rule_counts": dict(rule_counts),
            "matched_indicator_count": sum(1 for item in indicators if item.get("matched_rules")),
            "ioc_scanner_hit_count": sum(int(item.get("count") or 0) for item in ioc_scanner_hits),
            "ioc_scanner_row_count": len(ioc_scanner_hits),
            "ioc_scanner_rule_count": len(scanner_rule_counts),
            "enriched_indicator_count": sum(1 for item in indicators if item.get("ti_enrichment")),
            "ti_feed_count": len(ti_feed_sources),
            "commercial_gap_ids": [IOC_TI_GAP_ID],
            "commercial_grade_ready": False,
        },
        "ti_feed_sources": ti_feed_sources,
        "indicator_native_capabilities": dict(INDICATOR_NATIVE_CAPABILITIES),
        "ioc_scanner_hits": ioc_scanner_hits,
        "ioc_scanner_manifest": ioc_scanner_manifest,
        "ioc_scanner_manifest_hash": ioc_scanner_manifest["manifest_hash"],
        "ioc_ti_enrichment_manifest": enrichment_manifest,
        "ioc_ti_enrichment_manifest_hash": enrichment_manifest["manifest_hash"],
        "ti_enrichment_assessment": assessment,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": ioc_ti_commercial_uplift_evidence(
            indicators=indicators,
            ti_feed_sources=ti_feed_sources,
            core_accuracy_gates=core_accuracy_gates,
            assessment=assessment,
            max_indicators=max_indicators,
            max_sources_per_indicator=max_sources_per_indicator,
            enrichment_manifest=enrichment_manifest,
        ),
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


def collect_ioc_scanner_hits_from_payload(
    payload: Mapping[str, object],
    accumulator: MutableMapping[tuple[str, str, str], dict[str, object]],
    *,
    source: Mapping[str, str],
    max_sources_per_hit: int,
) -> None:
    """Collect rule-engine IOC hits that were attached to run component outputs."""

    nested_hits = list(iter_ioc_hit_contexts(payload, pointer="", include_root=False))
    hit_contexts = nested_hits or list(iter_ioc_hit_contexts(payload, pointer="", include_root=True))
    for pointer, hit, context in hit_contexts:
        rule_id = str(hit.get("rule_id") or "").strip()
        hit_type = str(hit.get("type") or "").strip().lower()
        value = normalize_ioc_scanner_value(hit_type, str(hit.get("value") or ""))
        if not rule_id or not hit_type or not value:
            continue
        count = safe_positive_int(hit.get("count"), default=1)
        add_ioc_scanner_hit(
            accumulator,
            rule_id=rule_id,
            hit_type=hit_type,
            value=value,
            count=count,
            source={**source, "pointer": pointer, **context},
            max_sources_per_hit=max_sources_per_hit,
        )


def iter_ioc_hit_contexts(
    value: object,
    *,
    pointer: str,
    include_root: bool,
) -> Iterable[tuple[str, Mapping[str, object], dict[str, str]]]:
    if isinstance(value, Mapping):
        raw_hits = value.get("ioc_hits")
        if (include_root or pointer) and isinstance(raw_hits, list):
            context = context_from_mapping(value)
            for index, hit in enumerate(raw_hits):
                if isinstance(hit, Mapping):
                    yield f"{pointer}/ioc_hits/{index}" if pointer else f"/ioc_hits/{index}", hit, context
        for key, item in value.items():
            if key == "ioc_hits":
                continue
            if isinstance(item, (Mapping, list)):
                yield from iter_ioc_hit_contexts(
                    item,
                    pointer=f"{pointer}/{escape_pointer(str(key))}",
                    include_root=include_root,
                )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (Mapping, list)):
                yield from iter_ioc_hit_contexts(item, pointer=f"{pointer}/{index}", include_root=include_root)


def add_ioc_scanner_hit(
    accumulator: MutableMapping[tuple[str, str, str], dict[str, object]],
    *,
    rule_id: str,
    hit_type: str,
    value: str,
    count: int,
    source: Mapping[str, str],
    max_sources_per_hit: int,
) -> None:
    key = (rule_id, hit_type, value)
    if key not in accumulator:
        accumulator[key] = {
            "rule_id": rule_id,
            "type": hit_type,
            "value": value,
            "count": 0,
            "sources": [],
        }
    record = accumulator[key]
    record["count"] = int(record["count"]) + max(count, 1)
    sources = record["sources"]
    if isinstance(sources, list) and len(sources) < max_sources_per_hit:
        compact_source = {key: val for key, val in source.items() if val}
        if compact_source not in sources:
            sources.append(compact_source)


def finalize_ioc_scanner_hits(
    accumulator: Mapping[tuple[str, str, str], Mapping[str, object]],
    *,
    limit: int,
) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for record in accumulator.values():
        hit = {
            "rule_id": str(record.get("rule_id") or ""),
            "type": str(record.get("type") or ""),
            "value": str(record.get("value") or ""),
            "count": int(record.get("count") or 0),
            "classification": classify_ioc_scanner_hit(str(record.get("type") or ""), str(record.get("value") or "")),
            "risk_flags": ioc_scanner_risk_flags(str(record.get("type") or ""), str(record.get("value") or "")),
            "sources": list(record.get("sources", [])) if isinstance(record.get("sources"), list) else [],
            "commercial_gap_ids": [IOC_TI_GAP_ID],
            "ready_for_court_report": False,
            "report_use_boundary": "local IOC/rule hit is a triage pivot; verify source artifact before reporting maliciousness",
        }
        hit["ioc_scanner_row_hash"] = stable_ioc_ti_sha256(
            {
                "rule_id": hit["rule_id"],
                "type": hit["type"],
                "value": hit["value"],
                "count": hit["count"],
                "sources": hit["sources"],
            }
        )
        hit["source_viewer_locator"] = build_ioc_scanner_source_viewer_locator(hit)
        hits.append(hit)
    hits.sort(key=lambda item: (-int(item.get("count") or 0), str(item.get("rule_id") or ""), str(item.get("type") or ""), str(item.get("value") or "")))
    return hits[:limit] if limit else hits


def normalize_ioc_scanner_value(hit_type: str, value: str) -> str:
    text = value.strip()
    if hit_type in {"hash", "md5", "sha1", "sha256"}:
        return text.lower()
    if hit_type in {"domain", "url", "ip", "keyword"}:
        return text.lower()
    return text


def safe_positive_int(value: object, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def classify_ioc_scanner_hit(hit_type: str, value: str) -> str:
    if hit_type == "keyword":
        return "content-keyword-rule-hit"
    if hit_type == "domain":
        return "network-domain-rule-hit"
    if hit_type == "url":
        return "network-url-rule-hit"
    if hit_type == "ip":
        return "network-ip-rule-hit"
    if hit_type in {"hash", "md5", "sha1", "sha256"} or HASH_RE.fullmatch(value):
        return "file-hash-rule-hit"
    return "local-rule-hit"


def ioc_scanner_risk_flags(hit_type: str, value: str) -> list[str]:
    flags = {"local-ioc-rule-hit"}
    if hit_type in {"domain", "url", "ip"}:
        flags.add("network-ioc-hit")
    if hit_type in {"hash", "md5", "sha1", "sha256"} or HASH_RE.fullmatch(value):
        flags.add("file-hash-ioc-hit")
    if hit_type == "keyword":
        flags.add("content-keyword-ioc-hit")
    return sorted(flags)


def build_ioc_scanner_source_viewer_locator(hit: Mapping[str, object]) -> dict[str, object]:
    sources = hit.get("sources") if isinstance(hit.get("sources"), list) else []
    first_source = sources[0] if sources and isinstance(sources[0], Mapping) else {}
    return {
        "viewer": "ioc-scanner-source-review",
        "open_action": "open-ioc-scanner-source",
        "output": str(first_source.get("output") or ""),
        "output_path": str(first_source.get("output_path") or ""),
        "pointer": str(first_source.get("pointer") or ""),
        "value_hash": stable_ioc_ti_sha256(
            {
                "rule_id": str(hit.get("rule_id") or ""),
                "type": str(hit.get("type") or ""),
                "value": str(hit.get("value") or ""),
            }
        ),
    }


def build_ioc_scanner_manifest(
    *,
    hits: Sequence[Mapping[str, object]],
    source_output_counts: Mapping[str, int],
    rule_set: RuleSet | None,
) -> dict[str, object]:
    hit_row_hashes = [str(hit.get("ioc_scanner_row_hash") or "") for hit in hits if hit.get("ioc_scanner_row_hash")]
    rule_ids = sorted({str(hit.get("rule_id") or "") for hit in hits if hit.get("rule_id")})
    manifest_core: dict[str, object] = {
        "manifest_version": "ioc-scanner-manifest-v1",
        "item_number": 63,
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "hit_row_count": len(hits),
        "hit_total_count": sum(int(hit.get("count") or 0) for hit in hits),
        "rule_count": len(rule_ids),
        "matched_rule_ids": rule_ids,
        "hit_row_hash_count": len(hit_row_hashes),
        "hit_row_hashes_head_hash": stable_ioc_ti_sha256(hit_row_hashes),
        "source_output_counts": dict(source_output_counts),
        "rule_set_path": rule_set.path if rule_set else "",
        "rule_set_format": rule_set.format if rule_set else "",
        "native_ioc_rule_engine": True,
        "bounded_file_content_keyword_scanning": True,
        "local_only": True,
        "no_external_calls": True,
        "yara_compatible_full_grammar": False,
        "commercial_claim_allowed": False,
        "validation_status": "local-rule-hit-review-required",
        "blockers": [
            "native-yara-full-grammar-engine",
            "trusted-yara-ioc-corpus-diff",
            "malware-corpus-false-positive-negative-report",
            "scanner-scale-benchmark",
        ],
    }
    return {**manifest_core, "manifest_hash": stable_ioc_ti_sha256(manifest_core)}


def finalize_indicator(
    record: Mapping[str, object],
    *,
    rule_set: RuleSet | None,
    enrichment: Mapping[tuple[str, str], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    indicator = {
        "type": str(record.get("type", "")),
        "value": str(record.get("value", "")),
        "count": int(record.get("count", 0)),
        "classification": classify_indicator(str(record.get("type", "")), str(record.get("value", ""))),
        "risk_flags": indicator_risk_flags(str(record.get("type", "")), str(record.get("value", ""))),
        "sources": list(record.get("sources", [])) if isinstance(record.get("sources"), list) else [],
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "ready_for_court_report": False,
    }
    matched_rules = match_indicator_rules(indicator, rule_set)
    if matched_rules:
        indicator["matched_rules"] = matched_rules
    enrichment_hit = lookup_ti_enrichment(indicator, enrichment or {})
    if enrichment_hit:
        indicator["ti_enrichment"] = dict(enrichment_hit)
        indicator["risk_flags"] = sorted(set(indicator["risk_flags"]) | {"ti-enriched"})
    return indicator


def load_ti_feeds(paths: Sequence[Path]) -> tuple[dict[tuple[str, str], dict[str, object]], list[dict[str, object]]]:
    feeds: dict[tuple[str, str], dict[str, object]] = {}
    sources: list[dict[str, object]] = []
    for path in paths:
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise IndicatorSummaryError(f"TI feed not found: {resolved}")
        if resolved.suffix.lower() == ".json":
            rows, metadata = read_ti_json_with_metadata(resolved)
        elif resolved.suffix.lower() == ".csv":
            rows = read_ti_csv(resolved)
            metadata = {}
        else:
            rows = read_ti_text(resolved)
            metadata = {}
        feed_source = {
            "path": str(resolved),
            "format": resolved.suffix.lower().lstrip(".") or "text",
            "name": str(metadata.get("name") or metadata.get("source") or resolved.name),
            "version": str(metadata.get("version") or ""),
            "sha256": sha256_file(resolved),
            "size_bytes": resolved.stat().st_size,
            "indicator_count": 0,
            "local_only": True,
            "commercial_gap_ids": [IOC_TI_GAP_ID],
            "validation_status": "analyst-feed-provenance-review-required",
        }
        feed_rows = []
        for row in rows:
            raw_value = str(row.get("value") or "")
            indicator_type = normalize_feed_type(str(row.get("type") or raw_value))
            value = normalize_feed_value(indicator_type, raw_value)
            if not value:
                continue
            feed_source["indicator_count"] = int(feed_source["indicator_count"]) + 1
            feed_row = build_ti_feed_row(
                row,
                indicator_type=indicator_type,
                value=value,
                feed_name=str(feed_source["name"]),
            )
            feed_rows.append(feed_row)
            feeds[(indicator_type, value)] = {
                "type": indicator_type,
                "value": value,
                "severity": str(row.get("severity") or row.get("risk") or "").strip(),
                "classification": str(row.get("classification") or row.get("label") or "").strip(),
                "source": str(row.get("source") or feed_source["name"]).strip(),
                "feed_name": str(feed_source["name"]),
                "feed_version": str(feed_source["version"]),
                "feed_path": str(resolved),
                "note": str(row.get("note") or row.get("description") or "").strip(),
                "commercial_gap_ids": [IOC_TI_GAP_ID],
                "validation_status": "analyst-feed-provenance-review-required",
                "feed_row_hash": feed_row["feed_row_hash"],
            }
        feed_manifest = build_ti_feed_manifest(feed_source=feed_source, feed_rows=feed_rows)
        feed_source["ti_feed_manifest"] = feed_manifest
        feed_source["ti_feed_manifest_hash"] = feed_manifest["manifest_hash"]
        sources.append(feed_source)
    return feeds, sources


def build_indicator_ti_enrichment_package(
    indicators_payload: Mapping[str, object],
    *,
    ti_feeds: Sequence[Path],
    include_unmatched: bool = False,
    limit: int = 250,
) -> dict[str, object]:
    """Apply local TI feeds to an existing indicator payload for analyst review."""

    raw_indicators = indicators_payload.get("indicators")
    if not isinstance(raw_indicators, list):
        raise IndicatorSummaryError("indicators payload does not include an indicators list")
    if not ti_feeds:
        raise IndicatorSummaryError("at least one local TI feed is required")

    enrichment, ti_feed_sources = load_ti_feeds(ti_feeds)
    reviewed: list[dict[str, object]] = []
    matched_total = 0
    severity_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    for raw_item in raw_indicators:
        if not isinstance(raw_item, Mapping):
            continue
        indicator = dict(raw_item)
        hit = lookup_ti_enrichment(indicator, enrichment)
        type_counts[str(indicator.get("type") or "unknown")] += 1
        if hit:
            matched_total += 1
            indicator["ti_enrichment"] = dict(hit)
            indicator["risk_flags"] = sorted(set(indicator.get("risk_flags") or []) | {"ti-enriched"})
            indicator["ti_review_status"] = "feed-match-review-required"
            severity = str(hit.get("severity") or "unspecified")
            severity_counts[severity] += 1
        elif include_unmatched:
            indicator["ti_review_status"] = "no-feed-match"
        else:
            continue
        indicator["commercial_gap_ids"] = sorted(set(indicator.get("commercial_gap_ids") or []) | {IOC_TI_GAP_ID})
        indicator["ready_for_court_report"] = False
        reviewed.append(indicator)

    returned = reviewed[: max(limit, 0)] if limit else reviewed
    returned = attach_ioc_ti_indicator_manifests(returned)
    reviewed_for_manifest = attach_ioc_ti_indicator_manifests(reviewed)
    enrichment_manifest = build_ioc_ti_enrichment_manifest(
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        max_indicators=limit,
        max_sources_per_indicator=DEFAULT_MAX_SOURCES_PER_INDICATOR,
    )
    core_accuracy_gates = ioc_ti_core_accuracy_gates(
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
    )
    assessment = ti_enrichment_assessment(ti_feed_sources=ti_feed_sources, enrichment_manifest=enrichment_manifest)
    uplift = ioc_ti_commercial_uplift_evidence(
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        core_accuracy_gates=core_accuracy_gates,
        assessment=assessment,
        max_indicators=limit,
        max_sources_per_indicator=DEFAULT_MAX_SOURCES_PER_INDICATOR,
        enrichment_manifest=enrichment_manifest,
    )
    return {
        "command": "indicator-ti-enrichment",
        "profile_version": "ioc-ti-enrichment-review-package-v1",
        "generated_at": dt.datetime.now().isoformat(),
        "local_only": True,
        "no_external_calls": True,
        "options": {
            "ti_feeds": [str(path) for path in ti_feeds],
            "include_unmatched": include_unmatched,
            "limit": limit,
        },
        "summary": {
            "source_indicator_count": len([item for item in raw_indicators if isinstance(item, Mapping)]),
            "matched_indicator_count": matched_total,
            "returned_indicator_count": len(returned),
            "ti_feed_count": len(ti_feed_sources),
            "type_counts": dict(type_counts),
            "severity_counts": dict(severity_counts),
            "commercial_gap_ids": [IOC_TI_GAP_ID],
            "commercial_grade_ready": False,
        },
        "ti_feed_sources": ti_feed_sources,
        "ioc_ti_enrichment_manifest": enrichment_manifest,
        "ioc_ti_enrichment_manifest_hash": enrichment_manifest["manifest_hash"],
        "ti_enrichment_assessment": assessment,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": uplift,
        "reportability_decision": uplift["reportability_decision"],
        "indicators": returned,
        "truncated": len(returned) < len(reviewed),
    }


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_ti_json(path: Path) -> list[dict[str, object]]:
    rows, _metadata = read_ti_json_with_metadata(path)
    return rows


def read_ti_json_with_metadata(path: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IndicatorSummaryError(f"invalid TI feed JSON: {path}") from exc
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, Mapping)], {}
    if isinstance(payload, Mapping):
        metadata = {}
        raw_metadata = payload.get("feed") or payload.get("plugin") or payload.get("metadata")
        if isinstance(raw_metadata, Mapping):
            metadata = dict(raw_metadata)
        if isinstance(payload.get("indicators"), list):
            return [dict(item) for item in payload["indicators"] if isinstance(item, Mapping)], metadata
        return [
            {"value": key, **dict(value)}
            for key, value in payload.items()
            if isinstance(value, Mapping) and key not in {"feed", "plugin", "metadata"}
        ], metadata
    raise IndicatorSummaryError(f"TI feed JSON must be a list or object: {path}")


def read_ti_csv(path: Path) -> list[dict[str, object]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def read_ti_text(path: Path) -> list[dict[str, object]]:
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        rows.append({"value": value, "source": path.name})
    return rows


def lookup_ti_enrichment(
    indicator: Mapping[str, object],
    enrichment: Mapping[tuple[str, str], Mapping[str, object]],
) -> Mapping[str, object] | None:
    indicator_type = str(indicator.get("type") or "")
    value = str(indicator.get("value") or "")
    keys = [(indicator_type, normalize_feed_value(indicator_type, value), "exact")]
    if indicator_type == "url":
        host = urlparse(value).hostname
        if host:
            keys.append(("domain", host.lower(), "url-host-domain"))
    for feed_type, feed_value, matched_on in keys:
        key = (feed_type, feed_value)
        if key in enrichment:
            return {**dict(enrichment[key]), "matched_on": matched_on}
    return None


def ti_enrichment_assessment(
    *,
    ti_feed_sources: Sequence[Mapping[str, object]],
    enrichment_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "component": "ioc-ti-enrichment-plugin",
        "status": "offline-feed-enabled" if ti_feed_sources else "available-no-feed-loaded",
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "feed_count": len(ti_feed_sources),
        "ioc_ti_enrichment_manifest_hash": str(enrichment_manifest.get("manifest_hash") or "") if enrichment_manifest else "",
        "indicator_row_hash_count": int(enrichment_manifest.get("indicator_row_hash_count") or 0) if enrichment_manifest else 0,
        "ready_for_court_report": False,
        "blockers": list(IOC_TI_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Preserve local TI feed files with name/version/path and explain why they were trusted.",
            "Treat enrichment as a triage label until corroborated by source evidence, timestamps, and network context.",
        ],
        "core_accuracy_gates": ioc_ti_core_accuracy_gates(
            indicators=[],
            ti_feed_sources=ti_feed_sources,
            enrichment_manifest=enrichment_manifest,
        ),
    }


def build_ti_feed_row(
    row: Mapping[str, object],
    *,
    indicator_type: str,
    value: str,
    feed_name: str,
) -> dict[str, object]:
    row_core = {
        "type": indicator_type,
        "value": value,
        "severity": str(row.get("severity") or row.get("risk") or "").strip(),
        "classification": str(row.get("classification") or row.get("label") or "").strip(),
        "source": str(row.get("source") or feed_name).strip(),
        "note_hash": stable_ioc_ti_sha256({"note": str(row.get("note") or row.get("description") or "").strip()}),
    }
    return {**row_core, "feed_row_hash": stable_ioc_ti_sha256(row_core)}


def build_ti_feed_manifest(*, feed_source: Mapping[str, object], feed_rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    feed_row_hashes = [str(row.get("feed_row_hash") or "") for row in feed_rows if row.get("feed_row_hash")]
    manifest_core: dict[str, object] = {
        "manifest_version": "ioc-ti-feed-manifest-v1",
        "item_number": 63,
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "feed_name": str(feed_source.get("name") or ""),
        "feed_version": str(feed_source.get("version") or ""),
        "feed_path": str(feed_source.get("path") or ""),
        "feed_sha256": str(feed_source.get("sha256") or ""),
        "feed_size_bytes": int(feed_source.get("size_bytes") or 0),
        "indicator_count": int(feed_source.get("indicator_count") or 0),
        "feed_row_hash_count": len(feed_row_hashes),
        "feed_row_hashes": feed_row_hashes,
        "feed_rows_head_hash": stable_ioc_ti_sha256(feed_row_hashes),
        "local_only": True,
        "no_external_calls": True,
        "validation_status": "analyst-feed-provenance-review-required",
        "blockers": [
            "signed-feed-package-validation",
            "stix-taxii-import",
            "confidence-decay-workflow",
            IOC_TI_TRUSTED_DIFF_BLOCKER_63,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_ioc_ti_sha256(manifest_core)}


def attach_ioc_ti_indicator_manifests(indicators: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    output = []
    for index, indicator in enumerate(indicators):
        item = dict(indicator)
        manifest = build_ioc_ti_indicator_manifest(item, index=index)
        item["ioc_ti_indicator_manifest"] = manifest
        item["ioc_ti_indicator_manifest_hash"] = manifest["manifest_hash"]
        item["indicator_row_hash"] = manifest["indicator_row_hash"]
        output.append(item)
    return output


def build_ioc_ti_indicator_manifest(indicator: Mapping[str, object], *, index: int) -> dict[str, object]:
    enrichment = indicator.get("ti_enrichment") if isinstance(indicator.get("ti_enrichment"), Mapping) else {}
    source_rows = []
    for source_index, source in enumerate(indicator.get("sources") or []):
        if not isinstance(source, Mapping):
            continue
        source_core = {
            "index": source_index,
            "output": str(source.get("output") or ""),
            "output_path": str(source.get("output_path") or ""),
            "pointer": str(source.get("pointer") or ""),
            "path": str(source.get("path") or source.get("source_path") or ""),
        }
        source_rows.append({**source_core, "source_row_hash": stable_ioc_ti_sha256(source_core)})
    indicator_row_core = {
        "index": index,
        "type": str(indicator.get("type") or ""),
        "value": str(indicator.get("value") or ""),
        "count": int(indicator.get("count") or 0),
        "matched_rules": sorted(str(rule) for rule in indicator.get("matched_rules") or []),
        "matched_on": str(enrichment.get("matched_on") or ""),
        "feed_name": str(enrichment.get("feed_name") or ""),
        "feed_version": str(enrichment.get("feed_version") or ""),
        "feed_row_hash": str(enrichment.get("feed_row_hash") or ""),
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "ioc-ti-indicator-manifest-v1",
        "item_number": 63,
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        **indicator_row_core,
        "indicator_value_hash": stable_ioc_ti_sha256(
            {"type": indicator_row_core["type"], "value": indicator_row_core["value"]}
        ),
        "source_row_hashes": [str(row.get("source_row_hash") or "") for row in source_rows],
        "source_row_count": len(source_rows),
        "source_rows_head_hash": stable_ioc_ti_sha256(source_rows),
        "source_viewer_locator": {
            "viewer": "indicator-source-review",
            "open_action": "open-indicator-source",
            "type": indicator_row_core["type"],
            "value_hash": stable_ioc_ti_sha256(
                {"type": indicator_row_core["type"], "value": indicator_row_core["value"]}
            ),
        },
        "report_use_boundary": "indicator and local TI enrichment are pivots, not standalone maliciousness proof",
        "commercial_claim_allowed": False,
    }
    manifest_core["indicator_row_hash"] = stable_ioc_ti_sha256(indicator_row_core)
    return {**manifest_core, "manifest_hash": stable_ioc_ti_sha256(manifest_core)}


def build_ioc_ti_enrichment_manifest(
    *,
    indicators: Sequence[Mapping[str, object]],
    ti_feed_sources: Sequence[Mapping[str, object]],
    max_indicators: int,
    max_sources_per_indicator: int,
) -> dict[str, object]:
    indicator_rows = []
    for indicator in indicators:
        manifest = indicator.get("ioc_ti_indicator_manifest") if isinstance(indicator.get("ioc_ti_indicator_manifest"), Mapping) else {}
        indicator_rows.append(
            {
                "type": str(indicator.get("type") or ""),
                "value_hash": str(manifest.get("indicator_value_hash") or ""),
                "matched_rules": sorted(str(rule) for rule in indicator.get("matched_rules") or []),
                "matched_on": str((indicator.get("ti_enrichment") or {}).get("matched_on") if isinstance(indicator.get("ti_enrichment"), Mapping) else ""),
                "indicator_row_hash": str(manifest.get("indicator_row_hash") or ""),
                "indicator_manifest_hash": str(manifest.get("manifest_hash") or ""),
                "source_row_count": int(manifest.get("source_row_count") or 0),
            }
        )
    feed_rows = []
    for source in ti_feed_sources:
        manifest = source.get("ti_feed_manifest") if isinstance(source.get("ti_feed_manifest"), Mapping) else {}
        feed_rows.append(
            {
                "feed_name": str(source.get("name") or ""),
                "feed_version": str(source.get("version") or ""),
                "feed_sha256": str(source.get("sha256") or ""),
                "feed_manifest_hash": str(manifest.get("manifest_hash") or ""),
                "feed_row_hash_count": int(manifest.get("feed_row_hash_count") or 0),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "ioc-ti-enrichment-manifest-v1",
        "item_number": 63,
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "indicator_count": len(indicators),
        "enriched_indicator_count": sum(1 for indicator in indicators if indicator.get("ti_enrichment")),
        "ti_feed_count": len(ti_feed_sources),
        "indicator_row_hash_count": sum(1 for row in indicator_rows if row.get("indicator_row_hash")),
        "feed_manifest_hash_count": sum(1 for row in feed_rows if row.get("feed_manifest_hash")),
        "indicator_rows": indicator_rows,
        "feed_rows": feed_rows,
        "indicator_rows_head_hash": stable_ioc_ti_sha256(indicator_rows),
        "feed_rows_head_hash": stable_ioc_ti_sha256(feed_rows),
        "max_indicators": max_indicators,
        "max_sources_per_indicator": max_sources_per_indicator,
        "local_only": True,
        "no_external_calls": True,
        "blockers": [
            "signed-feed-package-validation",
            "stix-taxii-import",
            "confidence-decay-workflow",
            "external-ti-api-governance",
            IOC_TI_TRUSTED_DIFF_BLOCKER_63,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_ioc_ti_sha256(manifest_core)}


def build_ioc_ti_trusted_diff(
    rapid_indicators: Sequence[Mapping[str, object]],
    trusted_indicators: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "ioc-ti-ground-truth-manifest",
) -> dict[str, object]:
    rapid_index = {ioc_ti_diff_key(item): ioc_ti_diff_value(item) for item in rapid_indicators}
    trusted_index = {ioc_ti_diff_key(item): ioc_ti_diff_value(item) for item in trusted_indicators}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "ioc-ti-trusted-enrichment-diff-v1",
        "item_number": 63,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def ioc_ti_diff_key(item: Mapping[str, object]) -> str:
    return f"{str(item.get('type') or '').lower()}|{str(item.get('value') or '').lower()}"


def ioc_ti_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    enrichment = item.get("ti_enrichment")
    enrichment_map = enrichment if isinstance(enrichment, Mapping) else {}
    return {
        "matched_rules": sorted(str(rule) for rule in item.get("matched_rules") or []),
        "matched_on": str(enrichment_map.get("matched_on") or item.get("matched_on") or ""),
        "feed_name": str(enrichment_map.get("feed_name") or item.get("feed_name") or ""),
        "severity": str(enrichment_map.get("severity") or item.get("severity") or ""),
    }


def ioc_ti_core_accuracy_gates(
    *,
    indicators: Sequence[Mapping[str, object]],
    ti_feed_sources: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
    enrichment_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["local-only/no-external-call warning"]
    if any(item.get("sources") for item in indicators):
        satisfied.append("indicator extraction and source links")
    if any(item.get("matched_rules") for item in indicators):
        satisfied.append("local rule match preservation")
    if ti_feed_sources:
        satisfied.append("offline feed provenance")
    if any(isinstance(item.get("ti_enrichment"), Mapping) and item["ti_enrichment"].get("matched_on") for item in indicators):
        satisfied.append("match mode recorded")
    if enrichment_manifest and enrichment_manifest.get("manifest_hash"):
        satisfied.append("ioc-ti enrichment manifest")
    if any(item.get("indicator_row_hash") for item in indicators):
        satisfied.append("indicator row hashes")
    if any(isinstance(item.get("ti_feed_manifest"), Mapping) or item.get("ti_feed_manifest_hash") for item in ti_feed_sources):
        satisfied.append("feed manifest hashes")
    evidence_refs = [
        f"indicator_count:{len(indicators)}",
        f"ti_feed_count:{len(ti_feed_sources)}",
        f"matched_rule_count:{sum(1 for item in indicators if item.get('matched_rules'))}",
    ]
    if enrichment_manifest and enrichment_manifest.get("manifest_hash"):
        evidence_refs.append(f"ioc_ti_enrichment_manifest_hash:{enrichment_manifest.get('manifest_hash', '')}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted IOC/TI enrichment diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            63,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def ioc_ti_commercial_uplift_evidence(
    *,
    indicators: Sequence[Mapping[str, object]],
    ti_feed_sources: Sequence[Mapping[str, object]],
    core_accuracy_gates: Sequence[Mapping[str, object]],
    assessment: Mapping[str, object],
    max_indicators: int,
    max_sources_per_indicator: int,
    enrichment_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == IOC_TI_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [63],
        "implementation_track": "offline-ioc-ti-enrichment-gate",
        "source_refs": [
            f"indicator_count:{len(indicators)}",
            f"ti_feed_count:{len(ti_feed_sources)}",
            *[f"ti_feed:{item.get('name', '')}:{item.get('version', '')}" for item in ti_feed_sources[:5]],
            f"ioc_ti_enrichment_manifest_hash:{enrichment_manifest.get('manifest_hash', '') if enrichment_manifest else ''}",
        ],
        "reportability_decision": ioc_ti_reportability_decision(
            failed_validation_check_ids=[
                "signed-feed-package-validation",
                "stix-taxii-import",
                "confidence-decay-workflow",
                "external-ti-api-governance",
                IOC_TI_TRUSTED_DIFF_BLOCKER_63,
            ],
            commercial_blockers=list(assessment.get("blockers") or []),
            indicator_count=len(indicators),
            ti_feed_count=len(ti_feed_sources),
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "signed-feed-package-validation",
            "stix-taxii-import",
            "confidence-decay-workflow",
            "external-ti-api-governance",
            IOC_TI_TRUSTED_DIFF_BLOCKER_63,
        ],
        "commercial_blockers": list(assessment.get("blockers") or []),
        "large_data_controls": {
            "max_indicators": max_indicators,
            "max_sources_per_indicator": max_sources_per_indicator,
            "indicator_count": len(indicators),
            "ti_feed_count": len(ti_feed_sources),
            "external_ti_api_calls": False,
            "local_only_enrichment": True,
            "ioc_ti_enrichment_manifest_hash": str(enrichment_manifest.get("manifest_hash") or "") if enrichment_manifest else "",
            "indicator_row_hash_count": int(enrichment_manifest.get("indicator_row_hash_count") or 0) if enrichment_manifest else 0,
            "feed_manifest_hash_count": int(enrichment_manifest.get("feed_manifest_hash_count") or 0) if enrichment_manifest else 0,
            "signed_feed_packages": False,
            "trusted_enrichment_diff": False,
        },
        "reporting_status": "offline-feed-enabled" if ti_feed_sources else "available-no-feed-loaded",
    }


def ioc_ti_reportability_decision(
    *,
    failed_validation_check_ids: Sequence[str],
    commercial_blockers: Sequence[str],
    indicator_count: int,
    ti_feed_count: int,
) -> dict[str, object]:
    blockers = {str(item) for item in commercial_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "ioc-ti-reportability-decision-v1",
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "decision": "do-not-report-ioc-enrichment-as-live-ti-verdict",
        "allowed_use": "offline-ioc-ti-triage-pivot",
        "blockers": sorted(blockers),
        "indicator_count": indicator_count,
        "ti_feed_count": ti_feed_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "attach signed feed package provenance, versioning, and freshness evidence",
            "document STIX/TAXII or provider-native import validation and confidence-decay policy",
            "record local-only versus external TI API governance before reporting maliciousness",
        ],
    }


def normalize_feed_type(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"ipv4", "ip-address", "address"}:
        return "ip"
    if normalized in {"hostname", "host", "fqdn"}:
        return "domain"
    if normalized in {"uri"}:
        return "url"
    if normalized in {"md5", "sha1", "sha256", "url", "domain", "ip"}:
        return normalized
    text = value.strip()
    if URL_RE.search(text):
        return "url"
    if valid_ipv4(text):
        return "ip"
    if HASH_RE.fullmatch(text):
        return hash_type(text)
    return "domain"


def normalize_feed_value(indicator_type: str, value: str) -> str:
    text = value.strip()
    if indicator_type == "url":
        return normalize_url(text)
    if indicator_type == "domain":
        return text.lower().strip(".")
    if indicator_type in {"md5", "sha1", "sha256"}:
        return text.lower()
    return text


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
