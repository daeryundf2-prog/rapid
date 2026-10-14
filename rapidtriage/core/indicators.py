from __future__ import annotations

import csv
import datetime as dt
import hashlib
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from pathlib import Path
from urllib.parse import urlparse

from .artifact_profiles import iter_payload_records
from .forensic_accuracy import build_accuracy_gate
from .json_stream import LazyArray, LazyObject, Scalar, open_json
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
    "yara_string_rule_import": True,
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
IOC_TI_REPORT_GRADE_VALIDATION_PLAN_VERSION = "ioc-ti-report-grade-validation-plan-v1"
IOC_TI_REPORT_GRADE_VALIDATION_BLOCKERS = [
    "signed-ti-feed-package-required",
    "stix-taxii-provider-validation-required",
    "confidence-decay-policy-required",
    "trusted-ioc-ti-enrichment-diff-required",
    "external-ti-api-governance-required",
    "ioc-ti-false-positive-correlation-corpus-required",
]


# --- evidence field policy (parser-quality r1, finding C5) ------------------
# Indicators are extracted only from evidence-derived values. Subtrees that
# hold tool provenance (manifests, validation plans, accuracy gates, hash
# blocks the tool computed, review profiles that copy primary fields) are
# skipped; so are leaf keys naming tool identities (row/manifest hashes,
# artifact ids, output paths).
PROVENANCE_SUBTREE_KEYS: frozenset[str] = frozenset(
    {
        "core_accuracy_gates",
        "commercial_uplift_evidence",
        "forensic_review",
        "source_hashes",
        "hashes",
        "artifact_record",
        "profile_ref",
        "validation_checks",
        "options",
        "filters",
        "inputs",
        "manifest",
        "index",
        "ioc_hits",
        "matched_rules",
        "hash_cache_manifest",
        "hash_cache_assessment",
        "duplicate_content_groups",
        "fuzzy_text_duplicate_groups",
        "known_good_suppressed_candidates",
        "known_good_match",
        "file_signature",
        "signature_mismatch_candidates",
        "time_provenance",
        "file_exclusions",
        "recovery",
        "source_viewer_locator",
        "commercial_grade_blockers",
        "parser_errors",
        "time_policy",
        "redacted_row_samples",
        "redaction",
        "field_hashes",
    }
)
PROVENANCE_SUBTREE_SUFFIXES: tuple[str, ...] = (
    "_manifest",
    "_validation_plan",
    "_assessment",
    "_profile",
    "_gates",
    "_matrix",
    "_capabilities",
    "_citation",
    "_locator",
    "_trusted_diffs",
    "_trusted_diff",
)
PROVENANCE_LEAF_KEYS: frozenset[str] = frozenset(
    {
        "input_file",
        "records_path",
        "records_file",
        "output",
        "output_path",
        "artifacts_output",
        "run_summary",
        "root",
        "case_id",
        "citation_id",
        "artifact_id",
        "record_key",
        "group_id",
        "profile_version",
        "manifest_version",
        "parser_version",
        "generated_at",
    }
)
PROVENANCE_LEAF_RE = re.compile(r"(_sha256|_sha1|_md5|_hash|_hashes|_fingerprint|_digest|_row_hash|_id_hash)$")
# Leaf keys whose values are hashes recorded *inside* the evidence (Amcache
# SHA-1, Sysmon Hashes=, file-id). Hash tokens elsewhere count only when the
# whole value is the hash ("standalone").
EVIDENCE_HASH_KEYS: frozenset[str] = frozenset(
    {"sha1", "sha256", "md5", "file_id", "fileid", "file_hash", "hash_value", "hashes_value", "imphash", "hashes"}
)
# Leaf-key words that make a dotted quad an IP even when every octet <= 9.
# Matched per word of the key (``script_block_text``/``description`` contain
# "ip" as letters, not as a word).
IP_CONTEXT_KEY_WORDS: frozenset[str] = frozenset(
    {"ip", "ipv4", "ipaddress", "addr", "address", "host", "hostname", "remote", "source", "destination", "dest",
     "peer", "client", "server", "gateway", "dns", "src", "dst", "nameserver", "servers"}
)
_KEY_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def field_key_words(field_key: str) -> set[str]:
    """Lower-case words of a field key (``ClientAddress`` -> client, address)."""
    return {word.lower() for word in _KEY_WORD_RE.findall(field_key)}


def has_ip_context_key(field_key: str) -> bool:
    return bool(field_key_words(field_key) & IP_CONTEXT_KEY_WORDS) or "ipaddress" in field_key.lower()


# Hex blobs that are not hashes: SOCKADDR (ClientAddress/RemoteAddress),
# transport/device descriptors, WER DynamicSig/bucket ids, raw Binary/Data.
HASH_BLOB_FIELD_RE = re.compile(
    r"(?i)(address|transport|dynamicsig|bucket|blob|binary|bytes|data$|^data|identity|device|cdb|sockaddr|buffer|payload)"
)
HASH_NAMED_FIELD_RE = re.compile(r"(?i)(sha1|sha256|sha-1|sha-256|md5|imphash|hash|digest|thumbprint|checksum)")
HASH_ZERO_RUN = "0" * 8
# "Version 1.0.0.0", "ModuleVersion = '3.0.0.0'": a dotted quad after a version word.
VERSION_CONTEXT_RE = re.compile(r"(?i)(version|build|release|revision)\W{0,24}$")
# Word-bounded: "SMSvcHost 3.0.0.0" is a service name + version, not "host 3.0.0.0".
IP_CONTEXT_TEXT_RE = re.compile(r"(?i)\b(?:ip|ipv4|address|addr|host|remote|server|client|gateway|dns|src|dst)\W{0,3}$")
# Bulk inventory rows with no evidence indicator content of their own
# (registry key tree: names/offsets; their values surface in semantic rows).
INDICATOR_EXCLUDED_ARTIFACT_TYPES: frozenset[str] = frozenset(
    {"registry-key-tree-node", "registry-hive-cell"}
)
# Outputs not scanned: the timeline re-copies artifact fields (double counting).
INDICATOR_SCANNED_OUTPUTS = ("docs", "files")


def is_provenance_subtree(key: str) -> bool:
    # ``source_hashes*`` (incl. ``source_hashes_by_file``) are hashes the tool
    # computed over evidence files, keyed by host path.
    return key in PROVENANCE_SUBTREE_KEYS or key.endswith(PROVENANCE_SUBTREE_SUFFIXES) or key.startswith("source_hash")


def is_provenance_leaf(key: str) -> bool:
    if key in PROVENANCE_LEAF_KEYS:
        return True
    if key in EVIDENCE_HASH_KEYS:
        return False
    return bool(PROVENANCE_LEAF_RE.search(key))


def pointer_field_key(pointer: str) -> str:
    """Leaf field name of a JSON pointer (``/a/b/0`` -> ``b``)."""
    for part in reversed(pointer.split("/")):
        if part and not part.isdigit():
            return part.replace("~1", "/").replace("~0", "~")
    return ""


VERSION_FIELD_RE = re.compile(r"(version|oid|build|revision|release|link_date)", re.IGNORECASE)
NAME_LIKE_FIELD_RE = re.compile(r"(name|path|file|dir|folder|guid|uuid|hex|offset|sid|key|cursor|id$|title|label|preview|raw|data|sha|md5|hash)", re.IGNORECASE)
HASH_LABEL_RE = re.compile(r"(?i)(sha256|sha-256|sha1|sha-1|md5|imphash|hash)\s*[=:]\s*$")
EMPTY_OR_PLACEHOLDER_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
)
# XML namespace / schema URLs and printf templates are not network indicators.
NON_INDICATOR_URL_HOSTS = frozenset(
    {
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "schemas.xmlsoap.org",
        "www.w3.org",
        "w3.org",
        "purl.org",
        "ns.adobe.com",
        "ns.microsoft.com",
        "www.hancom.co.kr",
        "schemas.android.com",
        "xml.org",
    }
)
# Evidence-recorded hash fields sit directly under a row's details (Amcache
# SHA-1/FileId, Sysmon Hashes); the same key nested deeper (ole_streams[].sha256,
# redacted samples) is a hash the tool computed.
EVIDENCE_HASH_POINTER_RE = re.compile(r"/details/(?:decoded_values/|event_data/|values/)?[^/]+$")


def is_evidence_hash_field(pointer: str, field_key: str) -> bool:
    key = field_key.lower()
    if key not in EVIDENCE_HASH_KEYS and not key.endswith(("_sha1", "_md5", "_sha256")):
        return False
    if key not in EVIDENCE_HASH_KEYS and is_provenance_leaf(field_key):
        return False
    return bool(EVIDENCE_HASH_POINTER_RE.search(pointer))


LOOPBACK_URL_HOSTS = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def url_indicator_status(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return "no-host"
    try:
        parsed.port  # noqa: B018 - raises ValueError on a malformed host:port
    except ValueError:
        # HTTP.sys URL-group registrations such as http://127.0.0.1:4567:127.0.0.1/...
        return "malformed-netloc"
    if host in LOOPBACK_URL_HOSTS:
        return "loopback-host"
    try:
        if ipaddress.ip_address(host.strip("[]")).is_loopback:
            return "loopback-host"
    except ValueError:
        pass
    if "%" in host or "{" in url[:16] or re.search(r"%[sdux]", url):
        return "format-template"
    if host in NON_INDICATOR_URL_HOSTS:
        return "xml-namespace"
    if host in ("*", "+") or url.split("://", 1)[-1][:1] in ("*", "+"):
        # HTTP.sys URL reservations (http://+:80/, https://*:5358/): wildcard bindings.
        return "wildcard-host"
    return "accept"


def _hostname_label(label: str) -> bool:
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(char.isalnum() or char in "-_" for char in label)


def domain_indicator_status(host: str) -> str:
    """``accept`` for a DNS hostname; bare IPs (an ``ip`` indicator), wildcard
    bindings and labels that are not hostname-shaped are rejected."""
    text = host.strip(".").lower()
    if not text:
        return "empty"
    if text in ("*", "+") or "*" in text or "+" in text:
        return "wildcard"
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        pass
    else:
        return "ip-address"
    if len(text) > 253 or "." not in text:
        return "not-hostname"
    labels = text.split(".")
    if any(not label or len(label) > 63 or not _hostname_label(label) for label in labels):
        return "not-hostname"
    if labels[-1].isdigit():
        return "not-hostname"
    return "accept"


def is_version_like_ipv4(text: str, start: int, end: int) -> bool:
    """Dotted runs longer than four groups, ``v1.2.3.4`` and path segments."""
    before = text[max(0, start - 2) : start]
    after = text[end : end + 2]
    if (len(before) == 2 and before[1] == "." and before[0].isdigit()) or (after[:1] == "." and after[1:2].isdigit()):
        return True  # part of a longer dotted sequence (10.0.19041.1)
    previous = text[start - 1] if start > 0 else ""
    if previous and (previous.isalnum() or previous in "-_@+~"):
        return True  # app-1.0.0.30, v1.2.3.4
    following = text[end] if end < len(text) else ""
    if following and (following.isalnum() or following in "-_"):
        return True
    if previous and previous in "\\/":
        # Path segment (``...\1.15.0.1\...``); a UNC host (``\\10.0.0.5\``) is not.
        unc = start >= 2 and text[start - 2] in "\\/" and (start == 2 or text[start - 3] not in "\\/:")
        if not unc and not text[: start - 1].endswith(("://", ":/")):
            return True
    return False


def ipv4_indicator_status(text: str, match: re.Match[str], field_key: str) -> str:
    """``accept``, ``private`` or a rejection reason for an IPv4 candidate token.

    Version strings are the dominant false positive (``1.0.0.30`` in paths,
    ``Version`` values, OIDs). A dotted quad needs a non-version shape: no
    version-like field, no path-segment/affix position, at least one octet
    above 9, no trailing ``.0``, and — without an IP context word in the
    field name or just before the token — no zero octet in a low-first-octet
    address. Private/loopback addresses are kept but flagged (never
    rule-matched).
    """
    value = match.group(0)
    if not valid_ipv4(value):
        return "invalid"
    parts = value.split(".")
    octets = [int(part) for part in parts]
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        return "leading-zero"
    if octets[0] in (0, 255) or value.endswith(".255.255") or value == "255.255.255.255":
        return "unspecified-or-broadcast"
    if VERSION_FIELD_RE.search(field_key):
        return "version-like"
    if is_version_like_ipv4(text, match.start(), match.end()):
        return "version-like"
    before = text[max(0, match.start() - 48) : match.start()]
    if VERSION_CONTEXT_RE.search(before):
        return "version-like"  # "Version 1.0.0.0", "ModuleVersion = '1.0.0.0'"
    has_context = has_ip_context_key(field_key) or bool(IP_CONTEXT_TEXT_RE.search(before))
    if not has_context:
        if max(octets) <= 9 or octets[3] == 0:
            return "version-like"
        if 0 in octets and octets[0] < 30:
            return "version-like"
        if octets[0] <= 2 and octets[1] <= 39:
            return "oid-like"  # X.509/ASN.1 object identifiers (2.5.4.10, 1.3.36.3)
        if match.start() == 0 and match.end() == len(text) and NAME_LIKE_FIELD_RE.search(field_key):
            return "name-like"  # a file/directory name that happens to be a dotted quad
    address = ipaddress.ip_address(value)
    if address.is_private or address.is_loopback or address.is_link_local:
        return "private"
    return "accept"


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
INDICATOR_LABEL_NO_RULES = "지표 후보"
INDICATOR_LABEL_WITH_RULES = "지표"
INDICATOR_FIELD_POLICY_NOTE = (
    "증거 유래 필드(경로·URL·호스트·IP·명령줄·레지스트리 값·증거 내부 해시)만 스캔합니다. "
    "도구 출처 필드(manifest/validation plan/row hash/source_hashes/artifact id)와 타임라인 사본은 제외합니다."
)
YARA_STATUS = {
    "engine_available": False,
    "native_yara_engine_integration": False,
    "string_rule_import": True,
    "message": "YARA 엔진 없음: .yar 파일은 문자열 규칙(yara-lite)으로만 가져오며 condition/정규식/모듈은 평가하지 않습니다.",
}


class IndicatorSummaryError(ValueError):
    """Raised when indicator summary input cannot be loaded."""


def stable_ioc_ti_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_indicator_summary(
    run_output: Path | Mapping[str, object],
    *,
    rule_set: RuleSet | None = None,
    ti_feeds: Sequence[Path] | None = None,
    max_indicators: int | None = DEFAULT_MAX_INDICATORS,
    max_sources_per_indicator: int = DEFAULT_MAX_SOURCES_PER_INDICATOR,
    output_payloads: Mapping[str, Mapping[str, object]] | None = None,
    streamed_outputs: Iterable[str] | None = None,
) -> dict[str, object]:
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise IndicatorSummaryError("run summary does not include outputs")

    streamed = set(streamed_outputs or ())
    accumulator: dict[tuple[str, str], dict[str, object]] = {}
    scanner_accumulator: dict[tuple[str, str, str], dict[str, object]] = {}
    source_counts: Counter[str] = Counter()
    rejections: Counter[str] = Counter()
    for output_name, output_path in iter_run_json_outputs(outputs):
        source = {
            "output": output_name,
            "output_path": str(output_path),
        }
        if output_name in streamed:
            if not output_path.is_file():
                continue
            source_counts[output_name] += 1
            collect_indicators_from_stream(
                output_path,
                accumulator,
                scanner_accumulator,
                source=source,
                max_sources_per_indicator=max_sources_per_indicator,
                rejections=rejections,
            )
            continue
        payload = (output_payloads or {}).get(output_name)
        if payload is None:
            payload = read_json_path(output_path)
        if not payload:
            continue
        source_counts[output_name] += 1
        if output_name.startswith("artifacts_") and (payload.get("records_path") or payload.get("records_file")):
            collect_indicators_from_artifact_records(
                payload,
                output_path,
                accumulator,
                scanner_accumulator,
                source=source,
                max_sources_per_indicator=max_sources_per_indicator,
                rejections=rejections,
            )
            continue
        collect_ioc_scanner_hits_from_payload(
            payload,
            scanner_accumulator,
            source=source,
            max_sources_per_hit=max_sources_per_indicator,
        )
        for pointer, value, context in iter_scalar_contexts(payload):
            collect_indicators_from_text(
                value,
                accumulator,
                source={
                    **source,
                    "pointer": pointer,
                    **context,
                },
                max_sources_per_indicator=max_sources_per_indicator,
                rejections=rejections,
            )

    enrichment, ti_feed_sources = load_ti_feeds(ti_feeds or [])
    indicators = [
        finalize_indicator(record, rule_set=rule_set, enrichment=enrichment)
        for record in accumulator.values()
    ]
    indicators.sort(key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity")), 9), -int(item["count"]), str(item["type"]), str(item["value"])))
    total_before_cap = len(indicators)
    type_counts_before_cap = Counter(str(item["type"]) for item in indicators)
    if max_indicators:
        indicators = indicators[:max_indicators]
    truncated = len(indicators) < total_before_cap
    cap_policy = indicator_cap_policy(max_indicators, total_before_cap=total_before_cap, kept=len(indicators))
    sources_truncated_count = sum(1 for item in indicators if int(item.get("count") or 0) > len(item.get("sources") or []))
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
    validation_plan = build_ioc_ti_report_grade_validation_plan(
        plan_context="indicator-summary",
        indicators=indicators,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        max_indicators=max_indicators,
        max_sources_per_indicator=max_sources_per_indicator,
        trusted_diff=None,
    )

    type_counts = Counter(str(item["type"]) for item in indicators)
    rule_counts = Counter(rule for item in indicators for rule in item.get("matched_rules", []))
    scanner_rule_counts = Counter(str(item.get("rule_id") or "") for item in ioc_scanner_hits if item.get("rule_id"))
    core_accuracy_gates = ioc_ti_core_accuracy_gates(
        indicators=indicators,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        validation_plan=validation_plan,
    )
    assessment = ti_enrichment_assessment(
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        validation_plan=validation_plan,
    )
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
            "total_before_cap": total_before_cap,
            "truncated": truncated,
            "max_indicators": max_indicators,
            "cap_policy": cap_policy,
            "type_counts_before_cap": dict(type_counts_before_cap),
            "sources_truncated_indicator_count": sources_truncated_count,
            "max_sources_per_indicator": max_sources_per_indicator,
            "severity_counts": dict(Counter(str(item.get("severity") or "") for item in indicators)),
            "rejected_token_counts": dict(sorted(rejections.items())),
            "scanned_outputs": sorted(source_counts),
            "field_policy": INDICATOR_FIELD_POLICY_NOTE,
            "rule_count": rule_set.rule_count if rule_set else 0,
            "rules_loaded": bool(rule_set and rule_set.rule_count),
            "display_label": INDICATOR_LABEL_WITH_RULES if rule_set and rule_set.rule_count else INDICATOR_LABEL_NO_RULES,
            "rule_status_message": (
                f"규칙 {rule_set.rule_count}개 적용 ({rule_set.format})"
                if rule_set and rule_set.rule_count
                else "적용된 탐지 규칙 0개: 아래 항목은 규칙 일치가 아닌 '지표 후보'(증거에서 추출한 URL·도메인·IP·해시)입니다."
            ),
            "yara": dict(YARA_STATUS),
            "type_counts": dict(type_counts),
            "source_output_counts": dict(source_counts),
            "matched_rule_counts": dict(rule_counts),
            "matched_indicator_count": sum(1 for item in indicators if item.get("matched_rules")),
            "ioc_scanner_hit_count": sum(int(item.get("count") or 0) for item in ioc_scanner_hits),
            "ioc_scanner_row_count": len(ioc_scanner_hits),
            "ioc_scanner_row_count_before_cap": len(scanner_accumulator),
            "ioc_scanner_truncated": len(ioc_scanner_hits) < len(scanner_accumulator),
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
        "ioc_ti_report_grade_validation_plan": validation_plan,
        "ioc_ti_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
            validation_plan=validation_plan,
        ),
        "indicators": indicators,
    }


def indicator_cap_policy(max_indicators: int | None, *, total_before_cap: int, kept: int) -> dict[str, object]:
    """Disclosure of the indicator cap (``None``/``0`` = uncapped)."""
    if not max_indicators:
        return {
            "mode": "uncapped",
            "max_indicators": None,
            "kept": kept,
            "total_before_cap": total_before_cap,
            "note": "상한 없음: 추출된 지표 후보를 모두 기록했습니다 (CLI `indicators --limit N`으로 상한 지정 가능).",
        }
    return {
        "mode": "capped",
        "max_indicators": int(max_indicators),
        "kept": kept,
        "total_before_cap": total_before_cap,
        "note": (
            f"상한 {int(max_indicators)}개 적용: 전체 {total_before_cap}개 중 {kept}개만 기록 "
            "(심각도·출현 빈도 순)."
            if kept < total_before_cap
            else f"상한 {int(max_indicators)}개 (도달하지 않음)."
        ),
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
        if not output_name.startswith("artifacts_") and output_name not in INDICATOR_SCANNED_OUTPUTS:
            continue
        path = Path(str(raw_path)).expanduser().resolve()
        if path.is_file():
            yield output_name, path


def collect_indicators_from_artifact_records(
    payload: Mapping[str, object],
    payload_path: Path,
    accumulator: MutableMapping[tuple[str, str], dict[str, object]],
    scanner_accumulator: MutableMapping[tuple[str, str, str], dict[str, object]],
    *,
    source: Mapping[str, str],
    max_sources_per_indicator: int,
    rejections: Counter[str] | None = None,
) -> None:
    """Scan a JSONL-backed per-kind payload one row at a time.

    Pointers keep the inline shape (``/artifacts/<index>/...``). Rows are
    scanned as stored: constant blocks hoisted to ``artifact_type_profiles``
    are scanned once there instead of once per row.
    """
    head = {key: value for key, value in payload.items() if key != "artifacts"}
    nested_hits = list(iter_ioc_hit_contexts(head, pointer="", include_root=False))
    for pointer, value, context in iter_scalar_contexts(head):
        collect_indicators_from_text(
            value,
            accumulator,
            source={**source, "pointer": pointer, **context},
            max_sources_per_indicator=max_sources_per_indicator,
            rejections=rejections,
        )
    for index, row in enumerate(iter_payload_records(payload, payload_path=payload_path, expand=False)):
        if str(row.get("artifact_type") or "") in INDICATOR_EXCLUDED_ARTIFACT_TYPES:
            continue
        row_pointer = f"/artifacts/{index}"
        nested_hits.extend(iter_ioc_hit_contexts(row, pointer=row_pointer, include_root=False))
        for pointer, value, context in iter_scalar_contexts(row, row_pointer):
            collect_indicators_from_text(
                value,
                accumulator,
                source={**source, "pointer": pointer, **context},
                max_sources_per_indicator=max_sources_per_indicator,
                rejections=rejections,
            )
    hit_contexts = nested_hits or list(iter_ioc_hit_contexts(head, pointer="", include_root=True))
    for pointer, hit, context in hit_contexts:
        add_ioc_scanner_hit_from_dict(
            scanner_accumulator,
            hit,
            pointer=pointer,
            context=context,
            source=source,
            max_sources_per_hit=max_sources_per_indicator,
        )


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
            key_text = str(key)
            child_pointer = f"{pointer}/{escape_pointer(key_text)}"
            if isinstance(item, (Mapping, list)):
                if is_provenance_subtree(key_text):
                    continue
                yield from iter_scalar_contexts(item, child_pointer)
                continue
            if item is None or is_provenance_leaf(key_text):
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
    rejections: Counter[str] | None = None,
) -> None:
    for raw_url in URL_RE.findall(text):
        url = normalize_url(raw_url)
        if not url:
            continue
        url_status = url_indicator_status(url)
        if url_status != "accept":
            if rejections is not None:
                rejections[f"url:{url_status}"] += 1
            continue
        add_indicator(accumulator, "url", url, source, max_sources_per_indicator=max_sources_per_indicator)
        host = (urlparse(url).hostname or "").lower()
        domain_status = domain_indicator_status(host)
        if domain_status == "accept":
            add_indicator(accumulator, "domain", host, source, max_sources_per_indicator=max_sources_per_indicator)
        elif rejections is not None:
            rejections[f"domain:{domain_status}"] += 1
    pointer = str(source.get("pointer") or "")
    field_key = pointer_field_key(pointer)
    for match in IP_RE.finditer(text):
        status = ipv4_indicator_status(text, match, field_key)
        if status not in {"accept", "private"}:
            if rejections is not None:
                rejections[f"ip:{status}"] += 1
            continue
        add_indicator(accumulator, "ip", match.group(0), source, max_sources_per_indicator=max_sources_per_indicator)
    hash_field = is_evidence_hash_field(pointer, field_key)
    name_like_field = bool(NAME_LIKE_FIELD_RE.search(field_key))
    stripped = text.strip().lower()
    for match in HASH_RE.finditer(text):
        raw_hash = match.group(0)
        lowered = raw_hash.lower()
        if lowered in EMPTY_OR_PLACEHOLDER_HASHES or len(set(lowered)) <= 2:
            if rejections is not None:
                rejections["hash:empty-or-placeholder"] += 1
            continue
        labeled = (
            not name_like_field
            and "/" not in field_key
            and "\\" not in field_key
            and bool(HASH_LABEL_RE.search(text[max(0, match.start() - 8) : match.start()]))
        )
        standalone = stripped == lowered and not name_like_field
        if standalone and not hash_field:
            # A bare hex value counts only in a field that may hold a hash:
            # never in a binary-blob field (SOCKADDR ClientAddress, Transport,
            # WER DynamicSig/bucket, Binary/Data), and an EventData value only
            # under a hash-named field.
            blob_reason = standalone_hash_blob_reason(pointer, field_key, lowered)
            if blob_reason:
                if rejections is not None:
                    rejections[f"hash:{blob_reason}"] += 1
                continue
        if not (hash_field or labeled or standalone):
            if rejections is not None:
                rejections["hash:not-hash-field"] += 1
            continue
        add_indicator(
            accumulator,
            hash_type(raw_hash),
            raw_hash.lower(),
            source,
            max_sources_per_indicator=max_sources_per_indicator,
        )


EVENT_DATA_POINTER_PARTS: tuple[str, ...] = ("/event_data/", "/EventData/", "/fields/", "/values/")


def standalone_hash_blob_reason(pointer: str, field_key: str, token: str) -> str:
    """Why a whole-value hex token is a binary blob, not a hash ('' = hash-like)."""
    if HASH_BLOB_FIELD_RE.search(field_key) and not HASH_NAMED_FIELD_RE.search(field_key):
        return "binary-blob-field"
    if HASH_ZERO_RUN in token:
        return "binary-blob-zero-run"  # SOCKADDR / structure padding; a digest has no 8-zero run
    if any(part in pointer for part in EVENT_DATA_POINTER_PARTS) and not HASH_NAMED_FIELD_RE.search(field_key):
        return "event-data-not-hash-field"
    return ""


def add_indicator(
    accumulator: MutableMapping[tuple[str, str], dict[str, object]],
    indicator_type: str,
    value: str,
    source: Mapping[str, str],
    *,
    max_sources_per_indicator: int,
) -> None:
    # URLs keep their original case in ``value``; the dedupe/compare key is
    # the case-folded form (``value_fold``). Other types are already folded.
    key = (indicator_type, indicator_compare_key(indicator_type, value))
    if key not in accumulator:
        accumulator[key] = {"type": indicator_type, "value": value, "count": 0, "sources": []}
        if indicator_type == "url":
            accumulator[key]["value_fold"] = key[1]
    record = accumulator[key]
    record["count"] = int(record["count"]) + 1
    sources = record["sources"]
    if isinstance(sources, list) and len(sources) < max_sources_per_indicator:
        compact_source = {key: val for key, val in source.items() if val}
        if compact_source not in sources:
            sources.append(compact_source)


def collect_indicators_from_stream(
    path: Path,
    accumulator: MutableMapping[tuple[str, str], dict[str, object]],
    scanner_accumulator: MutableMapping[tuple[str, str, str], dict[str, object]],
    *,
    source: Mapping[str, str],
    max_sources_per_indicator: int,
    rejections: Counter[str] | None = None,
) -> None:
    """Collect indicators and scanner IOC hits from an output too large to load.

    Performs a single ``json_stream`` walk so each array item or object
    member is materialized one at a time. Scalar coverage matches
    ``iter_scalar_contexts`` — only mapping members are yielded — but the
    per-object emit order differs (siblings are buffered so their context
    is complete), which can change which capped sources are recorded. The
    nested-before-root ``ioc_hits`` fallback matches
    collect_ioc_scanner_hits_from_payload.
    """
    pending_root_hits: list[tuple[str, Mapping[str, object], dict[str, str]]] = []
    nested_hit_seen = False
    with open_json(path) as root:
        for event in _iter_stream_events(root, pointer=""):
            kind = event[0]
            if kind == "scalar":
                _, pointer, text, context = event
                collect_indicators_from_text(
                    text,
                    accumulator,
                    source={**source, "pointer": pointer, **context},
                    max_sources_per_indicator=max_sources_per_indicator,
                    rejections=rejections,
                )
            elif kind == "ioc_root":
                _, pointer, hit, context = event
                pending_root_hits.append((pointer, hit, context))
            else:
                _, pointer, hit, context = event
                nested_hit_seen = True
                add_ioc_scanner_hit_from_dict(
                    scanner_accumulator,
                    hit,
                    pointer=pointer,
                    context=context,
                    source=source,
                    max_sources_per_hit=max_sources_per_indicator,
                )
    if not nested_hit_seen:
        for pointer, hit, context in pending_root_hits:
            add_ioc_scanner_hit_from_dict(
                scanner_accumulator,
                hit,
                pointer=pointer,
                context=context,
                source=source,
                max_sources_per_hit=max_sources_per_indicator,
            )


def _iter_stream_events(
    node: object,
    pointer: str,
) -> Iterable[tuple]:
    """Yield ``("scalar"|"ioc"|"ioc_root", pointer, payload, context)``.

    Mirrors iter_scalar_contexts + iter_ioc_hit_contexts over json_stream
    lazy nodes in one pass. ``ioc_root`` marks root-level ``ioc_hits``
    entries so callers can apply the nested-first fallback.
    """
    if isinstance(node, Scalar):
        return
    if isinstance(node, LazyArray):
        for index, item in enumerate(node.items(lazy=True)):
            yield from _iter_stream_events(item, f"{pointer}/{index}")
        return
    if not isinstance(node, LazyObject):
        return
    scalars: dict[str, object] = {}
    scalar_order: list[str] = []
    hits: list[tuple[str, Mapping[str, object]]] = []
    for key, child in node.members():
        if isinstance(child, Scalar):
            scalars[key] = child.value
            if not is_provenance_leaf(str(key)):
                scalar_order.append(key)
        elif key != "ioc_hits" and is_provenance_subtree(str(key)):
            continue  # lazy child is skipped by the members() cursor
        elif key == "ioc_hits" and isinstance(child, LazyArray):
            for index, hit in enumerate(child.items()):
                hit_pointer = f"{pointer}/ioc_hits/{index}"
                if isinstance(hit, Mapping):
                    hits.append((hit_pointer, hit))
                for scalar_pointer, scalar_text, scalar_context in iter_scalar_contexts(hit, hit_pointer):
                    yield "scalar", scalar_pointer, scalar_text, scalar_context
        else:
            # Lazy containers must be consumed while the parent members()
            # cursor is positioned on them — deferring past the loop leaves
            # the reader beyond the child's bytes.
            yield from _iter_stream_events(child, f"{pointer}/{escape_pointer(str(key))}")
    context = context_from_mapping(scalars)
    for key in scalar_order:
        item = scalars[key]
        if item is None:
            continue
        text = str(item)
        if text and len(text) <= MAX_SCALAR_LENGTH:
            yield "scalar", f"{pointer}/{escape_pointer(str(key))}", text, context
    tag = "ioc_root" if not pointer else "ioc"
    for hit_pointer, hit in hits:
        yield tag, hit_pointer, hit, context


def add_ioc_scanner_hit_from_dict(
    accumulator: MutableMapping[tuple[str, str, str], dict[str, object]],
    hit: Mapping[str, object],
    *,
    pointer: str,
    context: Mapping[str, str],
    source: Mapping[str, str],
    max_sources_per_hit: int,
) -> None:
    """Validate one scanner hit dict and accumulate it."""
    rule_id = str(hit.get("rule_id") or "").strip()
    hit_type = str(hit.get("type") or "").strip().lower()
    value = normalize_ioc_scanner_value(hit_type, str(hit.get("value") or ""))
    if not rule_id or not hit_type or not value:
        return
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
        add_ioc_scanner_hit_from_dict(
            accumulator,
            hit,
            pointer=pointer,
            context=context,
            source=source,
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
    limit: int | None,
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
        "rule_set_rule_count": rule_set.rule_count if rule_set else 0,
        "native_ioc_rule_engine": True,
        "bounded_file_content_keyword_scanning": True,
        "local_only": True,
        "no_external_calls": True,
        "yara_string_rule_import": bool(rule_set and rule_set.format == "yara-lite"),
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
        **({"value_fold": str(record.get("value_fold") or "")} if record.get("value_fold") else {}),
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
        indicator["rule_provenance"] = [
            {"rule_id": rule_id, "rule_set": rule_set.path if rule_set else "", "format": rule_set.format if rule_set else ""}
            for rule_id in matched_rules
        ]
    enrichment_hit = lookup_ti_enrichment(indicator, enrichment or {})
    if enrichment_hit:
        indicator["ti_enrichment"] = dict(enrichment_hit)
        indicator["risk_flags"] = sorted(set(indicator["risk_flags"]) | {"ti-enriched"})
    indicator["severity"] = indicator_severity(indicator)
    return indicator


def indicator_severity(indicator: Mapping[str, object]) -> str:
    """``high`` (rule/TI hit), ``medium`` (global IP, cleartext/IP-host URL), ``low``, ``info``."""
    if indicator.get("matched_rules") or indicator.get("ti_enrichment"):
        return "high"
    classification = str(indicator.get("classification") or "")
    if classification in {"private", "loopback", "reserved", "non-global"}:
        return "info"
    flags = set(indicator.get("risk_flags") or [])
    if flags & {"global-ip", "url-ip-host", "cleartext-url"}:
        return "medium"
    if str(indicator.get("type")) in {"md5", "sha1", "sha256"}:
        return "info"
    return "low"


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
    validation_plan = build_ioc_ti_report_grade_validation_plan(
        plan_context="api-review-package",
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        max_indicators=limit,
        max_sources_per_indicator=DEFAULT_MAX_SOURCES_PER_INDICATOR,
        trusted_diff=None,
    )
    core_accuracy_gates = ioc_ti_core_accuracy_gates(
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        validation_plan=validation_plan,
    )
    assessment = ti_enrichment_assessment(
        ti_feed_sources=ti_feed_sources,
        enrichment_manifest=enrichment_manifest,
        validation_plan=validation_plan,
    )
    uplift = ioc_ti_commercial_uplift_evidence(
        indicators=reviewed_for_manifest,
        ti_feed_sources=ti_feed_sources,
        core_accuracy_gates=core_accuracy_gates,
        assessment=assessment,
        max_indicators=limit,
        max_sources_per_indicator=DEFAULT_MAX_SOURCES_PER_INDICATOR,
        enrichment_manifest=enrichment_manifest,
        validation_plan=validation_plan,
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
        "ioc_ti_report_grade_validation_plan": validation_plan,
        "ioc_ti_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "component": "ioc-ti-enrichment-plugin",
        "status": "offline-feed-enabled" if ti_feed_sources else "available-no-feed-loaded",
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "feed_count": len(ti_feed_sources),
        "ioc_ti_enrichment_manifest_hash": str(enrichment_manifest.get("manifest_hash") or "") if enrichment_manifest else "",
        "indicator_row_hash_count": int(enrichment_manifest.get("indicator_row_hash_count") or 0) if enrichment_manifest else 0,
        "ioc_ti_report_grade_validation_plan": validation_plan if isinstance(validation_plan, Mapping) else {},
        "ioc_ti_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or "") if isinstance(validation_plan, Mapping) else "",
        "report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
        "report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
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
            validation_plan=validation_plan,
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
    max_indicators: int | None,
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


def build_ioc_ti_report_grade_validation_plan(
    *,
    plan_context: str,
    indicators: Sequence[Mapping[str, object]],
    ti_feed_sources: Sequence[Mapping[str, object]],
    enrichment_manifest: Mapping[str, object],
    max_indicators: int | None,
    max_sources_per_indicator: int,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    enriched_count = sum(1 for indicator in indicators if indicator.get("ti_enrichment"))
    matched_on_count = sum(
        1
        for indicator in indicators
        if isinstance(indicator.get("ti_enrichment"), Mapping) and indicator["ti_enrichment"].get("matched_on")
    )
    feed_manifest_hash_count = int(enrichment_manifest.get("feed_manifest_hash_count") or 0)
    indicator_row_hash_count = int(enrichment_manifest.get("indicator_row_hash_count") or 0)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "ioc-ti-local-only-boundary-recorded",
            ready=True,
            evidence="local_only=true no_external_calls=true",
            blocker_id="ioc-ti-local-only-boundary-required",
            operator_action="Preserve the local-only/no-external-call warning with every TI enrichment output.",
        ),
        slot(
            "ioc-ti-enrichment-manifest-emitted",
            ready=bool(enrichment_manifest.get("manifest_hash")),
            evidence=f"ioc_ti_enrichment_manifest_hash={enrichment_manifest.get('manifest_hash', '')}",
            blocker_id="ioc-ti-enrichment-manifest-required",
            operator_action="Attach the enrichment manifest before reviewing IOC/TI labels.",
        ),
        slot(
            "ioc-ti-indicator-row-hashes",
            ready=indicator_row_hash_count >= max(0, min(len(indicators), 1)),
            evidence=f"indicator_row_hash_count={indicator_row_hash_count} indicator_count={len(indicators)}",
            blocker_id="ioc-ti-indicator-row-hashes-required",
            operator_action="Preserve per-indicator row hashes and source locators for review.",
        ),
        slot(
            "ioc-ti-feed-provenance-recorded",
            ready=bool(ti_feed_sources),
            evidence=f"ti_feed_count={len(ti_feed_sources)}",
            blocker_id="ioc-ti-feed-provenance-required",
            operator_action="Record feed name, version, path, SHA-256, size, and row hashes.",
        ),
        slot(
            "ioc-ti-feed-manifest-hashes",
            ready=feed_manifest_hash_count >= max(0, min(len(ti_feed_sources), 1)),
            evidence=f"feed_manifest_hash_count={feed_manifest_hash_count}",
            blocker_id="ioc-ti-feed-manifest-hashes-required",
            operator_action="Attach feed manifests for every local TI feed used.",
        ),
        slot(
            "ioc-ti-match-mode-recorded",
            ready=enriched_count == 0 or matched_on_count >= enriched_count,
            evidence=f"enriched_indicator_count={enriched_count} matched_on_count={matched_on_count}",
            blocker_id="ioc-ti-match-mode-required",
            operator_action="Record exact or URL-host-domain match mode for enriched indicators.",
        ),
        slot(
            "ioc-ti-signed-feed-package",
            ready=False,
            evidence="signed_ti_feed_package=false",
            blocker_id="signed-ti-feed-package-required",
            operator_action="Attach signed feed package provenance, freshness, and retention metadata.",
        ),
        slot(
            "ioc-ti-stix-taxii-provider-validation",
            ready=False,
            evidence="stix_taxii_provider_validation=false",
            blocker_id="stix-taxii-provider-validation-required",
            operator_action="Validate STIX/TAXII/provider-native import semantics against known provider exports.",
        ),
        slot(
            "ioc-ti-confidence-decay-policy",
            ready=False,
            evidence="confidence_decay_policy=false",
            blocker_id="confidence-decay-policy-required",
            operator_action="Document feed age, revocation, scoring, and confidence decay before report-grade use.",
        ),
        slot(
            "ioc-ti-trusted-enrichment-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id="trusted-ioc-ti-enrichment-diff-required",
            operator_action="Attach a trusted IOC/TI enrichment diff before commercial verdict claims.",
        ),
        slot(
            "ioc-ti-external-api-governance",
            ready=False,
            evidence="external_ti_api_governance=false external_calls=false",
            blocker_id="external-ti-api-governance-required",
            operator_action="Define external API authority, logging, rate-limit, and evidence-sharing controls before live TI use.",
        ),
        slot(
            "ioc-ti-false-positive-correlation-corpus",
            ready=False,
            evidence=f"max_indicators={max_indicators} max_sources_per_indicator={max_sources_per_indicator} fp_corpus=false",
            blocker_id="ioc-ti-false-positive-correlation-corpus-required",
            operator_action="Validate IOC/TI false positives against benign corpora and source-context correlation cases.",
        ),
    ]
    blockers = sorted(
        {
            str(slot_row["blocker_id"])
            for slot_row in validation_slots
            if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
        }
    )
    plan_core: dict[str, object] = {
        "profile_version": IOC_TI_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 63,
        "gap_id": IOC_TI_GAP_ID,
        "batch_id": "commercial-uplift-061-065",
        "plan_context": plan_context,
        "selected_track": "offline-ioc-ti-enrichment-gate",
        "indicator_count": len(indicators),
        "enriched_indicator_count": enriched_count,
        "ti_feed_count": len(ti_feed_sources),
        "max_indicators": max_indicators,
        "max_sources_per_indicator": max_sources_per_indicator,
        "ioc_ti_enrichment_manifest_sha256": str(enrichment_manifest.get("manifest_hash") or ""),
        "indicator_row_hash_count": indicator_row_hash_count,
        "feed_manifest_hash_count": feed_manifest_hash_count,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete"),
        "blocking_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(IOC_TI_REPORT_GRADE_VALIDATION_BLOCKERS),
        "validation_commands": [
            "rapidtriage indicators <run-output> --ti-feed <local-feed.json> --json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-indicators.json --reference-output <trusted-ioc-ti-manifest> --backlog-item 63 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-061-070-known-answer.json --limit 63 --json",
        ],
        "report_guidance": {
            "allowed_use": "offline-ioc-ti-triage-pivot",
            "forbidden_claims": [
                "IOC/TI match proves maliciousness",
                "local feed match is a live TI verdict",
                "feed freshness and confidence are validated",
                "external TI API governance is enabled",
            ],
            "required_disclaimer": (
                "IOC/TI enrichment is an offline triage label. Do not report maliciousness or live TI verdicts "
                "until signed feed provenance, provider/schema validation, confidence decay, source-context "
                "correlation, and trusted enrichment diff evidence are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_ioc_ti_sha256(plan_core)}


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
    validation_plan: Mapping[str, object] | None = None,
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
    if validation_plan and validation_plan.get("validation_plan_sha256"):
        satisfied.append("ioc-ti report-grade validation plan")
    if validation_plan and int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("ioc-ti report-grade ready slots")
    evidence_refs = [
        f"indicator_count:{len(indicators)}",
        f"ti_feed_count:{len(ti_feed_sources)}",
        f"matched_rule_count:{sum(1 for item in indicators if item.get('matched_rules'))}",
    ]
    if enrichment_manifest and enrichment_manifest.get("manifest_hash"):
        evidence_refs.append(f"ioc_ti_enrichment_manifest_hash:{enrichment_manifest.get('manifest_hash', '')}")
    if validation_plan and validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(f"ioc_ti_report_grade_validation_plan_hash:{validation_plan['validation_plan_sha256']}")
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
    max_indicators: int | None,
    max_sources_per_indicator: int,
    enrichment_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
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
            validation_plan=validation_plan,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": sorted(set([
            "signed-feed-package-validation",
            "stix-taxii-import",
            "confidence-decay-workflow",
            "external-ti-api-governance",
            IOC_TI_TRUSTED_DIFF_BLOCKER_63,
            *[str(item) for item in (validation_plan.get("blockers") if isinstance(validation_plan, Mapping) else []) or []],
        ])),
        "commercial_blockers": sorted(
            set(
                [
                    *[str(item) for item in assessment.get("blockers") or []],
                    *IOC_TI_REPORT_GRADE_VALIDATION_BLOCKERS,
                ]
            )
        ),
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
            "ioc_ti_report_grade_validation_plan_present": isinstance(validation_plan, Mapping),
            "ioc_ti_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or "") if isinstance(validation_plan, Mapping) else "",
            "ioc_ti_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
            "ioc_ti_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
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
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in commercial_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    if isinstance(validation_plan, Mapping):
        blockers.update(str(item) for item in validation_plan.get("blockers") or [])
    return {
        "profile_version": "ioc-ti-reportability-decision-v1",
        "commercial_gap_ids": [IOC_TI_GAP_ID],
        "decision": "do-not-report-ioc-enrichment-as-live-ti-verdict",
        "allowed_use": "offline-ioc-ti-triage-pivot",
        "blockers": sorted(blockers),
        "indicator_count": indicator_count,
        "ti_feed_count": ti_feed_count,
        "ioc_ti_report_grade_validation_plan_present": isinstance(validation_plan, Mapping),
        "ioc_ti_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or "") if isinstance(validation_plan, Mapping) else "",
        "ioc_ti_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
        "ioc_ti_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
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
        return indicator_compare_key("url", normalize_url(text))
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
    if indicator_type == "ip" and classify_indicator(indicator_type, value) in {"private", "loopback"}:
        return []  # private addresses are flagged, never rule-matched
    for rule in rule_set.rules:
        if (
            (indicator_type == "domain" and any(value == item or value.endswith(f".{item}") for item in rule.domains))
            or (indicator_type == "url" and any(item.lower() in value for item in rule.urls))
            or (indicator_type in {"md5", "sha1", "sha256"} and value in rule.hashes)
        ):
            matched.append(rule.id)
    return sorted(set(matched))


def normalize_url(value: str) -> str:
    """Trim trailing punctuation; the original case is kept (paths and
    queries are case-sensitive). :func:`indicator_compare_key` folds."""
    return value.strip().rstrip(".,);]")


def indicator_compare_key(indicator_type: str, value: str) -> str:
    """Dedupe/compare key: URLs case-folded, other types as normalized."""
    return value.lower() if indicator_type == "url" else value


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
