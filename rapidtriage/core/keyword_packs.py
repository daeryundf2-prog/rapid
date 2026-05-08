from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .forensic_accuracy import build_accuracy_gate


BUILTIN_KEYWORD_PACKS: dict[str, list[str]] = {
    "credentials": [
        "password",
        "passwd",
        "credential",
        "secret",
        "token",
        "apikey",
        "api_key",
        "mnemonic",
        "recovery key",
    ],
    "execution": [
        "powershell",
        "cmd.exe",
        "wmic",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
        "schtasks",
        "mshta",
        "encodedcommand",
    ],
    "network": [
        "http://",
        "https://",
        "ftp://",
        "download",
        "upload",
        "proxy",
        "vpn",
        "tor",
        "onion",
        "webhook",
    ],
    "browser-ai": [
        "chatgpt",
        "openai",
        "claude",
        "anthropic",
        "gemini",
        "perplexity",
        "copilot",
        "prompt",
        "assistant",
        "conversation",
    ],
    "windows-ir": [
        "4624",
        "4625",
        "4688",
        "7045",
        "4698",
        "powershell",
        "script block",
        "defender",
        "firewall",
        "rdp",
        "runonce",
    ],
    "exfiltration": [
        "mega.nz",
        "dropbox",
        "drive.google.com",
        "onedrive",
        "rclone",
        "winscp",
        "scp",
        "sftp",
        "archive",
        "7z",
    ],
}
KEYWORD_PACK_GAP_ID = "#62"
KEYWORD_PACK_REPORT_GRADE_BLOCKERS = [
    "built-in-keyword-packs-are-starter-libraries-not-case-specific-legal-scope",
    "analyst-must-record-pack-name-version-and-added-case-specific-terms",
    "keyword-packs-do-not-replace-language-specific-or-domain-specific-review",
    "trusted-keyword-pack-expansion-diff-is-required-before-commercial-claim",
]
KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62 = "trusted-keyword-pack-expansion-diff-missing"


class KeywordPackError(ValueError):
    """Raised when keyword pack input cannot be resolved."""


def resolve_keyword_packs(
    keywords: Sequence[str],
    *,
    pack_names: Sequence[str] | None = None,
    pack_files: Sequence[Path] | None = None,
) -> list[str]:
    output = []
    seen = set()
    for keyword in keywords:
        add_keyword(output, seen, keyword)
    for pack_name in pack_names or []:
        name = pack_name.strip()
        if not name:
            continue
        try:
            values = BUILTIN_KEYWORD_PACKS[name]
        except KeyError as exc:
            supported = ", ".join(sorted(BUILTIN_KEYWORD_PACKS))
            raise KeywordPackError(f"unknown keyword pack: {name} (supported: {supported})") from exc
        for keyword in values:
            add_keyword(output, seen, keyword)
    for pack_file in pack_files or []:
        payload = read_keyword_pack_file(pack_file)
        for keyword in keywords_from_payload(payload):
            add_keyword(output, seen, keyword)
    return output


def list_keyword_packs() -> list[dict[str, object]]:
    rows = []
    for name, keywords in sorted(BUILTIN_KEYWORD_PACKS.items()):
        gates = keyword_pack_core_accuracy_gates(
            pack_count=1,
            keyword_count=len(keywords),
            custom_file_count=0,
            provenance_refs=[f"builtin_pack:{name}"],
        )
        rows.append(
            {
            "name": name,
            "keyword_count": len(keywords),
            "keywords": keywords,
            "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
            "library_scope": "built-in-triage-starter-pack",
            "ready_for_court_report": False,
            "core_accuracy_gates": gates,
            "commercial_uplift_evidence": keyword_pack_commercial_uplift_evidence(
                pack_count=1,
                keyword_count=len(keywords),
                custom_file_count=0,
                provenance_refs=[f"builtin_pack:{name}"],
                core_accuracy_gates=gates,
            ),
            }
        )
    return rows


def keyword_pack_library_assessment() -> dict[str, object]:
    gates = keyword_pack_core_accuracy_gates(
        pack_count=len(BUILTIN_KEYWORD_PACKS),
        keyword_count=sum(len(values) for values in BUILTIN_KEYWORD_PACKS.values()),
        custom_file_count=0,
        provenance_refs=["builtin_pack_library"],
    )
    return {
        "component": "saved-keyword-pack-library",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "pack_count": len(BUILTIN_KEYWORD_PACKS),
        "ready_for_court_report": False,
        "blockers": list(KEYWORD_PACK_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Document which built-in and custom packs were used for each case search.",
            "Review false positives/negatives and add case-specific terms before report reliance.",
        ],
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": keyword_pack_commercial_uplift_evidence(
            pack_count=len(BUILTIN_KEYWORD_PACKS),
            keyword_count=sum(len(values) for values in BUILTIN_KEYWORD_PACKS.values()),
            custom_file_count=0,
            provenance_refs=["builtin_pack_library"],
            core_accuracy_gates=gates,
        ),
    }


def keyword_pack_selection_profile(
    *,
    pack_names: Sequence[str],
    keyword_count: int,
    custom_file_count: int = 0,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    normalized_pack_names = [name.strip() for name in pack_names if name.strip()]
    provenance_refs = [f"builtin_pack:{name}" for name in normalized_pack_names] or ["manual_keywords_only"]
    gates = keyword_pack_core_accuracy_gates(
        pack_count=len(normalized_pack_names),
        keyword_count=keyword_count,
        custom_file_count=custom_file_count,
        provenance_refs=provenance_refs,
        trusted_diff=trusted_diff,
    )
    return {
        "profile_version": "keyword-pack-selection-profile-v1",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "selected_pack_names": normalized_pack_names,
        "selected_pack_count": len(normalized_pack_names),
        "expanded_keyword_count": keyword_count,
        "custom_file_count": custom_file_count,
        "provenance_refs": provenance_refs,
        "deduplicated_expansion": True,
        "case_specific_terms_allowed": True,
        "signed_pack_library": False,
        "case_pack_editor": False,
        "ready_for_court_report": False,
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": keyword_pack_commercial_uplift_evidence(
            pack_count=len(normalized_pack_names),
            keyword_count=keyword_count,
            custom_file_count=custom_file_count,
            provenance_refs=provenance_refs,
            core_accuracy_gates=gates,
        ),
        "report_use_warning": "Record selected pack names, added case-specific terms, and false-positive review before citing keyword-pack hits.",
    }


def keyword_pack_core_accuracy_gates(
    *,
    pack_count: int,
    keyword_count: int,
    custom_file_count: int,
    provenance_refs: Sequence[str] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["built-in pack inventory", "deduplicated keyword expansion", "pack provenance recorded", "case-specific validation warning"]
    if custom_file_count:
        satisfied.append("custom JSON pack support")
    evidence_refs = [
        f"pack_count:{pack_count}",
        f"keyword_count:{keyword_count}",
        f"custom_file_count:{custom_file_count}",
        *(provenance_refs or []),
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted keyword-pack expansion diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            62,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def keyword_pack_commercial_uplift_evidence(
    *,
    pack_count: int,
    keyword_count: int,
    custom_file_count: int,
    provenance_refs: Sequence[str],
    core_accuracy_gates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == KEYWORD_PACK_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [62],
        "implementation_track": "saved-keyword-pack-library-gate",
        "source_refs": list(provenance_refs),
        "reportability_decision": keyword_pack_reportability_decision(
            failed_validation_check_ids=[
                "per-case-pack-editor",
                "signed-pack-distribution",
                "release-reviewed-pack-versioning",
                "language-domain-specific-pack-corpus",
                KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
            ],
            pack_count=pack_count,
            keyword_count=keyword_count,
            custom_file_count=custom_file_count,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "per-case-pack-editor",
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
            KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
        ],
        "commercial_blockers": list(KEYWORD_PACK_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "pack_count": pack_count,
            "keyword_count": keyword_count,
            "custom_file_count": custom_file_count,
            "deduplicated_expansion": True,
            "signed_pack_library": False,
            "case_pack_editor": False,
            "trusted_expansion_diff": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def build_keyword_pack_trusted_diff(
    rapid_keywords: Sequence[str],
    trusted_keywords: Sequence[str],
    *,
    pack_name: str = "case-pack",
    trusted_tool: str = "keyword-expansion-manifest",
) -> dict[str, object]:
    rapid = normalize_keyword_set(rapid_keywords)
    trusted = normalize_keyword_set(trusted_keywords)
    missing = sorted(trusted - rapid)
    unexpected = sorted(rapid - trusted)
    status = "pass" if not missing and not unexpected else "fail"
    return {
        "profile": "keyword-pack-trusted-expansion-diff-v1",
        "item_number": 62,
        "pack_name": pack_name,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid),
        "trusted_count": len(trusted),
        "missing": missing,
        "unexpected": unexpected,
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def normalize_keyword_set(values: Sequence[str]) -> set[str]:
    return {str(value or "").strip().lower() for value in values if str(value or "").strip()}


def keyword_pack_reportability_decision(
    *,
    failed_validation_check_ids: Sequence[str],
    pack_count: int,
    keyword_count: int,
    custom_file_count: int,
) -> dict[str, object]:
    blockers = set(KEYWORD_PACK_REPORT_GRADE_BLOCKERS)
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "keyword-pack-reportability-decision-v1",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "decision": "do-not-report-keyword-pack-as-release-reviewed-or-complete",
        "allowed_use": "keyword-pack-expansion-triage-pivot",
        "blockers": sorted(blockers),
        "pack_count": pack_count,
        "keyword_count": keyword_count,
        "custom_file_count": custom_file_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "sign and version keyword packs with release review records",
            "validate pack false-positive/false-negative behavior against language and domain corpora",
            "record case-specific pack edits and provenance before using results as report scope",
        ],
    }


def add_keyword(output: list[str], seen: set[str], keyword: object) -> None:
    text = str(keyword or "").strip()
    if not text:
        return
    key = text.lower()
    if key in seen:
        return
    seen.add(key)
    output.append(text)


def read_keyword_pack_file(path: Path) -> object:
    resolved = path.expanduser().resolve()
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise KeywordPackError(f"keyword pack file not found: {resolved}") from exc
    except json.JSONDecodeError as exc:
        raise KeywordPackError(f"keyword pack file must be JSON: {resolved}") from exc


def keywords_from_payload(payload: object) -> Iterable[str]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                yield item
        return
    if isinstance(payload, Mapping):
        keywords = payload.get("keywords")
        if isinstance(keywords, list):
            for item in keywords:
                if isinstance(item, str):
                    yield item
        packs = payload.get("packs")
        if isinstance(packs, Mapping):
            for values in packs.values():
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, str):
                            yield item
        return
    raise KeywordPackError("keyword pack JSON must be a list or object with a keywords list")
