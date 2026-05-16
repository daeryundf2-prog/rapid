from __future__ import annotations

import hashlib
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
KEYWORD_PACK_REPORT_GRADE_VALIDATION_PLAN_VERSION = "keyword-pack-report-grade-validation-plan-v1"
KEYWORD_PACK_REPORT_GRADE_VALIDATION_BLOCKERS = [
    "signed-versioned-keyword-pack-library-required",
    "release-review-record-required",
    "per-case-pack-editor-audit-required",
    "language-domain-pack-corpus-required",
    "trusted-keyword-pack-expansion-diff-required",
    "large-case-keyword-pack-performance-required",
]


class KeywordPackError(ValueError):
    """Raised when keyword pack input cannot be resolved."""


def stable_keyword_pack_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


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
        manifest = build_keyword_pack_manifest(
            name=name,
            keywords=keywords,
            provenance_ref=f"builtin_pack:{name}",
            library_scope="built-in-triage-starter-pack",
        )
        validation_plan = build_keyword_pack_report_grade_validation_plan(
            plan_context="builtin-pack",
            pack_count=1,
            keyword_count=len(keywords),
            custom_file_count=0,
            provenance_refs=[f"builtin_pack:{name}", f"keyword_pack_manifest_hash:{manifest['manifest_hash']}"],
            manifest_hash=manifest["manifest_hash"],
            keyword_row_hash_count=int(manifest.get("keyword_row_hash_count") or 0),
            trusted_diff=None,
        )
        gates = keyword_pack_core_accuracy_gates(
            pack_count=1,
            keyword_count=len(keywords),
            custom_file_count=0,
            provenance_refs=[f"builtin_pack:{name}"],
            manifest_hash=str(manifest.get("manifest_hash") or ""),
            keyword_row_hash_count=int(manifest.get("keyword_row_hash_count") or 0),
            validation_plan=validation_plan,
        )
        rows.append(
            {
                "name": name,
                "keyword_count": len(keywords),
                "keywords": keywords,
                "keyword_pack_manifest": manifest,
                "keyword_pack_manifest_hash": manifest["manifest_hash"],
                "keyword_pack_report_grade_validation_plan": validation_plan,
                "keyword_pack_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
                "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
                "library_scope": "built-in-triage-starter-pack",
                "ready_for_court_report": False,
                "core_accuracy_gates": gates,
                "commercial_uplift_evidence": keyword_pack_commercial_uplift_evidence(
                    pack_count=1,
                    keyword_count=len(keywords),
                    custom_file_count=0,
                    provenance_refs=[f"builtin_pack:{name}", f"keyword_pack_manifest_hash:{manifest['manifest_hash']}"],
                    core_accuracy_gates=gates,
                    manifest_hash=manifest["manifest_hash"],
                    keyword_row_hash_count=int(manifest.get("keyword_row_hash_count") or 0),
                    validation_plan=validation_plan,
                ),
            }
        )
    return rows


def keyword_pack_library_assessment() -> dict[str, object]:
    library_manifest = build_keyword_pack_library_manifest()
    validation_plan = build_keyword_pack_report_grade_validation_plan(
        plan_context="library",
        pack_count=len(BUILTIN_KEYWORD_PACKS),
        keyword_count=sum(len(values) for values in BUILTIN_KEYWORD_PACKS.values()),
        custom_file_count=0,
        provenance_refs=["builtin_pack_library", f"keyword_pack_library_manifest_hash:{library_manifest['manifest_hash']}"],
        manifest_hash=library_manifest["manifest_hash"],
        keyword_row_hash_count=int(library_manifest.get("keyword_row_hash_count") or 0),
        trusted_diff=None,
    )
    gates = keyword_pack_core_accuracy_gates(
        pack_count=len(BUILTIN_KEYWORD_PACKS),
        keyword_count=sum(len(values) for values in BUILTIN_KEYWORD_PACKS.values()),
        custom_file_count=0,
        provenance_refs=["builtin_pack_library", f"keyword_pack_library_manifest_hash:{library_manifest['manifest_hash']}"],
        manifest_hash=library_manifest["manifest_hash"],
        keyword_row_hash_count=int(library_manifest.get("keyword_row_hash_count") or 0),
        validation_plan=validation_plan,
    )
    return {
        "component": "saved-keyword-pack-library",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "pack_count": len(BUILTIN_KEYWORD_PACKS),
        "keyword_pack_library_manifest": library_manifest,
        "keyword_pack_library_manifest_hash": library_manifest["manifest_hash"],
        "keyword_pack_report_grade_validation_plan": validation_plan,
        "keyword_pack_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
            provenance_refs=["builtin_pack_library", f"keyword_pack_library_manifest_hash:{library_manifest['manifest_hash']}"],
            core_accuracy_gates=gates,
            manifest_hash=library_manifest["manifest_hash"],
            keyword_row_hash_count=int(library_manifest.get("keyword_row_hash_count") or 0),
            validation_plan=validation_plan,
        ),
    }


def keyword_pack_selection_profile(
    *,
    pack_names: Sequence[str],
    keyword_count: int,
    custom_file_count: int = 0,
    expanded_keywords: Sequence[str] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    normalized_pack_names = [name.strip() for name in pack_names if name.strip()]
    provenance_refs = [f"builtin_pack:{name}" for name in normalized_pack_names] or ["manual_keywords_only"]
    selection_manifest = build_keyword_pack_selection_manifest(
        pack_names=normalized_pack_names,
        expanded_keywords=expanded_keywords or [],
        keyword_count=keyword_count,
        custom_file_count=custom_file_count,
        provenance_refs=provenance_refs,
    )
    validation_plan = build_keyword_pack_report_grade_validation_plan(
        plan_context="selection",
        pack_count=len(normalized_pack_names),
        keyword_count=keyword_count,
        custom_file_count=custom_file_count,
        provenance_refs=[*provenance_refs, f"keyword_pack_selection_manifest_hash:{selection_manifest['manifest_hash']}"],
        manifest_hash=selection_manifest["manifest_hash"],
        keyword_row_hash_count=int(selection_manifest.get("keyword_row_hash_count") or 0),
        trusted_diff=trusted_diff,
    )
    gates = keyword_pack_core_accuracy_gates(
        pack_count=len(normalized_pack_names),
        keyword_count=keyword_count,
        custom_file_count=custom_file_count,
        provenance_refs=[*provenance_refs, f"keyword_pack_selection_manifest_hash:{selection_manifest['manifest_hash']}"],
        trusted_diff=trusted_diff,
        manifest_hash=selection_manifest["manifest_hash"],
        keyword_row_hash_count=int(selection_manifest.get("keyword_row_hash_count") or 0),
        validation_plan=validation_plan,
    )
    return {
        "profile_version": "keyword-pack-selection-profile-v1",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "selected_pack_names": normalized_pack_names,
        "selected_pack_count": len(normalized_pack_names),
        "expanded_keyword_count": keyword_count,
        "custom_file_count": custom_file_count,
        "provenance_refs": provenance_refs,
        "keyword_pack_selection_manifest": selection_manifest,
        "keyword_pack_selection_manifest_hash": selection_manifest["manifest_hash"],
        "keyword_pack_report_grade_validation_plan": validation_plan,
        "keyword_pack_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "keyword_row_hash_count": selection_manifest["keyword_row_hash_count"],
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
            provenance_refs=[*provenance_refs, f"keyword_pack_selection_manifest_hash:{selection_manifest['manifest_hash']}"],
            core_accuracy_gates=gates,
            manifest_hash=selection_manifest["manifest_hash"],
            keyword_row_hash_count=int(selection_manifest.get("keyword_row_hash_count") or 0),
            validation_plan=validation_plan,
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
    manifest_hash: str = "",
    keyword_row_hash_count: int = 0,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["built-in pack inventory", "deduplicated keyword expansion", "pack provenance recorded", "case-specific validation warning"]
    if custom_file_count:
        satisfied.append("custom JSON pack support")
    if manifest_hash:
        satisfied.append("keyword-pack manifest hash")
    if keyword_row_hash_count:
        satisfied.append("keyword row hashes")
    if validation_plan and validation_plan.get("validation_plan_sha256"):
        satisfied.append("keyword-pack report-grade validation plan")
    if validation_plan and int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("keyword-pack report-grade ready slots")
    evidence_refs = [
        f"pack_count:{pack_count}",
        f"keyword_count:{keyword_count}",
        f"custom_file_count:{custom_file_count}",
        f"keyword_row_hash_count:{keyword_row_hash_count}",
        *(provenance_refs or []),
    ]
    if manifest_hash:
        evidence_refs.append(f"keyword_pack_manifest_hash:{manifest_hash}")
    if validation_plan and validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(f"keyword_pack_report_grade_validation_plan_hash:{validation_plan['validation_plan_sha256']}")
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
    manifest_hash: str = "",
    keyword_row_hash_count: int = 0,
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == KEYWORD_PACK_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    plan_hash = str(validation_plan.get("validation_plan_sha256") or "") if isinstance(validation_plan, Mapping) else ""
    plan_blockers = [
        str(item)
        for item in (validation_plan.get("blockers") if isinstance(validation_plan, Mapping) else []) or []
    ]
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
            validation_plan=validation_plan,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": sorted(set([
            "per-case-pack-editor",
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
            KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
            *plan_blockers,
        ])),
        "commercial_blockers": sorted(set([*KEYWORD_PACK_REPORT_GRADE_BLOCKERS, *KEYWORD_PACK_REPORT_GRADE_VALIDATION_BLOCKERS])),
        "large_data_controls": {
            "pack_count": pack_count,
            "keyword_count": keyword_count,
            "custom_file_count": custom_file_count,
            "deduplicated_expansion": True,
            "keyword_pack_manifest_hash": manifest_hash,
            "keyword_row_hash_count": keyword_row_hash_count,
            "keyword_pack_report_grade_validation_plan_present": bool(plan_hash),
            "keyword_pack_report_grade_validation_plan_hash": plan_hash,
            "keyword_pack_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
            "keyword_pack_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
            "signed_pack_library": False,
            "case_pack_editor": False,
            "trusted_expansion_diff": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def build_keyword_pack_manifest(
    *,
    name: str,
    keywords: Sequence[str],
    provenance_ref: str,
    library_scope: str,
) -> dict[str, object]:
    keyword_rows = build_keyword_rows(keywords)
    manifest_core: dict[str, object] = {
        "manifest_version": "keyword-pack-manifest-v1",
        "item_number": 62,
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "name": name,
        "library_scope": library_scope,
        "provenance_ref": provenance_ref,
        "keyword_count": len(keyword_rows),
        "keyword_row_hash_count": sum(1 for row in keyword_rows if row.get("keyword_row_hash")),
        "keyword_rows": keyword_rows,
        "expansion_head_hash": stable_keyword_pack_sha256(keyword_rows),
        "release_review_status": "not-release-reviewed",
        "signed_pack": False,
        "blockers": [
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
            KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_keyword_pack_sha256(manifest_core)}


def build_keyword_pack_library_manifest() -> dict[str, object]:
    pack_rows = []
    keyword_row_hash_count = 0
    for name, keywords in sorted(BUILTIN_KEYWORD_PACKS.items()):
        pack_manifest = build_keyword_pack_manifest(
            name=name,
            keywords=keywords,
            provenance_ref=f"builtin_pack:{name}",
            library_scope="built-in-triage-starter-pack",
        )
        keyword_row_hash_count += int(pack_manifest.get("keyword_row_hash_count") or 0)
        pack_rows.append(
            {
                "name": name,
                "keyword_count": int(pack_manifest.get("keyword_count") or 0),
                "pack_manifest_hash": str(pack_manifest.get("manifest_hash") or ""),
                "expansion_head_hash": str(pack_manifest.get("expansion_head_hash") or ""),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "keyword-pack-library-manifest-v1",
        "item_number": 62,
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "pack_count": len(pack_rows),
        "keyword_count": sum(len(values) for values in BUILTIN_KEYWORD_PACKS.values()),
        "keyword_row_hash_count": keyword_row_hash_count,
        "pack_rows": pack_rows,
        "library_head_hash": stable_keyword_pack_sha256(pack_rows),
        "signed_pack_library": False,
        "release_review_status": "not-release-reviewed",
        "blockers": [
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
            KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_keyword_pack_sha256(manifest_core)}


def build_keyword_pack_selection_manifest(
    *,
    pack_names: Sequence[str],
    expanded_keywords: Sequence[str],
    keyword_count: int,
    custom_file_count: int,
    provenance_refs: Sequence[str],
) -> dict[str, object]:
    keyword_rows = build_keyword_rows(expanded_keywords)
    manifest_core: dict[str, object] = {
        "manifest_version": "keyword-pack-selection-manifest-v1",
        "item_number": 62,
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "selected_pack_names": list(pack_names),
        "selected_pack_count": len(pack_names),
        "custom_file_count": custom_file_count,
        "expanded_keyword_count": keyword_count,
        "keyword_row_hash_count": sum(1 for row in keyword_rows if row.get("keyword_row_hash")),
        "provenance_refs": list(provenance_refs),
        "keyword_rows": keyword_rows,
        "expansion_head_hash": stable_keyword_pack_sha256(keyword_rows),
        "case_specific_terms_allowed": True,
        "release_review_status": "not-release-reviewed",
        "report_use_boundary": "keyword-pack expansion is a repeatable search scope, not proof that all relevant terms were covered",
        "blockers": [
            "per-case-pack-editor",
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
            KEYWORD_PACK_TRUSTED_DIFF_BLOCKER_62,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_keyword_pack_sha256(manifest_core)}


def build_keyword_pack_report_grade_validation_plan(
    *,
    plan_context: str,
    pack_count: int,
    keyword_count: int,
    custom_file_count: int,
    provenance_refs: Sequence[str],
    manifest_hash: str,
    keyword_row_hash_count: int,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

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
            "keyword-pack-inventory-recorded",
            ready=pack_count > 0 or plan_context == "selection",
            evidence=f"context={plan_context} pack_count={pack_count} custom_file_count={custom_file_count}",
            blocker_id="keyword-pack-inventory-required",
            operator_action="Record built-in/custom pack names and file counts with every search.",
        ),
        slot(
            "keyword-pack-expansion-manifest-emitted",
            ready=bool(manifest_hash),
            evidence=f"keyword_pack_manifest_hash={manifest_hash}",
            blocker_id="keyword-pack-expansion-manifest-required",
            operator_action="Attach the pack or selection manifest before review.",
        ),
        slot(
            "keyword-pack-keyword-row-hashes",
            ready=keyword_row_hash_count >= max(0, min(keyword_count, 1)),
            evidence=f"keyword_row_hash_count={keyword_row_hash_count} keyword_count={keyword_count}",
            blocker_id="keyword-pack-keyword-row-hashes-required",
            operator_action="Preserve per-keyword row hashes for repeatable expansion review.",
        ),
        slot(
            "keyword-pack-provenance-recorded",
            ready=bool(provenance_refs),
            evidence=f"provenance_ref_count={len(provenance_refs)}",
            blocker_id="keyword-pack-provenance-required",
            operator_action="Record built-in pack names, custom file refs, and manifest hashes.",
        ),
        slot(
            "keyword-pack-deduplicated-expansion-recorded",
            ready=True,
            evidence="deduplicated_expansion=true",
            blocker_id="keyword-pack-dedup-required",
            operator_action="Deduplicate expanded keywords before search and preserve the expansion order/hash.",
        ),
        slot(
            "keyword-pack-report-use-boundary-recorded",
            ready=True,
            evidence="report_use_boundary=triage-pivot-not-completeness-proof",
            blocker_id="keyword-pack-report-boundary-required",
            operator_action="Display the warning that keyword packs are repeatable triage scope, not completeness proof.",
        ),
        slot(
            "keyword-pack-signed-versioned-library",
            ready=False,
            evidence="signed_versioned_keyword_pack_library=false",
            blocker_id="signed-versioned-keyword-pack-library-required",
            operator_action="Sign and version built-in/release keyword packs before commercial report-grade claims.",
        ),
        slot(
            "keyword-pack-release-review-record",
            ready=False,
            evidence="release_review_record=false",
            blocker_id="release-review-record-required",
            operator_action="Attach reviewer/version/release notes for every shipped keyword pack.",
        ),
        slot(
            "keyword-pack-per-case-editor-audit",
            ready=False,
            evidence=f"case_pack_editor=false custom_file_count={custom_file_count}",
            blocker_id="per-case-pack-editor-audit-required",
            operator_action="Persist case pack edits, analyst identity, and edit history in the Case DB.",
        ),
        slot(
            "keyword-pack-language-domain-corpus",
            ready=False,
            evidence="language_domain_pack_corpus=false",
            blocker_id="language-domain-pack-corpus-required",
            operator_action="Validate each pack against Korean/English and domain-specific false-positive/coverage corpora.",
        ),
        slot(
            "keyword-pack-trusted-expansion-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id="trusted-keyword-pack-expansion-diff-required",
            operator_action="Attach a trusted expansion manifest diff before release-reviewed claims.",
        ),
        slot(
            "keyword-pack-large-case-performance",
            ready=False,
            evidence=f"keyword_count={keyword_count} large_case_keyword_pack_performance=false",
            blocker_id="large-case-keyword-pack-performance-required",
            operator_action="Measure large-case expansion/search latency and memory impact for pack-heavy searches.",
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
        "profile_version": KEYWORD_PACK_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 62,
        "gap_id": KEYWORD_PACK_GAP_ID,
        "batch_id": "commercial-uplift-061-065",
        "plan_context": plan_context,
        "selected_track": "saved-keyword-pack-library-gate",
        "pack_count": pack_count,
        "keyword_count": keyword_count,
        "custom_file_count": custom_file_count,
        "keyword_pack_manifest_sha256": manifest_hash,
        "keyword_row_hash_count": keyword_row_hash_count,
        "provenance_refs": list(provenance_refs),
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete"),
        "blocking_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(KEYWORD_PACK_REPORT_GRADE_VALIDATION_BLOCKERS),
        "validation_commands": [
            "rapidtriage keyword-packs --json",
            "rapidtriage search <case> --keyword-pack credentials --keyword-pack-file <case-pack.json> --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-061-070-known-answer.json --limit 62 --json",
        ],
        "report_guidance": {
            "allowed_use": "keyword-pack-expansion-triage-pivot",
            "forbidden_claims": [
                "keyword pack is release-reviewed",
                "keyword pack covers all relevant language/domain terms",
                "selected keyword pack proves absence of evidence",
                "custom pack edits are audited",
            ],
            "required_disclaimer": (
                "Keyword packs preserve a repeatable search vocabulary. Do not describe a pack as complete, "
                "release-reviewed, or report-grade until signed/versioned pack records, case edit audit, corpus "
                "validation, and trusted expansion diff evidence are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_keyword_pack_sha256(plan_core)}


def build_keyword_rows(keywords: Sequence[str]) -> list[dict[str, object]]:
    rows = []
    seen = set()
    for index, keyword in enumerate(keywords):
        text = str(keyword or "").strip()
        if not text:
            continue
        normalized = text.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        row_core = {
            "index": len(rows),
            "keyword": text,
            "normalized_keyword": normalized,
            "keyword_hash": stable_keyword_pack_sha256({"keyword": normalized}),
        }
        rows.append({**row_core, "keyword_row_hash": stable_keyword_pack_sha256(row_core)})
    return rows


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
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = set(KEYWORD_PACK_REPORT_GRADE_BLOCKERS)
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    if isinstance(validation_plan, Mapping):
        blockers.update(str(item) for item in validation_plan.get("blockers") or [])
    return {
        "profile_version": "keyword-pack-reportability-decision-v1",
        "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
        "decision": "do-not-report-keyword-pack-as-release-reviewed-or-complete",
        "allowed_use": "keyword-pack-expansion-triage-pivot",
        "blockers": sorted(blockers),
        "pack_count": pack_count,
        "keyword_count": keyword_count,
        "custom_file_count": custom_file_count,
        "keyword_pack_report_grade_validation_plan_present": isinstance(validation_plan, Mapping),
        "keyword_pack_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or "") if isinstance(validation_plan, Mapping) else "",
        "keyword_pack_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
        "keyword_pack_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0) if isinstance(validation_plan, Mapping) else 0,
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
