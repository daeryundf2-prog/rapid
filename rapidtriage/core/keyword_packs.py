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
]


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


def keyword_pack_core_accuracy_gates(
    *,
    pack_count: int,
    keyword_count: int,
    custom_file_count: int,
    provenance_refs: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["built-in pack inventory", "deduplicated keyword expansion", "pack provenance recorded", "case-specific validation warning"]
    if custom_file_count:
        satisfied.append("custom JSON pack support")
    return [
        build_accuracy_gate(
            62,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"pack_count:{pack_count}",
                f"keyword_count:{keyword_count}",
                f"custom_file_count:{custom_file_count}",
                *(provenance_refs or []),
            ],
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
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "per-case-pack-editor",
            "signed-pack-distribution",
            "release-reviewed-pack-versioning",
            "language-domain-specific-pack-corpus",
        ],
        "commercial_blockers": list(KEYWORD_PACK_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "pack_count": pack_count,
            "keyword_count": keyword_count,
            "custom_file_count": custom_file_count,
            "deduplicated_expansion": True,
            "signed_pack_library": False,
            "case_pack_editor": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
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
