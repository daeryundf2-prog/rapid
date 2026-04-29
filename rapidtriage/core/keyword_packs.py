from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence


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
    return [
        {
            "name": name,
            "keyword_count": len(keywords),
            "keywords": keywords,
            "commercial_gap_ids": [KEYWORD_PACK_GAP_ID],
            "library_scope": "built-in-triage-starter-pack",
            "ready_for_court_report": False,
        }
        for name, keywords in sorted(BUILTIN_KEYWORD_PACKS.items())
    ]


def keyword_pack_library_assessment() -> dict[str, object]:
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
