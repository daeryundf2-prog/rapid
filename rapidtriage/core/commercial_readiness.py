from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Iterable

from .docs import write_result


COMMERCIAL_READINESS_JSON_NAME = "rapidtriage-commercial-readiness.json"
COMMERCIAL_READINESS_MARKDOWN_NAME = "rapidtriage-commercial-readiness.md"

BACKLOG_ITEM_RE = re.compile(
    r"^(?P<number>\d+)\.\s+(?P<title>.+?)\.\s+Status:\s+(?P<status>[^.]+)\.\s*(?P<body>.*)$"
)


class CommercialReadinessError(ValueError):
    """Raised when commercial-readiness inputs are invalid."""


def default_backlog_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "rapidtriage-commercial-parity-backlog.md"


def build_commercial_readiness_report(
    *,
    backlog_path: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, object]:
    backlog_path = (backlog_path or default_backlog_path()).expanduser().resolve()
    if not backlog_path.is_file():
        raise CommercialReadinessError(f"commercial parity backlog not found: {backlog_path}")

    items = parse_backlog(backlog_path)
    if not items:
        raise CommercialReadinessError(f"no numbered backlog items found in: {backlog_path}")

    non_commercial = [item for item in items if not item["commercial_grade_ready"]]
    status_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for item in items:
        status = str(item["status"])
        severity = str(item["severity"])
        category = str(item["category"])
        status_counts[status] = status_counts.get(status, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    commercial_claim_allowed = not non_commercial
    readiness_score = calculate_readiness_score(items)
    payload: dict[str, object] = {
        "command": "commercial-readiness",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "backlog_path": str(backlog_path),
        "status": "commercial-ready" if commercial_claim_allowed else "commercial-gaps-present",
        "commercial_claim_allowed": commercial_claim_allowed,
        "release_claim": (
            "commercial forensic suite parity may be claimed"
            if commercial_claim_allowed
            else "do not claim AXIOM/WISDOM-class commercial parity; disclose triage/validation limits"
        ),
        "readiness_score": readiness_score,
        "item_count": len(items),
        "commercial_ready_count": len(items) - len(non_commercial),
        "non_commercial_count": len(non_commercial),
        "status_counts": status_counts,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "critical_non_commercial_items": [
            item for item in non_commercial if item["severity"] in {"critical", "high"}
        ],
        "non_commercial_items": non_commercial,
        "required_release_evidence": build_required_release_evidence(non_commercial),
        "operator_guidance": build_operator_guidance(non_commercial),
    }

    if output_dir is not None:
        output_dir = output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / COMMERCIAL_READINESS_JSON_NAME
        markdown_path = output_dir / COMMERCIAL_READINESS_MARKDOWN_NAME
        write_result(payload, json_path)
        markdown_path.write_text(render_commercial_readiness_markdown(payload), encoding="utf-8")
        payload["outputs"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
        }
    return payload


def parse_backlog(backlog_path: Path) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw_line in backlog_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = BACKLOG_ITEM_RE.match(line)
        if match:
            if current is not None:
                finalize_backlog_item(current)
                items.append(current)
            number = int(match.group("number"))
            body = match.group("body").strip()
            current = {
                "number": number,
                "title": match.group("title").strip(),
                "status": normalize_status(match.group("status")),
                "category": category_for_number(number),
                "severity": severity_for_number(number),
                "body": body,
                "remaining_gap": extract_remaining_gap(body),
            }
            continue
        if line.startswith("#"):
            continue
        if current is not None and line:
            current["body"] = f"{current.get('body', '')} {line}".strip()
    if current is not None:
        finalize_backlog_item(current)
        items.append(current)
    return items


def finalize_backlog_item(item: dict[str, object]) -> None:
    body = str(item.get("body") or "")
    if not item.get("remaining_gap"):
        item["remaining_gap"] = extract_remaining_gap(body)
    status = str(item.get("status") or "")
    blockers = extract_blockers(body)
    item["commercial_grade_ready"] = status == "Done" and not blockers and not item.get("remaining_gap")
    item["commercial_blockers"] = blockers or fallback_blockers(status, int(item.get("number", 0)))
    item["release_gate"] = release_gate_for_item(item)


def normalize_status(value: str) -> str:
    return " ".join(value.strip().split())


def extract_remaining_gap(body: str) -> str:
    markers = [
        "Remaining commercial gap:",
        "Remaining:",
        "Blockers:",
    ]
    for marker in markers:
        index = body.find(marker)
        if index >= 0:
            return body[index + len(marker) :].strip()
    return ""


def extract_blockers(body: str) -> list[str]:
    lowered = body.lower()
    blockers: list[str] = []
    keyword_map = {
        "commercial_grade_ready=false": "explicit-commercial-grade-ready-false",
        "remaining commercial gap": "remaining-commercial-gap",
        "external": "external-validation-or-infrastructure-required",
        "validation": "known-answer-or-independent-validation-required",
        "not implemented": "implementation-missing",
        "not-enabled": "feature-not-enabled",
        "planned": "planned-work-remaining",
        "native": "native-parser-depth-required",
        "signing": "platform-signing-required",
        "notarization": "platform-notarization-required",
    }
    for keyword, blocker in keyword_map.items():
        if keyword in lowered and blocker not in blockers:
            blockers.append(blocker)
    return blockers


def fallback_blockers(status: str, number: int) -> list[str]:
    if status.startswith("External"):
        return ["external-operator-evidence-required"]
    if status.startswith("Planned"):
        return ["implementation-not-enabled"]
    if status.startswith("Partial"):
        return ["partial-implementation-requires-validation"]
    if number:
        return ["commercial-readiness-not-proven"]
    return []


def category_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "core-forensics"
    if 26 <= number <= 45:
        return "mobile-cloud-apps"
    if 46 <= number <= 65:
        return "search-analysis-ux"
    if 66 <= number <= 80:
        return "performance-large-scale"
    if 81 <= number <= 100:
        return "validation-legal"
    if 101 <= number <= 120:
        return "deployment-operations"
    return "unknown"


def severity_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "critical"
    if 26 <= number <= 45:
        return "high"
    if 81 <= number <= 100:
        return "high"
    if 66 <= number <= 80 or 101 <= number <= 120:
        return "medium"
    if 46 <= number <= 65:
        return "medium"
    return "low"


def release_gate_for_item(item: dict[str, object]) -> str:
    number = int(item.get("number", 0))
    if item.get("commercial_grade_ready"):
        return "claim-allowed"
    if 1 <= number <= 45:
        return "must label as validation-required before report testimony"
    if 81 <= number <= 100:
        return "must attach legal/known-answer validation evidence"
    if 101 <= number <= 120:
        return "must attach platform/operations evidence before commercial distribution"
    return "must disclose partial implementation and UX/performance limits"


def calculate_readiness_score(items: Iterable[dict[str, object]]) -> int:
    total_weight = 0
    earned = 0.0
    status_points = {
        "Done": 1.0,
        "Partial++": 0.78,
        "Partial+": 0.65,
        "Partial": 0.45,
        "External+": 0.35,
        "Planned+": 0.25,
        "External": 0.2,
        "Planned": 0.1,
    }
    severity_weight = {"critical": 3, "high": 2, "medium": 1, "low": 1}
    for item in items:
        weight = severity_weight.get(str(item.get("severity")), 1)
        total_weight += weight
        status = str(item.get("status"))
        base_status = status.split(" with ", 1)[0]
        earned += weight * status_points.get(status, status_points.get(base_status, 0.3))
    if total_weight == 0:
        return 0
    return int(round((earned / total_weight) * 100))


def build_required_release_evidence(non_commercial: list[dict[str, object]]) -> list[dict[str, object]]:
    categories = {str(item["category"]) for item in non_commercial}
    evidence: list[dict[str, object]] = []
    if "core-forensics" in categories:
        evidence.append(
            {
                "id": "core-parser-known-answer-corpus",
                "required_for": "EVTX/Registry/SAM/MFT/USN/SRUM/EDB/native Windows artifact claims",
                "evidence": "known-answer corpus, external parser comparison, source hashes, offset-level diffs, reviewer sign-off",
            }
        )
    if "mobile-cloud-apps" in categories:
        evidence.append(
            {
                "id": "mobile-cloud-schema-validation",
                "required_for": "mobile app, cloud export, mailbox, and messenger claims",
                "evidence": "authorized export samples, app/provider schema versions, deleted/encrypted-store limitations, validation matrix",
            }
        )
    if "performance-large-scale" in categories:
        evidence.append(
            {
                "id": "large-case-stress-results",
                "required_for": "1TB-10TB and million-record usability claims",
                "evidence": "hardware profile, run logs, peak memory, p95 latency, failure thresholds, reproducibility notes",
            }
        )
    if "validation-legal" in categories:
        evidence.append(
            {
                "id": "legal-validation-package",
                "required_for": "court/report-grade evidence handling claims",
                "evidence": "NIST-style known-answer results, chain-of-custody records, audit hash chain, independent validation report",
            }
        )
    if "deployment-operations" in categories:
        evidence.append(
            {
                "id": "commercial-release-operations",
                "required_for": "commercial distribution and support claims",
                "evidence": "signed installers, notarization, CI scans, support SLA, staffed escalation, admin deployment proof",
            }
        )
    return evidence


def build_operator_guidance(non_commercial: list[dict[str, object]]) -> list[str]:
    if not non_commercial:
        return ["Commercial parity gates are satisfied for every tracked backlog item."]
    return [
        "Use RapidTriage as a triage/review accelerator, not as a sole AXIOM/WISDOM replacement.",
        "Any item marked non-commercial must keep validation_required/reportability warnings in artifacts and reports.",
        "For testimony-grade conclusions, attach trusted-tool comparison output and known-answer validation evidence.",
        "Do not advertise signed installer, notarized package, multi-user server, or support SLA until external evidence exists.",
    ]


def render_commercial_readiness_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Commercial Readiness Gate",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Backlog: `{payload.get('backlog_path', '')}`",
        f"- Status: `{payload.get('status', '')}`",
        f"- Commercial claim allowed: `{payload.get('commercial_claim_allowed', False)}`",
        f"- Readiness score: `{payload.get('readiness_score', 0)}/100`",
        f"- Non-commercial items: `{payload.get('non_commercial_count', 0)}`/`{payload.get('item_count', 0)}`",
        f"- Release claim: {payload.get('release_claim', '')}",
        "",
        "## Required Release Evidence",
        "",
    ]
    for item in payload.get("required_release_evidence", []):
        if isinstance(item, dict):
            lines.append(f"- `{item.get('id', '')}`: {item.get('evidence', '')}")
    lines.extend(["", "## Critical And High Non-Commercial Items", ""])
    for item in payload.get("critical_non_commercial_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('status', '')}, {item.get('severity', '')}): {item.get('release_gate', '')}"
        )
    lines.extend(["", "## All Non-Commercial Items", ""])
    for item in payload.get("non_commercial_items", []):
        if not isinstance(item, dict):
            continue
        gap = str(item.get("remaining_gap") or "").strip()
        if len(gap) > 220:
            gap = gap[:217].rstrip() + "..."
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('status', '')}, {item.get('category', '')}): {gap or item.get('release_gate', '')}"
        )
    lines.extend(["", "## Operator Guidance", ""])
    for item in payload.get("operator_guidance", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)
