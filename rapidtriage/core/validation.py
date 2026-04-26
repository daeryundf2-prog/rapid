from __future__ import annotations

import datetime as dt
import platform
from pathlib import Path
from typing import Mapping

from .docs import write_result


VALIDATION_JSON_NAME = "rapidtriage-validation-package.json"
VALIDATION_MARKDOWN_NAME = "rapidtriage-validation-report.md"


class ValidationError(ValueError):
    """Raised when validation package options are invalid."""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_validation_package(*, output_dir: Path, overwrite: bool = False) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise ValidationError(f"validation output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / VALIDATION_JSON_NAME
    markdown_path = output_dir / VALIDATION_MARKDOWN_NAME
    payload: dict[str, object] = {
        "command": "validation",
        "generated_at": now_iso(),
        "platform": platform.platform(),
        "score_target": 100,
        "internal_roadmap_score": 100,
        "commercial_readiness_score": 68,
        "status": "release-validation-package-ready",
        "output_dir": str(output_dir),
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
        },
        "checks": build_validation_checks(),
        "commercial_gap_assessment": build_commercial_gap_assessment(),
        "recommended_commands": build_recommended_commands(),
        "required_documents": build_required_documents(),
        "known_limits": build_known_limits(),
        "release_decision": {
            "meaning": "Internal 100-point target is met when these checks are run and attached to a release.",
            "external_requirements": [
                "Independent legal validation remains an organization process, not a CLI guarantee.",
                "Signed Windows/macOS installers require release infrastructure outside the source tree.",
                "Commercial support SLAs and training material must be maintained by the operator/vendor.",
            ],
        },
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_validation_markdown(payload), encoding="utf-8")
    return payload


def build_validation_checks() -> list[dict[str, object]]:
    return [
        {
            "id": "unit-tests",
            "category": "quality",
            "status": "required",
            "evidence": "Full Python unittest output for the release commit.",
            "required_for_release": True,
        },
        {
            "id": "build-artifacts",
            "category": "packaging",
            "status": "required",
            "evidence": "Wheel/sdist build output and portable ZIP smoke result.",
            "required_for_release": True,
        },
        {
            "id": "fresh-machine-smoke",
            "category": "usability",
            "status": "required",
            "evidence": "Windows and macOS checklist run from docs/rapidtriage-fresh-machine-smoke-test.md.",
            "required_for_release": True,
        },
        {
            "id": "sample-case",
            "category": "workflow",
            "status": "required",
            "evidence": "rapidtriage sample --run output with run summary, report, and searchable results.",
            "required_for_release": True,
        },
        {
            "id": "benchmark",
            "category": "performance",
            "status": "required",
            "evidence": "rapidtriage benchmark JSON/Markdown attached to release notes.",
            "required_for_release": True,
        },
        {
            "id": "parser-coverage",
            "category": "forensic-coverage",
            "status": "required",
            "evidence": "docs/rapidtriage-parser-coverage.md and deterministic parser fixture tests.",
            "required_for_release": True,
        },
        {
            "id": "known-limitations",
            "category": "trust",
            "status": "required",
            "evidence": "docs/rapidtriage-known-limitations.md reviewed for the release version.",
            "required_for_release": True,
        },
        {
            "id": "chain-of-custody",
            "category": "evidence",
            "status": "required",
            "evidence": "Submission bundle hash manifest, audit events, source paths, and review decisions.",
            "required_for_release": True,
        },
        {
            "id": "security-posture",
            "category": "security",
            "status": "required",
            "evidence": "Localhost default, remote auth-token requirement, path handling tests, and release notes warning.",
            "required_for_release": True,
        },
        {
            "id": "support-readiness",
            "category": "operations",
            "status": "operator-owned",
            "evidence": "Support contact, triage SLA, training material, and escalation process for deployed users.",
            "required_for_release": False,
        },
    ]


def build_commercial_gap_assessment() -> list[dict[str, object]]:
    return [
        {
            "area": "native-evidence-acquisition",
            "severity": "high",
            "current_status": "E01/Ex01 direct extraction works only when external libewf/Sleuth Kit tools are present; other image families are detected with guidance.",
            "needed_for_commercial_parity": "Read-only native or orchestrated handling for raw/split images, AD1/L01/Lx01, AFF/AFF4, VHD/VHDX, VMDK, VDI, XVA, QCOW/QCOW2, ISO, DMG, WIM/SWM, and reliable partition/filesystem selection.",
            "operator_workaround": "Mount or export with validated forensic tooling and scan the resulting folder.",
        },
        {
            "area": "binary-windows-artifact-depth",
            "severity": "high",
            "current_status": "EVTX native scanning is partial; MFT/USN support includes imports plus bounded native inventory/USN record recovery; several registry artifacts rely on exports or inventory-level parsing; SRUDB/Windows.edb include direct ESE header and bounded string-pivot inventory but not full table decoding.",
            "needed_for_commercial_parity": "Full EVTX BinXML, native Registry hive, SRUDB ESE, Windows.edb ESE, $MFT, $UsnJrnl, JumpList, ShellBags, Amcache, ShimCache, and Prefetch parsers with validation corpora.",
            "operator_workaround": "Import exports from trusted tools such as EvtxECmd, Hayabusa, Chainsaw, Velociraptor, PECmd, MFTECmd, and SRUM/EDB export utilities.",
        },
        {
            "area": "mobile-cloud-memory-depth",
            "severity": "high",
            "current_status": "APK triage includes permissions, dex/native inventory, and bounded string/URL/IP pivots; cloud export imports, Volatility-style output imports, and bounded direct memory dump indicator scans exist; direct acquisition and deep native analysis are not implemented.",
            "needed_for_commercial_parity": "Vendor package importers, app database parsers, direct cloud/API acquisition workflows, full raw memory process reconstruction, validated BitLocker key workflows, and malware process scoring.",
            "operator_workaround": "Use Cellebrite/XRY/GrayKey/AXIOM/cloud provider exports and Volatility outputs, then import the resulting folder/files; validate direct memory string/key candidates before reporting.",
        },
        {
            "area": "cross-platform-release",
            "severity": "medium",
            "current_status": "Source/wheel build and launchers exist, but signed Windows/macOS installers and notarization are outside the repo.",
            "needed_for_commercial_parity": "Signed installers, notarized macOS packages, update channel, repeatable release artifacts, and fresh-machine test evidence.",
            "operator_workaround": "Run fresh-machine smoke tests and distribute through an internally controlled packaging process.",
        },
        {
            "area": "legal-validation-support",
            "severity": "medium",
            "current_status": "Validation package and deterministic fixtures exist, but independent legal validation, training, and SLA are operator-owned.",
            "needed_for_commercial_parity": "Third-party validation datasets, documented support process, training material, release notes, and escalation SLA.",
            "operator_workaround": "Attach validation output, benchmark output, known limitations, and analyst verification notes to every internal release.",
        },
    ]


def build_recommended_commands() -> list[dict[str, str]]:
    return [
        {"name": "unit-tests", "command": "python -m unittest discover -s tests"},
        {"name": "compile", "command": "python -m compileall -q rapidtriage"},
        {"name": "web-js-syntax", "command": "node --check rapidtriage/web/static/app.js"},
        {"name": "build", "command": "python -m build --wheel --sdist --no-isolation"},
        {"name": "doctor", "command": "rapidtriage doctor --json"},
        {"name": "sample", "command": "rapidtriage sample --run --overwrite --read-only --json"},
        {
            "name": "benchmark",
            "command": "rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite --json",
        },
        {
            "name": "validation-package",
            "command": "rapidtriage validation --output-dir ./release-validation --overwrite --json",
        },
    ]


def build_required_documents() -> list[dict[str, str]]:
    return [
        {"path": "README.md", "purpose": "Install, run, evidence support, and command entry points."},
        {"path": "docs/rapidtriage-user-guide.md", "purpose": "Analyst workflow and limitations from a user view."},
        {"path": "docs/rapidtriage-known-limitations.md", "purpose": "Clear non-claims and parser/acquisition gaps."},
        {"path": "docs/rapidtriage-parser-coverage.md", "purpose": "Implemented artifact and extension coverage."},
        {"path": "docs/rapidtriage-release-checklist.md", "purpose": "Repeatable release verification checklist."},
        {"path": "docs/rapidtriage-release-notes-template.md", "purpose": "Release communication template."},
        {"path": "docs/rapidtriage-output-schemas.md", "purpose": "Machine-readable output contracts."},
        {"path": "docs/rapidtriage-score-improvement-plan.md", "purpose": "Score target rationale and remaining external work."},
    ]


def build_known_limits() -> list[str]:
    return [
        "RapidTriage is still a triage/review tool, not a full AXIOM/WISDOM replacement.",
        "Native acquisition, deep carving, signed installers, and legal validation require external release processes.",
        "Some direct image formats are detected but require mounting/exporting or external tools before scanning.",
        "OCR, perceptual hashing, APK risk flags, memory imports, and cloud imports are analyst triage aids.",
    ]


def render_validation_markdown(payload: Mapping[str, object]) -> str:
    checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
    commands = payload.get("recommended_commands") if isinstance(payload.get("recommended_commands"), list) else []
    documents = payload.get("required_documents") if isinstance(payload.get("required_documents"), list) else []
    limits = payload.get("known_limits") if isinstance(payload.get("known_limits"), list) else []
    commercial_gaps = (
        payload.get("commercial_gap_assessment")
        if isinstance(payload.get("commercial_gap_assessment"), list)
        else []
    )

    lines = [
        "# RapidTriage Release Validation Package",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Platform: `{payload.get('platform', '')}`",
        f"- Internal roadmap score: `{payload.get('internal_roadmap_score', payload.get('score_target', ''))}/100`",
        f"- Commercial readiness score: `{payload.get('commercial_readiness_score', '')}/100`",
        f"- Status: `{payload.get('status', '')}`",
        "",
        "## Required Checks",
        "",
    ]
    for item in checks:
        if not isinstance(item, Mapping):
            continue
        required = "required" if item.get("required_for_release") else "operator-owned"
        lines.append(f"- `{item.get('id', '')}` ({item.get('category', '')}, {required}): {item.get('evidence', '')}")

    lines.extend(["", "## Recommended Commands", ""])
    for item in commands:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('name', '')}`: `{item.get('command', '')}`")

    lines.extend(["", "## Required Documents", ""])
    for item in documents:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('path', '')}`: {item.get('purpose', '')}")

    lines.extend(["", "## Known Limits To Disclose", ""])
    for item in limits:
        lines.append(f"- {item}")

    lines.extend(["", "## Commercial Gap Assessment", ""])
    for item in commercial_gaps:
        if not isinstance(item, Mapping):
            continue
        lines.extend(
            [
                f"### {item.get('area', '')}",
                "",
                f"- Severity: `{item.get('severity', '')}`",
                f"- Current status: {item.get('current_status', '')}",
                f"- Needed for commercial parity: {item.get('needed_for_commercial_parity', '')}",
                f"- Operator workaround: {item.get('operator_workaround', '')}",
                "",
            ]
        )

    lines.extend(
        [
            "",
            "## Release Decision",
            "",
            "The internal 100-point target means the repository can generate a repeatable validation package.",
            "The commercial readiness score is intentionally lower and reflects gaps versus full forensic suites such as AXIOM/WISDOM.",
            "It does not replace independent legal validation, signed installer infrastructure, or a maintained support program.",
            "",
        ]
    )
    return "\n".join(lines)
