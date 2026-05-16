from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from .docs import write_result


COMMERCIAL_READINESS_JSON_NAME = "rapidtriage-commercial-readiness.json"
COMMERCIAL_READINESS_MARKDOWN_NAME = "rapidtriage-commercial-readiness.md"
KNOWN_ANSWER_TEMPLATE_MARKDOWN_SUFFIX = ".md"

BACKLOG_ITEM_RE = re.compile(
    r"^(?P<number>\d+)\.\s+(?P<title>.+?)\.\s+Status:\s+(?P<status>[^.]+)\.\s*(?P<body>.*)$"
)
MATURITY_GATE_ORDER = ("implemented", "usable", "validated", "commercial_grade")
COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT = 70
COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE = 5
FUNCTIONAL_DEFENSIBILITY_BATCH_ID = "commercial-uplift-041-045"
FUNCTIONAL_DEFENSIBILITY_PROGRESS_START = 42
FUNCTIONAL_DEFENSIBILITY_PROGRESS_END = 70
FUNCTIONAL_DEFENSIBILITY_PROGRESS_BATCH_ID = "commercial-uplift-042-070"
REVIEW_SCALE_PROGRESS_START = 76
REVIEW_SCALE_PROGRESS_END = 80
REVIEW_SCALE_PROGRESS_BATCH_ID = "commercial-uplift-076-080"
VALIDATION_SPINE_PROGRESS_START = 81
VALIDATION_SPINE_PROGRESS_END = 85
VALIDATION_SPINE_PROGRESS_BATCH_ID = "commercial-uplift-081-085"
FORENSIC_INTEGRITY_PROGRESS_START = 86
FORENSIC_INTEGRITY_PROGRESS_END = 90
FORENSIC_INTEGRITY_PROGRESS_BATCH_ID = "commercial-uplift-086-090"
REPORT_QUALITY_PROGRESS_START = 91
REPORT_QUALITY_PROGRESS_END = 95
REPORT_QUALITY_PROGRESS_BATCH_ID = "commercial-uplift-091-095"
ACQUISITION_QUALITY_PROGRESS_START = 96
ACQUISITION_QUALITY_PROGRESS_END = 100
ACQUISITION_QUALITY_PROGRESS_BATCH_ID = "commercial-uplift-096-100"
RELEASE_OPERATIONS_PROGRESS_START = 101
RELEASE_OPERATIONS_PROGRESS_END = 105
RELEASE_OPERATIONS_PROGRESS_BATCH_ID = "commercial-uplift-101-105"
ENTERPRISE_GOVERNANCE_PROGRESS_START = 106
ENTERPRISE_GOVERNANCE_PROGRESS_END = 110
ENTERPRISE_GOVERNANCE_PROGRESS_BATCH_ID = "commercial-uplift-106-110"
OPERATIONS_CONTINUITY_PROGRESS_START = 111
OPERATIONS_CONTINUITY_PROGRESS_END = 115
OPERATIONS_CONTINUITY_PROGRESS_BATCH_ID = "commercial-uplift-111-115"
FINAL_DELIVERY_PROGRESS_START = 116
FINAL_DELIVERY_PROGRESS_END = 120
FINAL_DELIVERY_PROGRESS_BATCH_ID = "commercial-uplift-116-120"
MATURITY_GATE_DEFINITIONS = {
    "implemented": "Code, workflow, import path, or release artifact evidence exists.",
    "usable": "An analyst can reach the feature through CLI/API/UI/docs without custom patching.",
    "validated": "Known-answer, fixture, cross-tool, or release-validation evidence is sufficient for the current claim.",
    "commercial_grade": "No remaining blocker prevents AXIOM/WISDOM-class parity wording for this item.",
}
SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CATEGORY_PRIORITY = {
    "core-forensics": 0,
    "mobile-cloud-apps": 1,
    "validation-legal": 2,
    "performance-large-scale": 3,
    "search-analysis-ux": 4,
    "deployment-operations": 5,
    "unknown": 9,
}
TRUSTED_DIFF_RUNNER_HINTS_BY_ITEM: dict[int, dict[str, object]] = {
    1: {
        "artifact_family": "evtx",
        "runner_group_item": 77,
        "trusted_tools": ["EvtxECmd", "Hayabusa"],
        "rapid_output_hint": "rapidtriage artifacts --kind eventlog --output rapid-evtx.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-evtx.json "
            "--reference-output evtxecmd=<EvtxECmd.csv> --reference-output hayabusa=<hayabusa.csv> "
            "--source-evidence <source.evtx> --tool-version evtxecmd=<version> --tool-command evtxecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 1 --backlog-item 2 --backlog-item 3"
        ),
    },
    2: {
        "artifact_family": "evtx",
        "runner_group_item": 77,
        "trusted_tools": ["EvtxECmd", "Hayabusa"],
        "rapid_output_hint": "rapidtriage artifacts --kind eventlog --output rapid-evtx.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-evtx.json "
            "--reference-output evtxecmd=<EvtxECmd.csv> --reference-output hayabusa=<hayabusa.csv> "
            "--source-evidence <source.evtx> --tool-version evtxecmd=<version> --tool-command evtxecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 1 --backlog-item 2 --backlog-item 3"
        ),
    },
    3: {
        "artifact_family": "evtx",
        "runner_group_item": 77,
        "trusted_tools": ["EvtxECmd", "Hayabusa"],
        "rapid_output_hint": "rapidtriage artifacts --kind eventlog --output rapid-evtx.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-evtx.json "
            "--reference-output evtxecmd=<EvtxECmd.csv> --reference-output hayabusa=<hayabusa.csv> "
            "--source-evidence <source.evtx> --tool-version evtxecmd=<version> --tool-command evtxecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 1 --backlog-item 2 --backlog-item 3"
        ),
    },
    4: {
        "artifact_family": "registry",
        "runner_group_item": 78,
        "trusted_tools": ["RECmd", "Registry Explorer"],
        "rapid_output_hint": "rapidtriage artifacts --kind registry --output rapid-registry.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-registry.json "
            "--reference-output recmd=<RECmd.csv> --reference-output registryexplorer=<RegistryExplorer.csv> "
            "--source-evidence <hive> --tool-version recmd=<version> --tool-command recmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 4 --backlog-item 5"
        ),
    },
    5: {
        "artifact_family": "registry",
        "runner_group_item": 78,
        "trusted_tools": ["RECmd", "Registry Explorer"],
        "rapid_output_hint": "rapidtriage artifacts --kind registry --output rapid-registry.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-registry.json "
            "--reference-output recmd=<RECmd.csv> --reference-output registryexplorer=<RegistryExplorer.csv> "
            "--source-evidence <hive> --tool-version recmd=<version> --tool-command recmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 4 --backlog-item 5"
        ),
    },
    6: {
        "artifact_family": "os-account-execution",
        "runner_group_item": 82,
        "trusted_tools": ["RECmd", "RegRipper"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-os-account --output rapid-os-account.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-os-account.json "
            "--reference-output recmd=<RECmd.csv> --reference-output regripper=<RegRipper.csv> "
            "--source-evidence <SAM-or-SECURITY-or-SYSTEM> --tool-version recmd=<version> "
            "--tool-command recmd=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 6"
        ),
    },
    7: {
        "artifact_family": "os-account-execution",
        "runner_group_item": 82,
        "trusted_tools": ["AmcacheParser", "RECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-execution --output rapid-execution.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-execution.json "
            "--reference-output amcacheparser=<AmcacheParser.csv> --reference-output recmd=<RECmd.csv> "
            "--source-evidence <Amcache.hve> --tool-version amcacheparser=<version> "
            "--tool-command amcacheparser=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 7"
        ),
    },
    8: {
        "artifact_family": "os-account-execution",
        "runner_group_item": 82,
        "trusted_tools": ["AppCompatCacheParser", "RECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-execution --output rapid-execution.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-execution.json "
            "--reference-output appcompatcacheparser=<AppCompatCacheParser.csv> --reference-output recmd=<RECmd.csv> "
            "--source-evidence <SYSTEM> --tool-version appcompatcacheparser=<version> "
            "--tool-command appcompatcacheparser=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 8"
        ),
    },
    9: {
        "artifact_family": "os-account-execution",
        "runner_group_item": 82,
        "trusted_tools": ["RECmd", "RegRipper"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-execution --output rapid-execution.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-execution.json "
            "--reference-output recmd=<RECmd.csv> --reference-output regripper=<RegRipper.csv> "
            "--source-evidence <SYSTEM> --tool-version recmd=<version> --tool-command recmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 9"
        ),
    },
    10: {
        "artifact_family": "ese",
        "runner_group_item": 80,
        "trusted_tools": ["SrumECmd", "libesedb esedbexport"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-srum --output rapid-srum.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-srum.json "
            "--reference-output srumecmd=<SrumECmd.csv> --reference-output libesedb=<esedbexport.csv> "
            "--source-evidence <SRUDB.dat> --tool-version srumecmd=<version> --tool-command srumecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 10"
        ),
    },
    11: {
        "artifact_family": "ese",
        "runner_group_item": 80,
        "trusted_tools": ["Windows Search DB Analyzer", "libesedb esedbexport"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-search --output rapid-windows-edb.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-windows-edb.json "
            "--reference-output winsearchdbanalyzer=<WinSearchDBAnalyzer.csv> "
            "--reference-output libesedb=<esedbexport.csv> --source-evidence <Windows.edb> "
            "--tool-version winsearchdbanalyzer=<version> --tool-command winsearchdbanalyzer=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 11"
        ),
    },
    12: {
        "artifact_family": "ntfs",
        "runner_group_item": 79,
        "trusted_tools": ["MFTECmd", "analyzeMFT"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-filesystem --output rapid-mft.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-mft.json "
            "--reference-output mftecmd=<MFTECmd.csv> --reference-output analyzemft=<analyzeMFT.csv> "
            "--source-evidence <$MFT> --tool-version mftecmd=<version> --tool-command mftecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 12"
        ),
    },
    13: {
        "artifact_family": "ntfs",
        "runner_group_item": 79,
        "trusted_tools": ["UsnJrnl2Csv", "MFTECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-filesystem --output rapid-usn.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-usn.json "
            "--reference-output usnjrnl2csv=<UsnJrnl2Csv.csv> --reference-output mftecmd=<MFTECmd.csv> "
            "--source-evidence <$UsnJrnl> --tool-version usnjrnl2csv=<version> "
            "--tool-command usnjrnl2csv=<command> --independent-report <review.md> --corpus-scope <scope> "
            "--backlog-item 13"
        ),
    },
    14: {
        "artifact_family": "execution-user-activity",
        "runner_group_item": 81,
        "trusted_tools": ["JLECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind execution --kind recent-files --output rapid-jumplist.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-jumplist.json "
            "--reference-output jlecmd=<JLECmd.csv> --source-evidence <AutomaticDestinations-or-CustomDestinations> "
            "--tool-version jlecmd=<version> --tool-command jlecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 14"
        ),
    },
    15: {
        "artifact_family": "execution-user-activity",
        "runner_group_item": 81,
        "trusted_tools": ["ShellBagsExplorer/SBECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind shellbags --output rapid-shellbags.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-shellbags.json "
            "--reference-output shellbagsexplorer=<ShellBagsExplorer.csv> --source-evidence <NTUSER.DAT-or-UsrClass.dat> "
            "--tool-version shellbagsexplorer=<version> --tool-command shellbagsexplorer=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 15"
        ),
    },
    16: {
        "artifact_family": "execution-user-activity",
        "runner_group_item": 81,
        "trusted_tools": ["PECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-prefetch --output rapid-prefetch.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-prefetch.json "
            "--reference-output pecmd=<PECmd.csv> --source-evidence <Prefetch-directory> "
            "--tool-version pecmd=<version> --tool-command pecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 16"
        ),
    },
    17: {
        "artifact_family": "execution-user-activity",
        "runner_group_item": 81,
        "trusted_tools": ["LECmd", "JLECmd"],
        "rapid_output_hint": "rapidtriage artifacts --kind recent-files --output rapid-lnk.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-lnk.json "
            "--reference-output lecmd=<LECmd.csv> --reference-output jlecmd=<JLECmd.csv> "
            "--source-evidence <LNK-directory> --tool-version lecmd=<version> --tool-command lecmd=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 17"
        ),
    },
    18: {
        "artifact_family": "windows-system-ir",
        "runner_group_item": 83,
        "trusted_tools": ["Velociraptor", "Chainsaw", "Autoruns"],
        "rapid_output_hint": "rapidtriage artifacts --kind windows-system --output rapid-windows-system.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-windows-system.json "
            "--reference-output velociraptor=<Velociraptor.jsonl> --reference-output chainsaw=<Chainsaw.json> "
            "--reference-output autoruns=<Autoruns.csv> --source-evidence <Windows-system-artifact-root> "
            "--tool-version velociraptor=<version> --tool-command velociraptor=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 18"
        ),
    },
    19: {
        "artifact_family": "browser-ai",
        "runner_group_item": 84,
        "trusted_tools": ["Hindsight", "DB Browser for SQLite", "Velociraptor"],
        "rapid_output_hint": "rapidtriage artifacts --kind browser --output rapid-browser-storage.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-browser-storage.json "
            "--reference-output hindsight=<Hindsight-storage.csv-or-json> --reference-output sqlitebrowser=<SQLite-export.csv> "
            "--source-evidence <browser-profile-root> --tool-version hindsight=<version> "
            "--tool-command hindsight=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 19"
        ),
    },
    20: {
        "artifact_family": "browser-ai",
        "runner_group_item": 84,
        "trusted_tools": ["Hindsight", "BrowserHistoryView", "Velociraptor"],
        "rapid_output_hint": "rapidtriage artifacts --kind browser --output rapid-browser-timeline.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-browser-timeline.json "
            "--reference-output hindsight=<Hindsight-history.csv-or-json> "
            "--reference-output browserhistoryview=<BrowserHistoryView.csv> --source-evidence <browser-profile-root> "
            "--tool-version browserhistoryview=<version> --tool-command browserhistoryview=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 20"
        ),
    },
    21: {
        "artifact_family": "browser-ai",
        "runner_group_item": 84,
        "trusted_tools": ["Service export", "Hindsight", "DB Browser for SQLite"],
        "rapid_output_hint": "rapidtriage artifacts --kind browser --output rapid-ai-transcripts.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-ai-transcripts.json "
            "--reference-output serviceexport=<ChatGPT-Claude-Gemini-Perplexity-export.json> "
            "--reference-output hindsight=<Hindsight-ai-storage.csv-or-json> --source-evidence <browser-profile-or-service-export> "
            "--tool-version serviceexport=<export-version-or-date> --tool-command serviceexport=<export-command-or-procedure> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 21"
        ),
    },
    22: {
        "artifact_family": "evidence-image-workflow",
        "runner_group_item": 85,
        "trusted_tools": ["libewf ewfverify", "Sleuth Kit", "FTK Imager"],
        "rapid_output_hint": "rapidtriage evidence <case.E01> --json; rapidtriage run <case.E01> --output-dir <run-dir>",
        "cross_tool_template": (
            "rapidtriage image-workflow-validate --item-number 22 --rapid-output <rapid-e01-workflow.json> "
            "--trusted-output <ewfverify-or-suite-reference.json> --trusted-tool ewfverify --output e01-image-diff.json --json"
        ),
    },
    23: {
        "artifact_family": "evidence-image-workflow",
        "runner_group_item": 85,
        "trusted_tools": ["Sleuth Kit", "FTK Imager", "X-Ways/EnCase/AXIOM vendor export"],
        "rapid_output_hint": "rapidtriage evidence <case.001-or-dd> --json; rapidtriage run <case.001-or-dd> --output-dir <run-dir>",
        "cross_tool_template": (
            "rapidtriage image-workflow-validate --item-number 23 --rapid-output <rapid-raw-workflow.json> "
            "--trusted-output <tsk-or-suite-reference.csv> --trusted-tool tsk_recover --output raw-image-diff.json --json"
        ),
    },
    24: {
        "artifact_family": "evidence-image-workflow",
        "runner_group_item": 85,
        "trusted_tools": ["qemu-img", "Sleuth Kit", "X-Ways/EnCase/AXIOM vendor export"],
        "rapid_output_hint": "rapidtriage evidence <disk.vmdk-or-vhdx> --json; rapidtriage run <disk.vmdk-or-vhdx> --output-dir <run-dir>",
        "cross_tool_template": (
            "rapidtriage image-workflow-validate --item-number 24 --rapid-output <rapid-virtual-disk-workflow.json> "
            "--trusted-output <qemu-or-suite-reference.json> --trusted-tool qemu-img --output virtual-disk-diff.json --json"
        ),
    },
    25: {
        "artifact_family": "evidence-image-workflow",
        "runner_group_item": 85,
        "trusted_tools": ["FTK Imager", "X-Ways/EnCase/AXIOM vendor export", "AFF/AFF4 tooling"],
        "rapid_output_hint": "rapidtriage evidence <case.AD1-or-AFF-or-XVA> --json; scan the verified vendor export folder after export",
        "cross_tool_template": (
            "rapidtriage image-workflow-validate --item-number 25 --rapid-output <rapid-container-preflight.json> "
            "--trusted-output <vendor-export-manifest.json> --trusted-tool 'vendor export manifest' "
            "--output container-export-diff.json --json"
        ),
    },
    26: {
        "artifact_family": "mobile-app-export",
        "runner_group_item": 86,
        "trusted_tools": ["Cellebrite Physical Analyzer/UFED", "MSAB XRY", "GrayKey/GrayKey FFS export", "Magnet AXIOM"],
        "rapid_output_hint": "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapid-mobile-vendor.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-mobile-vendor.json "
            "--reference-output cellebrite=<Cellebrite-export.csv> --reference-output xry=<XRY-export.csv> "
            "--reference-output graykey=<GrayKey-export.json> --reference-output axiom=<AXIOM-export.csv> "
            "--source-evidence <authorized-mobile-export-root> --tool-version cellebrite=<version> "
            "--tool-command cellebrite=<export-procedure> --independent-report <review.md> "
            "--corpus-scope <scope> --backlog-item 26"
        ),
    },
    27: {
        "artifact_family": "mobile-app-export",
        "runner_group_item": 86,
        "trusted_tools": ["iLEAPP", "Cellebrite Physical Analyzer/UFED", "Magnet AXIOM"],
        "rapid_output_hint": "rapidtriage artifacts <ios-backup-root> --kind ios-backup --output rapid-ios-backup.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-ios-backup.json "
            "--reference-output ileapp=<iLEAPP-ios-backup.csv-or-json> --reference-output cellebrite=<Cellebrite-ios.csv> "
            "--source-evidence <Manifest.db-or-backup-root> --tool-version ileapp=<version> "
            "--tool-command ileapp=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 27"
        ),
    },
    28: {
        "artifact_family": "mobile-app-export",
        "runner_group_item": 86,
        "trusted_tools": ["iLEAPP", "GrayKey/GrayKey FFS export", "Cellebrite Physical Analyzer/UFED"],
        "rapid_output_hint": "rapidtriage artifacts <ios-keychain-export> --kind ios-backup --output rapid-ios-keychain.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-ios-keychain.json "
            "--reference-output ileapp=<iLEAPP-keychain-redacted.csv> --reference-output graykey=<GrayKey-keychain-redacted.json> "
            "--source-evidence <authorized-keychain-export-or-inventory> --tool-version ileapp=<version> "
            "--tool-command ileapp=<command> --independent-report <review.md> --corpus-scope <scope> --backlog-item 28"
        ),
    },
    29: {
        "artifact_family": "mobile-app-export",
        "runner_group_item": 86,
        "trusted_tools": ["ALEAPP", "Mobile Verification Toolkit", "Magnet AXIOM", "Cellebrite Physical Analyzer/UFED"],
        "rapid_output_hint": "rapidtriage artifacts <android-export-root> --kind android --output rapid-android-artifacts.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-android-artifacts.json "
            "--reference-output aleapp=<ALEAPP-android.csv-or-json> --reference-output mvt=<MVT-android.json> "
            "--reference-output axiom=<AXIOM-android.csv> --source-evidence <authorized-android-export-root> "
            "--tool-version aleapp=<version> --tool-command aleapp=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 29"
        ),
    },
    30: {
        "artifact_family": "mobile-app-export",
        "runner_group_item": 86,
        "trusted_tools": ["apktool/aapt/jadx", "ALEAPP", "Mobile Verification Toolkit", "Magnet AXIOM"],
        "rapid_output_hint": "rapidtriage artifacts <apk-or-app-data-root> --kind android-apk --kind android --output rapid-android-app.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-android-app.json "
            "--reference-output apktool=<apktool-aapt-jadx-normalized.csv> --reference-output aleapp=<ALEAPP-app-data.csv> "
            "--source-evidence <APK-or-app-data-root> --tool-version apktool=<version> --tool-command apktool=<command> "
            "--independent-report <review.md> --corpus-scope <scope> --backlog-item 30"
        ),
    },
}


class CommercialReadinessError(ValueError):
    """Raised when commercial-readiness inputs are invalid."""


def default_backlog_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "rapidtriage-commercial-parity-backlog.md"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_validation_evidence(validation_package_path: Path | None = None) -> dict[int, list[dict[str, object]]]:
    if validation_package_path is None:
        return {}
    resolved = validation_package_path.expanduser().resolve()
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommercialReadinessError(f"failed to read validation evidence: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise CommercialReadinessError("validation evidence must be a JSON object")

    datasets = validation_datasets_from_payload(raw)
    evidence_by_item: dict[int, list[dict[str, object]]] = {}
    for dataset in datasets:
        if not isinstance(dataset, Mapping):
            continue
        status = str(dataset.get("status") or "").lower()
        evidence_paths_present = validation_evidence_paths_present(dataset, manifest_path=resolved)
        if status != "pass" or not evidence_paths_present:
            continue
        for number in validation_target_numbers(dataset):
            evidence_by_item.setdefault(number, []).append(
                {
                    "id": str(dataset.get("id") or ""),
                    "name": str(dataset.get("name") or dataset.get("id") or ""),
                    "source": str(dataset.get("source") or ""),
                    "status": status,
                    "manifest_path": str(resolved),
                    "evidence_paths": list(dataset.get("evidence_paths") or []),
                    "evidence_paths_present": True,
                    "notes": str(dataset.get("notes") or ""),
                }
            )
    return evidence_by_item


def resolve_validation_package_paths(
    *,
    validation_package_path: Path | None = None,
    validation_package_paths: Iterable[Path] | None = None,
) -> list[Path]:
    paths: list[Path] = []
    if validation_package_path is not None:
        paths.append(validation_package_path)
    paths.extend(path for path in (validation_package_paths or []) if path is not None)

    resolved_paths: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        resolved = path.expanduser().resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        resolved_paths.append(resolved)
    return resolved_paths


def load_validation_evidence_packages(
    validation_package_paths: Iterable[Path] | None = None,
) -> dict[int, list[dict[str, object]]]:
    evidence_by_item: dict[int, list[dict[str, object]]] = {}
    for validation_package_path in validation_package_paths or []:
        for item_number, evidence_rows in load_validation_evidence(validation_package_path).items():
            evidence_by_item.setdefault(item_number, []).extend(evidence_rows)
    return evidence_by_item


MAC_FIRST_PREPARABLE_BACKLOG_ITEMS = [61, 64, 65, 66, 68, 74, 78, 79]
MAC_FIRST_EVIDENCE_COMMANDS = {
    "macos-live-smoke",
    "large-case-readiness",
    "email-external-parse",
    "image-workflow-validate",
    "source-read",
    "source-search",
    "cloud-export",
}
MAC_FIRST_EVIDENCE_FILENAMES = {
    "macos-live-smoke.json",
    "large-case-readiness.json",
    "email-external-parser.json",
    "image-workflow-validate.json",
    "image-workflow-trusted-diff.json",
    "e01-workflow-trusted-diff.json",
    "raw-workflow-trusted-diff.json",
    "virtual-disk-workflow-trusted-diff.json",
    "container-workflow-trusted-diff.json",
    "source-read.json",
    "source-search.json",
    "cloud-export-artifacts.json",
    "cloud-artifacts.json",
    "cloud-ai-archive-artifacts.json",
    "cloud-archive-artifacts.json",
    "cloud-csv-artifacts.json",
    "iaas-cloud-artifacts.json",
}
MAC_FIRST_EVIDENCE_DISCOVERY_MAX_FILES = 100


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    rows: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in rows:
            rows.append(text)
    return rows


def _mac_first_evidence_command(raw: Mapping[str, object]) -> str:
    command = str(raw.get("command") or "")
    if command:
        return command
    kind = str(raw.get("kind") or "")
    if kind == "cloud-export":
        return kind
    return ""


def _cloud_export_evidence_summary(raw: Mapping[str, object]) -> dict[str, object]:
    artifacts = raw.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
    artifact_type_counts: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    ai_service_counts: dict[str, int] = {}
    manifest_hashes: set[str] = set()
    archive_manifest_hashes: set[str] = set()
    commercial_blockers: list[str] = []
    reportability_blockers: list[str] = []
    required_before_report: list[str] = []
    supported_items: set[int] = set()
    ai_conversation_count = 0
    ai_complete_pair_count = 0
    ai_orphan_question_count = 0
    ai_orphan_answer_count = 0
    ai_incomplete_conversation_count = 0
    ai_completeness_scores: list[float] = []
    ready_for_court_report_count = 0

    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        artifact_type = str(artifact.get("artifact_type") or "")
        if artifact_type:
            artifact_type_counts[artifact_type] = artifact_type_counts.get(artifact_type, 0) + 1
        details = artifact.get("details") if isinstance(artifact.get("details"), Mapping) else {}
        service = str(details.get("service") or details.get("profile") or "")
        family = str(details.get("cloud_family") or "").lower()
        service_key = (service or family or artifact_type or "unknown").lower()
        service_counts[service_key] = service_counts.get(service_key, 0) + 1

        if artifact_type == "ai-service-export-conversation":
            supported_items.add(21)
            ai_conversation_count += 1
            if service_key:
                ai_service_counts[service_key] = ai_service_counts.get(service_key, 0) + 1
            try:
                ai_complete_pair_count += int(details.get("complete_pair_count") or 0)
            except (TypeError, ValueError):
                pass
            try:
                ai_orphan_question_count += int(details.get("orphan_question_count") or 0)
            except (TypeError, ValueError):
                pass
            try:
                ai_orphan_answer_count += int(details.get("orphan_answer_count") or 0)
            except (TypeError, ValueError):
                pass
            try:
                ai_completeness_scores.append(float(details.get("transcript_completeness_score") or 0.0))
            except (TypeError, ValueError):
                ai_completeness_scores.append(0.0)
            if str(details.get("transcript_validation_status") or "").lower() != "complete":
                ai_incomplete_conversation_count += 1
        if "google" in family or "google" in service_key or "gmail" in service_key:
            supported_items.add(37)
        if "apple" in family or "icloud" in family or "icloud" in service_key:
            supported_items.add(38)
        if "microsoft" in family or "m365" in service_key or "teams" in service_key or "onedrive" in service_key:
            supported_items.add(39)

        for key in (
            "cloud_export_import_manifest_hash",
            "google_takeout_parser_manifest_hash",
            "icloud_export_parser_manifest_hash",
            "m365_export_parser_manifest_hash",
            "ai_service_export_parser_manifest_hash",
        ):
            value = str(details.get(key) or "")
            if value:
                manifest_hashes.add(value)
        archive_hash = str(details.get("cloud_archive_manifest_hash") or "")
        if archive_hash:
            archive_manifest_hashes.add(archive_hash)
        blockers = details.get("commercial_grade_blockers")
        if isinstance(blockers, list):
            for blocker in blockers:
                text = str(blocker)
                if text and text not in commercial_blockers:
                    commercial_blockers.append(text)
        uplift = details.get("commercial_uplift_evidence") if isinstance(details.get("commercial_uplift_evidence"), Mapping) else {}
        reportability = (
            uplift.get("reportability_decision")
            if isinstance(uplift.get("reportability_decision"), Mapping)
            else {}
        )
        if reportability.get("ready_for_court_report") is True:
            ready_for_court_report_count += 1
        for blocker in _string_list(reportability.get("blockers")):
            if blocker not in reportability_blockers:
                reportability_blockers.append(blocker)
        for requirement in _string_list(reportability.get("required_before_report")):
            if requirement not in required_before_report:
                required_before_report.append(requirement)

    summary = raw.get("summary") if isinstance(raw.get("summary"), Mapping) else {}
    return {
        "artifact_count": summary.get("artifact_count", len(artifacts)),
        "artifact_type_counts": dict(sorted(artifact_type_counts.items())),
        "service_counts": dict(sorted(service_counts.items())),
        "ai_service_counts": dict(sorted(ai_service_counts.items())),
        "parser_manifest_hash_count": len(manifest_hashes),
        "archive_manifest_hash_count": len(archive_manifest_hashes),
        "ai_conversation_count": ai_conversation_count,
        "ai_complete_pair_count": ai_complete_pair_count,
        "ai_orphan_question_count": ai_orphan_question_count,
        "ai_orphan_answer_count": ai_orphan_answer_count,
        "ai_incomplete_conversation_count": ai_incomplete_conversation_count,
        "ai_min_completeness_score": min(ai_completeness_scores) if ai_completeness_scores else None,
        "ready_for_court_report_count": ready_for_court_report_count,
        "supported_backlog_items": sorted(supported_items),
        "commercial_grade_blockers": commercial_blockers,
        "reportability_blockers": reportability_blockers,
        "required_before_report": required_before_report,
    }


def _mac_first_evidence_target_items(raw: Mapping[str, object]) -> list[int]:
    target_items: list[int] = []
    candidate_containers = [
        raw.get("readiness_attachment"),
        raw.get("commercial_uplift_evidence"),
        raw.get("summary"),
    ]
    for container in candidate_containers:
        if not isinstance(container, Mapping):
            continue
        values = (
            container.get("supported_backlog_items")
            or container.get("supports_backlog_items")
            or container.get("target_items")
            or []
        )
        for value in values if isinstance(values, list) else [values]:
            try:
                number = int(str(value).lstrip("#"))
            except ValueError:
                continue
            if 1 <= number <= 120 and number not in target_items:
                target_items.append(number)
    if not target_items:
        command = _mac_first_evidence_command(raw)
        if command in {"macos-live-smoke", "large-case-readiness"}:
            target_items.extend(MAC_FIRST_PREPARABLE_BACKLOG_ITEMS)
        elif command == "source-read":
            target_items.extend([52, 64, 65])
        elif command == "source-search":
            target_items.extend([52, 61, 64, 65])
        elif command == "image-workflow-validate":
            try:
                item_number = int(str(raw.get("item_number") or raw.get("gap_id") or "").lstrip("#"))
            except ValueError:
                item_number = 0
            if item_number in {22, 23, 24, 25}:
                target_items.append(item_number)
        elif command == "cloud-export":
            target_items.extend(_cloud_export_evidence_summary(raw)["supported_backlog_items"])
    return target_items


def discover_mac_first_evidence_paths(root: Path) -> list[Path]:
    resolved = root.expanduser().resolve()
    if not resolved.exists():
        raise CommercialReadinessError(f"Mac-first evidence path not found: {resolved}")
    if resolved.is_file():
        return [resolved]
    if not resolved.is_dir():
        raise CommercialReadinessError(f"Mac-first evidence path is not a file or directory: {resolved}")

    discovered: list[Path] = []
    seen: set[str] = set()
    for name in sorted(MAC_FIRST_EVIDENCE_FILENAMES):
        for candidate in resolved.rglob(name):
            candidate_resolved = candidate.resolve()
            key = str(candidate_resolved)
            if key in seen:
                continue
            seen.add(key)
            discovered.append(candidate_resolved)
            if len(discovered) >= MAC_FIRST_EVIDENCE_DISCOVERY_MAX_FILES:
                return discovered
    if not discovered:
        raise CommercialReadinessError(
            f"no supported Mac-first evidence JSON found under {resolved}; expected one of "
            f"{sorted(MAC_FIRST_EVIDENCE_FILENAMES)}"
        )
    return discovered


def resolve_mac_first_evidence_paths(paths: Iterable[Path] | None = None) -> list[Path]:
    resolved_paths: list[Path] = []
    seen: set[str] = set()
    for path in paths or []:
        for discovered in discover_mac_first_evidence_paths(path):
            key = str(discovered)
            if key in seen:
                continue
            seen.add(key)
            resolved_paths.append(discovered)
    return resolved_paths


def load_mac_first_evidence(path: Path) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommercialReadinessError(f"failed to read Mac-first evidence: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise CommercialReadinessError("Mac-first evidence must be a JSON object")
    command = _mac_first_evidence_command(raw)
    if command not in MAC_FIRST_EVIDENCE_COMMANDS:
        raise CommercialReadinessError(
            f"unsupported Mac-first evidence command in {resolved}: {command or '<missing>'}"
        )
    summary = raw.get("summary") if isinstance(raw.get("summary"), Mapping) else {}
    outputs = raw.get("outputs") if isinstance(raw.get("outputs"), Mapping) else {}
    blockers = raw.get("commercial_grade_blockers")
    blocker_list = list(blockers) if isinstance(blockers, list) else []
    embedded_large_case = raw.get("large_case_readiness") if isinstance(raw.get("large_case_readiness"), Mapping) else {}
    large_case = raw if command == "large-case-readiness" else embedded_large_case
    selected_tool = raw.get("selected_tool") if isinstance(raw.get("selected_tool"), Mapping) else {}
    evidence_manifest = raw.get("evidence_manifest") if isinstance(raw.get("evidence_manifest"), Mapping) else {}
    uplift = raw.get("commercial_uplift_evidence") if isinstance(raw.get("commercial_uplift_evidence"), Mapping) else {}
    source_locator = raw.get("source_locator") if isinstance(raw.get("source_locator"), Mapping) else {}
    source_citation_package = (
        raw.get("source_citation_package") if isinstance(raw.get("source_citation_package"), Mapping) else {}
    )
    reportability_decision = (
        raw.get("reportability_decision") if isinstance(raw.get("reportability_decision"), Mapping) else {}
    )
    source_accuracy_gates = (
        source_citation_package.get("core_accuracy_gates")
        if isinstance(source_citation_package.get("core_accuracy_gates"), Mapping)
        else {}
    )
    source_required_before_report = _string_list(reportability_decision.get("required_before_report"))
    source_reportability_blockers = [
        *_string_list(reportability_decision.get("blockers")),
        *_string_list(source_accuracy_gates.get("remaining_blockers")),
    ]
    source_reportability_blockers = list(dict.fromkeys(source_reportability_blockers))
    large_case_summary = large_case.get("summary") if isinstance(large_case.get("summary"), Mapping) else {}
    case_db_profile = large_case.get("case_db_profile") if isinstance(large_case.get("case_db_profile"), Mapping) else {}
    search_diagnostics = (
        case_db_profile.get("search_diagnostics") if isinstance(case_db_profile.get("search_diagnostics"), Mapping) else {}
    )
    cursor_diagnostics = (
        search_diagnostics.get("cursor_diagnostics")
        if isinstance(search_diagnostics.get("cursor_diagnostics"), Mapping)
        else {}
    )
    cursor_diagnostics_summary = (
        cursor_diagnostics.get("summary") if isinstance(cursor_diagnostics.get("summary"), Mapping) else {}
    )
    search_index_health = (
        case_db_profile.get("search_index_health") if isinstance(case_db_profile.get("search_index_health"), Mapping) else {}
    )
    search_index_health_summary = (
        search_index_health.get("summary") if isinstance(search_index_health.get("summary"), Mapping) else {}
    )
    cloud_export_summary = _cloud_export_evidence_summary(raw) if command == "cloud-export" else {}
    image_reportability = (
        raw.get("reportability_decision") if isinstance(raw.get("reportability_decision"), Mapping) else {}
    )
    for blocker in cloud_export_summary.get("commercial_grade_blockers", []):
        text = str(blocker)
        if text and text not in blocker_list:
            blocker_list.append(text)
    return {
        "path": str(resolved),
        "path_sha256": sha256_file(resolved),
        "command": command,
        "profile_version": str(raw.get("profile_version") or ""),
        "status": str(raw.get("status") or large_case.get("status") or "observed"),
        "local_smoke_score": summary.get("local_smoke_score"),
        "passed_count": summary.get("passed_count"),
        "failed_count": summary.get("failed_count"),
        "failed_check_ids": list(summary.get("failed_check_ids") or []),
        "failed_or_blocked_checks": list(uplift.get("failed_or_blocked_checks") or []),
        "commercial_grade_blockers": blocker_list,
        "large_case_status": str(large_case.get("status") or ""),
        "large_case_largest_record_count": large_case_summary.get("largest_benchmark_record_count"),
        "large_case_search_diagnostics_ready": large_case_summary.get("case_db_search_diagnostics_ready"),
        "large_case_search_diagnostics_hash": str(search_diagnostics.get("profile_hash") or ""),
        "large_case_search_diagnostics_fts_table_count": search_diagnostics.get("fts_table_count"),
        "large_case_cursor_diagnostics_ready": large_case_summary.get("case_db_cursor_diagnostics_ready"),
        "large_case_cursor_diagnostics_hash": str(
            large_case_summary.get("case_db_cursor_diagnostics_hash")
            or cursor_diagnostics.get("profile_hash")
            or ""
        ),
        "large_case_cursor_pagination_proven_tables": (
            large_case_summary.get("case_db_cursor_pagination_proven_tables")
            if large_case_summary.get("case_db_cursor_pagination_proven_tables") is not None
            else cursor_diagnostics_summary.get("pagination_proven_table_count")
        ),
        "large_case_search_index_healthy": large_case_summary.get("case_db_search_index_healthy"),
        "large_case_search_index_health_status": str(search_index_health.get("status") or ""),
        "large_case_search_index_health_hash": str(search_index_health.get("profile_hash") or ""),
        "large_case_search_index_missing_rows": search_index_health_summary.get("missing_index_rows"),
        "supported_backlog_items": _mac_first_evidence_target_items(raw),
        "evidence_manifest_hash": str(
            evidence_manifest.get("manifest_sha256") or uplift.get("evidence_manifest_hash") or ""
        ),
        "export_file_count": summary.get("export_file_count"),
        "ready_for_trusted_diff": summary.get("ready_for_trusted_diff"),
        "selected_tool": str(selected_tool.get("tool") or ""),
        "selected_tool_available": selected_tool.get("available"),
        "source_relative_path": str(raw.get("relative_path") or raw.get("path") or ""),
        "source_locator_type": str(source_locator.get("locator_type") or ""),
        "source_match_count": summary.get("match_count"),
        "source_searchable": raw.get("searchable"),
        "source_citation_package_hash": str(source_citation_package.get("package_hash") or ""),
        "source_ready_for_review_note": source_citation_package.get("ready_for_review_note"),
        "source_ready_for_court_report": source_citation_package.get("ready_for_court_report"),
        "source_reportability_decision": str(reportability_decision.get("decision") or ""),
        "source_required_before_report": source_required_before_report,
        "source_required_before_report_count": len(source_required_before_report),
        "source_reportability_blockers": source_reportability_blockers,
        "source_reportability_blocker_count": len(source_reportability_blockers),
        "cloud_export_artifact_count": cloud_export_summary.get("artifact_count"),
        "cloud_export_artifact_type_counts": cloud_export_summary.get("artifact_type_counts", {}),
        "cloud_export_service_counts": cloud_export_summary.get("service_counts", {}),
        "cloud_export_ai_service_counts": cloud_export_summary.get("ai_service_counts", {}),
        "cloud_export_parser_manifest_hash_count": cloud_export_summary.get("parser_manifest_hash_count"),
        "cloud_export_archive_manifest_hash_count": cloud_export_summary.get("archive_manifest_hash_count"),
        "cloud_export_ai_conversation_count": cloud_export_summary.get("ai_conversation_count"),
        "cloud_export_ai_complete_pair_count": cloud_export_summary.get("ai_complete_pair_count"),
        "cloud_export_ai_orphan_question_count": cloud_export_summary.get("ai_orphan_question_count"),
        "cloud_export_ai_orphan_answer_count": cloud_export_summary.get("ai_orphan_answer_count"),
        "cloud_export_ai_incomplete_conversation_count": cloud_export_summary.get("ai_incomplete_conversation_count"),
        "cloud_export_ai_min_completeness_score": cloud_export_summary.get("ai_min_completeness_score"),
        "cloud_export_ready_for_court_report_count": cloud_export_summary.get("ready_for_court_report_count"),
        "cloud_export_reportability_blockers": cloud_export_summary.get("reportability_blockers", []),
        "cloud_export_reportability_blocker_count": len(cloud_export_summary.get("reportability_blockers", [])),
        "cloud_export_required_before_report": cloud_export_summary.get("required_before_report", []),
        "cloud_export_required_before_report_count": len(cloud_export_summary.get("required_before_report", [])),
        "image_workflow_status": str(raw.get("status") or "") if command == "image-workflow-validate" else "",
        "image_workflow_gap_id": str(raw.get("gap_id") or "") if command == "image-workflow-validate" else "",
        "image_workflow_trusted_tool": str(raw.get("trusted_tool") or "") if command == "image-workflow-validate" else "",
        "image_workflow_matched_count": raw.get("matched_count") if command == "image-workflow-validate" else None,
        "image_workflow_mismatch_count": raw.get("mismatch_count") if command == "image-workflow-validate" else None,
        "image_workflow_missing_count": raw.get("missing_count") if command == "image-workflow-validate" else None,
        "image_workflow_extra_count": raw.get("extra_count") if command == "image-workflow-validate" else None,
        "image_workflow_commercial_grade_evidence": (
            raw.get("commercial_grade_evidence") if command == "image-workflow-validate" else None
        ),
        "image_workflow_reportability_decision": (
            str(image_reportability.get("decision") or "") if command == "image-workflow-validate" else ""
        ),
        "output_keys": sorted(str(key) for key in outputs),
    }


def build_mac_first_evidence_summary(
    mac_first_evidence_paths: Iterable[Path] | None = None,
) -> dict[str, object]:
    rows = [load_mac_first_evidence(path) for path in resolve_mac_first_evidence_paths(mac_first_evidence_paths)]
    blocker_counts: dict[str, int] = {}
    failed_check_counts: dict[str, int] = {}
    for row in rows:
        for blocker in row.get("commercial_grade_blockers", []):
            text = str(blocker)
            blocker_counts[text] = blocker_counts.get(text, 0) + 1
        for check_id in row.get("failed_check_ids", []):
            text = str(check_id)
            failed_check_counts[text] = failed_check_counts.get(text, 0) + 1
        for check_id in row.get("failed_or_blocked_checks", []):
            text = str(check_id)
            failed_check_counts[text] = failed_check_counts.get(text, 0) + 1
    supported_items = sorted(
        set(MAC_FIRST_PREPARABLE_BACKLOG_ITEMS)
        | {
            int(number)
            for row in rows
            for number in row.get("supported_backlog_items", [])
            if isinstance(number, int)
        }
    )
    return {
        "profile_version": "mac-first-evidence-attachment-v1",
        "attached": bool(rows),
        "evidence_count": len(rows),
        "rows": rows,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "failed_check_counts": dict(sorted(failed_check_counts.items())),
        "large_case_search_diagnostics_ready_count": sum(
            1 for row in rows if row.get("large_case_search_diagnostics_ready") is True
        ),
        "large_case_cursor_diagnostics_ready_count": sum(
            1 for row in rows if row.get("large_case_cursor_diagnostics_ready") is True
        ),
        "large_case_cursor_pagination_proven_table_count": sum(
            int(row.get("large_case_cursor_pagination_proven_tables") or 0) for row in rows
        ),
        "source_review_handoff_ready_count": sum(
            1 for row in rows if row.get("source_ready_for_review_note") is True
        ),
        "source_court_report_ready_count": sum(
            1 for row in rows if row.get("source_ready_for_court_report") is True
        ),
        "source_required_before_report_count": sum(
            int(row.get("source_required_before_report_count") or 0) for row in rows
        ),
        "source_reportability_blocker_count": sum(
            int(row.get("source_reportability_blocker_count") or 0) for row in rows
        ),
        "cloud_export_evidence_count": sum(1 for row in rows if row.get("command") == "cloud-export"),
        "cloud_export_artifact_count": sum(
            int(row.get("cloud_export_artifact_count") or 0) for row in rows
        ),
        "cloud_export_parser_manifest_hash_count": sum(
            int(row.get("cloud_export_parser_manifest_hash_count") or 0) for row in rows
        ),
        "cloud_export_ai_conversation_count": sum(
            int(row.get("cloud_export_ai_conversation_count") or 0) for row in rows
        ),
        "cloud_export_ai_incomplete_conversation_count": sum(
            int(row.get("cloud_export_ai_incomplete_conversation_count") or 0) for row in rows
        ),
        "cloud_export_reportability_blocker_count": sum(
            int(row.get("cloud_export_reportability_blocker_count") or 0) for row in rows
        ),
        "cloud_export_required_before_report_count": sum(
            int(row.get("cloud_export_required_before_report_count") or 0) for row in rows
        ),
        "image_workflow_evidence_count": sum(1 for row in rows if row.get("command") == "image-workflow-validate"),
        "image_workflow_pass_count": sum(
            1
            for row in rows
            if row.get("command") == "image-workflow-validate" and row.get("image_workflow_status") == "pass"
        ),
        "supports_backlog_items": supported_items,
        "claim_effect": (
            "Mac-first evidence is preparatory only: it can prove local plumbing, source-viewer handoff, "
            "external-parser wrapper evidence, and synthetic benchmark execution, but it does not by itself satisfy "
            "validated or commercial_grade gates."
        ),
        "next_internal_use": [
            "Attach macos-live-smoke.json after every Mac hardening batch.",
            "Attach large-case-readiness.json for search/index scalability review.",
            "Attach email-external-parser.json for PST/OST/MSG external-parser evidence and trusted diff planning.",
            "Attach cloud-export-artifacts.json for Gmail/Takeout, iCloud, M365, and AI service export parser evidence.",
            "Keep Windows image, independent lab, signed release, and 1TB-10TB hardware blockers separate.",
        ],
    }


def validation_evidence_paths_present(dataset: Mapping[str, object], *, manifest_path: Path) -> bool:
    explicit = dataset.get("evidence_paths_present")
    if explicit is False:
        return False
    raw_paths = dataset.get("evidence_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        return bool(explicit is True)
    repo_root = Path(__file__).resolve().parents[2]
    for raw_path in raw_paths:
        text = str(raw_path).strip()
        if not text:
            return False
        candidate = Path(text).expanduser()
        candidates = [candidate] if candidate.is_absolute() else [
            Path.cwd() / candidate,
            manifest_path.parent / candidate,
            repo_root / candidate,
        ]
        if not any(path.exists() for path in candidates):
            return False
    return True


def validation_datasets_from_payload(payload: Mapping[str, object]) -> list[object]:
    known_answer = payload.get("known_answer_validation")
    if isinstance(known_answer, Mapping) and isinstance(known_answer.get("datasets"), list):
        return list(known_answer["datasets"])
    datasets = payload.get("datasets")
    if isinstance(datasets, list):
        return list(datasets)
    return []


def validation_target_numbers(dataset: Mapping[str, object]) -> list[int]:
    raw_values = (
        dataset.get("backlog_items")
        or dataset.get("commercial_items")
        or dataset.get("item_numbers")
        or []
    )
    if not raw_values and isinstance(dataset.get("expected"), Mapping):
        expected = dataset["expected"]
        raw_values = (
            expected.get("backlog_items")
            or expected.get("commercial_items")
            or expected.get("item_numbers")
            or []
        )
    if isinstance(raw_values, (str, int)):
        raw_values = [raw_values]
    numbers: list[int] = []
    if isinstance(raw_values, list):
        for value in raw_values:
            try:
                number = int(str(value).lstrip("#"))
            except ValueError:
                continue
            if 1 <= number <= 120 and number not in numbers:
                numbers.append(number)
    return numbers


def attach_validation_evidence(
    items: list[dict[str, object]],
    evidence_by_item: dict[int, list[dict[str, object]]],
) -> dict[str, object]:
    attached_count = 0
    for item in items:
        number = int(item.get("number") or 0)
        evidence_rows = evidence_by_item.get(number, [])
        if not evidence_rows:
            item["validation_evidence"] = []
            continue
        attached_count += 1
        item["validation_evidence"] = evidence_rows
        gates = item.get("maturity_gates")
        if isinstance(gates, dict) and isinstance(gates.get("validated"), dict):
            gates["validated"] = maturity_gate(
                True,
                "attached known-answer validation evidence passed for this backlog item",
                "",
            )
            item["highest_maturity_stage"] = highest_maturity_stage(gates)
            item["next_required_gate"] = next_required_gate(gates)
    return {
        "validation_package_attached": bool(evidence_by_item),
        "items_with_passed_validation_evidence": attached_count,
        "mapped_item_numbers": sorted(evidence_by_item),
        "rule": "Only datasets with status=pass and present evidence paths can satisfy an item's validated gate; commercial_grade still requires blocker removal.",
    }


def build_known_answer_manifest_template(
    items: Iterable[dict[str, object]],
    *,
    next_gate: str = "validated",
    limit: int = 5,
    item_numbers: Iterable[int] | None = None,
) -> dict[str, object]:
    if next_gate not in MATURITY_GATE_ORDER:
        raise CommercialReadinessError(f"unknown maturity gate for known-answer template: {next_gate}")
    item_list = list(items)
    selected_numbers = list(dict.fromkeys(int(number) for number in (item_numbers or []) if 1 <= int(number) <= 120))
    if selected_numbers:
        items_by_number = {int(item.get("number") or 0): item for item in item_list}
        selected = [items_by_number[number] for number in selected_numbers if number in items_by_number]
    else:
        selected = [
            item for item in sorted(item_list, key=priority_sort_key)
            if item.get("next_required_gate") == next_gate
        ][: max(limit, 0)]
    datasets = [known_answer_dataset_template(item) for item in selected]
    return {
        "command": "commercial-readiness-known-answer-template",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "template-not-run",
        "next_gate": next_gate,
        "item_numbers": [int(item.get("number") or 0) for item in selected],
        "item_count": len(datasets),
        "instructions": [
            "Fill source, evidence_paths, expected assertions, and status after running real known-answer or cross-tool validation.",
            "Keep status as not-run/open/fail until every required assertion is independently verified.",
            "Only status=pass rows with present evidence paths can satisfy the commercial-readiness validated gate.",
        ],
        "datasets": datasets,
    }


def build_known_answer_template_batches(
    items: Iterable[dict[str, object]],
    *,
    item_numbers: Iterable[int],
    batch_size: int = 5,
    next_gate: str = "validated",
) -> dict[str, object]:
    if batch_size <= 0:
        raise CommercialReadinessError("known-answer template batch size must be greater than zero")
    numbers = [number for number in dict.fromkeys(int(value) for value in item_numbers) if 1 <= number <= 120]
    batches: list[dict[str, object]] = []
    for index in range(0, len(numbers), batch_size):
        batch_numbers = numbers[index : index + batch_size]
        template = build_known_answer_manifest_template(
            items,
            next_gate=next_gate,
            limit=batch_size,
            item_numbers=batch_numbers,
        )
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": batch_numbers,
                "item_count": len(batch_numbers),
                "template": template,
            }
        )
    return {
        "command": "commercial-readiness-known-answer-template-batches",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "templates-not-run",
        "next_gate": next_gate,
        "batch_size": batch_size,
        "batch_count": len(batches),
        "item_count": len(numbers),
        "item_numbers": numbers,
        "batches": batches,
        "rule": "Each batch starts as not-run. Fill evidence and change dataset status to pass only after real validation.",
    }


def known_answer_dataset_template(item: dict[str, object]) -> dict[str, object]:
    number = int(item.get("number") or 0)
    title = str(item.get("title") or f"Backlog item {number}")
    return {
        "id": f"commercial-item-{number:03d}-{slugify(title)}",
        "name": title,
        "source": "",
        "corpus_family": str(item.get("category") or ""),
        "status": "not-run",
        "backlog_items": [number],
        "evidence_paths": [],
        "expected": {
            "backlog_items": [number],
            "required_assertions": required_assertions_for_item(item),
            "reference_tools": reference_tools_for_item(number),
            "minimum_evidence": [
                "source evidence hash and acquisition notes",
                "RapidTriage output JSON/Markdown",
                "trusted reference tool output or known-answer expected-result file",
                "record-level or assertion-level diff",
                "reviewer sign-off with limitations",
            ],
        },
        "notes": gate_remaining_text(item, str(item.get("next_required_gate") or "validated")),
    }


def required_assertions_for_item(item: dict[str, object]) -> list[str]:
    number = int(item.get("number") or 0)
    title = str(item.get("title") or "")
    gap = gate_remaining_text(item, str(item.get("next_required_gate") or "validated"))
    assertions = [
        f"Backlog item #{number} ({title}) has passing known-answer or cross-tool evidence.",
        "RapidTriage output preserves source path, source hash, parser version, and relevant offsets where available.",
        "False-positive and false-negative limitations are documented for this item.",
    ]
    if gap:
        assertions.append(f"Remaining validation gap is specifically addressed: {gap}")
    if 1 <= number <= 3:
        assertions.extend(
            [
                "EVTX record counts, record IDs, timestamps, provider/channel/EventID fields, and recovered/corrupt candidates match expected results within documented tolerance.",
                "Message rendering/template fallback differences are explicitly diffed against the reference output.",
            ]
        )
    elif 4 <= number <= 6:
        assertions.extend(
            [
                "Registry/SAM/SECURITY/SYSTEM key, value, timestamp, deleted-cell, account, group, privilege, and transaction-log claims match expected results within documented tolerance.",
                "Any secret or protected value handling is authorized, redacted where required, and separately audited.",
            ]
        )
    elif 7 <= number <= 18:
        assertions.append(
            "Execution, filesystem, ESE, or system-artifact timestamps and semantic caveats are validated against a trusted parser export."
        )
    return assertions


def reference_tools_for_item(number: int) -> list[str]:
    if 1 <= number <= 3:
        return ["EvtxECmd", "Hayabusa", "Windows Event Viewer/wevtutil export where applicable"]
    if 4 <= number <= 6 or number == 15:
        return ["Registry Explorer/rla", "RegRipper", "Eric Zimmerman RECmd where applicable"]
    if number in {7, 8, 9, 16, 17}:
        return ["AmcacheParser", "AppCompatCacheParser", "PECmd", "LECmd/JLECmd where applicable"]
    if number in {10, 11}:
        return ["SrumECmd", "ESEDatabaseView/esedbexport", "Windows Search parser reference export"]
    if number in {12, 13}:
        return ["MFTECmd", "usn.py/USN Journal parser reference export", "Sleuth Kit where applicable"]
    return ["trusted commercial tool export", "known-answer expected-result manifest"]


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:72] or "validation"


def write_known_answer_manifest_template(template: dict[str, object], output: Path) -> dict[str, str]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    write_result(template, output)
    markdown_path = output.with_suffix(KNOWN_ANSWER_TEMPLATE_MARKDOWN_SUFFIX)
    markdown_path.write_text(render_known_answer_template_markdown(template), encoding="utf-8")
    return {"json": str(output), "markdown": str(markdown_path)}


def write_known_answer_template_batches(batch_payload: dict[str, object], output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    written_batches: list[dict[str, object]] = []
    for batch in batch_payload.get("batches", []):
        if not isinstance(batch, dict) or not isinstance(batch.get("template"), dict):
            continue
        item_numbers = [int(number) for number in batch.get("item_numbers", [])]
        if item_numbers:
            stem = f"known-answer-batch-{item_numbers[0]:03d}-{item_numbers[-1]:03d}.template.json"
        else:
            stem = f"known-answer-batch-{int(batch.get('batch_number') or 0):03d}.template.json"
        outputs = write_known_answer_manifest_template(batch["template"], output_dir / stem)
        written_batches.append(
            {
                "batch_number": batch.get("batch_number"),
                "item_numbers": item_numbers,
                "outputs": outputs,
            }
        )
    index_payload = {
        "command": batch_payload.get("command"),
        "generated_at": batch_payload.get("generated_at"),
        "status": batch_payload.get("status"),
        "next_gate": batch_payload.get("next_gate"),
        "batch_size": batch_payload.get("batch_size"),
        "batch_count": len(written_batches),
        "item_count": batch_payload.get("item_count"),
        "item_numbers": batch_payload.get("item_numbers"),
        "batches": written_batches,
        "rule": batch_payload.get("rule"),
    }
    index_json = output_dir / "known-answer-template-batches.index.json"
    index_md = output_dir / "known-answer-template-batches.index.md"
    write_result(index_payload, index_json)
    index_md.write_text(render_known_answer_batch_index_markdown(index_payload), encoding="utf-8")
    return {
        "directory": str(output_dir),
        "index_json": str(index_json),
        "index_markdown": str(index_md),
        "batch_count": len(written_batches),
        "batches": written_batches,
    }


def parse_item_range(value: str) -> list[int]:
    numbers: list[int] = []
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start = int(start_text.strip().lstrip("#"))
                end = int(end_text.strip().lstrip("#"))
            except ValueError as exc:
                raise CommercialReadinessError(f"invalid item range: {part}") from exc
            if end < start:
                start, end = end, start
            candidate_numbers = range(start, end + 1)
        else:
            try:
                candidate_numbers = [int(part.lstrip("#"))]
            except ValueError as exc:
                raise CommercialReadinessError(f"invalid item number: {part}") from exc
        for number in candidate_numbers:
            if not 1 <= number <= 120:
                raise CommercialReadinessError(f"item number out of supported range 1-120: {number}")
            if number not in numbers:
                numbers.append(number)
    return numbers


def render_known_answer_template_markdown(template: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Known-Answer Manifest Template",
        "",
        f"- Generated at: `{template.get('generated_at', '')}`",
        f"- Status: `{template.get('status', '')}`",
        f"- Next gate: `{template.get('next_gate', '')}`",
        f"- Dataset templates: `{template.get('item_count', 0)}`",
        "",
        "## Instructions",
        "",
    ]
    for item in template.get("instructions", []):
        lines.append(f"- {item}")
    lines.extend(["", "## Dataset Templates", ""])
    for dataset in template.get("datasets", []):
        if not isinstance(dataset, dict):
            continue
        expected = dataset.get("expected") if isinstance(dataset.get("expected"), dict) else {}
        reference_tools = expected.get("reference_tools") if isinstance(expected.get("reference_tools"), list) else []
        lines.append(f"- `{dataset.get('id', '')}`: {dataset.get('name', '')}")
        if reference_tools:
            lines.append(f"  Reference tools: {', '.join(str(tool) for tool in reference_tools)}")
        notes = str(dataset.get("notes") or "").strip()
        if notes:
            lines.append(f"  Validation focus: {notes}")
    lines.append("")
    return "\n".join(lines)


def render_known_answer_batch_index_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Known-Answer Template Batch Index",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Status: `{payload.get('status', '')}`",
        f"- Next gate: `{payload.get('next_gate', '')}`",
        f"- Batch size: `{payload.get('batch_size', '')}`",
        f"- Batch count: `{payload.get('batch_count', 0)}`",
        f"- Item count: `{payload.get('item_count', 0)}`",
        f"- Rule: {payload.get('rule', '')}",
        "",
        "## Batches",
        "",
    ]
    for batch in payload.get("batches", []):
        if not isinstance(batch, dict):
            continue
        outputs = batch.get("outputs") if isinstance(batch.get("outputs"), dict) else {}
        item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
        lines.append(
            f"- Batch `{batch.get('batch_number')}` ({item_numbers}): `{outputs.get('json', '')}`"
        )
    lines.append("")
    return "\n".join(lines)


def build_commercial_readiness_report(
    *,
    backlog_path: Path | None = None,
    output_dir: Path | None = None,
    validation_package_path: Path | None = None,
    validation_package_paths: Iterable[Path] | None = None,
    mac_first_evidence_paths: Iterable[Path] | None = None,
    uplift_targets: int = COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT,
    uplift_batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    backlog_path = (backlog_path or default_backlog_path()).expanduser().resolve()
    if not backlog_path.is_file():
        raise CommercialReadinessError(f"commercial parity backlog not found: {backlog_path}")

    items = parse_backlog(backlog_path)
    if not items:
        raise CommercialReadinessError(f"no numbered backlog items found in: {backlog_path}")

    resolved_validation_package_paths = resolve_validation_package_paths(
        validation_package_path=validation_package_path,
        validation_package_paths=validation_package_paths,
    )
    validation_evidence_summary = attach_validation_evidence(
        items,
        load_validation_evidence_packages(resolved_validation_package_paths),
    )
    validation_evidence_summary["validation_package_count"] = len(resolved_validation_package_paths)
    validation_evidence_summary["validation_package_paths"] = [
        str(path) for path in resolved_validation_package_paths
    ]
    mac_first_evidence_summary = build_mac_first_evidence_summary(mac_first_evidence_paths)
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
    maturity_gate_summary = build_maturity_gate_summary(items)
    commercial_blocker_matrix = build_commercial_blocker_matrix(items)
    blocker_separation_profile = build_blocker_separation_profile(commercial_blocker_matrix)
    blocker_execution_package = build_blocker_execution_package(
        commercial_blocker_matrix,
        blocker_separation_profile,
        validation_evidence_summary=validation_evidence_summary,
        mac_first_evidence_summary=mac_first_evidence_summary,
        batch_size=uplift_batch_size,
    )
    platform_uplift_actionability = build_platform_uplift_actionability(
        items,
        readiness_score=readiness_score,
        commercial_claim_allowed=commercial_claim_allowed,
    )
    commercial_uplift_plan = build_commercial_uplift_plan(
        items,
        readiness_score=readiness_score,
        target_count=uplift_targets,
        batch_size=uplift_batch_size,
    )
    functional_defensibility_progress = build_functional_defensibility_progress(
        items,
        start=FUNCTIONAL_DEFENSIBILITY_PROGRESS_START,
        end=FUNCTIONAL_DEFENSIBILITY_PROGRESS_END,
        batch_size=uplift_batch_size,
    )
    review_scale_resilience_progress = build_review_scale_resilience_progress(
        items,
        start=REVIEW_SCALE_PROGRESS_START,
        end=REVIEW_SCALE_PROGRESS_END,
    )
    validation_spine_progress = build_validation_spine_progress(
        items,
        start=VALIDATION_SPINE_PROGRESS_START,
        end=VALIDATION_SPINE_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    forensic_integrity_progress = build_forensic_integrity_progress(
        items,
        start=FORENSIC_INTEGRITY_PROGRESS_START,
        end=FORENSIC_INTEGRITY_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    report_quality_progress = build_report_quality_progress(
        items,
        start=REPORT_QUALITY_PROGRESS_START,
        end=REPORT_QUALITY_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    acquisition_quality_progress = build_acquisition_quality_progress(
        items,
        start=ACQUISITION_QUALITY_PROGRESS_START,
        end=ACQUISITION_QUALITY_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    release_operations_progress = build_release_operations_progress(
        items,
        start=RELEASE_OPERATIONS_PROGRESS_START,
        end=RELEASE_OPERATIONS_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    enterprise_governance_progress = build_enterprise_governance_progress(
        items,
        start=ENTERPRISE_GOVERNANCE_PROGRESS_START,
        end=ENTERPRISE_GOVERNANCE_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    operations_continuity_progress = build_operations_continuity_progress(
        items,
        start=OPERATIONS_CONTINUITY_PROGRESS_START,
        end=OPERATIONS_CONTINUITY_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    final_delivery_progress = build_final_delivery_progress(
        items,
        start=FINAL_DELIVERY_PROGRESS_START,
        end=FINAL_DELIVERY_PROGRESS_END,
        validation_evidence_summary=validation_evidence_summary,
    )
    claim_discipline_manifest = build_claim_discipline_manifest(
        commercial_claim_allowed=commercial_claim_allowed,
        non_commercial_count=len(non_commercial),
        readiness_score=readiness_score,
        validation_evidence_summary=validation_evidence_summary,
    )
    payload: dict[str, object] = {
        "command": "commercial-readiness",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "backlog_path": str(backlog_path),
        "status": "commercial-ready" if commercial_claim_allowed else "commercial-gaps-present",
        "commercial_claim_allowed": commercial_claim_allowed,
        "claim_discipline_profile": build_claim_discipline_profile(
            commercial_claim_allowed=commercial_claim_allowed,
            non_commercial_count=len(non_commercial),
            readiness_score=readiness_score,
            validation_evidence_summary=validation_evidence_summary,
            claim_discipline_manifest=claim_discipline_manifest,
        ),
        "claim_discipline_manifest": claim_discipline_manifest,
        "claim_discipline_manifest_hash": claim_discipline_manifest["manifest_hash"],
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
        "maturity_gate_definitions": dict(MATURITY_GATE_DEFINITIONS),
        "maturity_gate_summary": maturity_gate_summary,
        "commercial_blocker_matrix": commercial_blocker_matrix,
        "blocker_separation_profile": blocker_separation_profile,
        "blocker_execution_package": blocker_execution_package,
        "platform_uplift_actionability": platform_uplift_actionability,
        "commercial_uplift_plan": commercial_uplift_plan,
        "functional_defensibility_progress": functional_defensibility_progress,
        "review_scale_resilience_progress": review_scale_resilience_progress,
        "validation_spine_progress": validation_spine_progress,
        "forensic_integrity_progress": forensic_integrity_progress,
        "report_quality_progress": report_quality_progress,
        "acquisition_quality_progress": acquisition_quality_progress,
        "release_operations_progress": release_operations_progress,
        "enterprise_governance_progress": enterprise_governance_progress,
        "operations_continuity_progress": operations_continuity_progress,
        "final_delivery_progress": final_delivery_progress,
        "validation_evidence_summary": validation_evidence_summary,
        "mac_first_evidence_summary": mac_first_evidence_summary,
        "priority_work_plan": build_priority_work_plan(items),
        "all_items": items,
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


def build_claim_discipline_profile(
    *,
    commercial_claim_allowed: bool,
    non_commercial_count: int,
    readiness_score: int,
    validation_evidence_summary: Mapping[str, object],
    claim_discipline_manifest: Mapping[str, object],
) -> dict[str, object]:
    mapped_items = validation_evidence_summary.get("mapped_item_numbers")
    mapped_count = len(mapped_items) if isinstance(mapped_items, list) else 0
    failed_checks: list[str] = []
    if non_commercial_count:
        failed_checks.append("non-commercial-items-remain")
    if not commercial_claim_allowed:
        failed_checks.append("commercial-claim-blocked")
    if mapped_count < 120:
        failed_checks.append("all-items-validation-evidence-not-attached")
    return {
        "item_number": 45,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if commercial_claim_allowed and not failed_checks else "partial",
        "implemented_controls": {
            "commercial_claim_allowed": commercial_claim_allowed,
            "non_commercial_count": non_commercial_count,
            "readiness_score": readiness_score,
            "validation_evidence_mapped_count": mapped_count,
            "claim_discipline_manifest_hash": str(claim_discipline_manifest.get("manifest_hash") or ""),
            "release_claim_guard": (
                "allow-commercial-parity-wording"
                if commercial_claim_allowed
                else "block-commercial-parity-wording"
            ),
        },
        "passed_validation_check_ids": [
            "commercial-readiness-gate-computed",
            "non-commercial-item-count-emitted",
            "release-claim-text-derived-from-gate",
            "claim-discipline-manifest-hash-emitted",
            "operator-guidance-emitted-for-blocked-claims",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "commercial-claim-safety-gate",
            "commercial_claim_allowed": commercial_claim_allowed,
            "operator_warning": (
                "Commercial-grade wording is blocked until every item has validation evidence and no non-commercial items remain."
                if not commercial_claim_allowed
                else "Commercial wording may be used only with the attached validation evidence package."
            ),
        },
    }


def build_claim_discipline_manifest(
    *,
    commercial_claim_allowed: bool,
    non_commercial_count: int,
    readiness_score: int,
    validation_evidence_summary: Mapping[str, object],
) -> dict[str, object]:
    mapped_items = validation_evidence_summary.get("mapped_item_numbers")
    mapped_numbers = [int(value) for value in mapped_items] if isinstance(mapped_items, list) else []
    blocked_wording = [
        "commercial-grade",
        "AXIOM/WISDOM-class parity",
        "court-ready",
        "validated for all artifacts",
        "forensic suite parity",
    ]
    allowed_wording = [
        "triage-oriented forensic workflow",
        "internally implemented with validation blockers disclosed",
        "use with attached validation evidence only",
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "claim-discipline-manifest-v1",
        "item_number": 45,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#45",
        "commercial_claim_allowed": commercial_claim_allowed,
        "release_claim_guard": (
            "allow-commercial-parity-wording"
            if commercial_claim_allowed
            else "block-commercial-parity-wording"
        ),
        "readiness_score": readiness_score,
        "non_commercial_count": non_commercial_count,
        "validation_evidence_mapped_count": len(mapped_numbers),
        "validation_evidence_complete_for_all_items": len(set(mapped_numbers)) >= 120,
        "blocked_wording": [] if commercial_claim_allowed else blocked_wording,
        "allowed_wording": (
            ["commercial forensic suite parity may be claimed with attached evidence"]
            if commercial_claim_allowed
            else allowed_wording
        ),
        "required_disclaimer": (
            "Commercial-grade wording is blocked: disclose triage/validation limits and attach item-level evidence."
            if not commercial_claim_allowed
            else "Commercial-grade wording must cite the exact validation evidence package and release manifest."
        ),
        "ui_guardrails": {
            "show_commercial_badge": commercial_claim_allowed,
            "show_validation_blocker_badge": not commercial_claim_allowed,
            "disable_commercial_report_template": not commercial_claim_allowed,
            "require_disclaimer_in_reports": not commercial_claim_allowed,
        },
        "commercial_claim_allowed_only_if": [
            "commercial_claim_allowed=true",
            "non_commercial_count=0",
            "readiness_score=100",
            "validation evidence mapped for all 120 items",
            "commercial_grade gate passed for every item",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(
            json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


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
    item["maturity_gates"] = build_maturity_gates(item)
    item["highest_maturity_stage"] = highest_maturity_stage(item["maturity_gates"])
    item["next_required_gate"] = next_required_gate(item["maturity_gates"])


def build_maturity_gates(item: dict[str, object]) -> dict[str, dict[str, object]]:
    body = str(item.get("body") or "")
    status = str(item.get("status") or "")
    remaining_gap = str(item.get("remaining_gap") or "")
    blockers = list(item.get("commercial_blockers") or [])
    commercial_ready = bool(item.get("commercial_grade_ready"))

    implemented_passed = status_indicates_implementation(status) or (
        status_can_use_current_evidence(status) and has_current_evidence(body)
    )
    usable_passed = implemented_passed and status_indicates_usability(status, body)
    validated_passed = commercial_ready or has_validation_evidence_without_open_validation_gap(body, remaining_gap, blockers)
    commercial_passed = commercial_ready

    return {
        "implemented": maturity_gate(
            implemented_passed,
            "implementation evidence present in backlog status/body" if implemented_passed else "no implementation evidence",
            "" if implemented_passed else "Add code or verified workflow evidence for this item.",
        ),
        "usable": maturity_gate(
            usable_passed,
            "analyst-facing workflow is documented or exposed" if usable_passed else "analyst-facing workflow not proven",
            "" if usable_passed else "Expose the feature through CLI/API/UI/docs and add smoke coverage.",
        ),
        "validated": maturity_gate(
            validated_passed,
            "validation evidence is sufficient for the current claim" if validated_passed else "validation evidence is incomplete",
            "" if validated_passed else validation_remaining_text(remaining_gap, blockers),
        ),
        "commercial_grade": maturity_gate(
            commercial_passed,
            "no commercial parity blockers remain" if commercial_passed else "commercial parity blockers remain",
            "" if commercial_passed else commercial_remaining_text(item),
        ),
    }


def maturity_gate(passed: bool, evidence: str, remaining: str) -> dict[str, object]:
    return {
        "passed": passed,
        "evidence": evidence,
        "remaining": remaining,
    }


def status_indicates_implementation(status: str) -> bool:
    return status.startswith("Done") or status.startswith("Partial")


def status_can_use_current_evidence(status: str) -> bool:
    return not (status.startswith("Planned") or status.startswith("External"))


def has_current_evidence(body: str) -> bool:
    lowered = body.lower()
    return "current:" in lowered or "current rows" in lowered or "current output" in lowered


def status_indicates_usability(status: str, body: str) -> bool:
    lowered = body.lower()
    if status.startswith("Planned") or status == "External":
        return False
    usable_markers = (
        "cli",
        "api",
        "ui",
        "web",
        "collector",
        "rows",
        "output",
        "imports",
        "emits",
        "records",
        "report",
        "package",
        "workflow",
        "current:",
    )
    return any(marker in lowered for marker in usable_markers)


def has_validation_evidence_without_open_validation_gap(
    body: str,
    remaining_gap: str,
    blockers: list[object],
) -> bool:
    lowered_body = body.lower()
    lowered_gap = remaining_gap.lower()
    blocker_text = " ".join(str(item).lower() for item in blockers)
    validation_markers = (
        "known-answer",
        "fixture-backed",
        "fixture",
        "validation package",
        "cross-tool",
        "independent validation",
        "smoke test",
        "release gate",
    )
    open_validation_terms = (
        "remaining",
        "validation required",
        "known-answer",
        "corpus",
        "broad",
        "independent",
        "external",
        "commercial gap",
    )
    has_marker = any(marker in lowered_body for marker in validation_markers)
    open_gap = any(term in lowered_gap for term in open_validation_terms) or "validation" in blocker_text
    return has_marker and not open_gap


def validation_remaining_text(remaining_gap: str, blockers: list[object]) -> str:
    if remaining_gap:
        return remaining_gap
    if blockers:
        return "Resolve validation blockers: " + ", ".join(str(item) for item in blockers)
    return "Attach fixture, known-answer, cross-tool, or independent validation evidence."


def commercial_remaining_text(item: dict[str, object]) -> str:
    gap = str(item.get("remaining_gap") or "").strip()
    if gap:
        return gap
    blockers = list(item.get("commercial_blockers") or [])
    if blockers:
        return "Resolve commercial blockers: " + ", ".join(str(item) for item in blockers)
    return str(item.get("release_gate") or "Commercial parity evidence is incomplete.")


def highest_maturity_stage(gates: object) -> str:
    if not isinstance(gates, dict):
        return "none"
    highest = "none"
    for gate_name in MATURITY_GATE_ORDER:
        gate = gates.get(gate_name)
        if isinstance(gate, dict) and gate.get("passed"):
            highest = gate_name
        else:
            break
    return highest


def next_required_gate(gates: object) -> str:
    if not isinstance(gates, dict):
        return MATURITY_GATE_ORDER[0]
    for gate_name in MATURITY_GATE_ORDER:
        gate = gates.get(gate_name)
        if not (isinstance(gate, dict) and gate.get("passed")):
            return gate_name
    return ""


def build_maturity_gate_summary(items: Iterable[dict[str, object]]) -> dict[str, object]:
    item_list = list(items)
    gate_counts = {
        gate_name: {
            "passed": sum(
                1
                for item in item_list
                if isinstance(item.get("maturity_gates"), dict)
                and isinstance(item["maturity_gates"].get(gate_name), dict)
                and item["maturity_gates"][gate_name].get("passed")
            ),
            "failed": 0,
        }
        for gate_name in MATURITY_GATE_ORDER
    }
    for gate_name, counts in gate_counts.items():
        counts["failed"] = len(item_list) - int(counts["passed"])

    next_gate_counts: dict[str, int] = {}
    for item in item_list:
        gate_name = str(item.get("next_required_gate") or "complete")
        next_gate_counts[gate_name] = next_gate_counts.get(gate_name, 0) + 1

    maturity_stage_counts: dict[str, int] = {}
    for item in item_list:
        stage_name = str(item.get("highest_maturity_stage") or "none")
        maturity_stage_counts[stage_name] = maturity_stage_counts.get(stage_name, 0) + 1

    next_gate_samples: dict[str, list[dict[str, object]]] = {}
    for gate_name in MATURITY_GATE_ORDER:
        gate_items = [item for item in item_list if item.get("next_required_gate") == gate_name]
        next_gate_samples[gate_name] = [
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "remaining": gate_remaining_text(item, gate_name),
            }
            for item in sorted(gate_items, key=priority_sort_key)[:10]
        ]

    return {
        "item_count": len(item_list),
        "gate_counts": gate_counts,
        "next_gate_counts": next_gate_counts,
        "next_gate_samples": next_gate_samples,
        "next_gate_blocker_counts": build_next_gate_blocker_counts(item_list),
        "highest_maturity_stage_counts": maturity_stage_counts,
        "commercial_grade_count": gate_counts["commercial_grade"]["passed"],
        "commercial_grade_missing_count": gate_counts["commercial_grade"]["failed"],
        "rule": "implemented -> usable -> validated -> commercial_grade; do not claim a higher gate until every earlier gate passes.",
    }


COMMERCIAL_BLOCKER_LANES = {
    "native-parser-depth": {
        "patterns": (
            "native",
            "parser",
            "binxml",
            "ese",
            "registry",
            "mft",
            "usn",
            "edb",
            "sqlite",
            "artifact",
            "schema",
        ),
        "internally_actionable": True,
        "next_action": "Implement or deepen parser logic, then lock row-level expected output with fixtures.",
    },
    "known-answer-validation": {
        "patterns": (
            "known-answer",
            "validation",
            "fixture",
            "corpus",
            "cross-tool",
            "false-positive",
            "false-negative",
            "trusted diff",
        ),
        "internally_actionable": True,
        "next_action": "Attach fixture/corpus manifests and pass/fail assertions that map directly to item numbers.",
    },
    "large-scale-performance": {
        "patterns": (
            "large",
            "1tb",
            "10tb",
            "10m",
            "memory",
            "latency",
            "benchmark",
            "stress",
            "pagination",
            "cursor",
            "virtualization",
        ),
        "internally_actionable": True,
        "next_action": "Run bounded synthetic benchmarks now and reserve real-device scale proof as external evidence.",
    },
    "security-legal-assurance": {
        "patterns": (
            "legal",
            "audit",
            "custody",
            "tamper",
            "signed",
            "signing",
            "signature",
            "appsec",
            "sandbox",
            "credential",
            "rbac",
        ),
        "internally_actionable": False,
        "next_action": "Produce internal controls first; commercial claim still needs independent/security signoff evidence.",
    },
    "platform-release-evidence": {
        "patterns": (
            "windows",
            "macos",
            "linux",
            "installer",
            "notarization",
            "authenticode",
            "linux package",
            "platform package",
            "release",
            "auto-update",
            "sbom",
            "ci advisory",
            "scheduled ci",
        ),
        "internally_actionable": False,
        "next_action": "Generate packaging manifests internally; final commercial gate needs signed platform smoke evidence.",
    },
    "external-operator-evidence": {
        "patterns": (
            "external",
            "independent",
            "operator",
            "staffed",
            "sla",
            "training",
            "lab-run",
            "deployment proof",
            "real hardware",
        ),
        "internally_actionable": False,
        "next_action": "Record the blocker explicitly and collect the external run/signoff artifact when available.",
    },
}
COMMERCIAL_BLOCKER_LANE_PRIORITY = (
    "external-operator-evidence",
    "platform-release-evidence",
    "security-legal-assurance",
    "large-scale-performance",
    "native-parser-depth",
    "known-answer-validation",
)


def build_commercial_blocker_matrix(items: Iterable[dict[str, object]]) -> dict[str, object]:
    item_list = [item for item in items if not bool(item.get("commercial_grade_ready"))]
    rows = [commercial_blocker_row(item) for item in sorted(item_list, key=priority_sort_key)]
    lane_counts: dict[str, int] = {}
    actionability_counts = {"internal": 0, "external_or_trusted_evidence": 0}
    next_gate_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for row in rows:
        lanes = row.get("blocker_lanes") if isinstance(row.get("blocker_lanes"), list) else []
        for lane_value in lanes or [row.get("blocker_lane") or "unknown"]:
            lane = str(lane_value or "unknown")
            lane_counts[lane] = lane_counts.get(lane, 0) + 1
        if row.get("internally_actionable"):
            actionability_counts["internal"] += 1
        if row.get("external_or_trusted_evidence_required"):
            actionability_counts["external_or_trusted_evidence"] += 1
        next_gate = str(row.get("next_required_gate") or "complete")
        next_gate_counts[next_gate] = next_gate_counts.get(next_gate, 0) + 1
        category = str(row.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
        severity = str(row.get("severity") or "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "version": "commercial-blocker-matrix-v1",
        "item_count": len(rows),
        "commercial_claim_allowed": len(rows) == 0,
        "lane_counts": lane_counts,
        "actionability_counts": actionability_counts,
        "next_gate_counts": next_gate_counts,
        "category_counts": category_counts,
        "severity_counts": severity_counts,
        "internally_actionable_count": actionability_counts["internal"],
        "external_or_trusted_evidence_count": actionability_counts["external_or_trusted_evidence"],
        "top_internal_items": [row for row in rows if row.get("internally_actionable")][:10],
        "top_external_evidence_items": [row for row in rows if not row.get("internally_actionable")][:10],
        "rows": rows,
        "rule": (
            "Rows classify why commercial_grade is blocked; internally_actionable=true does not mean commercial-ready, "
            "only that the next narrowing step can be produced inside the repo before external evidence is collected."
        ),
    }


def build_blocker_separation_profile(blocker_matrix: Mapping[str, object]) -> dict[str, object]:
    rows = [row for row in blocker_matrix.get("rows", []) if isinstance(row, Mapping)]
    internal_only = [
        row for row in rows
        if bool(row.get("internally_actionable")) and not bool(row.get("external_or_trusted_evidence_required"))
    ]
    internal_then_external = [
        row for row in rows
        if bool(row.get("internally_actionable")) and bool(row.get("external_or_trusted_evidence_required"))
    ]
    external_only = [
        row for row in rows
        if not bool(row.get("internally_actionable")) and bool(row.get("external_or_trusted_evidence_required"))
    ]
    next_internal_batch = [
        blocker_separation_work_item(row, lane="internal-implementation")
        for row in (internal_only + internal_then_external)[:5]
    ]
    next_external_evidence_batch = [
        blocker_separation_work_item(row, lane="external-evidence")
        for row in (external_only + internal_then_external)[:5]
    ]
    lane_action_map = {
        lane: {
            "internally_actionable": bool(profile.get("internally_actionable")),
            "next_action": str(profile.get("next_action") or ""),
        }
        for lane, profile in COMMERCIAL_BLOCKER_LANES.items()
    }
    return {
        "version": "blocker-separation-profile-v1",
        "immediate_queue_item": 10,
        "status": "separated-internal-and-external-blockers",
        "internal_only_count": len(internal_only),
        "internal_then_external_count": len(internal_then_external),
        "external_only_count": len(external_only),
        "summary": {
            "internal_work_available": len(internal_only) + len(internal_then_external),
            "external_or_trusted_evidence_required": len(external_only) + len(internal_then_external),
            "commercial_claim_allowed": bool(blocker_matrix.get("commercial_claim_allowed")),
        },
        "lane_action_map": lane_action_map,
        "next_internal_batch": next_internal_batch,
        "next_external_evidence_batch": next_external_evidence_batch,
        "operator_rule": (
            "Do internal implementation/fixture/reporting work first, but keep commercial_grade=false until "
            "the paired trusted-tool, independent-review, signed-platform, large-hardware, or staffed-support evidence is attached."
        ),
    }


def build_blocker_execution_package(
    blocker_matrix: Mapping[str, object],
    blocker_separation_profile: Mapping[str, object],
    *,
    validation_evidence_summary: Mapping[str, object],
    mac_first_evidence_summary: Mapping[str, object],
    batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    """Create an operator-friendly next-action package without satisfying gates."""

    rows = [row for row in blocker_matrix.get("rows", []) if isinstance(row, Mapping)]
    internal_rows = [
        blocker_execution_row(row, lane="internal")
        for row in rows
        if bool(row.get("internally_actionable"))
    ][: max(1, batch_size)]
    external_rows = [
        blocker_execution_row(row, lane="external")
        for row in rows
        if bool(row.get("external_or_trusted_evidence_required"))
    ][: max(1, batch_size)]
    internal_item_numbers = [int(row["number"]) for row in internal_rows if int(row.get("number") or 0)]
    external_item_numbers = [int(row["number"]) for row in external_rows if int(row.get("number") or 0)]
    mapped_validation_items = validation_evidence_summary.get("mapped_item_numbers")
    if not isinstance(mapped_validation_items, list):
        mapped_validation_items = []
    supported_mac_items = mac_first_evidence_summary.get("supports_backlog_items")
    if not isinstance(supported_mac_items, list):
        supported_mac_items = []
    package: dict[str, object] = {
        "profile_version": "commercial-blocker-execution-package-v1",
        "status": "commercial-claim-blocked" if rows else "commercial-ready",
        "commercial_claim_allowed": not bool(rows),
        "batch_size": max(1, batch_size),
        "internal_batch": internal_rows,
        "external_evidence_batch": external_rows,
        "internal_item_numbers": internal_item_numbers,
        "external_evidence_item_numbers": external_item_numbers,
        "validation_evidence_attached_item_count": len(mapped_validation_items),
        "mac_first_supported_item_count": len(supported_mac_items),
        "recommended_commands": blocker_execution_commands(internal_item_numbers),
        "operator_evidence_checklist": [
            "Attach known-answer or trusted-tool diff JSON before moving an item to validated.",
            "Attach provider/export/API diff evidence for cloud, mailbox, messenger, and AI service outputs.",
            "Attach signed platform smoke, notarization, and installer evidence before release claims.",
            "Attach large hardware benchmark logs before 1TB-10TB or million-record claims.",
            "Rerun commercial-readiness after each evidence batch and keep blocker rows non-destructive.",
        ],
        "separation_counts": blocker_separation_profile.get("summary", {}),
        "claim_rule": (
            "This package is an execution checklist. It does not pass validation or commercial_grade gates; "
            "only attached validation packages and cleared blockers can do that."
        ),
    }
    package["package_hash"] = sha256_json({key: value for key, value in package.items() if key != "package_hash"})
    return package


def blocker_execution_row(row: Mapping[str, object], *, lane: str) -> dict[str, object]:
    number = int(row.get("number") or 0)
    lanes = row.get("blocker_lanes") if isinstance(row.get("blocker_lanes"), list) else []
    output = {
        "number": number,
        "title": str(row.get("title") or ""),
        "lane": lane,
        "category": str(row.get("category") or ""),
        "severity": str(row.get("severity") or ""),
        "next_required_gate": str(row.get("next_required_gate") or ""),
        "blocker_lanes": [str(value) for value in lanes],
        "action": str(row.get("next_internal_or_evidence_action") or ""),
        "requires_external_or_trusted_evidence": bool(row.get("external_or_trusted_evidence_required")),
        "blocker_summary": str(row.get("blocker_summary") or ""),
        "acceptance_evidence": blocker_acceptance_evidence(row),
        "review_status": "todo",
    }
    runner_hint = trusted_diff_runner_hint(number)
    if runner_hint:
        output["trusted_diff_runner_hint"] = runner_hint
    return output


def blocker_acceptance_evidence(row: Mapping[str, object]) -> list[str]:
    raw_lanes = row.get("blocker_lanes", [])
    lanes = {str(value) for value in raw_lanes if value} if isinstance(raw_lanes, list) else set()
    evidence = [
        "RapidTriage output JSON with source path/hash/parser version",
        "commercial-readiness JSON after the change",
    ]
    if "known-answer-validation" in lanes:
        evidence.append("known-answer or trusted-tool diff manifest mapped to this item number")
    if "native-parser-depth" in lanes:
        evidence.append("parser fixture with expected rows, edge cases, and limitation text")
    if "large-scale-performance" in lanes:
        evidence.append("benchmark JSON with record count, p95 latency, memory profile, and hardware notes")
    if "security-legal-assurance" in lanes:
        evidence.append("audit/legal/security review artifact with reviewer and limitation signoff")
    if "platform-release-evidence" in lanes:
        evidence.append("signed/notarized/package smoke output with artifact SHA256")
    if "external-operator-evidence" in lanes:
        evidence.append("external lab/operator evidence file with provenance and reviewer signoff")
    return evidence


def trusted_diff_runner_hint(item_number: int) -> dict[str, object]:
    hint = TRUSTED_DIFF_RUNNER_HINTS_BY_ITEM.get(item_number)
    if not hint:
        return {}
    return {
        "profile_version": "trusted-diff-runner-hint-v1",
        "artifact_family": hint["artifact_family"],
        "validation_diff_runner_group_item": hint["runner_group_item"],
        "trusted_tools": list(hint["trusted_tools"]),
        "rapid_output_hint": hint["rapid_output_hint"],
        "cross_tool_template": hint["cross_tool_template"],
        "preflight_command": "rapidtriage validation-diff-runners --json",
        "claim_rule": "Runner hints prepare validation only; they do not pass trusted-diff gates until outputs and signoff are attached.",
    }


def blocker_execution_commands(item_numbers: list[int]) -> list[str]:
    commands = [
        "rapidtriage commercial-readiness --output-dir ./commercial-readiness --json",
        "rapidtriage validation-diff-runners --output ./qc/validation-diff-runners.json --json",
    ]
    if item_numbers:
        item_range = ",".join(str(number) for number in item_numbers)
        commands.append(
            "rapidtriage commercial-readiness "
            f"--template-items {item_range} "
            "--write-known-answer-template-dir ./known-answer-next-batch "
            "--output-dir ./commercial-readiness --json"
        )
    commands.append(
        "rapidtriage commercial-readiness "
        "--validation-package ./validation/rapidtriage-validation-package.json "
        "--mac-first-evidence ./qc "
        "--output-dir ./commercial-readiness --json"
    )
    return commands


def build_platform_uplift_actionability(
    items: Iterable[dict[str, object]],
    *,
    readiness_score: int,
    commercial_claim_allowed: bool,
) -> dict[str, object]:
    """Separate 90->100 work into Mac-local prep, Windows evidence, and external authority."""
    blocked_rows = [
        commercial_blocker_row(item)
        for item in sorted(items, key=priority_sort_key)
        if not bool(item.get("commercial_grade_ready"))
    ]
    windows_rows = [
        row for row in blocked_rows
        if row_requires_windows_or_windows_evidence(row)
    ]
    external_rows = [
        row for row in blocked_rows
        if bool(row.get("external_or_trusted_evidence_required"))
    ]
    mac_prep_rows = [
        row for row in blocked_rows
        if row_allows_mac_local_preparation(row)
    ]
    mac_commands = [
        {
            "id": "macos-live-smoke",
            "command": "rapidtriage macos-live-smoke --output-dir ./qc/macos-live --overwrite --json",
            "purpose": "Generate redacted local macOS smoke, small triage benchmark, SQLite FTS benchmark, and validation-tool availability evidence.",
            "commercial_grade_effect": "preparatory-evidence-only",
        },
        {
            "id": "validation-diff-runners",
            "command": "rapidtriage validation-diff-runners --output ./qc/runner-matrix.json --probe-versions --json",
            "purpose": "Record trusted-tool runner matrix and version probe readiness where tools are installed.",
            "commercial_grade_effect": "preparatory-evidence-only",
        },
        {
            "id": "sample-workflow",
            "command": "rapidtriage sample --output-dir ./qc/sample --run --overwrite --json",
            "purpose": "Exercise end-to-end ingest/search/artifact/report plumbing with a synthetic case.",
            "commercial_grade_effect": "internal-smoke-only",
        },
        {
            "id": "submission-bundle",
            "command": "rapidtriage bundle ./case.json --allowed-root ./qc/sample --output-dir ./qc/submission-bundle --include-all --json",
            "purpose": "Generate reviewer, report, court-exhibit, selected-evidence, and tamper-bundle artifacts from reviewed case bookmarks.",
            "commercial_grade_effect": "workflow-proof-only-unless-real-case-and-reviewer-signoff",
        },
        {
            "id": "final-qc-report",
            "command": "rapidtriage final-qc-report --validation-package ./validation.json --runner-matrix ./qc/runner-matrix.json --chain-of-custody ./custody.json --audit-bundle ./audit.json --exhibit-bundle ./exhibit.zip --performance-run ./benchmark.json --browser-trace ./trace.json --reviewer-signoff ./review.md --output ./qc/final-qc.json --json",
            "purpose": "Hash QC evidence into one wrapper and make missing operator-owned evidence explicit.",
            "commercial_grade_effect": "qc-wrapper-only",
        },
        {
            "id": "commercial-readiness",
            "command": "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --output-dir ./qc/commercial-readiness --json",
            "purpose": "Recalculate the readiness gate after every internal or external evidence batch.",
            "commercial_grade_effect": "score-report-only",
        },
    ]
    return {
        "profile_version": "platform-uplift-actionability-v1",
        "readiness_score": readiness_score,
        "target_score": 100,
        "remaining_score_points": max(100 - readiness_score, 0),
        "commercial_claim_allowed": commercial_claim_allowed,
        "can_reach_100_on_mac_alone": False,
        "mac_can_generate_preparatory_evidence": True,
        "reason_mac_alone_is_not_enough": (
            "The remaining score is the commercial-grade band. It requires real source evidence, "
            "trusted-tool diffs, large-corpus/hardware proof, independent reviewer signoff, and platform release evidence; "
            "Mac-local smoke outputs can prepare and verify workflow plumbing but cannot replace those operator-owned artifacts."
        ),
        "counts": {
            "blocked_item_count": len(blocked_rows),
            "mac_preparable_item_count": len(mac_prep_rows),
            "windows_or_windows_evidence_item_count": len(windows_rows),
            "external_or_trusted_evidence_item_count": len(external_rows),
        },
        "mac_executable_commands": mac_commands,
        "mac_preparable_samples": [platform_actionability_row(row) for row in mac_prep_rows[:10]],
        "windows_or_windows_evidence_samples": [platform_actionability_row(row) for row in windows_rows[:10]],
        "external_or_trusted_evidence_samples": [platform_actionability_row(row) for row in external_rows[:10]],
        "operator_rule": (
            "Run Mac-local QC whenever possible, but do not mark commercial_grade true until the Windows/E01/trusted-tool/large-case/"
            "independent-review evidence is attached and passes."
        ),
    }


def row_allows_mac_local_preparation(row: Mapping[str, object]) -> bool:
    lanes = {str(lane) for lane in row.get("blocker_lanes", []) if lane}
    category = str(row.get("category") or "")
    return bool(
        lanes.intersection(
            {
                "known-answer-validation",
                "large-scale-performance",
                "security-legal-assurance",
                "platform-release-evidence",
                "external-operator-evidence",
            }
        )
        or category in {"search-analysis-ux", "performance-large-scale", "validation-legal", "deployment-operations"}
    )


def row_requires_windows_or_windows_evidence(row: Mapping[str, object]) -> bool:
    number = int(row.get("number") or 0)
    title = str(row.get("title") or "").lower()
    category = str(row.get("category") or "")
    windows_terms = (
        "evtx",
        "registry",
        "sam/security/system",
        "amcache",
        "shimcache",
        "bam/dam",
        "srum",
        "windows.edb",
        "mft",
        "usn",
        "prefetch",
        "lnk",
        "wer/defender/firewall/task/wmi",
        "e01",
        "ex01",
        "windows installer",
    )
    return bool(
        (category == "core-forensics" and number <= 25)
        or number == 101
        or any(term in title for term in windows_terms)
    )


def platform_actionability_row(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "number": int(row.get("number") or 0),
        "title": str(row.get("title") or ""),
        "category": str(row.get("category") or ""),
        "severity": str(row.get("severity") or ""),
        "blocker_lanes": list(row.get("blocker_lanes") or []),
        "next_action": str(row.get("next_internal_or_evidence_action") or ""),
        "commercial_claim_allowed_after_action": False,
    }


def blocker_separation_work_item(row: Mapping[str, object], *, lane: str) -> dict[str, object]:
    lanes = row.get("blocker_lanes") if isinstance(row.get("blocker_lanes"), list) else []
    primary_lane = str(row.get("blocker_lane") or (lanes[0] if lanes else "known-answer-validation"))
    profile = COMMERCIAL_BLOCKER_LANES.get(primary_lane, {})
    return {
        "number": int(row.get("number") or 0),
        "title": str(row.get("title") or ""),
        "category": str(row.get("category") or ""),
        "severity": str(row.get("severity") or ""),
        "work_lane": lane,
        "blocker_lane": primary_lane,
        "blocker_lanes": list(lanes),
        "next_required_gate": str(row.get("next_required_gate") or ""),
        "next_action": str(row.get("next_internal_or_evidence_action") or profile.get("next_action") or ""),
        "commercial_claim_allowed_after_this_action": False,
        "reason": (
            "This narrows or proves the blocker, but final commercial-grade status still depends on every maturity gate."
        ),
    }


def commercial_blocker_row(item: dict[str, object]) -> dict[str, object]:
    blocker_text = commercial_blocker_text(item)
    lanes = classify_commercial_blocker_lanes(blocker_text)
    primary_lane = lanes[0] if lanes else "known-answer-validation"
    lane_profile = COMMERCIAL_BLOCKER_LANES.get(primary_lane, {})
    internally_actionable = any(
        bool(COMMERCIAL_BLOCKER_LANES.get(lane, {}).get("internally_actionable"))
        for lane in lanes
    )
    external_required = any(
        not bool(COMMERCIAL_BLOCKER_LANES.get(lane, {}).get("internally_actionable"))
        for lane in lanes
    )
    return {
        "number": int(item.get("number") or 0),
        "title": str(item.get("title") or ""),
        "category": str(item.get("category") or ""),
        "severity": str(item.get("severity") or ""),
        "status": str(item.get("status") or ""),
        "highest_maturity_stage": str(item.get("highest_maturity_stage") or "none"),
        "next_required_gate": str(item.get("next_required_gate") or ""),
        "blocker_lane": primary_lane,
        "blocker_lanes": lanes,
        "internally_actionable": internally_actionable,
        "external_or_trusted_evidence_required": external_required,
        "blocker_summary": blocker_text[:360],
        "next_internal_or_evidence_action": str(lane_profile.get("next_action") or "Define measurable evidence and rerun commercial-readiness."),
        "release_gate": str(item.get("release_gate") or ""),
        "blocker_ids": [normalize_blocker_key(str(blocker)) for blocker in item.get("commercial_blockers", [])],
    }


def commercial_blocker_text(item: dict[str, object]) -> str:
    parts = [
        str(item.get("title") or ""),
        str(item.get("remaining_gap") or ""),
        str(item.get("release_gate") or ""),
        gate_remaining_text(item, str(item.get("next_required_gate") or "commercial_grade")),
        " ".join(str(blocker) for blocker in item.get("commercial_blockers", [])),
    ]
    return " | ".join(part for part in parts if part).strip()


def classify_commercial_blocker_lane(text: str) -> str:
    lanes = classify_commercial_blocker_lanes(text)
    return lanes[0] if lanes else "known-answer-validation"


def classify_commercial_blocker_lanes(text: str) -> list[str]:
    lowered = text.lower()
    lanes: list[str] = []
    for lane in COMMERCIAL_BLOCKER_LANE_PRIORITY:
        profile = COMMERCIAL_BLOCKER_LANES[lane]
        patterns = profile.get("patterns")
        if isinstance(patterns, tuple) and any(pattern in lowered for pattern in patterns):
            lanes.append(lane)
    return lanes or ["known-answer-validation"]


def build_functional_defensibility_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = FUNCTIONAL_DEFENSIBILITY_PROGRESS_START,
    end: int = FUNCTIONAL_DEFENSIBILITY_PROGRESS_END,
    batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    """Summarize the analyst-facing #42-#70 uplift without overstating commercial parity."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    safe_batch_size = max(1, batch_size)
    gate_counts = functional_progress_gate_counts(item_list)
    next_gate_counts: dict[str, int] = {}
    stage_counts: dict[str, int] = {}
    for item in item_list:
        next_gate = str(item.get("next_required_gate") or "complete")
        stage = str(item.get("highest_maturity_stage") or "none")
        next_gate_counts[next_gate] = next_gate_counts.get(next_gate, 0) + 1
        stage_counts[stage] = stage_counts.get(stage, 0) + 1

    batches: list[dict[str, object]] = []
    for index in range(0, len(item_list), safe_batch_size):
        batch_items = item_list[index : index + safe_batch_size]
        batch_gate_counts = functional_progress_gate_counts(batch_items)
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "batch_id": (
                    f"{FUNCTIONAL_DEFENSIBILITY_PROGRESS_BATCH_ID}-"
                    f"{len(batches) + 1:02d}"
                ),
                "item_numbers": [int(item.get("number") or 0) for item in batch_items],
                "item_count": len(batch_items),
                "categories": sorted({str(item.get("category") or "unknown") for item in batch_items}),
                "status": functional_progress_status(batch_gate_counts, len(batch_items)),
                "gate_counts": batch_gate_counts,
                "next_gate_counts": functional_next_gate_counts(batch_items),
                "items": [functional_progress_item_digest(item) for item in batch_items],
                "required_outputs_before_commercial_claim": [
                    "known-answer-or-cross-tool-validation-evidence",
                    "false-positive-and-false-negative-limitations",
                    "source-hash-parser-version-provenance",
                    "operator-review-signoff",
                    "commercial-readiness-recalculation",
                ],
            }
        )

    next_validation_items = [
        functional_progress_item_digest(item)
        for item in item_list
        if item.get("next_required_gate") in {"validated", "commercial_grade"}
    ][:10]
    return {
        "version": "functional-defensibility-progress-v1",
        "batch_id": FUNCTIONAL_DEFENSIBILITY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "batch_size": safe_batch_size,
        "batch_count": len(batches),
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "commercial_claim_rule": (
            "This section tracks #42-#70 implementation/usability progress only; "
            "commercial-grade claims still require validated and commercial_grade gates for every item."
        ),
        "gate_counts": gate_counts,
        "next_gate_counts": next_gate_counts,
        "highest_maturity_stage_counts": stage_counts,
        "next_validation_items": next_validation_items,
        "batches": batches,
    }


def functional_progress_gate_counts(items: Iterable[dict[str, object]]) -> dict[str, int]:
    item_list = list(items)
    return {
        gate_name: sum(1 for item in item_list if maturity_gate_passed(item, gate_name))
        for gate_name in MATURITY_GATE_ORDER
    }


def maturity_gate_passed(item: dict[str, object], gate_name: str) -> bool:
    gates = item.get("maturity_gates")
    if not isinstance(gates, dict):
        return False
    gate = gates.get(gate_name)
    return bool(isinstance(gate, dict) and gate.get("passed"))


def functional_next_gate_counts(items: Iterable[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        gate_name = str(item.get("next_required_gate") or "complete")
        counts[gate_name] = counts.get(gate_name, 0) + 1
    return counts


def functional_progress_status(gate_counts: dict[str, int], item_count: int) -> str:
    if item_count == 0:
        return "empty"
    if gate_counts.get("commercial_grade", 0) == item_count:
        return "commercial-grade"
    if gate_counts.get("validated", 0) == item_count:
        return "validated-not-commercial"
    if gate_counts.get("usable", 0) == item_count:
        return "usable-internal-validation-required"
    if gate_counts.get("implemented", 0) == item_count:
        return "implemented-usability-required"
    return "implementation-required"


def functional_progress_item_digest(item: dict[str, object]) -> dict[str, object]:
    next_gate = str(item.get("next_required_gate") or "")
    return {
        "number": int(item.get("number") or 0),
        "title": str(item.get("title") or ""),
        "category": str(item.get("category") or ""),
        "severity": str(item.get("severity") or ""),
        "status": str(item.get("status") or ""),
        "highest_maturity_stage": str(item.get("highest_maturity_stage") or "none"),
        "next_required_gate": next_gate,
        "next_required_action": gate_remaining_text(item, next_gate or "commercial_grade"),
        "commercial_grade_ready": bool(item.get("commercial_grade_ready")),
    }


def build_review_scale_resilience_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = REVIEW_SCALE_PROGRESS_START,
    end: int = REVIEW_SCALE_PROGRESS_END,
) -> dict[str, object]:
    """Track #76-#80 review-scale controls across file, API, UI, and job surfaces."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "review-scale-resilience-progress-v1",
        "batch_id": REVIEW_SCALE_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "surface_map": review_scale_surface_map(),
        "items": [review_scale_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-hash-cache-manifest",
            "trusted-duplicate-file-manifest",
            "trusted-pagination-cursor-manifest",
            "trusted-ui-virtualization-browser-e2e-manifest",
            "trusted-cancellation-retry-transition-manifest",
            "large-case replay proving stable latency, bounded memory, and no hidden dropped rows",
        ],
        "reportability_rule": (
            "#76-#80 controls reduce review overload, but they must not be advertised as commercial-scale "
            "complete until trusted manifests and large-case replay evidence are attached."
        ),
    }


def review_scale_surface_map() -> dict[str, dict[str, object]]:
    return {
        "76": {
            "component": "hash-cache",
            "primary_outputs": ["files.hash_cache_assessment", "api metadata hash assessment"],
            "trusted_manifest": "hash-cache-manifest",
        },
        "77": {
            "component": "duplicate-detection",
            "primary_outputs": [
                "files.duplicate_detection_assessment",
                "duplicate_content_groups",
                "duplicate_content_manifest",
            ],
            "trusted_manifest": "duplicate-file-manifest",
        },
        "78": {
            "component": "cursor-api",
            "primary_outputs": [
                "api pagination.cursor",
                "next_cursor",
                "previous_cursor",
                "pagination-cursor-manifest-v1",
                "page_window_id",
            ],
            "trusted_manifest": "pagination-cursor-manifest",
        },
        "79": {
            "component": "ui-virtualization",
            "primary_outputs": [
                "api pagination.ui_virtualization",
                "ui-virtualization-manifest-v1",
                "ui-virtualization-report-grade-validation-plan-v1",
                "web bounded row rendering notice",
                "web virtual row-window controls",
            ],
            "trusted_manifest": "ui-virtualization-manifest",
        },
        "80": {
            "component": "cancel-retry",
            "primary_outputs": [
                "run job cancellation_retry_assessment",
                "cancellation-retry-manifest-v1",
                "cancellation-retry-report-grade-validation-plan-v1",
                "retry_lineage_profile",
                "partial_output_policy",
                "job step operational_gap_ids",
            ],
            "trusted_manifest": "cancellation-retry-transition-manifest",
        },
    }


def review_scale_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    surface = review_scale_surface_map().get(str(digest["number"]), {})
    digest["component"] = surface.get("component", "")
    digest["primary_outputs"] = surface.get("primary_outputs", [])
    digest["trusted_manifest_required"] = surface.get("trusted_manifest", "")
    return digest


def build_validation_spine_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = VALIDATION_SPINE_PROGRESS_START,
    end: int = VALIDATION_SPINE_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track the #81-#85 evidence spine that turns implemented parsers into defensible claims."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "validation-spine-progress-v1",
        "batch_id": VALIDATION_SPINE_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": validation_spine_evidence_chain(),
        "items": [validation_spine_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "known-answer-manifest-with-existing-evidence-paths",
            "fixture-corpus-manifest",
            "fp-fn-risk-register",
            "independent-validation-signoff",
            "validation-package-hash-manifest",
            "commercial-readiness-rerun-showing-commercial-grade-gates-with-no-blockers",
        ],
        "reportability_rule": (
            "#81-#85 are validation infrastructure controls. They can promote internal validated gates, "
            "but commercial-grade claims still require matching external/trusted evidence and no remaining item blockers."
        ),
    }


def validation_spine_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 81,
            "component": "known-answer-validation",
            "produces": "known_answer_validation.datasets",
            "primary_outputs": [
                "known_answer_validation.datasets",
                "known_answer_validation.manifest_digest",
                "known_answer_validation.known_answer_report_grade_validation_plan_hash",
                "datasets[].dataset_hash",
                "datasets[].evidence_files[].sha256",
            ],
            "trusted_diff": "trusted-known-answer-manifest-diff",
        },
        {
            "item_number": 82,
            "component": "parser-fixture-corpus",
            "produces": "parser_fixture_corpus.areas",
            "primary_outputs": [
                "parser_fixture_corpus.areas",
                "parser_fixture_corpus.fixture_corpus_digest",
                "parser_fixture_corpus.fixture_corpus_report_grade_validation_plan_hash",
                "areas[].area_manifest_hash",
                "areas[].fixture_file_manifest[].sha256",
                "areas[].test_file_manifest[].sha256",
            ],
            "trusted_diff": "trusted-fixture-corpus-manifest-diff",
        },
        {
            "item_number": 83,
            "component": "fp-fn-risk-register",
            "produces": "parser_false_positive_false_negative_notes",
            "primary_outputs": [
                "parser_false_positive_false_negative_notes[].risk_note_hash",
                "parser_false_positive_false_negative_notes[].fp_fn_report_grade_validation_plan_hash",
                "parser_false_positive_false_negative_notes[].minimum_quantification_fields",
                "parser_false_positive_false_negative_notes[].reportability_boundary",
                "parser_fp_fn_risk_register_profile.register_digest",
            ],
            "trusted_diff": "trusted-fp-fn-risk-register-diff",
        },
        {
            "item_number": 84,
            "component": "independent-validation-report",
            "produces": "independent_validation_report.sha256",
            "primary_outputs": [
                "independent_validation_report.sha256",
                "independent_validation_report.independent_validation_manifest.report_manifest_hash",
                "independent_validation_report.independent_validation_report_grade_validation_plan_hash",
                "independent_validation_report.minimum_section_presence",
                "independent_validation_report.signoff_slots",
            ],
            "trusted_diff": "trusted-independent-validation-signoff-diff",
        },
        {
            "item_number": 85,
            "component": "validation-package",
            "produces": "rapidtriage-validation-artifacts.json",
            "primary_outputs": [
                "rapidtriage-validation-artifacts.json",
                "validation_package_manifest.package_manifest_hash",
                "validation_package_assessment.validation_package_report_grade_validation_plan_hash",
                "validation_package_manifest.artifact_hashes",
                "validation_package_manifest.reproduction_commands",
            ],
            "trusted_diff": "trusted-validation-package-manifest-diff",
        },
    ]


def validation_spine_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in validation_spine_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_forensic_integrity_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = FORENSIC_INTEGRITY_PROGRESS_START,
    end: int = FORENSIC_INTEGRITY_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #86-#90 custody, hash, audit, reproducibility, and provenance controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "forensic-integrity-progress-v1",
        "batch_id": FORENSIC_INTEGRITY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": forensic_integrity_evidence_chain(),
        "items": [forensic_integrity_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-custody-event-manifest",
            "trusted-acquisition-hash-manifest",
            "trusted-audit-hash-chain-manifest",
            "trusted-report-replay-manifest",
            "trusted-report-provenance-manifest",
            "case-export-json-bundled-with-citation-index-and-source-hashes",
        ],
        "reportability_rule": (
            "#86-#90 make single-case review exports more defensible, but commercial/court-grade claims "
            "still require trusted custody, acquisition hash, audit, replay, and provenance manifests."
        ),
    }


def forensic_integrity_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 86,
            "component": "chain-of-custody",
            "produces": "case-db-report-export.custody_workflow",
            "primary_outputs": [
                "case-db-report-export.custody_workflow",
                "custody_workflow.custody_event_manifest.manifest_hash",
                "custody_workflow.custody_report_grade_validation_plan_hash",
                "custody_workflow.evidence_sources[].custody_row_hash",
                "custody_workflow.custody_events[].custody_row_hash",
            ],
            "trusted_diff": "trusted-custody-event-manifest-diff",
        },
        {
            "item_number": 87,
            "component": "acquisition-hash-workflow",
            "produces": "case-db-report-export.acquisition_hash_workflow",
            "primary_outputs": [
                "case-db-report-export.acquisition_hash_workflow",
                "acquisition_hash_workflow.acquisition_hash_manifest.manifest_hash",
                "acquisition_hash_workflow.acquisition_hash_report_grade_validation_plan_hash",
                "acquisition_hash_workflow.hashes[].acquisition_hash_row_hash",
                "acquisition_hash_workflow.acquisition_hash_manifest.algorithm_coverage",
            ],
            "trusted_diff": "trusted-acquisition-hash-manifest-diff",
        },
        {
            "item_number": 88,
            "component": "immutable-audit-log",
            "produces": "case-db-report-export.audit_integrity",
            "primary_outputs": [
                "case-db-report-export.audit_integrity",
                "audit_integrity.audit_hash_chain_manifest.manifest_hash",
                "audit_integrity.immutable_audit_report_grade_validation_plan_hash",
                "audit_integrity.events[].previous_event_hash",
                "audit_integrity.events[].event_hash",
                "audit_integrity.summary.head_hash",
            ],
            "trusted_diff": "trusted-audit-hash-chain-manifest-diff",
        },
        {
            "item_number": 89,
            "component": "report-reproducibility",
            "produces": "case-db-report-export.reproducibility",
            "primary_outputs": [
                "case-db-report-export.reproducibility",
                "reproducibility.stable_payload_sha256",
                "reproducibility.report_replay_manifest.manifest_hash",
                "reproducibility.report_reproducibility_report_grade_validation_plan_hash",
                "reproducibility.report_replay_manifest.item_row_hashes",
                "reproducibility.report_replay_manifest.citation_row_hashes",
            ],
            "trusted_diff": "trusted-report-replay-manifest-diff",
        },
        {
            "item_number": 90,
            "component": "report-item-provenance",
            "produces": "case-db-report-export.items[].provenance",
            "primary_outputs": [
                "case-db-report-export.items[].provenance",
                "items[].provenance.provenance_row_hash",
                "items[].provenance.provenance_manifest.manifest_hash",
                "items[].provenance.source_provenance_report_grade_validation_plan_hash",
                "items[].provenance.source_path",
                "items[].provenance.parser_version",
                "items[].provenance.record_offset",
            ],
            "trusted_diff": "trusted-report-provenance-manifest-diff",
        },
    ]


def forensic_integrity_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in forensic_integrity_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_report_quality_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = REPORT_QUALITY_PROGRESS_START,
    end: int = REPORT_QUALITY_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #91-#95 reportability, warning, legal, exhibit, and tool-version controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "report-quality-progress-v1",
        "batch_id": REPORT_QUALITY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": report_quality_evidence_chain(),
        "items": [report_quality_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-parser-confidence-calibration-manifest",
            "trusted-validation-warning-checklist",
            "jurisdiction-approved-legal-limitation-wording",
            "signed-or-notarized-court-exhibit-manifest",
            "trusted-external-tool-transcripts-and-version-log",
        ],
        "reportability_rule": (
            "#91-#95 make report exports safer to review, cite, and package, but commercial/court-grade "
            "claims still require trusted calibration, warning, legal, exhibit, and external-tool evidence."
        ),
    }


def report_quality_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 91,
            "component": "parser-confidence-scoring",
            "produces": "case-db-report-export.items[].validation_assessment.parser_confidence",
            "primary_outputs": [
                "case-db-report-export.items[].validation_assessment",
                "items[].validation_assessment.parser_confidence",
                "items[].validation_assessment.confidence_band",
                "items[].validation_assessment.reportability_score",
                "items[].validation_assessment.parser_confidence_calibration_manifest.manifest_hash",
                "items[].validation_assessment.parser_confidence_report_grade_validation_plan_hash",
            ],
            "trusted_diff": "trusted-parser-confidence-calibration-diff",
        },
        {
            "item_number": 92,
            "component": "validation-warning-ux",
            "produces": "case-db-report-export.items[].validation_assessment.warnings",
            "primary_outputs": [
                "case-db-report-export.items[].validation_assessment.warnings",
                "items[].validation_assessment.warning_details",
                "items[].validation_assessment.warning_ux_badges",
                "items[].validation_assessment.validation_warning_checklist_manifest.manifest_hash",
                "items[].validation_assessment.validation_warning_report_grade_validation_plan_hash",
                "case-db-report-export.summary.validation_warning_count",
            ],
            "trusted_diff": "trusted-validation-warning-checklist-diff",
        },
        {
            "item_number": 93,
            "component": "legal-limitation-statements",
            "produces": "case-db-report-export.items[].legal_limitations_assessment",
            "primary_outputs": [
                "case-db-report-export.items[].legal_limitations",
                "items[].legal_limitations_assessment.limitation_details",
                "items[].legal_limitations_assessment.limitation_category_counts",
                "items[].legal_limitations_assessment.legal_limitation_manifest.manifest_hash",
                "items[].legal_limitations_assessment.legal_limitation_report_grade_validation_plan_hash",
            ],
            "trusted_diff": "trusted-legal-limitation-wording-diff",
        },
        {
            "item_number": 94,
            "component": "court-exhibit-package",
            "produces": "reviewer-bundle.exhibit_index",
            "primary_outputs": [
                "reviewer-bundle.rapidtriage-court-exhibit-index.json",
                "court_exhibit_index.exhibits[].exhibit_id",
                "court_exhibit_index.exhibits[].exhibit_row_hash",
                "court_exhibit_index.court_exhibit_manifest.selected_evidence_manifest_hash",
                "court_exhibit_index.court_exhibit_manifest.manifest_hash",
                "court_exhibit_index.court_exhibit_report_grade_validation_plan_hash",
                "court_exhibit_index.signing_slots.external_signature",
            ],
            "trusted_diff": "trusted-court-exhibit-manifest-diff",
        },
        {
            "item_number": 95,
            "component": "external-tool-version-capture",
            "produces": "validation-package.external_tool_versions",
            "primary_outputs": [
                "validation-package.external_tool_versions[]",
                "external_tool_versions[].command",
                "external_tool_versions[].version_output_sha256",
                "external_tool_versions[].tool_version_row_hash",
                "external_tool_version_assessment.external_tool_version_manifest.manifest_hash",
                "external_tool_version_assessment.external_tool_version_report_grade_validation_plan_hash",
                "external_tool_version_assessment.trusted_external_tool_version_diff",
            ],
            "trusted_diff": "trusted-external-tool-transcript-diff",
        },
    ]


def report_quality_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in report_quality_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_acquisition_quality_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = ACQUISITION_QUALITY_PROGRESS_START,
    end: int = ACQUISITION_QUALITY_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #96-#100 acquisition metadata, time normalization, contamination, and tamper controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "acquisition-quality-progress-v1",
        "batch_id": ACQUISITION_QUALITY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": acquisition_quality_evidence_chain(),
        "items": [acquisition_quality_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "signed-acquisition-handoff-with-write-blocker-metadata",
            "trusted-timezone-normalization-matrix",
            "trusted-clock-skew-baseline",
            "trusted-contamination-checklist",
            "external-signature-or-notarization-attestation",
        ],
        "reportability_rule": (
            "#96-#100 make evidence handling and export warnings visible, but commercial/court-grade "
            "claims still require signed acquisition, trusted time/skew/contamination manifests, and external notarization."
        ),
    }


def acquisition_quality_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 96,
            "component": "write-blocker-acquisition-metadata",
            "produces": "case-db-report-export.acquisition_metadata",
            "primary_outputs": [
                "case-db-report-export.acquisition_metadata.records[]",
                "acquisition_metadata.records[].acquisition_metadata_row_hash",
                "acquisition_metadata.evidence_sources[].acquisition_evidence_source_row_hash",
                "acquisition_metadata.acquisition_metadata_handoff_manifest.manifest_hash",
                "acquisition_metadata.validation_assessment.ready_for_submission",
                "acquisition_metadata.acquisition_metadata_report_grade_validation_plan_hash",
                "acquisition_metadata.trusted_acquisition_metadata_diff",
            ],
            "trusted_diff": "trusted-acquisition-metadata-handoff-diff",
        },
        {
            "item_number": 97,
            "component": "timezone-normalization-validation",
            "produces": "case-db-report-export.timezone_validation",
            "primary_outputs": [
                "case-db-report-export.timezone_validation.summary.timezone_counts",
                "timezone_validation.samples[].timezone_sample_row_hash",
                "timezone_validation.timezone_normalization_manifest.manifest_hash",
                "timezone_validation.validation_assessment.normalized_utc_assumption",
                "timezone_validation.timezone_report_grade_validation_plan_hash",
                "timezone_validation.trusted_timezone_validation_diff",
            ],
            "trusted_diff": "trusted-timezone-normalization-matrix-diff",
        },
        {
            "item_number": 98,
            "component": "clock-skew-analysis",
            "produces": "case-db-report-export.clock_skew_analysis",
            "primary_outputs": [
                "case-db-report-export.clock_skew_analysis.summary.earliest_timestamp",
                "clock_skew_analysis.summary.latest_timestamp",
                "clock_skew_analysis.warnings[].clock_skew_warning_row_hash",
                "clock_skew_analysis.clock_skew_baseline_manifest.manifest_hash",
                "clock_skew_analysis.validation_assessment.baseline_required",
                "clock_skew_analysis.clock_skew_report_grade_validation_plan_hash",
                "clock_skew_analysis.trusted_clock_skew_diff",
            ],
            "trusted_diff": "trusted-clock-skew-baseline-diff",
        },
        {
            "item_number": 99,
            "component": "evidence-contamination-warning",
            "produces": "case-db-report-export.contamination_warnings",
            "primary_outputs": [
                "case-db-report-export.contamination_warnings.warnings[]",
                "contamination_warnings.warnings[].contamination_warning_row_hash",
                "contamination_warnings.contamination_checklist_manifest.manifest_hash",
                "contamination_warnings.validation_assessment.checks[]",
                "contamination_warnings.contamination_report_grade_validation_plan_hash",
                "contamination_warnings.trusted_contamination_warning_diff",
            ],
            "trusted_diff": "trusted-contamination-checklist-diff",
        },
        {
            "item_number": 100,
            "component": "tamper-evident-audit-bundle",
            "produces": "reviewer-bundle.rapidtriage-tamper-evident-audit-bundle.json",
            "primary_outputs": [
                "reviewer-bundle.rapidtriage-tamper-evident-audit-bundle.json",
                "tamper_evident_audit_bundle.entries[].entry_hash",
                "tamper_evident_audit_bundle.summary.head_hash",
                "tamper_evident_audit_bundle.tamper_evident_manifest.manifest_hash",
                "tamper_evident_audit_bundle.signing_slots.external_signature",
                "tamper_evident_audit_bundle.tamper_evident_report_grade_validation_plan_hash",
            ],
            "trusted_diff": "trusted-tamper-signature-attestation-diff",
        },
    ]


def acquisition_quality_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in acquisition_quality_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_release_operations_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = RELEASE_OPERATIONS_PROGRESS_START,
    end: int = RELEASE_OPERATIONS_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #101-#105 installer, package, update, and crash-reporting release controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "release-operations-progress-v1",
        "batch_id": RELEASE_OPERATIONS_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": release_operations_evidence_chain(),
        "items": [release_operations_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "signed-windows-msi-or-exe-with-authenticode-timestamp-log",
            "notarized-macos-pkg-or-dmg-with-gatekeeper-assessment",
            "linux-deb-rpm-appimage-with-clean-install-smoke-logs",
            "hosted-signed-update-channel-with-rollback-test-evidence",
            "trusted-local-crash-redaction-export-review",
        ],
        "reportability_rule": (
            "#101-#105 make local release artifacts and crash reports inspectable, but commercial deployment "
            "claims still require real platform signing, notarization, package smoke logs, hosted update evidence, and crash export review."
        ),
    }


def release_operations_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 101,
            "component": "windows-signed-installer",
            "produces": "release-manifest.package_readiness.windows_signed_installer",
            "primary_outputs": [
                "release-manifest.package_readiness.windows_signed_installer",
                "windows_signed_installer.windows_signing_evidence_manifest.manifest_hash",
                "windows_signed_installer.windows_signing_report_grade_validation_plan_hash",
                "windows_signed_installer.signing_slots.signature_log",
                "windows_signed_installer.signing_slots.timestamp_authority",
                "windows_signed_installer.signing_slots.fresh_windows_smoke",
                "windows_signed_installer.trusted_windows_signing_diff",
                "packaging-plan.platform_packages.windows",
            ],
            "trusted_diff": "trusted-windows-signing-evidence-diff",
        },
        {
            "item_number": 102,
            "component": "macos-notarized-package",
            "produces": "release-manifest.package_readiness.macos_notarized_package",
            "primary_outputs": [
                "release-manifest.package_readiness.macos_notarized_package",
                "macos_notarized_package.macos_notarization_evidence_manifest.manifest_hash",
                "macos_notarized_package.macos_notarization_report_grade_validation_plan_hash",
                "macos_notarized_package.notarization_slots.codesign_verification",
                "macos_notarized_package.notarization_slots.notarytool_submission",
                "macos_notarized_package.notarization_slots.gatekeeper_assessment",
                "macos_notarized_package.trusted_macos_notarization_diff",
                "packaging-plan.platform_packages.macos",
            ],
            "trusted_diff": "trusted-macos-notarization-evidence-diff",
        },
        {
            "item_number": 103,
            "component": "linux-package",
            "produces": "release-manifest.package_readiness.linux_package",
            "primary_outputs": [
                "release-manifest.package_readiness.linux_package",
                "linux_package.linux_package_evidence_manifest.manifest_hash",
                "linux_package.linux_package_report_grade_validation_plan_hash",
                "linux_package.package_evidence_slots.deb_build_log",
                "linux_package.package_evidence_slots.rpm_build_log",
                "linux_package.package_evidence_slots.appimage_build_log",
                "linux_package.package_evidence_slots.install_uninstall_smoke",
                "linux_package.trusted_linux_package_diff",
                "packaging-plan.platform_packages.linux",
            ],
            "trusted_diff": "trusted-linux-package-smoke-diff",
        },
        {
            "item_number": 104,
            "component": "auto-update-channel",
            "produces": "update-manifest.json",
            "primary_outputs": [
                "update-manifest.json",
                "update-manifest.auto_update_evidence_manifest.manifest_hash",
                "update-manifest.auto_update_report_grade_validation_plan_hash",
                "update-manifest.update_evidence_slots.signed_manifest",
                "update-manifest.update_evidence_slots.hosted_channel",
                "update-manifest.update_evidence_slots.rollback_test",
                "release-manifest.package_readiness.auto_update_channel",
            ],
            "trusted_diff": "trusted-auto-update-channel-diff",
        },
        {
            "item_number": 105,
            "component": "local-crash-reporting",
            "produces": "crash-report.json",
            "primary_outputs": [
                "crash-report.json",
                "crash-report.crash_export_evidence_manifest.manifest_hash",
                "crash-report.crash_report_grade_validation_plan_hash",
                "crash-report.export_evidence_slots.operator_export_ui_smoke",
                "crash-report.export_evidence_slots.redaction_checklist",
                "crash-report.export_evidence_slots.enterprise_no_upload_review",
                "crash-report.trusted_crash_report_diff",
            ],
            "trusted_diff": "trusted-crash-redaction-export-diff",
        },
    ]


def release_operations_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in release_operations_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_enterprise_governance_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = ENTERPRISE_GOVERNANCE_PROGRESS_START,
    end: int = ENTERPRISE_GOVERNANCE_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #106-#110 local-only, license, RBAC, multi-user, and collaboration audit controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "enterprise-governance-progress-v1",
        "batch_id": ENTERPRISE_GOVERNANCE_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": enterprise_governance_evidence_chain(),
        "items": [enterprise_governance_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-local-only-deployment-policy-and-network-egress-smoke",
            "trusted-license-authority-review-if-activation-is-enabled",
            "per-action-rbac-enforcement-test-log",
            "multi-user-case-server-security-architecture-review",
            "trusted-collaboration-audit-and-conflict-handling-review",
        ],
        "reportability_rule": (
            "#106-#110 document local-first enterprise guardrails and review/audit scope, but commercial "
            "multi-user or RBAC claims still require a real shared server, enforcement tests, identity handling, and trusted audit review."
        ),
    }


def enterprise_governance_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 106,
            "component": "telemetry-free-local-only-mode",
            "produces": "enterprise-policy.telemetry",
            "primary_outputs": [
                "enterprise-policy.telemetry",
                "enterprise-policy.telemetry.local_only_evidence_manifest.manifest_hash",
                "enterprise-policy.telemetry.local_only_report_grade_validation_plan_hash",
                "enterprise-policy.telemetry.local_only_evidence_slots.network_egress_smoke",
                "enterprise-policy.telemetry.local_only_evidence_slots.remote_bind_auth_smoke",
                "enterprise-policy.network",
            ],
            "trusted_diff": "trusted-local-only-deployment-policy-diff",
        },
        {
            "item_number": 107,
            "component": "license-activation-policy",
            "produces": "enterprise-policy.license_activation",
            "primary_outputs": [
                "enterprise-policy.license_activation",
                "enterprise-policy.license_activation.license_evidence_manifest.manifest_hash",
                "enterprise-policy.license_activation.license_report_grade_validation_plan_hash",
                "enterprise-policy.license_activation.license_evidence_slots.license_authority_review",
                "enterprise-policy.license_activation.license_evidence_slots.offline_activation_smoke",
            ],
            "trusted_diff": "trusted-license-authority-diff",
        },
        {
            "item_number": 108,
            "component": "role-based-access-control",
            "produces": "enterprise-policy.rbac",
            "primary_outputs": [
                "enterprise-policy.rbac",
                "enterprise-policy.rbac.rbac_evidence_manifest.manifest_hash",
                "enterprise-policy.rbac.rbac_report_grade_validation_plan_hash",
                "enterprise-policy.rbac.rbac_evidence_slots.per_action_enforcement_test",
                "enterprise-policy.rbac.rbac_evidence_slots.export_control_review",
            ],
            "trusted_diff": "trusted-rbac-enforcement-diff",
        },
        {
            "item_number": 109,
            "component": "multi-user-case-server",
            "produces": "enterprise-policy.multi_user_case_server",
            "primary_outputs": [
                "enterprise-policy.multi_user_case_server",
                "enterprise-policy.multi_user_case_server.multi_user_evidence_manifest.manifest_hash",
                "enterprise-policy.multi_user_case_server.multi_user_report_grade_validation_plan_hash",
                "enterprise-policy.multi_user_case_server.multi_user_evidence_slots.architecture_security_review",
                "enterprise-policy.multi_user_case_server.multi_user_evidence_slots.locking_conflict_test",
            ],
            "trusted_diff": "trusted-multi-user-server-review-diff",
        },
        {
            "item_number": 110,
            "component": "collaboration-audit-trail",
            "produces": "enterprise-policy.collaboration_audit_trail",
            "primary_outputs": [
                "enterprise-policy.collaboration_audit_trail",
                "enterprise-policy.collaboration_audit_trail.collaboration_audit_evidence_manifest.manifest_hash",
                "enterprise-policy.collaboration_audit_trail.collaboration_audit_report_grade_validation_plan_hash",
                "enterprise-policy.collaboration_audit_trail.collaboration_audit_evidence_slots.audit_append_only_review",
                "enterprise-policy.collaboration_audit_trail.collaboration_audit_evidence_slots.identity_attribution_review",
            ],
            "trusted_diff": "trusted-collaboration-audit-diff",
        },
    ]


def enterprise_governance_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in enterprise_governance_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_operations_continuity_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = OPERATIONS_CONTINUITY_PROGRESS_START,
    end: int = OPERATIONS_CONTINUITY_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #111-#115 backup, release-note, LTS, support, and training controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "operations-continuity-progress-v1",
        "batch_id": OPERATIONS_CONTINUITY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": operations_continuity_evidence_chain(),
        "items": [operations_continuity_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-backup-restore-rehearsal-log-and-migration-corpus",
            "release-notes-ci-gate-with-known-limits-validation-and-migration-notes",
            "operator-maintained-lts-branch-and-hotfix-backport-proof",
            "staffed-support-desk-sla-attestation",
            "training-delivery-log-with-scoring-rubric",
        ],
        "reportability_rule": (
            "#111-#115 provide local continuity commands and packaged operations documents, but commercial "
            "operations claims still require real restore drills, CI release-note gates, maintained LTS/hotfix process, staffed SLA, and training delivery evidence."
        ),
    }


def operations_continuity_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 111,
            "component": "backup-restore-migration",
            "produces": "case-backup/case-restore payloads",
            "primary_outputs": [
                "case-backup/case-restore payloads",
                "case-backup.backup_restore_evidence_manifest.manifest_hash",
                "case-restore.backup_restore_evidence_manifest.manifest_hash",
                "case-restore.rehearsal_evidence_slots.restore_drill_log",
                "case-backup.migration_readiness",
            ],
            "trusted_diff": "trusted-backup-restore-rehearsal-diff",
        },
        {
            "item_number": 112,
            "component": "release-notes-changelog-discipline",
            "produces": "release-manifest.package_readiness.operations_documents",
            "primary_outputs": [
                "release-manifest.package_readiness.operations_documents",
                "operations_documents.document_evidence_manifests.112.manifest_hash",
                "operations_documents.document_evidence_slots.112.ci_changelog_gate",
            ],
            "trusted_diff": "trusted-release-notes-ci-gate-diff",
        },
        {
            "item_number": 113,
            "component": "lts-hotfix-policy",
            "produces": "docs/rapidtriage-lts-hotfix-policy.md",
            "primary_outputs": [
                "docs/rapidtriage-lts-hotfix-policy.md",
                "operations_documents.document_evidence_manifests.113.manifest_hash",
                "operations_documents.document_evidence_slots.113.maintained_branch_proof",
            ],
            "trusted_diff": "trusted-lts-hotfix-policy-diff",
        },
        {
            "item_number": 114,
            "component": "support-sla-documentation",
            "produces": "docs/rapidtriage-support-sla.md",
            "primary_outputs": [
                "docs/rapidtriage-support-sla.md",
                "operations_documents.document_evidence_manifests.114.manifest_hash",
                "operations_documents.document_evidence_slots.114.staffed_support_attestation",
            ],
            "trusted_diff": "trusted-support-desk-sla-diff",
        },
        {
            "item_number": 115,
            "component": "training-curriculum",
            "produces": "docs/rapidtriage-training-curriculum.md",
            "primary_outputs": [
                "docs/rapidtriage-training-curriculum.md",
                "operations_documents.document_evidence_manifests.115.manifest_hash",
                "operations_documents.document_evidence_slots.115.training_delivery_log",
            ],
            "trusted_diff": "trusted-training-delivery-diff",
        },
    ]


def operations_continuity_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in operations_continuity_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_final_delivery_progress(
    items: Iterable[dict[str, object]],
    *,
    start: int = FINAL_DELIVERY_PROGRESS_START,
    end: int = FINAL_DELIVERY_PROGRESS_END,
    validation_evidence_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Track #116-#120 quickstart, admin, hardening, sandbox, and dependency release controls."""

    item_list = [
        item for item in sorted(items, key=lambda current: int(current.get("number") or 0))
        if start <= int(item.get("number") or 0) <= end
    ]
    validation_evidence_summary = validation_evidence_summary or {}
    mapped_numbers = validation_evidence_summary.get("mapped_item_numbers")
    mapped_set = {
        int(number)
        for number in mapped_numbers
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
    } if isinstance(mapped_numbers, list) else set()
    gate_counts = functional_progress_gate_counts(item_list)
    return {
        "version": "final-delivery-progress-v1",
        "batch_id": FINAL_DELIVERY_PROGRESS_BATCH_ID,
        "target_range": {"start": start, "end": end},
        "item_count": len(item_list),
        "item_numbers": [int(item.get("number") or 0) for item in item_list],
        "status": functional_progress_status(gate_counts, len(item_list)),
        "commercial_claim_allowed": False,
        "gate_counts": gate_counts,
        "next_gate_counts": functional_next_gate_counts(item_list),
        "validation_package_attached": bool(validation_evidence_summary.get("validation_package_attached")),
        "mapped_item_numbers_in_range": sorted(number for number in mapped_set if start <= number <= end),
        "evidence_chain": final_delivery_evidence_chain(),
        "items": [final_delivery_item_digest(item) for item in item_list],
        "required_outputs_before_commercial_claim": [
            "trusted-quickstart-lab-run-log",
            "trusted-admin-deployment-proof",
            "independent-appsec-review",
            "trusted-malicious-evidence-sandbox-corpus",
            "scheduled-ci-advisory-scan-and-sbom-publication",
        ],
        "reportability_rule": (
            "#116-#120 package the final analyst/admin/security/dependency materials, but commercial release "
            "claims still require real lab runs, admin deployment proof, independent AppSec, OS/corpus sandbox evidence, and CI/SBOM monitoring."
        ),
    }


def final_delivery_evidence_chain() -> list[dict[str, object]]:
    return [
        {
            "item_number": 116,
            "component": "analyst-quickstart-lab",
            "produces": "docs/rapidtriage-training-curriculum.md quickstart lab section",
            "primary_outputs": [
                "docs/rapidtriage-training-curriculum.md quickstart lab section",
                "operations_documents.document_evidence_manifests.116.manifest_hash",
                "operations_documents.document_evidence_slots.116.quickstart_lab_run_log",
            ],
            "trusted_diff": "trusted-quickstart-lab-run-diff",
        },
        {
            "item_number": 117,
            "component": "admin-deployment-guide",
            "produces": "docs/rapidtriage-admin-deployment-guide.md",
            "primary_outputs": [
                "docs/rapidtriage-admin-deployment-guide.md",
                "operations_documents.document_evidence_manifests.117.manifest_hash",
                "operations_documents.document_evidence_slots.117.fresh_deployment_proof",
            ],
            "trusted_diff": "trusted-admin-deployment-proof-diff",
        },
        {
            "item_number": 118,
            "component": "security-hardening-review",
            "produces": "enterprise-policy.security_hardening",
            "primary_outputs": [
                "enterprise-policy.security_hardening",
                "operations_documents.document_evidence_manifests.118.manifest_hash",
                "operations_documents.document_evidence_slots.118.independent_appsec_review",
            ],
            "trusted_diff": "trusted-security-hardening-review-diff",
        },
        {
            "item_number": 119,
            "component": "malicious-evidence-sandboxing",
            "produces": "enterprise-policy.security_hardening.trusted_malicious_sandbox_diff",
            "primary_outputs": [
                "enterprise-policy.security_hardening.trusted_malicious_sandbox_diff",
                "operations_documents.document_evidence_manifests.119.manifest_hash",
                "operations_documents.document_evidence_slots.119.malicious_corpus_validation",
            ],
            "trusted_diff": "trusted-malicious-evidence-sandbox-diff",
        },
        {
            "item_number": 120,
            "component": "dependency-vulnerability-monitoring",
            "produces": "dependency-monitoring.json",
            "primary_outputs": [
                "dependency-monitoring.json",
                "operations_documents.document_evidence_manifests.120.manifest_hash",
                "operations_documents.document_evidence_slots.120.scheduled_ci_advisory_scan",
            ],
            "trusted_diff": "trusted-dependency-advisory-sbom-diff",
        },
    ]


def final_delivery_item_digest(item: dict[str, object]) -> dict[str, object]:
    digest = functional_progress_item_digest(item)
    chain = {
        int(row["item_number"]): row
        for row in final_delivery_evidence_chain()
        if isinstance(row.get("item_number"), int)
    }
    row = chain.get(int(digest["number"]))
    if row:
        digest["component"] = row["component"]
        digest["produces"] = row["produces"]
        digest["primary_outputs"] = row.get("primary_outputs", [row["produces"]])
        digest["trusted_diff_required"] = row["trusted_diff"]
    return digest


def build_priority_work_plan(items: Iterable[dict[str, object]], *, limit: int = 25) -> list[dict[str, object]]:
    actionable = [item for item in items if item.get("next_required_gate")]
    plan: list[dict[str, object]] = []
    for item in sorted(actionable, key=priority_sort_key)[:limit]:
        next_gate = str(item.get("next_required_gate") or "")
        plan.append(
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "current_stage": item.get("highest_maturity_stage") or "none",
                "next_gate": next_gate,
                "required_action": gate_remaining_text(item, next_gate),
                "release_gate": item.get("release_gate"),
            }
        )
    return plan


def priority_sort_key(item: dict[str, object]) -> tuple[int, int, int, int]:
    next_gate = str(item.get("next_required_gate") or "complete")
    gate_priority = MATURITY_GATE_ORDER.index(next_gate) if next_gate in MATURITY_GATE_ORDER else len(MATURITY_GATE_ORDER)
    severity_priority = SEVERITY_PRIORITY.get(str(item.get("severity") or "low"), 9)
    category_priority = CATEGORY_PRIORITY.get(str(item.get("category") or "unknown"), 9)
    return (gate_priority, severity_priority, category_priority, int(item.get("number") or 0))


def gate_remaining_text(item: dict[str, object], gate_name: str) -> str:
    gates = item.get("maturity_gates")
    if isinstance(gates, dict):
        gate = gates.get(gate_name)
        if isinstance(gate, dict):
            remaining = str(gate.get("remaining") or "").strip()
            if remaining:
                return remaining
    return str(item.get("remaining_gap") or item.get("release_gate") or "No remaining action recorded.")


def build_next_gate_blocker_counts(items: Iterable[dict[str, object]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {gate_name: {} for gate_name in MATURITY_GATE_ORDER}
    for item in items:
        gate_name = str(item.get("next_required_gate") or "")
        if gate_name not in counts:
            continue
        blocker_ids = list(item.get("commercial_blockers") or [])
        if not blocker_ids:
            blocker_ids = [gate_remaining_text(item, gate_name)]
        for blocker in blocker_ids:
            blocker_key = normalize_blocker_key(str(blocker))
            counts[gate_name][blocker_key] = counts[gate_name].get(blocker_key, 0) + 1
    return counts


def normalize_blocker_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9가-힣]+", "-", value.strip().lower()).strip("-")
    return normalized[:96] or "unspecified"


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
    severity_weight = {"critical": 3, "high": 2, "medium": 1, "low": 1}
    validated_weight = 0
    commercial_grade_weight = 0
    for item in items:
        weight = severity_weight.get(str(item.get("severity")), 1)
        total_weight += weight
        earned += weight * readiness_status_points(str(item.get("status")))
        gates = item.get("maturity_gates")
        if isinstance(gates, Mapping):
            validated = gates.get("validated")
            commercial = gates.get("commercial_grade")
            if isinstance(validated, Mapping) and validated.get("passed"):
                validated_weight += weight
            if isinstance(commercial, Mapping) and commercial.get("passed"):
                commercial_grade_weight += weight
    if total_weight == 0:
        return 0
    status_score = (earned / total_weight) * 100
    validation_bonus = 2.0 * (validated_weight / total_weight)
    score = int(round(status_score + validation_bonus))
    if commercial_grade_weight < total_weight:
        score = min(score, 90)
    return min(score, 100)


def readiness_status_points(status: str) -> float:
    base_status = status.split(" with ", 1)[0]
    if base_status == "Done":
        return 1.0
    if base_status.startswith("Partial"):
        plus_count = base_status.count("+")
        if plus_count <= 0:
            return 0.45
        if plus_count == 1:
            return 0.65
        return min(0.95, 0.84 + (0.02 * plus_count))
    if base_status == "External+":
        return 0.35
    if base_status == "Planned+":
        return 0.25
    if base_status == "External":
        return 0.2
    if base_status == "Planned":
        return 0.1
    return 0.3


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


def build_commercial_uplift_plan(
    items: Iterable[dict[str, object]],
    *,
    readiness_score: int,
    target_count: int = COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT,
    batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    """Build a repeatable, prioritized plan for moving strict blockers forward."""

    item_list = list(items)
    safe_target_count = max(0, target_count)
    safe_batch_size = max(1, batch_size)
    candidates = [
        item for item in sorted(item_list, key=priority_sort_key)
        if item.get("next_required_gate")
    ][:safe_target_count]
    goals = [
        build_commercial_uplift_goal(item, priority_rank=index + 1, batch_size=safe_batch_size)
        for index, item in enumerate(candidates)
    ]
    batches: list[dict[str, object]] = []
    for index in range(0, len(goals), safe_batch_size):
        batch_goals = goals[index : index + safe_batch_size]
        batch_numbers = [goal["number"] for goal in batch_goals]
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": batch_numbers,
                "item_count": len(batch_goals),
                "primary_categories": sorted({str(goal["category"]) for goal in batch_goals}),
                "required_outputs": [
                    "code_or_workflow_change",
                    "unit_or_fixture_test",
                    "known_answer_or_cross_tool_artifact",
                    "documentation_update",
                    "commercial_readiness_recalculation",
                    "git_commit",
                ],
                "goals": batch_goals,
            }
        )

    category_counts: dict[str, int] = {}
    for goal in goals:
        category = str(goal["category"])
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "version": "commercial-uplift-plan-v1",
        "status": "active" if goals else "complete",
        "current_readiness_score": readiness_score,
        "target_goal_count": safe_target_count,
        "selected_goal_count": len(goals),
        "batch_size": safe_batch_size,
        "batch_count": len(batches),
        "category_counts": category_counts,
        "score_strategy": [
            "Do not raise commercial-grade gates by wording alone.",
            "Prioritize critical parser depth, then validation/legal, then performance and UX bottlenecks.",
            "Attach real corpus, cross-tool diff, benchmark, or operator evidence before claiming commercial parity.",
            "Use five-item batches so every uplift produces code, tests, docs, validation evidence, and a commit.",
        ],
        "large_data_strategy": build_large_data_strategy(),
        "goals": goals,
        "batches": batches,
    }


def build_commercial_uplift_goal(
    item: dict[str, object],
    *,
    priority_rank: int,
    batch_size: int,
) -> dict[str, object]:
    number = int(item.get("number") or 0)
    category = str(item.get("category") or "unknown")
    blockers = [str(blocker) for blocker in item.get("commercial_blockers") or []]
    remaining = gate_remaining_text(item, str(item.get("next_required_gate") or "commercial_grade"))
    return {
        "priority_rank": priority_rank,
        "batch_number": ((priority_rank - 1) // max(1, batch_size)) + 1,
        "number": number,
        "title": str(item.get("title") or ""),
        "category": category,
        "severity": str(item.get("severity") or ""),
        "current_status": str(item.get("status") or ""),
        "current_stage": str(item.get("highest_maturity_stage") or "none"),
        "next_gate": str(item.get("next_required_gate") or ""),
        "objective": uplift_objective_for_item(number, category),
        "implementation_track": uplift_track_for_item(number, category),
        "acceptance_evidence": uplift_acceptance_evidence_for_item(number, category),
        "large_data_strategy": large_data_strategy_for_item(number, category),
        "remaining_gap": remaining,
        "commercial_blockers": blockers,
        "external_evidence_required": external_evidence_required(blockers, remaining),
        "internal_next_step": internal_next_step_for_item(number, category, remaining),
    }


def uplift_objective_for_item(number: int, category: str) -> str:
    if 1 <= number <= 25:
        return "Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence."
    if 26 <= number <= 45:
        return "Turn mobile, messenger, email, or cloud handling into a versioned import/acquisition workflow with redaction, schema tracking, and legal authority gates."
    if 46 <= number <= 65:
        return "Reduce analyst review friction with scalable search, viewer, comparison, citation, and review-state workflows that preserve provenance."
    if 66 <= number <= 80:
        return "Prove large-case behavior through bounded memory, resumable jobs, cursor APIs, deterministic scheduling, and benchmark evidence."
    if 81 <= number <= 100:
        return "Harden court defensibility with known-answer validation, audit chains, provenance completeness, legal warnings, and reproducible exhibit bundles."
    if 101 <= number <= 120:
        return "Produce operator-verifiable release, security, deployment, support, and monitoring evidence without overstating unavailable external services."
    return f"Close the remaining {category} commercial-readiness blocker with measurable implementation and validation evidence."


def uplift_track_for_item(number: int, category: str) -> str:
    if 1 <= number <= 25:
        return "native-parser-depth"
    if 26 <= number <= 45:
        return "schema-import-and-authority-gates"
    if 46 <= number <= 65:
        return "analyst-ux-and-review"
    if 66 <= number <= 80:
        return "large-scale-performance"
    if 81 <= number <= 100:
        return "legal-validation"
    if 101 <= number <= 120:
        return "release-operations"
    return category


def uplift_acceptance_evidence_for_item(number: int, category: str) -> list[str]:
    common = [
        "updated production code or operator workflow",
        "unit/fixture test covering success and limitation behavior",
        "documentation of user-facing behavior and remaining limits",
        "commercial-readiness output showing the next blocker has changed or narrowed",
    ]
    if 1 <= number <= 25:
        return [
            "record/row-level output with source offsets and hashes",
            "trusted-tool or known-answer diff artifact",
            "malformed/deleted/large fixture coverage where relevant",
            *common,
        ]
    if 26 <= number <= 45:
        return [
            "versioned schema matrix or provider export contract",
            "secret/value redaction and authority-gate evidence",
            "sample import fixture with expected rows",
            *common,
        ]
    if 46 <= number <= 65:
        return [
            "cursor-paged API or virtualized UI evidence",
            "review/citation state persisted in Case DB or export",
            "viewer/search smoke test for large result sets",
            *common,
        ]
    if 66 <= number <= 80:
        return [
            "benchmark or stress-plan JSON with hardware/resource assumptions",
            "checkpoint/resume/cancel or bounded-memory evidence",
            "deterministic output and retry behavior test",
            *common,
        ]
    if 81 <= number <= 100:
        return [
            "known-answer, audit, hash-chain, or provenance package evidence",
            "report/export artifact with limitation text",
            "reproducibility or tamper-evidence test",
            *common,
        ]
    return [
        "release/deployment/security evidence artifact",
        "operator smoke or policy check",
        "explicit blocker for external signing, notarization, support, or CI where applicable",
        *common,
    ]


def large_data_strategy_for_item(number: int, category: str) -> str:
    if number in {10, 11, 12, 13, 22, 23, 24}:
        return "Use streaming or mmap-friendly parsing, cursor checkpoints, bounded page/record batches, and never require whole-image or whole-database memory residency."
    if 1 <= number <= 25:
        return "Emit bounded row batches with stable offsets, parser confidence, and per-file checkpoint metadata so corrupt artifacts cannot block the case."
    if 26 <= number <= 45:
        return "Import provider exports in batches, keep raw payloads external or hashed, and maintain schema-version cursors for very large chat/mail/cloud datasets."
    if 46 <= number <= 65:
        return "Route every large table, timeline, graph, and gallery through cursor APIs, server-side filters, dedupe suppression, and virtualized viewers."
    if 66 <= number <= 80:
        return "Measure throughput, peak memory, p95 latency, retry behavior, and checkpoint reuse across 100k/1M/10M-row scenarios before raising claims."
    if 81 <= number <= 100:
        return "Keep validation and report bundles manifest-based with hashes instead of copying large evidence blobs unless explicitly selected."
    if 101 <= number <= 120:
        return "Package and verify release artifacts without embedding evidence data; smoke tests should use small known-answer cases and recorded large-case logs."
    return "Keep processing incremental, bounded, checkpointed, and evidence-hash referenced."


def internal_next_step_for_item(number: int, category: str, remaining: str) -> str:
    if external_evidence_required([], remaining) and 101 <= number <= 120:
        return "Record the external blocker, add an operator evidence slot, and implement the strongest local smoke/policy check available."
    if 1 <= number <= 25:
        return "Add one deeper native parser assertion, a fixture or cross-tool comparator hook, and a reportability warning test."
    if 26 <= number <= 45:
        return "Add a versioned schema/import fixture plus redaction and legal-authority checks."
    if 46 <= number <= 65:
        return "Add a user-facing search/view/review workflow improvement with persisted state and pagination coverage."
    if 66 <= number <= 80:
        return "Add benchmark/checkpoint/resource evidence and enforce bounded processing in the relevant path."
    if 81 <= number <= 100:
        return "Add validation-package, audit, provenance, or report evidence that can be independently reviewed."
    return "Add release-operation evidence and keep external commercial blockers explicit."


def external_evidence_required(blockers: list[str], remaining: str) -> bool:
    text = " ".join([*blockers, remaining]).lower()
    markers = (
        "external",
        "independent",
        "signing",
        "notarization",
        "staffed",
        "hosted",
        "hardware",
        "10tb",
        "third-party",
        "contractual",
    )
    return any(marker in text for marker in markers)


def build_large_data_strategy() -> dict[str, object]:
    return {
        "rule": "Large evidence must be streamed, checkpointed, cursor-paged, and hash-referenced; UI and reports must never require loading all rows.",
        "parser_runtime": "Keep Python as orchestration/API/UI glue; move hot EVTX/Registry/ESE/MFT/USN/hash/OCR workers toward Rust or isolated native subprocesses.",
        "storage": "Use SQLite/PostgreSQL for case metadata, FTS/Tantivy-style indexes for search, and Parquet/DuckDB-style sidecars for large analytical outputs when needed.",
        "api": "Every massive table/search/timeline endpoint should expose cursor tokens, limits, total estimates, and snapshot warnings.",
        "ui": "Use virtualized result tables, lazy previews, dedupe collapse, and explicit loading/progress states.",
        "proof": "Publish benchmark JSON with hardware profile, evidence size, record count, wall time, peak memory, p95 latency, failures, and resume behavior.",
    }


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
        "## Maturity Gate Summary",
        "",
    ]
    maturity_summary = payload.get("maturity_gate_summary") if isinstance(payload.get("maturity_gate_summary"), dict) else {}
    gate_counts = maturity_summary.get("gate_counts") if isinstance(maturity_summary.get("gate_counts"), dict) else {}
    for gate_name in MATURITY_GATE_ORDER:
        counts = gate_counts.get(gate_name) if isinstance(gate_counts.get(gate_name), dict) else {}
        lines.append(
            f"- `{gate_name}`: `{counts.get('passed', 0)}` passed, `{counts.get('failed', 0)}` remaining"
        )
    blocker_matrix = (
        payload.get("commercial_blocker_matrix")
        if isinstance(payload.get("commercial_blocker_matrix"), dict)
        else {}
    )
    if blocker_matrix:
        lane_counts = (
            blocker_matrix.get("lane_counts")
            if isinstance(blocker_matrix.get("lane_counts"), dict)
            else {}
        )
        actionability_counts = (
            blocker_matrix.get("actionability_counts")
            if isinstance(blocker_matrix.get("actionability_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Commercial Blocker Matrix",
                "",
                f"- Matrix version: `{blocker_matrix.get('version', '')}`",
                f"- Blocked items: `{blocker_matrix.get('item_count', 0)}`",
                f"- Internally actionable next steps: `{actionability_counts.get('internal', 0)}`",
                f"- External/trusted evidence required: `{actionability_counts.get('external_or_trusted_evidence', 0)}`",
                f"- Lane counts: `{lane_counts}`",
                f"- Rule: {blocker_matrix.get('rule', '')}",
                "",
                "### Top Internal Blockers",
                "",
            ]
        )
        for row in blocker_matrix.get("top_internal_items", []):
            if not isinstance(row, dict):
                continue
            lines.append(
                f"- `#{row.get('number')}` {row.get('title', '')}: lane `{row.get('blocker_lane', '')}`, "
                f"next `{row.get('next_required_gate', '')}`"
            )
        lines.extend(["", "### Top External Evidence Blockers", ""])
        for row in blocker_matrix.get("top_external_evidence_items", []):
            if not isinstance(row, dict):
                continue
            lines.append(
                f"- `#{row.get('number')}` {row.get('title', '')}: lane `{row.get('blocker_lane', '')}`, "
                f"next `{row.get('next_required_gate', '')}`"
            )
    separation_profile = (
        payload.get("blocker_separation_profile")
        if isinstance(payload.get("blocker_separation_profile"), dict)
        else {}
    )
    if separation_profile:
        summary = (
            separation_profile.get("summary")
            if isinstance(separation_profile.get("summary"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Internal vs External Blockers",
                "",
                f"- Profile: `{separation_profile.get('version', '')}`",
                f"- Immediate queue item: `#{separation_profile.get('immediate_queue_item', '')}`",
                f"- Internal-only blockers: `{separation_profile.get('internal_only_count', 0)}`",
                f"- Internal then external blockers: `{separation_profile.get('internal_then_external_count', 0)}`",
                f"- External-only blockers: `{separation_profile.get('external_only_count', 0)}`",
                f"- Internal work available: `{summary.get('internal_work_available', 0)}`",
                f"- External/trusted evidence required: `{summary.get('external_or_trusted_evidence_required', 0)}`",
                f"- Rule: {separation_profile.get('operator_rule', '')}",
                "",
                "### Next Internal Batch",
                "",
            ]
        )
        for row in separation_profile.get("next_internal_batch", []):
            if isinstance(row, dict):
                lines.append(f"- `#{row.get('number')}` {row.get('title', '')}: {row.get('next_action', '')}")
        lines.extend(["", "### Next External Evidence Batch", ""])
        for row in separation_profile.get("next_external_evidence_batch", []):
            if isinstance(row, dict):
                lines.append(f"- `#{row.get('number')}` {row.get('title', '')}: {row.get('next_action', '')}")
    platform_actionability = (
        payload.get("platform_uplift_actionability")
        if isinstance(payload.get("platform_uplift_actionability"), dict)
        else {}
    )
    if platform_actionability:
        counts = (
            platform_actionability.get("counts")
            if isinstance(platform_actionability.get("counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Platform Uplift Actionability",
                "",
                f"- Profile: `{platform_actionability.get('profile_version', '')}`",
                f"- Can reach 100 on Mac alone: `{platform_actionability.get('can_reach_100_on_mac_alone', False)}`",
                f"- Mac preparatory evidence available: `{platform_actionability.get('mac_can_generate_preparatory_evidence', False)}`",
                f"- Remaining score points: `{platform_actionability.get('remaining_score_points', 0)}`",
                f"- Mac-preparable blocked items: `{counts.get('mac_preparable_item_count', 0)}`",
                f"- Windows/Windows-evidence blocked items: `{counts.get('windows_or_windows_evidence_item_count', 0)}`",
                f"- External/trusted-evidence blocked items: `{counts.get('external_or_trusted_evidence_item_count', 0)}`",
                f"- Rule: {platform_actionability.get('operator_rule', '')}",
                "",
                "### Mac-Executable Commands",
                "",
            ]
        )
        for command in platform_actionability.get("mac_executable_commands", []):
            if isinstance(command, dict):
                lines.append(f"- `{command.get('id', '')}`: `{command.get('command', '')}`")
        lines.extend(["", "### Windows Or External Evidence Samples", ""])
        for row in platform_actionability.get("windows_or_windows_evidence_samples", [])[:5]:
            if isinstance(row, dict):
                lines.append(f"- `#{row.get('number')}` {row.get('title', '')}")
    mac_first = (
        payload.get("mac_first_evidence_summary")
        if isinstance(payload.get("mac_first_evidence_summary"), dict)
        else {}
    )
    if mac_first and mac_first.get("attached"):
        lines.extend(
            [
                "",
                "## Mac-First Evidence Attachments",
                "",
                f"- Profile: `{mac_first.get('profile_version', '')}`",
                f"- Evidence files: `{mac_first.get('evidence_count', 0)}`",
                f"- Supports backlog items: `{mac_first.get('supports_backlog_items', [])}`",
                f"- Claim effect: {mac_first.get('claim_effect', '')}",
                "",
                "### Attached Evidence",
                "",
            ]
        )
        for row in mac_first.get("rows", []):
            if isinstance(row, dict):
                email_bits = ""
                if row.get("command") == "email-external-parse":
                    email_bits = (
                        f", exports `{row.get('export_file_count', '')}`, "
                        f"trusted-diff-ready `{row.get('ready_for_trusted_diff', '')}`, "
                        f"manifest `{row.get('evidence_manifest_hash', '')}`"
                    )
                lines.append(
                    f"- `{row.get('command', '')}` `{row.get('status', '')}`: "
                    f"score `{row.get('local_smoke_score', '')}`, "
                    f"large-case `{row.get('large_case_status', '')}`, "
                    f"sha256 `{row.get('path_sha256', '')}`"
                    f"{email_bits}"
                )
    functional_progress = (
        payload.get("functional_defensibility_progress")
        if isinstance(payload.get("functional_defensibility_progress"), dict)
        else {}
    )
    if functional_progress:
        target_range = (
            functional_progress.get("target_range")
            if isinstance(functional_progress.get("target_range"), dict)
            else {}
        )
        functional_gate_counts = (
            functional_progress.get("gate_counts")
            if isinstance(functional_progress.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Functional Defensibility Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{functional_progress.get('status', '')}`",
                f"- Item count: `{functional_progress.get('item_count', 0)}`",
                f"- Batch count: `{functional_progress.get('batch_count', 0)}`",
                f"- Commercial claim allowed by this section: `{functional_progress.get('commercial_claim_allowed', False)}`",
                f"- Rule: {functional_progress.get('commercial_claim_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{functional_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Functional Batches", ""])
        for batch in functional_progress.get("batches", []):
            if not isinstance(batch, dict):
                continue
            item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
            next_counts = (
                batch.get("next_gate_counts") if isinstance(batch.get("next_gate_counts"), dict) else {}
            )
            lines.append(
                f"- Batch `{batch.get('batch_number')}` ({item_numbers}) status `{batch.get('status', '')}`, "
                f"next gates `{next_counts}`"
            )
    review_scale_progress = (
        payload.get("review_scale_resilience_progress")
        if isinstance(payload.get("review_scale_resilience_progress"), dict)
        else {}
    )
    if review_scale_progress:
        target_range = (
            review_scale_progress.get("target_range")
            if isinstance(review_scale_progress.get("target_range"), dict)
            else {}
        )
        review_gate_counts = (
            review_scale_progress.get("gate_counts")
            if isinstance(review_scale_progress.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Review Scale Resilience Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{review_scale_progress.get('status', '')}`",
                f"- Item count: `{review_scale_progress.get('item_count', 0)}`",
                f"- Commercial claim allowed by this section: `{review_scale_progress.get('commercial_claim_allowed', False)}`",
                f"- Rule: {review_scale_progress.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{review_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Review-Scale Items", ""])
        for item in review_scale_progress.get("items", []):
            if not isinstance(item, dict):
                continue
            outputs = ", ".join(str(output) for output in item.get("primary_outputs", []))
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"trusted manifest `{item.get('trusted_manifest_required', '')}`, outputs `{outputs}`"
            )
    validation_spine = (
        payload.get("validation_spine_progress")
        if isinstance(payload.get("validation_spine_progress"), dict)
        else {}
    )
    if validation_spine:
        target_range = (
            validation_spine.get("target_range")
            if isinstance(validation_spine.get("target_range"), dict)
            else {}
        )
        spine_gate_counts = (
            validation_spine.get("gate_counts")
            if isinstance(validation_spine.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Validation Spine Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{validation_spine.get('status', '')}`",
                f"- Item count: `{validation_spine.get('item_count', 0)}`",
                f"- Validation package attached: `{validation_spine.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{validation_spine.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{validation_spine.get('commercial_claim_allowed', False)}`",
                f"- Rule: {validation_spine.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{spine_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Validation Evidence Chain", ""])
        for item in validation_spine.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    forensic_integrity = (
        payload.get("forensic_integrity_progress")
        if isinstance(payload.get("forensic_integrity_progress"), dict)
        else {}
    )
    if forensic_integrity:
        target_range = (
            forensic_integrity.get("target_range")
            if isinstance(forensic_integrity.get("target_range"), dict)
            else {}
        )
        integrity_gate_counts = (
            forensic_integrity.get("gate_counts")
            if isinstance(forensic_integrity.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Forensic Integrity Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{forensic_integrity.get('status', '')}`",
                f"- Item count: `{forensic_integrity.get('item_count', 0)}`",
                f"- Validation package attached: `{forensic_integrity.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{forensic_integrity.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{forensic_integrity.get('commercial_claim_allowed', False)}`",
                f"- Rule: {forensic_integrity.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{integrity_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Forensic Integrity Evidence Chain", ""])
        for item in forensic_integrity.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    report_quality = (
        payload.get("report_quality_progress")
        if isinstance(payload.get("report_quality_progress"), dict)
        else {}
    )
    if report_quality:
        target_range = (
            report_quality.get("target_range")
            if isinstance(report_quality.get("target_range"), dict)
            else {}
        )
        quality_gate_counts = (
            report_quality.get("gate_counts")
            if isinstance(report_quality.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Report Quality Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{report_quality.get('status', '')}`",
                f"- Item count: `{report_quality.get('item_count', 0)}`",
                f"- Validation package attached: `{report_quality.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{report_quality.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{report_quality.get('commercial_claim_allowed', False)}`",
                f"- Rule: {report_quality.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{quality_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Report Quality Evidence Chain", ""])
        for item in report_quality.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    acquisition_quality = (
        payload.get("acquisition_quality_progress")
        if isinstance(payload.get("acquisition_quality_progress"), dict)
        else {}
    )
    if acquisition_quality:
        target_range = (
            acquisition_quality.get("target_range")
            if isinstance(acquisition_quality.get("target_range"), dict)
            else {}
        )
        acquisition_gate_counts = (
            acquisition_quality.get("gate_counts")
            if isinstance(acquisition_quality.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Acquisition Quality Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{acquisition_quality.get('status', '')}`",
                f"- Item count: `{acquisition_quality.get('item_count', 0)}`",
                f"- Validation package attached: `{acquisition_quality.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{acquisition_quality.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{acquisition_quality.get('commercial_claim_allowed', False)}`",
                f"- Rule: {acquisition_quality.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{acquisition_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Acquisition Quality Evidence Chain", ""])
        for item in acquisition_quality.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    release_operations = (
        payload.get("release_operations_progress")
        if isinstance(payload.get("release_operations_progress"), dict)
        else {}
    )
    if release_operations:
        target_range = (
            release_operations.get("target_range")
            if isinstance(release_operations.get("target_range"), dict)
            else {}
        )
        release_gate_counts = (
            release_operations.get("gate_counts")
            if isinstance(release_operations.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Release Operations Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{release_operations.get('status', '')}`",
                f"- Item count: `{release_operations.get('item_count', 0)}`",
                f"- Validation package attached: `{release_operations.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{release_operations.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{release_operations.get('commercial_claim_allowed', False)}`",
                f"- Rule: {release_operations.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{release_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Release Operations Evidence Chain", ""])
        for item in release_operations.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    enterprise_governance = (
        payload.get("enterprise_governance_progress")
        if isinstance(payload.get("enterprise_governance_progress"), dict)
        else {}
    )
    if enterprise_governance:
        target_range = (
            enterprise_governance.get("target_range")
            if isinstance(enterprise_governance.get("target_range"), dict)
            else {}
        )
        enterprise_gate_counts = (
            enterprise_governance.get("gate_counts")
            if isinstance(enterprise_governance.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Enterprise Governance Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{enterprise_governance.get('status', '')}`",
                f"- Item count: `{enterprise_governance.get('item_count', 0)}`",
                f"- Validation package attached: `{enterprise_governance.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{enterprise_governance.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{enterprise_governance.get('commercial_claim_allowed', False)}`",
                f"- Rule: {enterprise_governance.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{enterprise_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Enterprise Governance Evidence Chain", ""])
        for item in enterprise_governance.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    operations_continuity = (
        payload.get("operations_continuity_progress")
        if isinstance(payload.get("operations_continuity_progress"), dict)
        else {}
    )
    if operations_continuity:
        target_range = (
            operations_continuity.get("target_range")
            if isinstance(operations_continuity.get("target_range"), dict)
            else {}
        )
        operations_gate_counts = (
            operations_continuity.get("gate_counts")
            if isinstance(operations_continuity.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Operations Continuity Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{operations_continuity.get('status', '')}`",
                f"- Item count: `{operations_continuity.get('item_count', 0)}`",
                f"- Validation package attached: `{operations_continuity.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{operations_continuity.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{operations_continuity.get('commercial_claim_allowed', False)}`",
                f"- Rule: {operations_continuity.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{operations_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Operations Continuity Evidence Chain", ""])
        for item in operations_continuity.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    final_delivery = (
        payload.get("final_delivery_progress")
        if isinstance(payload.get("final_delivery_progress"), dict)
        else {}
    )
    if final_delivery:
        target_range = (
            final_delivery.get("target_range")
            if isinstance(final_delivery.get("target_range"), dict)
            else {}
        )
        final_gate_counts = (
            final_delivery.get("gate_counts")
            if isinstance(final_delivery.get("gate_counts"), dict)
            else {}
        )
        lines.extend(
            [
                "",
                "## Final Delivery Progress",
                "",
                f"- Range: `#{target_range.get('start', '')}`-`#{target_range.get('end', '')}`",
                f"- Status: `{final_delivery.get('status', '')}`",
                f"- Item count: `{final_delivery.get('item_count', 0)}`",
                f"- Validation package attached: `{final_delivery.get('validation_package_attached', False)}`",
                f"- Mapped items in range: `{final_delivery.get('mapped_item_numbers_in_range', [])}`",
                f"- Commercial claim allowed by this section: `{final_delivery.get('commercial_claim_allowed', False)}`",
                f"- Rule: {final_delivery.get('reportability_rule', '')}",
            ]
        )
        for gate_name in MATURITY_GATE_ORDER:
            lines.append(f"- `{gate_name}` in range: `{final_gate_counts.get(gate_name, 0)}`")
        lines.extend(["", "### Final Delivery Evidence Chain", ""])
        for item in final_delivery.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `#{item.get('number')}` {item.get('component', '')}: next `{item.get('next_required_gate', '')}`, "
                f"produces `{item.get('produces', '')}`, trusted diff `{item.get('trusted_diff_required', '')}`"
            )
    validation_summary = (
        payload.get("validation_evidence_summary")
        if isinstance(payload.get("validation_evidence_summary"), dict)
        else {}
    )
    if validation_summary.get("validation_package_attached"):
        mapped = ", ".join(f"#{number}" for number in validation_summary.get("mapped_item_numbers", []))
        lines.extend(
            [
                "",
                "## Attached Validation Evidence",
                "",
                f"- Items with passed evidence: `{validation_summary.get('items_with_passed_validation_evidence', 0)}`",
                f"- Mapped items: {mapped or '`none`'}",
                f"- Rule: {validation_summary.get('rule', '')}",
            ]
        )
    lines.extend(["", "## Priority Work Plan", ""])
    for item in payload.get("priority_work_plan", []):
        if not isinstance(item, dict):
            continue
        action = str(item.get("required_action") or "").strip()
        if len(action) > 220:
            action = action[:217].rstrip() + "..."
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('category', '')}, {item.get('severity', '')}, next `{item.get('next_gate', '')}`): {action}"
        )
    uplift_plan = payload.get("commercial_uplift_plan") if isinstance(payload.get("commercial_uplift_plan"), dict) else {}
    if uplift_plan:
        lines.extend(
            [
                "",
                "## 70-Goal Commercial Uplift Plan",
                "",
                f"- Status: `{uplift_plan.get('status', '')}`",
                f"- Selected goals: `{uplift_plan.get('selected_goal_count', 0)}`/`{uplift_plan.get('target_goal_count', 0)}`",
                f"- Batch size: `{uplift_plan.get('batch_size', 0)}`",
                f"- Batch count: `{uplift_plan.get('batch_count', 0)}`",
                f"- Current readiness score: `{uplift_plan.get('current_readiness_score', 0)}/100`",
                "",
                "### Large Data Strategy",
                "",
            ]
        )
        large_strategy = uplift_plan.get("large_data_strategy")
        if isinstance(large_strategy, dict):
            for key, value in large_strategy.items():
                lines.append(f"- `{key}`: {value}")
        lines.extend(["", "### Five-Item Batches", ""])
        for batch in uplift_plan.get("batches", []):
            if not isinstance(batch, dict):
                continue
            item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
            categories = ", ".join(str(item) for item in batch.get("primary_categories", []))
            lines.append(
                f"- Batch `{batch.get('batch_number')}` ({item_numbers}) categories `{categories}`: "
                f"{batch.get('item_count', 0)} goals"
            )
        lines.extend(["", "### First Goals", ""])
        for goal in uplift_plan.get("goals", [])[:20]:
            if not isinstance(goal, dict):
                continue
            remaining = str(goal.get("remaining_gap") or "")
            if len(remaining) > 160:
                remaining = remaining[:157].rstrip() + "..."
            lines.append(
                f"- Rank `{goal.get('priority_rank')}` batch `{goal.get('batch_number')}` "
                f"`#{goal.get('number')}` {goal.get('title', '')}: {goal.get('objective', '')} "
                f"Remaining: {remaining}"
            )
    lines.extend([
        "",
        "## Required Release Evidence",
        "",
    ])
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
        highest_stage = str(item.get("highest_maturity_stage") or "none")
        next_gate = str(item.get("next_required_gate") or "")
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('status', '')}, {item.get('category', '')}, highest `{highest_stage}`, next `{next_gate}`): "
            f"{gap or item.get('release_gate', '')}"
        )
    lines.extend(["", "## Operator Guidance", ""])
    for item in payload.get("operator_guidance", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)
