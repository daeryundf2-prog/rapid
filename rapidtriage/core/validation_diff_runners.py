from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Mapping, Sequence


PUBLIC_CORPUS_ROWS: tuple[dict[str, object], ...] = (
    {
        "item_number": 76,
        "corpus_name": "NIST CFReDS",
        "purpose": "Public forensic reference datasets for known-answer case validation.",
        "evidence_required": [
            "dataset identifier and acquisition notes",
            "source evidence SHA256",
            "expected-answer notes or lab oracle",
            "RapidTriage output",
            "trusted-tool output",
            "row/field diff output",
            "reviewer signoff",
        ],
        "licensing_gate": "operator-must-confirm-download-and-redistribution-terms",
    },
    {
        "item_number": 76,
        "corpus_name": "NIST CFTT",
        "purpose": "Tool-testing assertions and methodology for forensic functions.",
        "evidence_required": [
            "test assertion identifier",
            "expected result",
            "observed RapidTriage result",
            "pass/fail decision",
            "limitation note",
            "reviewer signoff",
        ],
        "licensing_gate": "operator-must-confirm-test-material-scope",
    },
)


RUNNER_GROUPS: tuple[dict[str, object], ...] = (
    {
        "item_number": 77,
        "artifact_family": "evtx",
        "title": "EVTX trusted diff runners",
        "trusted_tools": (
            {
                "name": "EvtxECmd",
                "binary_candidates": ("EvtxECmd", "EvtxECmd.exe"),
                "reference_name": "evtxecmd",
                "output_format": "CSV",
                "command_template": "EvtxECmd -f <source.evtx> --csv <reference-dir>",
            },
            {
                "name": "Hayabusa",
                "binary_candidates": ("hayabusa", "hayabusa.exe"),
                "reference_name": "hayabusa",
                "output_format": "CSV/JSON timeline",
                "command_template": "hayabusa csv-timeline -d <evtx-dir> -o <reference.csv>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind eventlog --output rapid-evtx.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-evtx.json "
            "--reference-output evtxecmd=<EvtxECmd.csv> --reference-output hayabusa=<hayabusa.csv> "
            "--backlog-item 1 --backlog-item 2 --backlog-item 3"
        ),
    },
    {
        "item_number": 78,
        "artifact_family": "registry",
        "title": "Registry trusted diff runners",
        "trusted_tools": (
            {
                "name": "RECmd",
                "binary_candidates": ("RECmd", "RECmd.exe"),
                "reference_name": "recmd",
                "output_format": "CSV",
                "command_template": "RECmd -f <hive> --csv <reference-dir>",
            },
            {
                "name": "Registry Explorer",
                "binary_candidates": ("RegistryExplorer", "RegistryExplorer.exe"),
                "reference_name": "registryexplorer",
                "output_format": "CSV export",
                "command_template": "RegistryExplorer.exe <hive> <manual/exported-csv>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind registry --output rapid-registry.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-registry.json "
            "--reference-output recmd=<RECmd.csv> --reference-output registryexplorer=<RegistryExplorer.csv> "
            "--backlog-item 4 --backlog-item 5 --backlog-item 15"
        ),
    },
    {
        "item_number": 79,
        "artifact_family": "ntfs",
        "title": "MFT/USN trusted diff runners",
        "trusted_tools": (
            {
                "name": "MFTECmd",
                "binary_candidates": ("MFTECmd", "MFTECmd.exe"),
                "reference_name": "mftecmd",
                "output_format": "CSV",
                "command_template": "MFTECmd -f <$MFT> --csv <reference-dir>",
            },
            {
                "name": "analyzeMFT",
                "binary_candidates": ("analyzeMFT.py", "analyzeMFT"),
                "reference_name": "analyzemft",
                "output_format": "CSV",
                "command_template": "analyzeMFT.py -f <$MFT> -o <analyzeMFT.csv>",
            },
            {
                "name": "UsnJrnl2Csv",
                "binary_candidates": ("UsnJrnl2Csv", "UsnJrnl2Csv.exe"),
                "reference_name": "usnjrnl2csv",
                "output_format": "CSV",
                "command_template": "UsnJrnl2Csv <\\$J> <reference.csv>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind filesystem --output rapid-ntfs.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-ntfs.json "
            "--reference-output mftecmd=<MFTECmd.csv> --reference-output usnjrnl2csv=<UsnJrnl2Csv.csv> "
            "--backlog-item 12 --backlog-item 13"
        ),
    },
    {
        "item_number": 80,
        "artifact_family": "ese",
        "title": "SRUM/Windows.edb trusted diff runners",
        "trusted_tools": (
            {
                "name": "SrumECmd",
                "binary_candidates": ("SrumECmd", "SrumECmd.exe"),
                "reference_name": "srumecmd",
                "output_format": "CSV",
                "command_template": "SrumECmd -f <SRUDB.dat> --csv <reference-dir>",
            },
            {
                "name": "libesedb esedbexport",
                "binary_candidates": ("esedbexport",),
                "reference_name": "libesedb",
                "output_format": "tables/CSV conversion",
                "command_template": "esedbexport -t <reference-dir> <Windows.edb-or-SRUDB.dat>",
            },
            {
                "name": "Windows Search DB Analyzer",
                "binary_candidates": ("WinSearchDBAnalyzer", "WinSearchDBAnalyzer.exe"),
                "reference_name": "winsearchdbanalyzer",
                "output_format": "CSV/SQLite export",
                "command_template": "WinSearchDBAnalyzer <Windows.edb> <reference-export>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind windows-search --output rapid-ese.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-ese.json "
            "--reference-output srumecmd=<SrumECmd.csv> --reference-output libesedb=<esedbexport.csv> "
            "--backlog-item 10 --backlog-item 11"
        ),
    },
)


def build_validation_diff_runner_matrix(*, search_path: str | None = None) -> dict[str, object]:
    runner_groups = [_runner_group_with_preflight(group, search_path=search_path) for group in RUNNER_GROUPS]
    installed_tool_count = sum(
        1
        for group in runner_groups
        for tool in group["trusted_tools"]
        if isinstance(tool, Mapping) and tool.get("available")
    )
    total_tool_count = sum(len(group["trusted_tools"]) for group in runner_groups)
    core = {
        "profile_version": "validation-diff-runner-matrix-v1",
        "qc_prep_item_numbers": [76, 77, 78, 79, 80],
        "public_corpus_registry": list(PUBLIC_CORPUS_ROWS),
        "runner_groups": runner_groups,
        "summary": {
            "runner_group_count": len(runner_groups),
            "trusted_tool_count": total_tool_count,
            "available_tool_count": installed_tool_count,
            "missing_tool_count": total_tool_count - installed_tool_count,
            "all_runner_groups_defined": all(group.get("trusted_tools") for group in runner_groups),
            "public_corpus_registry_defined": bool(PUBLIC_CORPUS_ROWS),
        },
        "commercial_grade_blockers": [
            "public-corpus-download-and-license-confirmation-required",
            "trusted-tool-binaries-and-versions-required",
            "real-source-evidence-hashes-required",
            "row-field-diff-outputs-required",
            "independent-reviewer-signoff-required",
        ],
    }
    return {
        **core,
        "matrix_hash": hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def write_validation_diff_runner_matrix(payload: Mapping[str, object], output: Path) -> dict[str, object]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "output": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "bytes": output.stat().st_size,
    }


def _runner_group_with_preflight(group: Mapping[str, object], *, search_path: str | None) -> dict[str, object]:
    tools = []
    for tool in group.get("trusted_tools") or []:
        if not isinstance(tool, Mapping):
            continue
        found_path = _first_binary(tool.get("binary_candidates") or (), search_path=search_path)
        tools.append(
            {
                **dict(tool),
                "available": bool(found_path),
                "resolved_path": found_path,
                "version_capture_required": True,
                "command_capture_required": True,
            }
        )
    return {
        **dict(group),
        "trusted_tools": tools,
        "available_tool_count": sum(1 for tool in tools if tool.get("available")),
        "ready_to_execute_locally": any(tool.get("available") for tool in tools),
        "required_cross_tool_metadata": [
            "--source-evidence",
            "--tool-version",
            "--tool-command",
            "--independent-report",
            "--corpus-scope",
        ],
    }


def _first_binary(candidates: Sequence[object], *, search_path: str | None) -> str:
    for candidate in candidates:
        name = str(candidate)
        if not name:
            continue
        resolved = shutil.which(name, path=search_path)
        if resolved:
            return resolved
    return ""
