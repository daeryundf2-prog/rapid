from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


VERSION_PROBE_TIMEOUT_SECONDS = 3.0
VERSION_PROBE_ARGUMENTS: tuple[tuple[str, ...], ...] = (
    ("--version",),
    ("-V",),
    ("version",),
    ("-h",),
)
MAX_VERSION_PROBE_OUTPUT_CHARS = 2000


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
    {
        "item_number": 81,
        "artifact_family": "execution-user-activity",
        "title": "Execution and user-activity trusted diff runners",
        "trusted_tools": (
            {
                "name": "PECmd",
                "binary_candidates": ("PECmd", "PECmd.exe"),
                "reference_name": "pecmd",
                "output_format": "CSV",
                "command_template": "PECmd -d <Prefetch-dir> --csv <reference-dir>",
            },
            {
                "name": "JLECmd",
                "binary_candidates": ("JLECmd", "JLECmd.exe"),
                "reference_name": "jlecmd",
                "output_format": "CSV",
                "command_template": "JLECmd -d <JumpList-dir> --csv <reference-dir>",
            },
            {
                "name": "LECmd",
                "binary_candidates": ("LECmd", "LECmd.exe"),
                "reference_name": "lecmd",
                "output_format": "CSV",
                "command_template": "LECmd -d <LNK-dir> --csv <reference-dir>",
            },
            {
                "name": "ShellBagsExplorer",
                "binary_candidates": ("ShellBagsExplorer", "ShellBagsExplorer.exe", "SBECmd", "SBECmd.exe"),
                "reference_name": "shellbagsexplorer",
                "output_format": "CSV export",
                "command_template": "SBECmd -d <NTUSER-UsrClass-root> --csv <reference-dir>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind execution --kind shellbags --kind recent-files --output rapid-user-activity.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-user-activity.json "
            "--reference-output pecmd=<PECmd.csv> --reference-output jlecmd=<JLECmd.csv> "
            "--reference-output lecmd=<LECmd.csv> --reference-output shellbagsexplorer=<ShellBagsExplorer.csv> "
            "--backlog-item 14 --backlog-item 15 --backlog-item 16 --backlog-item 17"
        ),
    },
    {
        "item_number": 82,
        "artifact_family": "os-account-execution",
        "title": "SAM/SECURITY/SYSTEM and execution artifact trusted diff runners",
        "trusted_tools": (
            {
                "name": "RECmd",
                "binary_candidates": ("RECmd", "RECmd.exe"),
                "reference_name": "recmd",
                "output_format": "CSV",
                "command_template": "RECmd -f <SAM-or-SYSTEM-or-Amcache.hve> --csv <reference-dir>",
            },
            {
                "name": "RegRipper",
                "binary_candidates": ("rip.pl", "regripper", "rr", "rr.exe"),
                "reference_name": "regripper",
                "output_format": "text/CSV normalized export",
                "command_template": "rip.pl -r <hive> -p <sam|security|system|bam|shimcache> > <reference.txt>",
            },
            {
                "name": "AmcacheParser",
                "binary_candidates": ("AmcacheParser", "AmcacheParser.exe"),
                "reference_name": "amcacheparser",
                "output_format": "CSV",
                "command_template": "AmcacheParser -f <Amcache.hve> --csv <reference-dir>",
            },
            {
                "name": "AppCompatCacheParser",
                "binary_candidates": ("AppCompatCacheParser", "AppCompatCacheParser.exe", "ShimCacheParser.py", "ShimCacheParser"),
                "reference_name": "appcompatcacheparser",
                "output_format": "CSV",
                "command_template": "AppCompatCacheParser -f <SYSTEM> --csv <reference-dir>",
            },
            {
                "name": "SrumECmd",
                "binary_candidates": ("SrumECmd", "SrumECmd.exe"),
                "reference_name": "srumecmd",
                "output_format": "CSV",
                "command_template": "SrumECmd -f <SRUDB.dat> --csv <reference-dir>",
            },
        ),
        "rapid_output_hint": "rapidtriage artifacts --kind windows-os-account --kind windows-execution --kind windows-srum --output rapid-os-exec.json",
        "cross_tool_template": (
            "rapidtriage cross-tool-validate --rapid-output rapid-os-exec.json "
            "--reference-output recmd=<RECmd.csv> --reference-output amcacheparser=<AmcacheParser.csv> "
            "--reference-output appcompatcacheparser=<AppCompatCacheParser.csv> --reference-output srumecmd=<SrumECmd.csv> "
            "--backlog-item 6 --backlog-item 7 --backlog-item 8 --backlog-item 9 --backlog-item 10"
        ),
    },
)


def build_validation_diff_runner_matrix(
    *,
    search_path: str | None = None,
    probe_versions: bool = False,
    version_probe_timeout_seconds: float = VERSION_PROBE_TIMEOUT_SECONDS,
) -> dict[str, object]:
    runner_groups = [
        _runner_group_with_preflight(
            group,
            search_path=search_path,
            probe_versions=probe_versions,
            version_probe_timeout_seconds=version_probe_timeout_seconds,
        )
        for group in RUNNER_GROUPS
    ]
    installed_tool_count = sum(
        1
        for group in runner_groups
        for tool in group["trusted_tools"]
        if isinstance(tool, Mapping) and tool.get("available")
    )
    version_captured_count = sum(
        1
        for group in runner_groups
        for tool in group["trusted_tools"]
        if isinstance(tool, Mapping)
        and isinstance(tool.get("version_probe"), Mapping)
        and tool["version_probe"].get("status") == "captured"
    )
    total_tool_count = sum(len(group["trusted_tools"]) for group in runner_groups)
    core = {
        "profile_version": "validation-diff-runner-matrix-v1",
        "qc_prep_item_numbers": [76, 77, 78, 79, 80, 81, 82],
        "public_corpus_registry": list(PUBLIC_CORPUS_ROWS),
        "runner_groups": runner_groups,
        "summary": {
            "runner_group_count": len(runner_groups),
            "trusted_tool_count": total_tool_count,
            "available_tool_count": installed_tool_count,
            "missing_tool_count": total_tool_count - installed_tool_count,
            "version_probe_enabled": probe_versions,
            "version_captured_count": version_captured_count,
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


def _runner_group_with_preflight(
    group: Mapping[str, object],
    *,
    search_path: str | None,
    probe_versions: bool,
    version_probe_timeout_seconds: float,
) -> dict[str, object]:
    tools = []
    for tool in group.get("trusted_tools") or []:
        if not isinstance(tool, Mapping):
            continue
        found_path = _first_binary(tool.get("binary_candidates") or (), search_path=search_path)
        version_probe = _version_probe_manifest(
            found_path,
            probe_versions=probe_versions,
            timeout_seconds=version_probe_timeout_seconds,
        )
        tools.append(
            {
                **dict(tool),
                "available": bool(found_path),
                "resolved_path": found_path,
                "version_probe": version_probe,
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


def build_tool_search_path(extra_paths: Sequence[str] | None, *, base_path: str | None = None) -> str | None:
    """Prepend operator-supplied tool directories without hiding the existing PATH."""
    if not extra_paths:
        return base_path
    segments: list[str] = []
    for raw_value in extra_paths:
        for segment in str(raw_value).split(os.pathsep):
            if segment:
                segments.append(str(Path(segment).expanduser()))
    base = os.environ.get("PATH", "") if base_path is None else base_path
    if base:
        segments.append(base)
    return os.pathsep.join(segments) if segments else base_path


def _version_probe_manifest(
    binary_path: str,
    *,
    probe_versions: bool,
    timeout_seconds: float,
) -> dict[str, object]:
    if not binary_path:
        return {
            "status": "not-run",
            "reason": "binary-not-found",
            "candidate_commands": [],
        }
    candidate_commands = [_format_command([binary_path, *arguments]) for arguments in VERSION_PROBE_ARGUMENTS]
    if not probe_versions:
        return {
            "status": "not-run",
            "reason": "probe-disabled",
            "candidate_commands": candidate_commands,
            "timeout_seconds": timeout_seconds,
        }
    return _probe_tool_version(binary_path, timeout_seconds=timeout_seconds, candidate_commands=candidate_commands)


def _probe_tool_version(
    binary_path: str,
    *,
    timeout_seconds: float,
    candidate_commands: Sequence[str],
) -> dict[str, object]:
    attempts: list[dict[str, object]] = []
    for arguments in VERSION_PROBE_ARGUMENTS:
        command = [binary_path, *arguments]
        command_text = _format_command(command)
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            attempts.append(
                {
                    "command": command_text,
                    "status": "timeout",
                    "timeout_seconds": timeout_seconds,
                    "output_preview": _output_preview(output),
                    "output_sha256": _output_hash(output),
                }
            )
            continue
        except OSError as exc:
            attempts.append(
                {
                    "command": command_text,
                    "status": "error",
                    "error": str(exc),
                }
            )
            continue
        output = completed.stdout or ""
        attempt = {
            "command": command_text,
            "status": "completed",
            "exit_code": completed.returncode,
            "output_preview": _output_preview(output),
            "output_sha256": _output_hash(output),
        }
        attempts.append(attempt)
        if completed.returncode == 0 and output.strip():
            return {
                "status": "captured",
                "command": command_text,
                "exit_code": completed.returncode,
                "output_preview": _output_preview(output),
                "output_sha256": _output_hash(output),
                "attempt_count": len(attempts),
                "timeout_seconds": timeout_seconds,
                "candidate_commands": list(candidate_commands),
            }
    return {
        "status": "failed",
        "reason": "no-version-output-captured",
        "attempt_count": len(attempts),
        "attempts": attempts,
        "timeout_seconds": timeout_seconds,
        "candidate_commands": list(candidate_commands),
    }


def _format_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def _output_preview(output: str) -> str:
    return output[:MAX_VERSION_PROBE_OUTPUT_CHARS]


def _output_hash(output: str) -> str:
    return hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest()
