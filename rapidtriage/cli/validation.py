"""Validation and cross-tool-diff subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.cross_tool import (
        CrossToolValidationError,
        build_cross_tool_validation_report,
        write_usn_state_replay_known_answer_template,
)
from ..core.e01 import build_image_workflow_trusted_diff
from ..core.known_answer_qc import run_known_answer_qc
from ..core.run_validation import (
        RunValidationAttachmentError,
        attach_validation_diff_outputs,
)
from ..core.validation import ValidationError, build_validation_package
from ..core.validation_diff_runners import (
        build_tool_search_path,
        build_validation_diff_runner_matrix,
        write_validation_diff_runner_matrix,
)
from ..core.validation_final_qc import (
        build_final_qc_execution_report,
        write_final_qc_execution_report,
)
from .helpers import load_image_workflow_rows, parse_named_cli_values


def handle_validation(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_validation_package(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
                known_answer_manifest=Path(args.known_answer_manifest).expanduser().resolve()
                if args.known_answer_manifest
                else None,
                fixture_root=Path(args.fixture_root).expanduser().resolve() if args.fixture_root else None,
                independent_report=Path(args.independent_report).expanduser().resolve() if args.independent_report else None,
            )
        except (ValidationError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved validation JSON: {payload['outputs']['json']}")
            print(f"Saved validation report: {payload['outputs']['markdown']}")
            print(f"Score target: {payload['score_target']}/100")
        return 0



def handle_validation_diff_runners(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = build_validation_diff_runner_matrix(
            search_path=build_tool_search_path(args.search_path),
            probe_versions=args.probe_versions,
            version_probe_timeout_seconds=max(float(args.version_timeout_seconds), 0.1),
        )
        if args.output:
            payload["output_manifest"] = write_validation_diff_runner_matrix(
                payload,
                Path(args.output).expanduser().resolve(),
            )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage validation diff runner matrix")
            print(f"QC items: {payload['qc_prep_item_numbers']}")
            print(
                f"Runner groups: {summary['runner_group_count']}  "
                f"Tools: {summary['available_tool_count']}/{summary['trusted_tool_count']} available"
            )
            if payload.get("output_manifest"):
                print(f"Saved matrix: {payload['output_manifest']['output']}")
        return 0



def handle_final_qc_report(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = build_final_qc_execution_report(
            validation_package=Path(args.validation_package).expanduser().resolve() if args.validation_package else None,
            runner_matrix=Path(args.runner_matrix).expanduser().resolve() if args.runner_matrix else None,
            chain_of_custody=Path(args.chain_of_custody).expanduser().resolve() if args.chain_of_custody else None,
            audit_bundle=Path(args.audit_bundle).expanduser().resolve() if args.audit_bundle else None,
            exhibit_bundle=Path(args.exhibit_bundle).expanduser().resolve() if args.exhibit_bundle else None,
            performance_runs=[Path(path).expanduser().resolve() for path in args.performance_run or []],
            browser_traces=[Path(path).expanduser().resolve() for path in args.browser_trace or []],
            reviewer_signoffs=[Path(path).expanduser().resolve() for path in args.reviewer_signoff or []],
        )
        if args.output:
            payload["output_manifest"] = write_final_qc_execution_report(
                payload,
                Path(args.output).expanduser().resolve(),
            )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage final QC execution report")
            print(f"QC items: {payload['qc_prep_item_numbers']}")
            print(f"Status: {payload['status']}")
            print(f"Failed checks: {len(payload['final_qc_checklist']['failed_check_ids'])}")
            if payload.get("output_manifest"):
                print(f"Saved report: {payload['output_manifest']['output']}")
        return 0



def handle_known_answer_qc(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_known_answer_qc(
                manifest_path=Path(args.manifest).expanduser().resolve(),
                trusted_manifest_path=Path(args.trusted_manifest).expanduser().resolve() if args.trusted_manifest else None,
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (ValidationError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved known-answer QC JSON: {payload['outputs']['json']}")
            print(f"Saved known-answer QC report: {payload['outputs']['markdown']}")
            print(f"Status: {payload['summary']['status']}  Datasets: {payload['summary']['dataset_count']}")
        return 0



def handle_cross_tool_validate(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        references: dict[str, Path] = {}
        for value in args.reference_output or []:
            if "=" not in value:
                parser.error("--reference-output must use NAME=PATH")
            name, path = value.split("=", 1)
            if not name.strip() or not path.strip():
                parser.error("--reference-output must use NAME=PATH")
            references[name.strip()] = Path(path).expanduser().resolve()
        tool_versions = parse_named_cli_values(args.tool_version or [], option_name="--tool-version", parser=parser)
        tool_commands = parse_named_cli_values(args.tool_command or [], option_name="--tool-command", parser=parser)
        try:
            payload = build_cross_tool_validation_report(
                rapid_output=Path(args.rapid_output).expanduser().resolve(),
                reference_outputs=references,
                output=Path(args.output).expanduser().resolve() if args.output else None,
                min_overlap=args.min_overlap,
                backlog_items=args.backlog_item or [],
                tool_versions=tool_versions,
                tool_commands=tool_commands,
                source_evidence=[Path(path).expanduser().resolve() for path in args.source_evidence or []],
                independent_reports=[Path(path).expanduser().resolve() for path in args.independent_report or []],
                corpus_scope=args.corpus_scope or "",
            )
        except (CrossToolValidationError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage cross-tool validation")
            print(f"Status: {payload['status']}")
            for item in payload["comparisons"]:
                print(
                    f"- {item['reference_name']}: status={item['status']} "
                    f"overlap={item['overlap_ratio']} row_delta={item['row_count_delta']}"
                )
            if payload.get("output"):
                print(f"Saved report: {payload['output']}")
        return 0



def handle_image_workflow_validate(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        rapid_path = Path(args.rapid_output).expanduser().resolve()
        trusted_path = Path(args.trusted_output).expanduser().resolve()
        try:
            rapid_rows = load_image_workflow_rows(rapid_path, max_rows=50000)
            trusted_rows = load_image_workflow_rows(trusted_path, max_rows=50000)
            payload = build_image_workflow_trusted_diff(
                args.item_number,
                rapid_rows,
                trusted_rows,
                trusted_tool=args.trusted_tool,
            )
            payload["command"] = "image-workflow-validate"
            payload["rapid_output"] = str(rapid_path)
            payload["trusted_output"] = str(trusted_path)
            payload["rapid_row_count"] = len(rapid_rows)
            payload["trusted_row_count"] = len(trusted_rows)
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                payload["output"] = str(output_path)
        except (CrossToolValidationError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage image workflow validation")
            print(f"Status: {payload['status']}")
            print(f"Matched: {payload['matched_count']}  Mismatches: {payload['mismatch_count']}")
            if payload.get("output"):
                print(f"Saved report: {payload['output']}")
        return 0



def handle_usn_state_replay_template(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = write_usn_state_replay_known_answer_template(
                Path(args.output).expanduser().resolve(),
                include_examples=not args.empty,
            )
        except OSError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage USN state replay known-answer template")
            print(f"Saved CSV: {payload['csv_path']}")
            print(f"Saved manifest: {payload['manifest_path']}")
            print(f"Rows: {payload['row_count']}")
            print(f"Trusted tool name: {payload['trusted_tool_name']}")
        return 0



def handle_run_attach_validation_diff(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        diff_outputs = {
            name: Path(path).expanduser().resolve()
            for name, path in parse_named_cli_values(
                args.diff_output or [],
                option_name="--diff-output",
                parser=parser,
            ).items()
        }
        try:
            payload = attach_validation_diff_outputs(
                Path(args.run_output).expanduser().resolve(),
                diff_outputs,
                overwrite=args.overwrite,
            )
        except (RunValidationAttachmentError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage run validation diff attachment")
            print(f"Summary: {payload['summary_path']}")
            print(f"Attached outputs: {payload['attached_count']}")
            print(f"Audit: {payload['audit_path']}")
            print("Next: open the run in the web workbench or export its validation package.")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "validation": handle_validation,
    "validation-diff-runners": handle_validation_diff_runners,
    "final-qc-report": handle_final_qc_report,
    "known-answer-qc": handle_known_answer_qc,
    "cross-tool-validate": handle_cross_tool_validate,
    "image-workflow-validate": handle_image_workflow_validate,
    "usn-state-replay-template": handle_usn_state_replay_template,
    "run-attach-validation-diff": handle_run_attach_validation_diff,
}
