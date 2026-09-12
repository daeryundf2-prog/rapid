"""Commercial-readiness and forensic-validation subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.commercial_readiness import (
        CommercialReadinessError,
        build_commercial_readiness_report,
        build_known_answer_manifest_template,
        build_known_answer_template_batches,
        parse_item_range,
        write_known_answer_manifest_template,
        write_known_answer_template_batches,
)
from ..core.confidence import (
        ConfidenceDashboardError,
        build_confidence_dashboard,
        build_parser_explainability,
        build_reproducibility_kit,
)
from ..core.forensic_validation_plan import (
        assess_forensic_validation_batches,
        assess_forensic_validation_pack,
        build_forensic_validation_pack,
        build_forensic_validation_plan,
        import_forensic_validation_evidence_manifest,
        populate_forensic_validation_smoke_fixtures,
        write_forensic_validation_batches,
        write_forensic_validation_pack,
        write_forensic_validation_plan,
)
from .helpers import compact_commercial_readiness_payload


def handle_commercial_readiness(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_commercial_readiness_report(
                backlog_path=Path(args.backlog).expanduser().resolve() if args.backlog else None,
                output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
                validation_package_paths=[
                    Path(path).expanduser().resolve() for path in (args.validation_package or [])
                ],
                mac_first_evidence_paths=[
                    Path(path).expanduser().resolve() for path in (args.mac_first_evidence or [])
                ],
                uplift_targets=args.uplift_targets,
                uplift_batch_size=args.uplift_batch_size,
            )
        except CommercialReadinessError as exc:
            parser.error(str(exc))
        focused_items = []
        if args.next_gate:
            focused_items = [
                item
                for item in payload.get("all_items", [])
                if isinstance(item, dict) and item.get("next_required_gate") == args.next_gate
            ]
            focused_items = focused_items[: max(args.limit, 0)]
            payload["focused_next_gate"] = args.next_gate
            payload["focused_items"] = focused_items
        elif args.limit != 25:
            payload["priority_work_plan"] = payload.get("priority_work_plan", [])[: max(args.limit, 0)]
        if args.write_known_answer_template:
            template_next_gate = args.next_gate or "validated"
            template_payload = build_known_answer_manifest_template(
                payload.get("all_items", []),
                next_gate=template_next_gate,
                limit=args.limit,
            )
            template_outputs = write_known_answer_manifest_template(
                template_payload,
                Path(args.write_known_answer_template).expanduser().resolve(),
            )
            template_payload["outputs"] = template_outputs
            payload["known_answer_manifest_template"] = template_payload
        if args.write_known_answer_template_dir:
            template_next_gate = args.next_gate or "validated"
            try:
                template_item_numbers = parse_item_range(args.template_items)
                batch_payload = build_known_answer_template_batches(
                    payload.get("all_items", []),
                    item_numbers=template_item_numbers,
                    batch_size=args.template_batch_size,
                    next_gate=template_next_gate,
                )
                batch_outputs = write_known_answer_template_batches(
                    batch_payload,
                    Path(args.write_known_answer_template_dir).expanduser().resolve(),
                )
            except CommercialReadinessError as exc:
                parser.error(str(exc))
            batch_payload["outputs"] = batch_outputs
            payload["known_answer_manifest_template_batches"] = batch_payload
        stdout_payload = compact_commercial_readiness_payload(payload, limit=args.limit)
        if args.json:
            print(json.dumps(stdout_payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage commercial readiness gate")
            print(f"Status: {payload['status']}")
            print(f"Readiness score: {payload['readiness_score']}/100")
            print(f"Non-commercial items: {payload['non_commercial_count']}/{payload['item_count']}")
            print(f"Commercial claim allowed: {payload['commercial_claim_allowed']}")
            maturity_summary = payload.get("maturity_gate_summary")
            if isinstance(maturity_summary, dict):
                gate_counts = maturity_summary.get("gate_counts")
                if isinstance(gate_counts, dict):
                    print("Maturity gates:")
                    for gate_name in ("implemented", "usable", "validated", "commercial_grade"):
                        counts = gate_counts.get(gate_name)
                        if isinstance(counts, dict):
                            print(f"- {gate_name}: {counts.get('passed', 0)} passed / {counts.get('failed', 0)} remaining")
            validation_summary = payload.get("validation_evidence_summary")
            if isinstance(validation_summary, dict) and validation_summary.get("validation_package_attached"):
                print(
                    "Validation evidence attached: "
                    f"{validation_summary.get('items_with_passed_validation_evidence', 0)} items"
                )
            mac_first_summary = payload.get("mac_first_evidence_summary")
            if isinstance(mac_first_summary, dict) and mac_first_summary.get("attached"):
                print(f"Mac-first evidence attached: {mac_first_summary.get('evidence_count', 0)} file(s)")
            separation = payload.get("blocker_separation_profile")
            if isinstance(separation, dict):
                summary = separation.get("summary") if isinstance(separation.get("summary"), dict) else {}
                print(
                    "Blocker separation: "
                    f"internal work {summary.get('internal_work_available', 0)}, "
                    f"external/trusted evidence {summary.get('external_or_trusted_evidence_required', 0)}"
                )
            if args.next_gate:
                print(f"Focused next gate: {args.next_gate}")
                focus_source = focused_items
            else:
                focus_source = payload.get("priority_work_plan", [])
            if isinstance(focus_source, list) and focus_source:
                print("Priority work plan:")
                for item in focus_source[: max(args.limit, 0)]:
                    if not isinstance(item, dict):
                        continue
                    action = str(item.get("required_action") or item.get("remaining_gap") or item.get("release_gate") or "")
                    if len(action) > 140:
                        action = action[:137].rstrip() + "..."
                    print(
                        f"- #{item.get('number')} {item.get('title')} "
                        f"[{item.get('category')}, {item.get('severity')}, next={item.get('next_gate') or item.get('next_required_gate')}]: "
                        f"{action}"
                    )
            if payload.get("outputs"):
                outputs = payload["outputs"]
                print(f"Saved JSON: {outputs['json']}")
                print(f"Saved Markdown: {outputs['markdown']}")
            if payload.get("known_answer_manifest_template"):
                template = payload["known_answer_manifest_template"]
                if isinstance(template, dict) and isinstance(template.get("outputs"), dict):
                    outputs = template["outputs"]
                    print(f"Saved known-answer template JSON: {outputs['json']}")
                    print(f"Saved known-answer template Markdown: {outputs['markdown']}")
            if payload.get("known_answer_manifest_template_batches"):
                batches = payload["known_answer_manifest_template_batches"]
                if isinstance(batches, dict) and isinstance(batches.get("outputs"), dict):
                    outputs = batches["outputs"]
                    print(f"Saved known-answer batch index JSON: {outputs['index_json']}")
                    print(f"Saved known-answer batch index Markdown: {outputs['index_markdown']}")
                    print(f"Known-answer batches: {outputs['batch_count']}")
        return 1 if args.strict and not payload["commercial_claim_allowed"] else 0



def handle_forensic_validation_plan(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_forensic_validation_plan(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.output_dir:
            payload["outputs"] = write_forensic_validation_plan(payload, Path(args.output_dir).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic validation plan")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Validated: {summary['validated_count']}/{summary['item_count']}")
            print(f"Commercial-ready: {summary['commercial_grade_ready_count']}/{summary['item_count']}")
            print("Highest-priority open items:")
            for number in summary["highest_priority_open_items"]:
                row = next((item for item in payload["rows"] if item["number"] == number), None)
                if row:
                    print(f"- #{number} {row['title']} [{row['lane']}]: {row['next_internal_work']}")
            if payload.get("outputs"):
                outputs = payload["outputs"]
                print(f"Saved JSON: {outputs['json']}")
                print(f"Saved Markdown: {outputs['markdown']}")
        return 0



def handle_forensic_validation_pack(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_forensic_validation_pack(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except ValueError as exc:
            parser.error(str(exc))
        payload["outputs"] = write_forensic_validation_pack(payload, Path(args.output_dir).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic validation pack")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Required datasets: {summary['required_dataset_count']}")
            print(f"Required checks: {summary['required_check_count']}")
            print("Required tool families:")
            for tool in summary["required_tool_families"]:
                print(f"- {tool}")
            outputs = payload["outputs"]
            print(f"Saved JSON: {outputs['json']}")
            print(f"Saved Markdown: {outputs['markdown']}")
            print(f"Saved dataset template: {outputs['dataset_template']}")
            print(f"Saved command checklist: {outputs['reference_commands']}")
        return 0



def handle_forensic_validation_pack_assess(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = assess_forensic_validation_pack(
                Path(args.pack).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation pack assessment")
            print(f"Datasets: {payload['ready_dataset_count']}/{payload['dataset_count']} validation-ready")
            print(f"Commercial-ready datasets: {payload['commercial_ready_dataset_count']}/{payload['dataset_count']}")
            print(f"Ready for validated gate: {payload['ready_for_validated_gate']}")
            print(f"Ready for commercial grade: {payload['ready_for_commercial_grade']}")
            if payload.get("remaining_blockers"):
                print("Remaining blockers:")
                for blocker in payload["remaining_blockers"]:
                    print(f"- {blocker}")
        return 0



def handle_forensic_validation_batches(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = write_forensic_validation_batches(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation batches")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Batches: {payload['batch_count']}")
            if payload.get("outputs"):
                print(f"Saved JSON: {payload['outputs']['json']}")
                print(f"Saved Markdown: {payload['outputs']['markdown']}")
        return 0



def handle_forensic_validation_batches_assess(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = assess_forensic_validation_batches(
                Path(args.root_dir).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation batch assessment")
            print(f"Batches: {payload['batch_count']}")
            print(f"Datasets: {payload['ready_dataset_count']}/{payload['dataset_count']} validation-ready")
            print(f"External datasets: {payload['external_ready_dataset_count']}/{payload['dataset_count']} external-validation-ready")
            print(f"Commercial-ready datasets: {payload['commercial_ready_dataset_count']}/{payload['dataset_count']}")
            print(f"Ready for validated gate: {payload['ready_for_validated_gate']}")
            print(f"Ready for external validated gate: {payload['ready_for_external_validated_gate']}")
        if args.strict_commercial and not payload["ready_for_commercial_grade"]:
            return 2
        if args.strict_external and not payload["ready_for_external_validated_gate"]:
            return 2
        return 0



def handle_forensic_validation_smoke_populate(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = populate_forensic_validation_smoke_fixtures(
                Path(args.root_dir).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            assessment = payload["assessment"]
            print("RapidTriage forensic validation smoke population")
            print(f"Populated datasets: {payload['populated_dataset_count']}")
            print(f"Batches: {assessment['batch_count']}")
            print(f"Datasets: {assessment['ready_dataset_count']}/{assessment['dataset_count']} validation-ready")
            print(f"External datasets: {assessment['external_ready_dataset_count']}/{assessment['dataset_count']} external-validation-ready")
            print("Commercial-ready: false (internal smoke fixtures only)")
        return 0



def handle_forensic_validation_evidence_import(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = import_forensic_validation_evidence_manifest(
                Path(args.root_dir).expanduser().resolve(),
                Path(args.manifest).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            assessment = payload["assessment"]
            print("RapidTriage forensic validation evidence import")
            print(f"Imported datasets: {payload['imported_dataset_count']}")
            print(f"Missing datasets: {payload['missing_dataset_count']}")
            print(f"External datasets: {assessment['external_ready_dataset_count']}/{assessment['dataset_count']} external-validation-ready")
            print(f"Ready for external validated gate: {assessment['ready_for_external_validated_gate']}")
        return 0



def handle_confidence_dashboard(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_confidence_dashboard(
                Path(args.run_output).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            counts = payload["summary"]["confidence_counts"]
            print("RapidTriage evidence confidence dashboard")
            print(f"Status: {payload['status']}")
            print(
                "Counts: "
                f"report-grade={counts['report-grade']} "
                f"needs-validation={counts['needs-validation']} "
                f"triage={counts['triage']} unsupported={counts['unsupported']}"
            )
            if payload.get("output"):
                print(f"Saved dashboard: {payload['output']}")
        return 0



def handle_parser_explainability(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_parser_explainability(
                Path(args.run_output).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
                markdown_output=Path(args.markdown_output).expanduser().resolve() if args.markdown_output else None,
                limit=args.limit,
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage parser explainability")
            print(f"Entries: {payload['summary']['entry_count']}")
            print(f"Incomplete: {payload['summary']['incomplete_count']}")
            if payload.get("output"):
                print(f"Saved JSON: {payload['output']}")
            if payload.get("markdown_output"):
                print(f"Saved Markdown: {payload['markdown_output']}")
        return 0



def handle_reproducibility_kit(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_reproducibility_kit(
                baseline_run=Path(args.baseline_run).expanduser().resolve(),
                candidate_run=Path(args.candidate_run).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage reproducibility kit")
            print(f"Status: {payload['status']}")
            print(f"Diff count: {payload['summary']['diff_count']}")
            print(f"Saved JSON: {payload['outputs']['json']}")
            print(f"Saved Markdown: {payload['outputs']['markdown']}")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "commercial-readiness": handle_commercial_readiness,
    "forensic-validation-plan": handle_forensic_validation_plan,
    "forensic-validation-pack": handle_forensic_validation_pack,
    "forensic-validation-pack-assess": handle_forensic_validation_pack_assess,
    "forensic-validation-batches": handle_forensic_validation_batches,
    "forensic-validation-batches-assess": handle_forensic_validation_batches_assess,
    "forensic-validation-smoke-populate": handle_forensic_validation_smoke_populate,
    "forensic-validation-evidence-import": handle_forensic_validation_evidence_import,
    "confidence-dashboard": handle_confidence_dashboard,
    "parser-explainability": handle_parser_explainability,
    "reproducibility-kit": handle_reproducibility_kit,
}
