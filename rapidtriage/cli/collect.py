"""Collection, VSC, and carving subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.audit import audit_path_for, write_audit_record
from ..core.carving import CarvingError, run_bounded_carving
from ..core.cloud_api import CloudApiCollectionError, run_cloud_api_collection
from ..core.collect_plan import CollectPlanError, build_collect_plan, run_collect_export
from ..core.docs import write_result
from ..core.input_root import resolve_input_root
from ..core.vsc import (
        VscCompareError,
        compare_vsc_snapshots,
        discover_vsc_snapshot_roots,
        extract_vsc_changes,
)


def handle_cloud_collect(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        manifest_path = Path(args.manifest).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = run_cloud_api_collection(
                manifest_path,
                output_dir=output_dir,
                bearer_token_env=args.bearer_token_env,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.max_response_bytes,
                allow_insecure_http=args.allow_insecure_http,
                dry_run=args.dry_run,
            )
        except CloudApiCollectionError as exc:
            parser.error(str(exc))
        output = Path(str(payload["output"]))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="cloud-collect",
            options={
                "output_dir": str(output_dir),
                "bearer_token_env": args.bearer_token_env,
                "timeout_seconds": args.timeout_seconds,
                "max_response_bytes": args.max_response_bytes,
                "allow_insecure_http": args.allow_insecure_http,
                "dry_run": args.dry_run,
            },
            input_files=[("cloud-api-manifest", manifest_path)],
            output_files=[("cloud-collect-json", output)],
        )
        print(f"Saved cloud collection JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(
            f"Requests: {payload['summary']['request_count']}  "
            f"Collected: {payload['summary']['collected_count']}  Errors: {payload['summary']['error_count']}"
        )
        return 0



def handle_collect_plan(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = build_collect_plan(root, profile=args.profile, input_kind=args.input_kind)
        except CollectPlanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="collect-plan",
            options={
                "root": str(root),
                "profile": args.profile,
                "input_kind": args.input_kind,
                "output": str(output),
            },
            output_files=[("collect-plan-json", output)],
            notes=[
                "collect-plan intentionally does not hash or inventory the entire input root to keep large evidence planning fast.",
                "Use manifest/run when a full input-root inventory hash is required.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved collect plan JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Profile: {payload['profile']}  "
                f"Present: {summary['present_count']}  Missing: {summary['missing_count']}"
            )
            for category, counts in summary["category_counts"].items():
                print(
                    f"- {category}: {counts['present_count']}/{counts['target_count']} present "
                    f"({counts['missing_count']} missing)"
                )
        return 0



def handle_collect_export(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        manifest_output = (
            Path(args.manifest).expanduser().resolve()
            if args.manifest
            else output_dir / "rapidtriage-collect-export.json"
        )
        try:
            payload = run_collect_export(
                root,
                output_dir,
                profile=args.profile,
                input_kind=args.input_kind,
                copy_files=args.copy,
                max_file_count=args.max_file_count,
                max_total_bytes=args.max_total_bytes,
                overwrite=args.overwrite,
            )
        except CollectPlanError as exc:
            parser.error(str(exc))
        write_result(payload, manifest_output)
        audit_output = audit_path_for(manifest_output)
        write_audit_record(
            audit_output,
            command="collect-export",
            options={
                "root": str(root),
                "profile": args.profile,
                "input_kind": args.input_kind,
                "output_dir": str(output_dir),
                "manifest": str(manifest_output),
                "copy": args.copy,
                "max_file_count": args.max_file_count,
                "max_total_bytes": args.max_total_bytes,
                "overwrite": args.overwrite,
            },
            input_files=[
                (f"source:{index}", Path(entry["source_path"]))
                for index, entry in enumerate(payload.get("entries", []), start=1)
                if isinstance(entry, dict) and entry.get("source_path")
            ],
            output_files=[("collect-export-json", manifest_output)]
            + [
                (f"exported:{entry['relative_path']}", Path(entry["destination_path"]))
                for entry in payload.get("entries", [])
                if isinstance(entry, dict) and entry.get("copied") and entry.get("destination_path")
            ],
            notes=[
                "collect-export copies only selected profile targets and skips broad inventory-only directories by default.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved collect export JSON: {manifest_output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Evidence directory: {payload['evidence_dir']}")
            print(
                f"Selected: {summary['selected_file_count']}  "
                f"Copied: {summary['copied_file_count']}  Skipped: {summary['skipped_count']}"
            )
        return 0



def handle_vsc_compare(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        current_root = Path(args.current_root).expanduser().resolve()
        snapshot_roots = [Path(item).expanduser().resolve() for item in args.snapshot_roots]
        output = Path(args.output).expanduser().resolve()
        try:
            payload = compare_vsc_snapshots(
                current_root,
                snapshot_roots,
                compute_hashes=args.hash,
                case_sensitive=args.case_sensitive,
                max_records=args.max_records,
            )
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-compare",
            options={
                "current_root": str(current_root),
                "snapshot_roots": [str(path) for path in snapshot_roots],
                "output": str(output),
                "hash": args.hash,
                "case_sensitive": args.case_sensitive,
                "max_records": args.max_records,
            },
            input_root=current_root,
            output_files=[("vsc-compare-json", output)],
            notes=[
                "Snapshot roots are recorded in options; input_root inventory covers the current root only.",
                "Use --hash for byte-level modified confirmation when runtime permits.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved VSC compare JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Snapshots: {summary['snapshot_count']}  "
                f"Deleted: {summary['deleted']}  Added: {summary['added']}  Modified: {summary['modified']}"
            )
        return 0



def handle_vsc_discover(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        current_root = Path(args.current_root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = discover_vsc_snapshot_roots(current_root, max_depth=args.max_depth)
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-discover",
            options={
                "current_root": str(current_root),
                "output": str(output),
                "max_depth": args.max_depth,
            },
            input_root=current_root,
            output_files=[("vsc-discovery-json", output)],
            notes=[
                "Discovery searches for mounted/exported snapshot folders by name; it does not mount VSC from an E01/RAW image.",
                "Use vsc-compare and vsc-extract after confirming the discovered snapshot roots.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved VSC discovery JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Snapshots: {payload['snapshot_count']}")
        return 0



def handle_vsc_extract(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        current_root = Path(args.current_root).expanduser().resolve()
        snapshot_roots = [Path(item).expanduser().resolve() for item in args.snapshot_roots]
        output_dir = Path(args.output_dir).expanduser().resolve()
        output = Path(args.manifest).expanduser().resolve() if args.manifest else output_dir / "rapidtriage-vsc-extract.json"
        try:
            payload = extract_vsc_changes(
                current_root,
                snapshot_roots,
                output_dir,
                statuses=args.status or ["deleted", "modified"],
                compute_hashes=not args.no_hash,
                case_sensitive=args.case_sensitive,
                max_records=args.max_records,
                max_file_count=args.max_file_count,
                max_total_bytes=args.max_total_bytes,
                overwrite=args.overwrite,
            )
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-extract",
            options={
                "current_root": str(current_root),
                "snapshot_roots": [str(path) for path in snapshot_roots],
                "output_dir": str(output_dir),
                "manifest": str(output),
                "status": args.status or ["deleted", "modified"],
                "hash": not args.no_hash,
                "case_sensitive": args.case_sensitive,
                "overwrite": args.overwrite,
                "max_records": args.max_records,
                "max_file_count": args.max_file_count,
                "max_total_bytes": args.max_total_bytes,
            },
            input_root=current_root,
            output_files=[("vsc-extract-json", output), ("vsc-extract-evidence", Path(str(payload["evidence_root"])))],
            notes=[
                "VSC extract copies selected snapshot/current files into an evidence folder and records SHA256 values.",
                "Deleted and modified statuses preserve the snapshot-side file; added status preserves the current-side file.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved VSC extract JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Selected: {summary['selected_count']}  "
                f"Copied: {summary['copied_count']}  Skipped: {summary['skipped_count']}"
            )
        return 0



def handle_carve(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        input_root = resolve_input_root(Path(args.root), kind=args.input_kind)
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = run_bounded_carving(
                input_root,
                output_dir,
                extract=args.extract,
                max_scan_bytes=args.max_scan_bytes,
                max_carve_bytes=args.max_carve_bytes,
                max_candidates=args.max_candidates,
                extensions=args.ext,
            )
        except (CarvingError, OSError, ValueError) as exc:
            parser.error(str(exc))
        output = output_dir / "rapidtriage-carve.json"
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="carve",
            options={
                "output_dir": str(output_dir),
                "extract": args.extract,
                "max_scan_bytes": args.max_scan_bytes,
                "max_carve_bytes": args.max_carve_bytes,
                "max_candidates": args.max_candidates,
                "extensions": args.ext or [],
            },
            input_root=input_root,
            output_files=[("carve-json", output)]
            + [
                (f"carved:{entry['kind']}:{entry['offset']}", Path(str(entry["extracted_path"])).resolve())
                for entry in payload.get("entries", [])
                if entry.get("extracted_path")
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved carve JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Candidates: {payload['summary']['candidate_count']}  Extracted: {payload['summary']['extracted_count']}")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "cloud-collect": handle_cloud_collect,
    "collect-plan": handle_collect_plan,
    "collect-export": handle_collect_export,
    "vsc-compare": handle_vsc_compare,
    "vsc-discover": handle_vsc_discover,
    "vsc-extract": handle_vsc_extract,
    "carve": handle_carve,
}
