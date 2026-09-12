"""Run, web, doctor, and operations subcommand handlers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ..core.artifacts import ArtifactCollectionError, run_artifact_collection
from ..core.audit import audit_path_for, write_audit_record
from ..core.docs import write_result
from ..core.doctor import format_doctor_text, run_doctor
from ..core.enterprise import build_enterprise_policy
from ..core.input_root import resolve_input_root
from ..core.keyword_packs import keyword_pack_library_assessment, list_keyword_packs
from ..core.plugins import (
        PluginError,
        load_plugin_registry,
        read_plugin_manifest,
        validate_plugin_manifest,
)
from ..core.rearchitecture import build_rearchitecture_status
from ..core.run import RunModeError, run_triage_mode
from ..core.worker import RustWorkerClient, WorkerError
from .web import run_web_server


def handle_run(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else root / f"rapidtriage-run-{args.mode.lower()}"
        )
        try:
            payload = run_triage_mode(
                root,
                mode=args.mode,
                output_dir=output_dir,
                input_kind=args.input_kind,
                dry_run=args.dry_run,
                read_only=args.read_only,
                max_extract_size_bytes=args.max_extract_size_bytes,
                max_file_count=args.max_file_count,
                memory_cap_bytes=args.memory_cap_bytes,
                e01_partition_start_sector=getattr(args, "e01_partition_start_sector", None),
                overwrite=args.overwrite,
                resume=args.resume,
                known_good_hash_feeds=args.known_good_hash_feed,
                hide_known_good=args.hide_known_good,
                known_good_max_hash_bytes=args.known_good_max_hash_bytes,
                rule_set=rule_set,
                columnar_store=args.columnar_store,
            )
        except RunModeError as exc:
            parser.error(str(exc))
        print(f"Saved run summary JSON: {payload['outputs']['summary']}")
        print(f"Saved run report: {payload['outputs']['report']}")
        if payload.get("audit"):
            print(f"Saved audit JSON: {payload['audit']}")
        print(
            f"Docs matches: {payload['summary']['document_match_count']}  "
            f"File candidates: {payload['summary']['file_candidate_count']}"
        )
        return 0



def handle_artifacts(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        input_root = resolve_input_root(root, kind=getattr(args, "input_kind", None))
        if args.eventlog_message_catalog and args.kind != "eventlog":
            parser.error("--eventlog-message-catalog can only be used with --kind eventlog")
        output = (
            Path(args.output).expanduser().resolve()
            if args.output
            else (Path.cwd() / f"rapidtriage-artifacts-{args.kind}.json").resolve()
        )
        collector_options = {}
        if args.eventlog_message_catalog:
            collector_options["message_catalog_path"] = Path(args.eventlog_message_catalog).expanduser().resolve()
        try:
            payload = run_artifact_collection(
                root,
                kind=args.kind,
                input_kind=args.input_kind,
                rule_set=rule_set,
                collector_options=collector_options,
            )
        except ArtifactCollectionError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="artifacts",
            options={
                "kind": args.kind,
                "output": str(output),
                "input_kind": args.input_kind,
                "rules": args.rules,
                "eventlog_message_catalog": args.eventlog_message_catalog,
            },
            input_root=input_root,
            output_files=[("artifacts-json", output)],
        )
        print(f"Saved artifact collector JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Kind: {payload['kind']}  Artifacts: {payload['summary']['artifact_count']}")
        return 0



def handle_web(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            return run_web_server(
                args.host,
                args.port,
                args.reload,
                args.auth_token,
                args.allow_remote_without_auth,
                args.crash_log_dir,
            )
        except RuntimeError as exc:
            parser.error(str(exc))



def handle_doctor(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = run_doctor(
            host=args.host,
            port=args.port,
            app_data_dir=Path(args.app_data_dir).expanduser().resolve() if args.app_data_dir else None,
            write_probe=not args.no_write_probe,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(format_doctor_text(payload))
        return 1 if args.strict and payload["status"] == "error" else 0



def handle_enterprise_policy(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = build_enterprise_policy()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage enterprise policy")
            print(f"Telemetry enabled: {payload['telemetry']['enabled']}")
            print(f"License required: {payload['license_activation']['required']}")
            print(f"RBAC status: {payload['rbac']['status']}")
            print(f"Multi-user server: {payload['multi_user_case_server']['status']}")
        return 0



def handle_rearchitecture_status(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = build_rearchitecture_status()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage re-architecture status")
            print(f"Overall: {payload['overall_status']}")
            print(f"Checks: {payload['passed_count']}/{payload['check_count']} passed")
            focus = payload.get("focus_balance") if isinstance(payload.get("focus_balance"), dict) else {}
            if focus:
                print(f"Focus lanes: {focus.get('lane_count')} ({', '.join(sorted(focus.get('lanes', {}).keys()))})")
            if payload["blocked_count"]:
                print(f"Blocked checks: {payload['blocked_count']}")
            plan_items = payload.get("balanced_next_stage_plan")
            if isinstance(plan_items, list) and plan_items:
                print("Balanced 1-18 plan:")
                for item in plan_items:
                    if not isinstance(item, dict):
                        continue
                    print(
                        f"- {item.get('number')}. {item.get('title')} "
                        f"[{item.get('lane')}, {item.get('status')}]"
                    )
            print("Next steps:")
            for item in payload["next_steps"]:
                print(f"- {item}")
        return 0



def handle_worker_parse(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        env_worker = os.environ.get("RAPIDTRIAGE_RUST_WORKER") or ""
        client = (
            RustWorkerClient(executable=Path(args.worker).expanduser().resolve(), timeout_seconds=args.timeout_seconds)
            if args.worker
            else RustWorkerClient(
                executable=Path(env_worker).expanduser().resolve() if env_worker else None,
                timeout_seconds=args.timeout_seconds,
            )
        )
        try:
            payload = client.parse_to_jsonl(
                kind=args.kind,
                source=Path(args.source).expanduser().resolve(),
                output_path=Path(args.output).expanduser().resolve(),
                case_id=args.case_id,
                source_id=args.source_id,
                extra_args=args.extra_arg or (),
            )
        except (WorkerError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Worker pipeline: {payload['pipeline_status']}")
            print(f"Records: {payload['artifact_store']['record_count']}")
            print(f"Output: {payload['artifact_store']['path']}")
        return 0



def handle_plugins(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            if args.validate:
                plugin = validate_plugin_manifest(
                    read_plugin_manifest(Path(args.validate).expanduser().resolve()),
                    manifest_path=Path(args.validate).expanduser().resolve(),
                )
                payload = {"command": "plugins", "validated": plugin, "plugins": [plugin], "errors": []}
            else:
                payload = load_plugin_registry([Path(path) for path in (args.plugin_dir or [])])
        except PluginError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            for plugin in payload.get("plugins", []):
                print(f"- {plugin['id']} [{plugin['kind']}] {plugin['version']} enabled={plugin['enabled']}")
            for error in payload.get("errors", []):
                print(f"! {error['path']}: {error['error']}")
        return 0



def handle_keyword_packs(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = {
            "command": "keyword-packs",
            "packs": list_keyword_packs(),
            "keyword_pack_library_assessment": keyword_pack_library_assessment(),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            for pack in payload["packs"]:
                print(f"- {pack['name']}: {pack['keyword_count']} keywords")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "run": handle_run,
    "artifacts": handle_artifacts,
    "web": handle_web,
    "doctor": handle_doctor,
    "enterprise-policy": handle_enterprise_policy,
    "rearchitecture-status": handle_rearchitecture_status,
    "worker-parse": handle_worker_parse,
    "plugins": handle_plugins,
    "keyword-packs": handle_keyword_packs,
}
