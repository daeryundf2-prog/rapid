"""Run, web, doctor, and operations subcommand handlers."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from collections.abc import Mapping
from pathlib import Path

from ..core.artifacts import ArtifactCollectionError, run_artifact_collection
from ..core.audit import audit_path_for, write_audit_record
from ..core.docs import write_result
from ..core.doctor import format_doctor_text, run_doctor
from ..core.enterprise import build_enterprise_policy
from ..core.files import MOBILE_INNER_DIR_NAME, path_is_within
from ..core.input_root import resolve_input_root
from ..core.jobs import default_run_output_dir
from ..core.keyword_packs import keyword_pack_library_assessment, list_keyword_packs
from ..core.plugins import (
    PluginError,
    load_plugin_registry,
    read_plugin_manifest,
    validate_plugin_manifest,
)
from ..core.rearchitecture import build_rearchitecture_status
from ..core.rules import RuleConfigError, load_rule_set
from ..core.run import (
    KNOWN_GOOD_FEED_ARCHIVE_DIR_NAME,
    RunModeError,
    known_good_feed_sha256,
    run_tool_build_identity,
    run_triage_mode,
)
from ..core.run.plan import (
    ControlFileError,
    PlanTargetError,
    append_control_request,
    build_run_plan,
    evaluate_control,
    plan_counts_brief,
)
from ..core.run.progress import active_run_progress, load_run_progress_view
from ..core.worker import RustWorkerClient, WorkerError
from .helpers import eventlog_collector_options
from .web import run_web_server

EXIT_CANCELLED = 130
PLAN_STATUS_LABELS = {
    "queued": "대기",
    "running": "실행 중",
    "completed": "완료",
    "partial": "일부 완료",
    "failed": "실패",
    "skipped": "건너뜀",
    "cancelled": "취소됨",
}


def format_plan_table(plan: Mapping[str, object]) -> str:
    """Plain-text run plan: one line per group, indented task lines."""
    brief = plan_counts_brief(plan) or {}
    lines = [
        f"그룹 {brief.get('groups', 0)} / 태스크 {brief.get('tasks', 0)}"
        f" · 완료 {brief.get('completed', 0)} · 부분 {brief.get('partial', 0)} · 건너뜀 {brief.get('skipped', 0)}"
        f" · 취소 {brief.get('cancelled', 0)} · 실패 {brief.get('failed', 0)}"
        + (f" · 결과 {plan.get('outcome')}" if plan.get("outcome") else "")
    ]
    for group in plan.get("groups") or []:
        if not isinstance(group, Mapping):
            continue
        counts = group.get("counts") if isinstance(group.get("counts"), Mapping) else {}
        done = int(counts.get("completed") or 0) + int(counts.get("partial") or 0)
        lines.append(
            f"[{PLAN_STATUS_LABELS.get(str(group.get('status')), group.get('status'))}] {group.get('id')} {group.get('label')}"
            f" ({done}/{counts.get('total', 0)})"
        )
        for task in group.get("tasks") or []:
            if not isinstance(task, Mapping):
                continue
            extra = []
            if task.get("artifact_count") is not None:
                extra.append(f"{int(task['artifact_count']):,}행")
            elif task.get("status") == "running":
                extra.append(f"{int(task.get('rows_so_far') or 0):,}행 진행 중")
            if isinstance(task.get("duration_ms"), int):
                extra.append(f"{task['duration_ms'] / 1000:.1f}s")
            if task.get("reused"):
                extra.append("재사용")
            if task.get("reason"):
                extra.append(str(task["reason"]))
            lines.append(
                f"    - {task.get('id')} {task.get('label')}: {PLAN_STATUS_LABELS.get(str(task.get('status')), task.get('status'))}"
                + (f" ({', '.join(extra)})" if extra else "")
            )
    return "\n".join(lines)


def _install_cancel_handlers(output_dir: Path) -> list[tuple[int, object]]:
    """Ctrl+C (and Ctrl+Break on Windows) = "모두 취소"; a second press stops at once."""
    presses = {"count": 0}

    def on_signal(signum, frame) -> None:
        presses["count"] += 1
        if presses["count"] > 1:
            raise KeyboardInterrupt
        print(
            "모두 취소 요청: 실행 중 처리는 지금까지의 행을 남기고 멈추고, 요약·보고서·감사를 기록합니다."
            " 즉시 중단하려면 한 번 더 누르세요.",
            file=sys.stderr,
            flush=True,
        )
        progress = active_run_progress(output_dir)
        if progress is not None:
            # Off the signal frame: the main thread may hold the progress lock.
            threading.Thread(target=progress.request_cancel_all, kwargs={"actor": "cli"}, daemon=True).start()

    previous: list[tuple[int, object]] = []
    if threading.current_thread() is not threading.main_thread():
        return previous
    for name in ("SIGINT", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous.append((signum, signal.signal(signum, on_signal)))
        except (OSError, ValueError):
            continue
    return previous


def _restore_handlers(previous: list[tuple[int, object]]) -> None:
    for signum, handler in previous:
        try:
            signal.signal(signum, handler)
        except (OSError, ValueError, TypeError):
            continue


def _run_interruptibly(handlers_installed: bool, function, *args, **kwargs):
    """Run ``function`` in a worker thread while the main thread waits in short joins.

    On Windows a main thread blocked on a lock (thread pools) never runs a
    Python signal handler; waking every 0.2 s lets Ctrl+C request "모두 취소"
    at any point of the run. Without installed handlers the call is direct.
    """
    if not handlers_installed:
        return function(*args, **kwargs)
    outcome: dict[str, object] = {}

    def target() -> None:
        try:
            outcome["value"] = function(*args, **kwargs)
        except BaseException as exc:  # re-raised in the main thread
            outcome["error"] = exc

    worker = threading.Thread(target=target, name="rapidtriage-run-main", daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(0.2)
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome.get("value")


def _replay_input_file(candidates: list[Path], expected_sha256: str) -> Path | None:
    """The first candidate whose bytes still hash to the audited SHA-256."""
    for candidate in candidates:
        if candidate.is_file() and known_good_feed_sha256(candidate) == expected_sha256:
            return candidate
    return None


def apply_replay_audit(args: argparse.Namespace, parser: argparse.ArgumentParser):
    """Load the run settings recorded in a run audit into ``args``.

    Every recorded option replaces the command-line value (only ROOT and
    --output-dir come from the command line), and every recorded input
    revision is located and checked before the run starts: a known-good feed
    is read from the archived copy beside the audit, else from its original
    path, and only when the bytes still hash to the audited SHA-256; a rules
    file likewise. A revised feed or rules file stops the replay here.
    Returns the rule set to use (``None`` without rules)."""
    audit_path = Path(args.replay_audit).expanduser().resolve()
    try:
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        options = audit["provenance"]["options"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(f"--replay-audit: 실행 감사 기록을 읽을 수 없습니다 ({exc})")
    if audit.get("command") != "run" or not isinstance(options, Mapping):
        parser.error("--replay-audit: rapidtriage run 감사 기록(rapidtriage-run-audit.json)이 아닙니다")
    args.mode = options.get("mode")
    args.input_kind = options.get("input_kind")
    for name in ("dry_run", "read_only", "extract", "overwrite", "hide_known_good", "columnar_store", "carve"):
        setattr(args, name, bool(options.get(name)))
    args.case_db = bool(options.get("case_db", True))
    for name in ("max_extract_size_bytes", "max_file_count", "known_good_max_hash_bytes"):
        setattr(args, name, int(options.get(name) or 0))
    args.memory_cap_bytes = int(options.get("memory_cap_bytes_requested", options.get("memory_cap_bytes")) or 0)
    args.e01_partition_start_sector = options.get("e01_partition_start_sector")
    args.skip_group = list(options.get("skip_groups") or [])
    args.skip_task = list(options.get("skip_tasks") or [])
    args.resume = False
    eventlog_options = (options.get("collector_options") or {}).get("eventlog") or {}
    args.eventlog_structure_rows = bool(eventlog_options.get("structure_rows"))
    args.eventlog_record_detail = eventlog_options.get("record_detail")
    if options.get("known_good_hash_feeds") and not options.get("known_good_hash_feed_files"):
        parser.error("--replay-audit: 감사 기록에 알려진 정상 해시 목록의 판본(SHA-256)이 없어 같은 목록을 특정할 수 없습니다.")
    archive_dir = audit_path.parent / KNOWN_GOOD_FEED_ARCHIVE_DIR_NAME
    feeds: list[str] = []
    for record in options.get("known_good_hash_feed_files") or []:
        expected = str(record.get("sha256") or "")
        original = Path(str(record.get("path") or ""))
        archived = Path(str(record.get("archived_copy") or ""))
        found = _replay_input_file(
            [archive_dir / f"{expected}{original.suffix}", archived, original], expected
        ) if expected else None
        if found is None:
            parser.error(
                f"--replay-audit: 감사 기록의 알려진 정상 해시 목록 {original} (SHA-256 {expected or '기록 없음'})과 "
                "같은 판본을 찾을 수 없습니다. 목록이 개정되었거나 보관 사본이 없습니다."
            )
        feeds.append(str(found))
    args.known_good_hash_feed = feeds
    rule_set = None
    if options.get("rules"):
        rules_record = next(
            (item for item in audit["provenance"].get("input_files") or [] if item.get("label") == "rules"), {}
        )
        rules_path = _replay_input_file([Path(str(options["rules"]))], str(rules_record.get("sha256") or ""))
        if rules_path is None:
            parser.error(f"--replay-audit: 감사 기록의 규칙 파일 {options['rules']}과 같은 판본을 찾을 수 없습니다.")
        try:
            rule_set = load_rule_set(rules_path)
        except (OSError, ValueError, RuleConfigError) as exc:
            parser.error(f"--replay-audit: invalid rules file: {exc}")
    recorded_build = options.get("tool_build") if isinstance(options.get("tool_build"), Mapping) else {}
    current_build = run_tool_build_identity()
    if recorded_build and recorded_build.get("package_source_sha256") != current_build["package_source_sha256"]:
        print(
            "경고: 감사 기록과 다른 rapidtriage 빌드로 재생합니다 "
            f"(기록 {recorded_build.get('version')} {str(recorded_build.get('package_source_sha256'))[:12]}, "
            f"현재 {current_build['version']} {str(current_build['package_source_sha256'])[:12]}).",
            file=sys.stderr,
        )
    return rule_set


def handle_run(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        if getattr(args, "replay_audit", None):
            rule_set = apply_replay_audit(args, parser)
        elif not args.mode:
            parser.error("the following arguments are required: --mode (or --replay-audit)")
        root = Path(args.root).expanduser().resolve()
        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else default_run_output_dir(root, args.mode, read_only=args.read_only)
        )
        skip_groups = list(getattr(args, "skip_group", None) or [])
        skip_tasks = list(getattr(args, "skip_task", None) or [])
        if not getattr(args, "kakaotalk_memory", True) and "kakaotalk-memory" not in skip_tasks:
            skip_tasks.append("kakaotalk-memory")
        if getattr(args, "print_plan", None):
            try:
                plan = build_run_plan(
                    mode=args.mode,
                    carve=getattr(args, "carve", False),
                    extract=getattr(args, "extract", False),
                    case_db=getattr(args, "case_db", True),
                    skip_groups=skip_groups,
                    skip_tasks=skip_tasks,
                )
            except PlanTargetError as exc:
                parser.error(str(exc))
            if args.print_plan == "json":
                print(json.dumps(plan, ensure_ascii=False, indent=2))
            else:
                print(format_plan_table(plan))
            return 0
        previous_handlers = _install_cancel_handlers(output_dir)
        try:
            payload = _run_interruptibly(
                bool(previous_handlers),
                run_triage_mode,
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
                extract_enabled=getattr(args, "extract", False),
                known_good_hash_feeds=args.known_good_hash_feed,
                hide_known_good=args.hide_known_good,
                known_good_max_hash_bytes=args.known_good_max_hash_bytes,
                rule_set=rule_set,
                columnar_store=args.columnar_store,
                carve=getattr(args, "carve", False),
                collector_options=(
                    {"eventlog": eventlog_collector_options(args)} if eventlog_collector_options(args) else None
                ),
                case_db=getattr(args, "case_db", True),
                skip_groups=skip_groups,
                skip_tasks=skip_tasks,
                actor="cli",
            )
        except (RunModeError, PlanTargetError) as exc:
            parser.error(str(exc))
        finally:
            _restore_handlers(previous_handlers)
        plan = payload.get("plan") if isinstance(payload.get("plan"), Mapping) else {}
        print(f"Saved run summary JSON: {payload['outputs']['summary']}")
        print(f"Saved run report: {payload['outputs']['report']}")
        if payload.get("audit"):
            print(f"Saved audit JSON: {payload['audit']}")
        print(
            f"Docs matches: {payload['summary']['document_match_count']}  "
            f"File candidates: {payload['summary']['file_candidate_count']}"
        )
        if plan.get("outcome") and plan.get("outcome") != "complete":
            print(f"Run plan outcome: {plan.get('outcome')} (see {payload['outputs'].get('plan')})")
        stuck = [item for item in plan.get("stuck_providers") or [] if isinstance(item, Mapping)]
        if stuck:
            print(
                "Providers still inside a call after the cancel grace period (left running, rows after the cancel dropped): "
                + ", ".join(str(item.get("task")) for item in stuck)
            )
        if plan.get("outcome") == "cancelled":
            return EXIT_CANCELLED
        return 0


def handle_run_plan(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        output_dir = Path(args.output_dir).expanduser().resolve()
        progress = load_run_progress_view(output_dir)
        plan = progress.get("plan") if isinstance(progress, Mapping) else None
        if not isinstance(plan, Mapping):
            plan_file = output_dir / "rapidtriage-run-plan.json"
            try:
                plan = json.loads(plan_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                parser.error(f"run plan not found in {output_dir}")
        if args.json:
            print(json.dumps({**plan, "run_status": (progress or {}).get("status")}, ensure_ascii=False, indent=2))
            return 0
        status = (progress or {}).get("status")
        print(f"런 상태: {status}" + (" · 응답 없음(심장박동 90초 넘게 없음)" if (progress or {}).get("stale") else ""))
        if (progress or {}).get("heartbeat_at"):
            print(f"마지막 신호: {progress['heartbeat_at']}")
        print(format_plan_table(plan))
        return 0


def parse_control_targets(raw_targets: list[str]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for raw in raw_targets:
        key, sep, value = str(raw).partition(":")
        if not sep or key not in {"group", "task"} or not value.strip():
            raise PlanTargetError(f"대상 형식은 group:ID 또는 task:ID 입니다: {raw}")
        targets.append({key: value.strip()})
    return targets


def handle_run_control(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        output_dir = Path(args.output_dir).expanduser().resolve()
        progress = load_run_progress_view(output_dir)
        if not isinstance(progress, Mapping) or progress.get("status") != "running":
            print("실행 중인 런이 아닙니다", file=sys.stderr)
            return 2
        try:
            targets = parse_control_targets(args.target)
        except PlanTargetError as exc:
            parser.error(str(exc))
        action = args.action.replace("-", "_")
        if action == "cancel" and not targets:
            action = "cancel_all"
        if action == "skip" and not targets:
            parser.error("대상을 지정하세요 (--target group:ID|task:ID)")
        plan = progress.get("plan") if isinstance(progress.get("plan"), Mapping) else {}
        accepted, rejected, _effects = evaluate_control(plan, action, targets)
        for item in rejected:
            print(f"거부: {item.get('target')} — {item.get('reason')}", file=sys.stderr)
        if action in {"cancel", "skip"} and not accepted:
            return 1
        if action in {"cancel_all", "finish"} and rejected:
            # The report stage started: the run's outcome is settled.
            return 1
        try:
            request = append_control_request(output_dir, action, accepted, actor="cli")
        except ControlFileError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(json.dumps({"request": request, "accepted": accepted, "rejected": rejected}, ensure_ascii=False, indent=2))
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
        collector_options: dict[str, object] = {}
        if args.eventlog_message_catalog:
            collector_options["message_catalog_path"] = Path(args.eventlog_message_catalog).expanduser().resolve()
        eventlog_options = eventlog_collector_options(args)
        if eventlog_options and args.kind != "eventlog":
            parser.error("--eventlog-structure-rows/--eventlog-record-detail can only be used with --kind eventlog")
        collector_options.update(eventlog_options)
        if args.kind == "mobile-export":
            # R6 S2: adb backup inner databases are copied next to --output (never the evidence tree).
            inner_dir = output.parent / MOBILE_INNER_DIR_NAME
            if root.is_dir() and path_is_within(inner_dir, root):
                # R6 S2 review: never write copies into the evidence being scanned. The provider
                # also refuses such a folder (member inventory only, with a collection note).
                print(
                    f"경고: adb 백업 해제 사본 폴더({inner_dir})가 스캔 대상 증거 폴더({root}) 안이라 "
                    "내부 DB 해제를 건너뜁니다(구성원 목록만 기록). --output을 증거 폴더 밖으로 지정하십시오.",
                    file=sys.stderr,
                )
            collector_options["inner_dir"] = inner_dir
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
                remote=args.remote,
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
    "run-plan": handle_run_plan,
    "run-control": handle_run_control,
    "artifacts": handle_artifacts,
    "web": handle_web,
    "doctor": handle_doctor,
    "enterprise-policy": handle_enterprise_policy,
    "rearchitecture-status": handle_rearchitecture_status,
    "worker-parse": handle_worker_parse,
    "plugins": handle_plugins,
    "keyword-packs": handle_keyword_packs,
}
