"""Timeline, search, and evidence-analysis subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.audit import audit_path_for, write_audit_record
from ..core.docs import write_result
from ..core.evidence import identify_evidence
from ..core.indicators import IndicatorSummaryError, build_indicator_summary
from ..core.input_root import resolve_input_root
from ..core.keyword_packs import (
        KeywordPackError,
        keyword_pack_selection_profile,
        resolve_keyword_packs,
)
from ..core.ocr_queue import OcrQueueError, build_ocr_queue
from ..core.search import SearchError, run_unified_search
from ..core.source_reader import (
        SourceReadError,
        render_source_read_text,
        run_source_read,
        run_source_search,
)
from ..core.timeline import TimelineError, build_timeline_report, run_timeline
from ..core.timeline_export import TimelineExportError, build_unified_timeline_export


def handle_timeline(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        report_output = (
            Path(args.report).expanduser().resolve()
            if args.report
            else output.with_name(f"{output.stem}-report.md")
        )
        try:
            payload = run_timeline(
                root=root,
                input_kind=args.input_kind,
                files_inputs=[Path(value) for value in (args.files or [])],
                docs_inputs=[Path(value) for value in (args.docs or [])],
                artifacts_inputs=[Path(value) for value in (args.artifacts or [])],
                rule_set=rule_set,
            )
        except TimelineError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        report_output.parent.mkdir(parents=True, exist_ok=True)
        report_output.write_text(build_timeline_report(payload), encoding="utf-8")
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="timeline",
            options={
                "files": args.files or [],
                "docs": args.docs or [],
                "artifacts": args.artifacts or [],
                "input_kind": args.input_kind,
                "rules": str(rule_set.path) if rule_set else None,
                "output": str(output),
                "report": str(report_output),
            },
            input_root=resolve_input_root(root, kind=args.input_kind),
            input_files=[
                *[(f"files:{index}", Path(path)) for index, path in enumerate(args.files or [], start=1)],
                *[(f"docs:{index}", Path(path)) for index, path in enumerate(args.docs or [], start=1)],
                *[(f"artifacts:{index}", Path(path)) for index, path in enumerate(args.artifacts or [], start=1)],
            ],
            output_files=[("timeline-json", output), ("timeline-report", report_output)],
        )
        print(f"Saved timeline JSON: {output}")
        print(f"Saved timeline report: {report_output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Events: {payload['summary']['event_count']}")
        return 0



def handle_timeline_export(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_unified_timeline_export(
                Path(args.run_output).expanduser().resolve(),
                start=args.start,
                end=args.end,
                source=args.source,
                event_type=args.event_type,
                reviewed_status=args.reviewed_status,
                limit=args.limit,
            )
        except (TimelineExportError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        output = Path(args.output).expanduser().resolve()
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved timeline export JSON: {output}")
            print(f"Events: {payload['summary']['event_count']}")
        return 0



def handle_search(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            resolved_keywords = resolve_keyword_packs(
                args.keyword,
                pack_names=args.keyword_pack,
                pack_files=[Path(path) for path in (args.keyword_pack_file or [])],
            )
        except KeywordPackError as exc:
            parser.error(str(exc))
        try:
            payload = run_unified_search(
                run_output,
                resolved_keywords,
                include_ocr=not args.no_ocr,
                limit=args.limit,
                include_analysis=not args.no_analysis,
                search_mode=args.search_mode,
                fuzzy_distance=args.fuzzy_distance,
                proximity_window=args.proximity_window,
                hide_known_good=args.hide_known_good,
            )
            if args.keyword_pack or args.keyword_pack_file:
                payload["keyword_pack_selection_profile"] = keyword_pack_selection_profile(
                    pack_names=args.keyword_pack or [],
                    keyword_count=len(resolved_keywords),
                    custom_file_count=len(args.keyword_pack_file or []),
                    expanded_keywords=resolved_keywords,
                )
        except SearchError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="search",
            options={
                "keywords": resolved_keywords,
                "output": str(output),
                "limit": args.limit,
                "ocr": not args.no_ocr,
                "analysis": not args.no_analysis,
                "search_mode": args.search_mode,
                "fuzzy_distance": args.fuzzy_distance,
                "proximity_window": args.proximity_window,
                "hide_known_good": args.hide_known_good,
                "keyword_pack": args.keyword_pack or [],
                "keyword_pack_file": args.keyword_pack_file or [],
            },
            input_files=[("run-summary", input_summary)],
            output_files=[("search-json", output)],
        )
        print(f"Saved search JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Matches: {payload['summary']['match_count']}")
        return 0



def handle_source_read(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_source_read(
                run_output,
                args.path,
                include_hashes=args.hash,
                max_chars=args.max_chars,
                hex_bytes=args.hex_bytes,
                sqlite_table=args.sqlite_table,
                sqlite_offset=args.sqlite_offset,
                sqlite_limit=args.sqlite_limit,
                sqlite_where_column=args.sqlite_where_column,
                sqlite_where_contains=args.sqlite_where_contains,
            )
        except SourceReadError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="source-read",
            options={
                "path": args.path,
                "output": str(output),
                "max_chars": args.max_chars,
                "hex_bytes": args.hex_bytes,
                "sqlite_table": args.sqlite_table,
                "sqlite_offset": args.sqlite_offset,
                "sqlite_limit": args.sqlite_limit,
                "sqlite_where_column": args.sqlite_where_column,
                "sqlite_where_contains": bool(args.sqlite_where_contains),
                "hash": args.hash,
            },
            input_files=[("run-summary", input_summary), ("source-file", Path(str(payload["path"])))],
            output_files=[("source-read-json", output)],
        )
        print(f"Saved source-read JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(render_source_read_text(payload))
        return 0



def handle_source_search(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_source_search(
                run_output,
                args.path,
                args.keyword,
                limit=args.limit,
                context=args.context,
                max_chars=args.max_chars,
                byte_offset=args.byte_offset,
                max_search_bytes=args.max_search_bytes,
                sqlite_row_scan_limit=args.sqlite_row_scan_limit,
            )
        except SourceReadError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="source-search",
            options={
                "path": args.path,
                "keywords": args.keyword,
                "output": str(output),
                "limit": args.limit,
                "context": args.context,
                "max_chars": args.max_chars,
                "byte_offset": args.byte_offset,
                "max_search_bytes": args.max_search_bytes,
                "sqlite_row_scan_limit": args.sqlite_row_scan_limit,
            },
            input_files=[("run-summary", input_summary), ("source-file", Path(str(payload["path"])))],
            output_files=[("source-search-json", output)],
            notes=[
                "source-search is bounded current-source hit context; verify matches in source-read/source viewer before reporting.",
            ],
        )
        print(f"Saved source-search JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(
                f"Matches: {summary['match_count']}  Searchable: {payload['searchable']}  "
                f"Path: {payload['relative_path']}"
            )
            for match in payload["matches"][:8]:
                print(f"- {match['citation']}: {match['snippet']}")
        return 0



def handle_ocr_queue(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        previous = Path(args.previous).expanduser().resolve() if args.previous else None
        try:
            payload = build_ocr_queue(
                root,
                previous_queue=previous,
                retry_failures=args.retry_failures,
                max_items=args.max_items,
            )
        except OcrQueueError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="ocr-queue",
            options={
                "root": str(root),
                "output": str(output),
                "previous": str(previous) if previous else "",
                "retry_failures": args.retry_failures,
                "max_items": args.max_items,
            },
            input_files=[("root", root), *([("previous-queue", previous)] if previous else [])],
            output_files=[("ocr-queue-json", output)],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved OCR queue JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Candidates: {payload['summary']['candidate_count']}")
        return 0



def handle_indicators(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = build_indicator_summary(
                run_output,
                rule_set=rule_set,
                ti_feeds=[Path(path) for path in (args.ti_feed or [])],
                max_indicators=args.limit,
                max_sources_per_indicator=args.max_sources,
            )
        except IndicatorSummaryError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="indicators",
            options={
                "output": str(output),
                "limit": args.limit,
                "max_sources": args.max_sources,
                "rules": str(rule_set.path) if rule_set else None,
                "ti_feed": args.ti_feed or [],
            },
            input_files=[("run-summary", input_summary)],
            output_files=[("indicators-json", output)],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved indicators JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Indicators: {payload['summary']['indicator_count']}")
        return 0



def handle_evidence(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = identify_evidence(Path(args.source)).to_dict()
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Adapter: {payload['adapter']}")
            print(f"Format: {payload['detected_format']}")
            print(f"Supported now: {payload['supported']}")
            print(f"Support level: {payload.get('support_level', '')}")
            print(f"Scan strategy: {payload.get('scan_strategy', '')}")
            print(f"Message: {payload['message']}")
            if payload["missing_tools"]:
                print(f"Missing tools: {', '.join(payload['missing_tools'])}")
            next_actions = payload.get("next_actions") if isinstance(payload.get("next_actions"), list) else []
            if next_actions:
                print("Next actions:")
                for action in next_actions:
                    print(f"- {action}")
            warnings = payload.get("warnings") if isinstance(payload.get("warnings"), list) else []
            if warnings:
                print("Warnings:")
                for warning in warnings:
                    print(f"- {warning}")
            if args.output:
                print(f"Saved: {Path(args.output).expanduser().resolve()}")
            runbook = payload.get("ingest_workflow", {}).get("operator_runbook") if isinstance(payload.get("ingest_workflow"), dict) else None
            if isinstance(runbook, dict):
                commands = runbook.get("recommended_commands") if isinstance(runbook.get("recommended_commands"), dict) else {}
                if commands:
                    print("Recommended commands:")
                    for name, command in commands.items():
                        print(f"- {name}: {command}")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "timeline": handle_timeline,
    "timeline-export": handle_timeline_export,
    "search": handle_search,
    "source-read": handle_source_read,
    "source-search": handle_source_search,
    "ocr-queue": handle_ocr_queue,
    "indicators": handle_indicators,
    "evidence": handle_evidence,
}
