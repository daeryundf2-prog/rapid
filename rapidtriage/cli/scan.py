"""Document, file, and artifact scan subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..artifacts.email_external import (
        EmailExternalParserError,
        run_email_external_parse,
)
from ..core.artifact_taxonomy import build_taxonomy_audit
from ..core.audit import audit_path_for, write_audit_record
from ..core.compare import CompareError, compare_many_paths, compare_paths
from ..core.docs import build_manifest, query_docs_index, run_docs_search, write_result
from ..core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, run_extract
from ..core.files import FileScanError, build_known_good_index_payload, run_files_scan
from ..core.input_root import resolve_input_root
from ..core.normalize import NormalizationError, build_normalized_case


def handle_docs(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        input_root = resolve_input_root(root, kind=getattr(args, "input_kind", None))
        output = Path(args.output).expanduser().resolve()
        index_output = Path(args.index_output).expanduser().resolve() if args.index_output else None
        payload = run_docs_search(
            root,
            args.keyword,
            limit=args.limit,
            input_kind=args.input_kind,
            rule_set=rule_set,
            index_output=index_output,
        )
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="docs",
            options={
                "keywords": args.keyword,
                "limit": args.limit,
                "output": str(output),
                "index_output": str(index_output) if index_output else None,
                "input_kind": args.input_kind,
                "rules": args.rules,
            },
            input_root=input_root,
            output_files=[("docs-json", output)] + ([("docs-index", index_output)] if index_output else []),
        )
        print(f"Saved docs search JSON: {output}")
        if index_output is not None:
            print(f"Saved docs index JSON: {index_output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Candidates: {payload['summary']['candidate_count']}  Matches: {payload['summary']['match_count']}")
        return 0



def handle_docs_index_search(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        keywords = list(args.keyword or []) + list(args.terms or [])
        if not keywords:
            parser.error("docs-index-search requires at least one -k/--keyword or positional term")
        index_path = Path(args.index).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = query_docs_index(index_path, keywords, limit=args.limit)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="docs-index-search",
            options={
                "keywords": keywords,
                "limit": args.limit,
                "output": str(output),
            },
            input_files=[("docs-index", index_path)],
            output_files=[("docs-index-search-json", output)],
            notes=[
                "docs-index-search does not store or return full extracted text; verify hits with the source viewer before reporting.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved docs index search JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Matched documents: {summary['matched_document_count']}  "
                f"Returned: {summary['returned_result_count']}  "
                f"Truncated: {summary['truncated']}"
            )
        return 0



def handle_manifest(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        input_root = resolve_input_root(root, kind=getattr(args, "input_kind", None))
        output = Path(args.output).expanduser().resolve()
        payload = build_manifest(root, [], input_kind=args.input_kind)
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="manifest",
            options={"keywords": [], "output": str(output), "input_kind": args.input_kind},
            input_root=input_root,
            output_files=[("manifest-json", output)],
        )
        print(f"Saved manifest JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        return 0



def handle_files(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        input_root = resolve_input_root(root, kind=getattr(args, "input_kind", None))
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_files_scan(
                root,
                input_kind=args.input_kind,
                categories=args.category,
                name_contains=args.name_contains,
                path_contains=args.path_contains,
                extensions=args.ext,
                modified_after=args.modified_after,
                modified_before=args.modified_before,
                limit=args.limit,
                rule_set=rule_set,
                known_good_hash_feeds=args.known_good_hash_feed,
                hide_known_good=args.hide_known_good,
                known_good_max_hash_bytes=args.known_good_max_hash_bytes,
            )
        except FileScanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="files",
            options={
                "categories": args.category or [],
                "name_contains": args.name_contains or [],
                "path_contains": args.path_contains or [],
                "extensions": args.ext or [],
                "modified_after": args.modified_after,
                "modified_before": args.modified_before,
                "limit": args.limit,
                "known_good_hash_feeds": args.known_good_hash_feed,
                "hide_known_good": args.hide_known_good,
                "known_good_max_hash_bytes": args.known_good_max_hash_bytes,
                "output": str(output),
                "input_kind": args.input_kind,
                "rules": args.rules,
            },
            input_root=input_root,
            output_files=[("files-json", output)],
        )
        print(f"Saved file scan JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Scanned: {payload['summary']['scanned_file_count']}  Candidates: {payload['summary']['candidate_count']}")
        return 0



def handle_extract(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        input_json = Path(args.input_json).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        manifest_output = (
            Path(args.manifest).expanduser().resolve()
            if args.manifest
            else output_dir / DEFAULT_EXTRACT_MANIFEST_NAME
        )
        try:
            payload = run_extract(
                input_json,
                output_dir,
                name_contains=args.name_contains,
                path_contains=args.path_contains,
                extensions=args.ext,
                categories=args.category,
                kinds=args.kind,
                limit=args.limit,
                dry_run=args.dry_run,
                read_only=args.read_only,
                max_extract_size_bytes=args.max_extract_size_bytes,
                max_file_count=args.max_file_count,
                overwrite=args.overwrite,
            )
        except ExtractError as exc:
            parser.error(str(exc))
        write_result(payload, manifest_output)
        audit_output = audit_path_for(manifest_output)
        write_audit_record(
            audit_output,
            command="extract",
            options={
                "manifest": str(manifest_output),
                "output_dir": str(output_dir),
                "name_contains": args.name_contains or [],
                "path_contains": args.path_contains or [],
                "extensions": args.ext or [],
                "categories": args.category or [],
                "kinds": args.kind or [],
                "limit": args.limit,
                "dry_run": args.dry_run,
                "read_only": args.read_only,
                "max_extract_size_bytes": args.max_extract_size_bytes,
                "max_file_count": args.max_file_count,
                "overwrite": args.overwrite,
            },
            input_root=Path(payload["root"]).resolve() if payload.get("root") else None,
            input_files=[("input-json", input_json)],
            output_files=[("extract-manifest", manifest_output)]
            + [
                (f"extracted:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in payload.get("entries", [])
            ],
        )
        print(f"Saved extract manifest JSON: {manifest_output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Selected: {payload['summary']['selected_count']}  Extracted: {payload['summary']['extracted_count']}")
        return 0



def handle_compare(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        compare_paths_input = [Path(value).expanduser().resolve() for value in args.paths]
        if len(compare_paths_input) < 2:
            parser.error("compare requires at least two files")
        output = Path(args.output).expanduser().resolve()
        try:
            if len(compare_paths_input) == 2:
                payload = compare_paths(
                    compare_paths_input[0],
                    compare_paths_input[1],
                    left_label=args.left_label,
                    right_label=args.right_label,
                    hash_files=not args.no_hash,
                    include_text_diff=not args.no_text_diff,
                    max_text_bytes=args.max_text_bytes,
                    diff_context=args.diff_context,
                    selection_rationale=args.selection_rationale,
                    review_notes=args.review_note,
                )
            else:
                payload = compare_many_paths(
                    compare_paths_input,
                    labels=args.label,
                    hash_files=not args.no_hash,
                    include_text_diff=not args.no_text_diff,
                    max_text_bytes=args.max_text_bytes,
                    diff_context=args.diff_context,
                    selection_rationale=args.selection_rationale,
                    review_notes=args.review_note,
                )
        except CompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="compare",
            options={
                "paths": [str(path) for path in compare_paths_input],
                "left_label": args.left_label,
                "right_label": args.right_label,
                "labels": args.label or [],
                "output": str(output),
                "hash": not args.no_hash,
                "text_diff": not args.no_text_diff,
                "max_text_bytes": args.max_text_bytes,
                "diff_context": args.diff_context,
                "selection_rationale": args.selection_rationale,
                "review_note_count": len(args.review_note or []),
            },
            input_files=[(f"input:{index}", path) for index, path in enumerate(compare_paths_input, start=1)],
            output_files=[("compare-json", output)],
            notes=[
                "Compare output is review-oriented; preserve the original files and hashes for evidentiary submission.",
                "Use vsc-compare for directory tree or Volume Shadow Copy comparisons.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            status_counts = summary.get("status_counts", {})
            status_text = ", ".join(f"{key}={value}" for key, value in status_counts.items())
            print(f"Saved compare JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Results: {summary['result_count']}  Status: {status_text or 'none'}")
        return 0



def handle_known_good_index(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        output = Path(args.output).expanduser().resolve()
        try:
            payload = build_known_good_index_payload([Path(feed) for feed in args.feed])
        except FileScanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="known-good-index",
            options={
                "feeds": [str(Path(feed).expanduser().resolve()) for feed in args.feed],
                "output": str(output),
            },
            output_files=[("known-good-index-json", output)],
            notes=[
                "Local known-good index generation does not download or update NSRL by itself.",
                "Use an organization-approved NSRL/RDS source and preserve this JSON with the validation bundle.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved known-good index JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Feeds: {summary['feed_count']}  Records: {summary['record_count']}  "
                f"NSRL feeds: {summary['nsrl_rds_feed_count']}  Rejected tokens: {summary['rejected_feed_token_count']}"
            )
        return 0



def handle_normalize(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_normalized_case(Path(args.run_output).expanduser().resolve(), case_id=args.case_id)
        except (NormalizationError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        output = Path(args.output).expanduser().resolve()
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved normalized case JSON: {output}")
            print(f"Models: {payload['summary']}")
        return 0



def handle_taxonomy_audit(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        repo_root = Path(args.repo_root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        payload = build_taxonomy_audit(repo_root)
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic artifact taxonomy audit")
            print(f"Saved taxonomy audit JSON: {output}")
            print(
                "Targets: "
                f"{summary['target_count']}  Covered: {summary['covered_count']}  "
                f"Partial: {summary['partial_count']}  Missing: {summary['missing_count']}"
            )
            print(
                "Implementation evidence: "
                f"collectors={summary['collector_count']}  "
                f"artifact_type_literals={summary['artifact_type_literal_count']}"
            )
            priority_missing = payload.get("priority_missing")
            if isinstance(priority_missing, list) and priority_missing:
                print("Priority missing targets:")
                for item in priority_missing[:8]:
                    if isinstance(item, dict):
                        print(f"- {item.get('id')}: {item.get('title')}")
            priority_partial = payload.get("priority_partial")
            if isinstance(priority_partial, list) and priority_partial:
                print("Priority partial targets:")
                for item in priority_partial[:8]:
                    if isinstance(item, dict):
                        print(f"- {item.get('id')}: {item.get('title')}")
        return 1 if args.strict and not payload["summary"]["strict_pass"] else 0



def handle_email_external_parse(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_email_external_parse(
                source_path=Path(args.source).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                preferred_tool=args.preferred_tool,
                timeout_seconds=args.timeout_seconds,
                overwrite=args.overwrite,
            )
        except (EmailExternalParserError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved email external parser JSON: {payload['outputs']['json']}")
            print(f"Saved email external parser report: {payload['outputs']['markdown']}")
            print(f"Status: {payload['status']}  Export files: {payload['summary']['export_file_count']}")
        return 1 if payload["status"] == "failed" else 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "docs": handle_docs,
    "docs-index-search": handle_docs_index_search,
    "manifest": handle_manifest,
    "files": handle_files,
    "extract": handle_extract,
    "compare": handle_compare,
    "known-good-index": handle_known_good_index,
    "normalize": handle_normalize,
    "taxonomy-audit": handle_taxonomy_audit,
    "email-external-parse": handle_email_external_parse,
}
