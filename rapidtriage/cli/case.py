"""Case-file, case-database, sample-case, and bundle subcommand handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.audit import audit_path_for, write_audit_record
from ..core.backup import BackupError, build_case_backup, restore_case_backup
from ..core.bundle import BundleError, build_submission_bundle
from ..core.case import (
        CaseBookmarkError,
        create_or_update_case_payload,
        load_case_payload,
        save_case_payload,
)
from ..core.case_catalog import CaseCatalog, CaseCatalogError
from ..core.case_db import CaseDatabaseError, open_case_database
from ..core.docs import write_result
from ..core.keyword_packs import KeywordPackError, resolve_keyword_packs
from ..core.run import RunModeError
from ..core.sample_case import SampleCaseError, create_sample_case, run_sample_workflow
from .helpers import (
        build_source_read_review_note,
        load_source_read_review_package,
        resolve_reviewer_identity,
)


def handle_case(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        case_path = Path(args.case_json).expanduser().resolve()
        if args.show:
            try:
                payload = load_case_payload(case_path)
            except (FileNotFoundError, CaseBookmarkError) as exc:
                parser.error(str(exc))
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0

        source_path = Path(args.source).expanduser().resolve() if args.source else None
        try:
            payload = create_or_update_case_payload(
                case_path,
                case_id=args.case_id,
                title=args.title,
                source_path=source_path,
                source_pointer=args.pointer,
                bookmark_id=args.bookmark_id,
                tags=args.tag or [],
                note=args.note,
                review_status=args.review_status,
                include_in_report=args.include_in_report if args.include_in_report else None,
            )
        except (FileNotFoundError, CaseBookmarkError) as exc:
            parser.error(str(exc))
        save_case_payload(case_path, payload)
        audit_output = audit_path_for(case_path)
        write_audit_record(
            audit_output,
            command="case",
            options={
                "case_id": args.case_id,
                "title": args.title,
                "source": str(source_path) if source_path else None,
                "pointer": args.pointer,
                "bookmark_id": args.bookmark_id,
                "tags": args.tag or [],
                "review_status": args.review_status,
                "include_in_report": args.include_in_report,
            },
            input_files=[("source-json", source_path)] if source_path else [],
            output_files=[("case-json", case_path)],
        )
        print(f"Saved case JSON: {case_path}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Bookmarks: {payload['summary']['bookmark_count']}")
        return 0



def handle_case_backup(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_case_backup(
                database_path=Path(args.database).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (BackupError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved case backup manifest: {Path(args.output_dir).expanduser().resolve() / 'rapidtriage-case-backup-manifest.json'}")
            print(f"Copied files: {payload['copied_count']}")
        return 0



def handle_case_restore(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = restore_case_backup(
                manifest_path=Path(args.manifest).expanduser().resolve(),
                output_path=Path(args.output).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (BackupError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Restored case database: {payload['restored_database']}")
            print(f"Hash verified: {payload['hash_verified']}")
        return 0



def handle_case_acquisition(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        database = open_case_database(Path(args.database).expanduser().resolve())
        try:
            if args.list:
                records = database.list_acquisition_metadata(args.case_id)
                payload = {
                    "command": "case-acquisition",
                    "database": str(database.path),
                    "case_id": args.case_id,
                    "records": records,
                    "record_count": len(records),
                }
            else:
                record = database.record_acquisition_metadata(
                    case_id=args.case_id,
                    evidence_source_citation_id=args.evidence_source_citation_id,
                    operator=args.operator,
                    acquisition_started_at=args.started_at,
                    acquisition_completed_at=args.completed_at,
                    source_identifier=args.source_identifier,
                    write_blocker=args.write_blocker,
                    acquisition_tool=args.tool,
                    acquisition_tool_version=args.tool_version,
                    whole_source_sha256=args.whole_source_sha256,
                    notes=args.notes,
                )
                payload = {
                    "command": "case-acquisition",
                    "database": str(database.path),
                    "case_id": args.case_id,
                    "record": record,
                }
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        elif args.list:
            print(f"Acquisition metadata records: {payload['record_count']}")
            for record in payload["records"]:
                print(f"- {record['citation_id']} source={record['source_identifier']} operator={record['operator']}")
        else:
            record = payload["record"]
            print(f"Recorded acquisition metadata: {record['citation_id']}")
            if record.get("whole_source_sha256"):
                print(f"Whole-source SHA256: {record['whole_source_sha256']}")
        return 0



def handle_case_db(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        database_path = Path(args.database).expanduser().resolve()
        try:
            database = open_case_database(database_path)
            init_payload = database.initialize()
            created_case = None
            imported_run = None
            imported_vsc_compare = None
            imported_worker_jsonl = None
            search_index_health = None
            rebuilt_search_indexes = None
            if args.create_case:
                created_case = database.create_case(
                    case_id=args.create_case,
                    name=args.name,
                    description=args.description,
                    examiner=args.examiner,
                    organization=args.organization,
                    case_root=Path(args.case_root).expanduser().resolve() if args.case_root else None,
                )
                database.add_audit_event(
                    case_id=created_case.case_id,
                    action="case.created",
                    target_type="case",
                    target_id=created_case.case_id,
                    params_json=json.dumps({"command": "case-db"}, ensure_ascii=False),
                )
            if args.import_run:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-run")
                imported_run = database.import_run_output(
                    Path(args.import_run).expanduser().resolve(),
                    case_id=import_case_id,
                    case_name=args.name,
                )
            if args.import_vsc_compare:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-vsc-compare")
                imported_vsc_compare = database.import_vsc_compare(
                    Path(args.import_vsc_compare).expanduser().resolve(),
                    case_id=import_case_id,
                    case_name=args.name,
                )
            if args.import_worker_jsonl:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-worker-jsonl")
                imported_worker_jsonl = database.import_worker_jsonl(
                    Path(args.import_worker_jsonl).expanduser().resolve(),
                    case_id=import_case_id,
                    case_name=args.name,
                )
            if args.search_index_health:
                health_case_id = args.case_id or args.create_case
                if not health_case_id:
                    parser.error("--case-id or --create-case is required with --search-index-health")
                search_index_health = database.search_index_health(health_case_id)
            if args.rebuild_search_indexes:
                rebuild_case_id = args.case_id or args.create_case
                if not rebuild_case_id:
                    parser.error("--case-id or --create-case is required with --rebuild-search-indexes")
                rebuilt_search_indexes = database.rebuild_search_indexes(rebuild_case_id)
                search_index_health = rebuilt_search_indexes["after"]
            cases = database.list_cases() if args.list or created_case is not None else []
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        payload = {
            "command": "case-db",
            "database": str(database_path),
            "schema_version": init_payload["schema_version"],
            "tables": init_payload["tables"],
            "created_case": created_case.to_dict() if created_case else None,
            "imported_run": imported_run,
            "imported_vsc_compare": imported_vsc_compare,
            "imported_worker_jsonl": imported_worker_jsonl,
            "search_index_health": search_index_health,
            "rebuilt_search_indexes": rebuilt_search_indexes,
            "cases": [case.to_dict() for case in cases],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Initialized case DB: {database_path}")
            print(f"Schema version: {payload['schema_version']}")
            if created_case:
                print(f"Created case: {created_case.case_id}")
            if imported_run:
                print(f"Imported run into case: {imported_run['case_id']}")
                print(f"Import counts: {imported_run['summary']}")
            if imported_vsc_compare:
                print(f"Imported VSC compare into case: {imported_vsc_compare['case_id']}")
                print(f"VSC import counts: {imported_vsc_compare['summary']}")
            if imported_worker_jsonl:
                print(f"Imported worker JSONL into case: {imported_worker_jsonl['case_id']}")
                print(f"Worker import counts: {imported_worker_jsonl['summary']}")
            if search_index_health:
                print(
                    "Search index health: "
                    f"{search_index_health['status']} "
                    f"(missing={search_index_health['summary']['missing_index_rows']}, "
                    f"orphan={search_index_health['summary']['orphan_fts_rows']})"
                )
            if rebuilt_search_indexes:
                print(f"Rebuilt search indexes: {rebuilt_search_indexes['status']}")
            if cases:
                print(f"Cases: {len(cases)}")
                for case in cases:
                    print(f"- {case.case_id}: {case.name}")
        return 0



def handle_case_search(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        database_path = Path(args.database).expanduser().resolve()
        try:
            resolved_keywords = resolve_keyword_packs(
                args.keyword,
                pack_names=args.keyword_pack,
                pack_files=[Path(path) for path in (args.keyword_pack_file or [])],
            )
        except KeywordPackError as exc:
            parser.error(str(exc))
        try:
            database = open_case_database(database_path)
            payload = database.search_case(
                case_id=args.case_id,
                keywords=resolved_keywords,
                limit=args.limit,
                cursor=args.cursor,
                sources=args.source,
                metadata_filters=args.metadata,
                review_status=args.review_status,
                verification_status=args.verification_status,
            )
            if args.save_as:
                payload["saved_search"] = database.save_search(
                    case_id=args.case_id,
                    name=args.save_as,
                    keywords=resolved_keywords,
                    limit=args.limit,
                    sources=args.source,
                    metadata_filters=args.metadata,
                    review_status=args.review_status,
                    verification_status=args.verification_status,
                    created_by="cli",
                )
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json or args.output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Case search matches: {payload['summary']['match_count']}")
            for match in payload["matches"]:
                print(
                    f"- {match['citation_id']} [{match['source']}] "
                    f"{match.get('title') or match.get('path')}: {match.get('preview') or ''}"
                )
        return 0



def handle_case_review(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            database = open_case_database(Path(args.database).expanduser().resolve())
            review_note_parts = [args.note.strip()] if args.note else []
            source_citation_package = None
            if args.source_read_json:
                source_citation_package = load_source_read_review_package(Path(args.source_read_json).expanduser().resolve())
                review_note_parts.append(build_source_read_review_note(source_citation_package))
            payload = database.mark_review(
                case_id=args.case_id,
                target_type=args.target_type,
                target_id=args.target_id,
                status=args.status,
                verification_status=args.verification_status,
                tags=args.tag or [],
                note="\n\n".join(review_note_parts) if review_note_parts else None,
                reviewer=resolve_reviewer_identity(args.reviewer),
                assignee=args.assignee,
                priority=args.priority,
                due_at=args.due_at,
                include_in_report=args.include_in_report,
                source_citation_package=source_citation_package,
            )
        except (CaseDatabaseError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved review mark: {payload['citation_id']}")
            print(f"Target: {payload['target_type']}:{payload['target_id']}")
            print(f"Status: {payload['status']} / {payload['verification_status']}")
        return 0



def handle_case_db_report(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            database = open_case_database(Path(args.database).expanduser().resolve())
            payload = database.export_reviewed_items(
                case_id=args.case_id,
                include_all=args.include_all,
                max_items=args.max_items,
            )
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json or args.output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Case DB report candidates: {payload['summary']['exported_item_count']}")
            for item in payload["items"]:
                print(
                    f"- {item['review_citation_id']} -> {item['target_citation_id']} "
                    f"[{item['source']}] {item.get('title') or item.get('path')}"
                )
        return 0



def handle_case_catalog(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        catalog = CaseCatalog(Path(args.catalog).expanduser().resolve())
        added_case = None
        exported = None
        imported = None
        try:
            if args.add_run:
                if not args.case_id:
                    parser.error("--case-id is required with --add-run")
                added_case = catalog.add_run(
                    run_output=Path(args.add_run).expanduser().resolve(),
                    case_id=args.case_id,
                    name=args.name,
                    description=args.description,
                    examiner=args.examiner,
                    organization=args.organization,
                )
            if args.export:
                archive = Path(args.archive).expanduser().resolve() if args.archive else Path(f"{args.export}.zip").resolve()
                exported = catalog.export_case(case_id=args.export, output_zip=archive)
            if args.import_archive:
                imported = catalog.import_archive(Path(args.import_archive).expanduser().resolve())
            cases = catalog.list_cases() if args.list or not any([added_case, exported, imported]) else []
        except CaseCatalogError as exc:
            parser.error(str(exc))
        payload = {
            "command": "case-catalog",
            "catalog": str(catalog.path),
            "added_case": added_case,
            "exported": exported,
            "imported": imported,
            "cases": cases,
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            if added_case:
                print(f"Added case: {added_case['case_id']}")
            if exported:
                print(f"Exported case archive: {exported['archive']}")
            if imported:
                print(f"Imported case: {imported['case_id']}")
            if cases:
                print(f"Cases: {len(cases)}")
                for case in cases:
                    print(f"- {case.get('case_id')}: {case.get('name')} ({len(case.get('runs', []))} runs)")
        return 0



def handle_sample(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = (
                run_sample_workflow(output_dir, mode=args.mode, overwrite=args.overwrite, read_only=args.read_only)
                if args.run
                else create_sample_case(output_dir, overwrite=args.overwrite)
            )
        except (SampleCaseError, RunModeError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Created sample evidence: {payload['evidence_root']}")
            print(f"Saved expected output guide: {payload['expected']}")
            if payload.get("run"):
                run_payload = payload["run"]
                print(f"Saved sample run summary JSON: {run_payload['summary']}")
                print(f"Saved sample run report: {run_payload['report']}")
                print(f"Saved training lab manifest: {run_payload['training_lab_manifest']}")
        return 0



def handle_bundle(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_submission_bundle(
                case_json=Path(args.case_json).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                allowed_roots=[Path(path).expanduser().resolve() for path in args.allowed_root],
                include_all=args.include_all,
                max_items=args.max_items,
                title=args.title,
            )
        except (BundleError, CaseBookmarkError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved bundle manifest: {payload['outputs']['manifest']}")
            print(f"Saved bundle archive: {payload['outputs']['archive']}")
            print(f"Archive SHA256: {payload['archive_hashes']['sha256']}")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "case": handle_case,
    "case-backup": handle_case_backup,
    "case-restore": handle_case_restore,
    "case-acquisition": handle_case_acquisition,
    "case-db": handle_case_db,
    "case-search": handle_case_search,
    "case-review": handle_case_review,
    "case-db-report": handle_case_db_report,
    "case-catalog": handle_case_catalog,
    "sample": handle_sample,
    "bundle": handle_bundle,
}
