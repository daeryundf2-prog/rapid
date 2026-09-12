"""KakaoTalk artifact subcommand handlers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ..artifacts.kakaotalk_macos import (
        KakaoTalkMacOsReportError,
        run_kakaotalk_macos_report,
)
from ..core.audit import audit_path_for, write_audit_record
from ..core.kakaotalk import (
        KakaoTalkDecryptError,
        run_kakaotalk_decrypt,
        run_kakaotalk_key_store_inspect,
        run_kakaotalk_memory_carve,
        run_kakaotalk_sqlcipher_probe,
        run_kakaotalk_userdir_bruteforce,
        run_kakaotalk_windows_collect,
)
from .helpers import write_kakaotalk_message_residue_csv


def handle_kakaotalk_decrypt(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        decrypted_dir = Path(args.decrypted_dir).expanduser().resolve() if args.decrypted_dir else None
        try:
            payload = run_kakaotalk_decrypt(
                root,
                output=output,
                key_hex=args.key_hex,
                iv_hex=args.iv_hex,
                pragma=args.pragma,
                user_id=args.user_id,
                pragma_key_hex=args.pragma_key_hex,
                sys_uuid=args.sys_uuid,
                hdd_model=args.hdd_model,
                hdd_serial=args.hdd_serial,
                key_hex_env=args.key_hex_env,
                iv_hex_env=args.iv_hex_env,
                pragma_env=args.pragma_env,
                user_id_env=args.user_id_env,
                pragma_key_hex_env=args.pragma_key_hex_env,
                sys_uuid_env=args.sys_uuid_env,
                hdd_model_env=args.hdd_model_env,
                hdd_serial_env=args.hdd_serial_env,
                include_message_preview=args.include_message_preview,
                write_decrypted=args.write_decrypted,
                decrypted_dir=decrypted_dir,
                max_databases=args.max_databases,
                max_messages_per_db=args.max_messages_per_db,
                openssl_bin=args.openssl_bin,
                postpatch_memory_carve=not args.no_postpatch_memory_carve,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-decrypt",
            options={
                "output": str(output),
                "include_message_preview": args.include_message_preview,
                "write_decrypted": args.write_decrypted,
                "decrypted_dir": str(decrypted_dir) if decrypted_dir else None,
                "max_databases": args.max_databases,
                "max_messages_per_db": args.max_messages_per_db,
                "openssl_bin": args.openssl_bin,
                "postpatch_memory_carve": not args.no_postpatch_memory_carve,
                "auth_material_source": payload["auth_material"]["source"],
                "auth_material_ready": payload["auth_material"]["ready"],
                "secrets_redacted": True,
            },
            output_files=[("kakaotalk-decrypt-json", output)]
            + (
                [
                    ("decrypted-dir", Path(str(payload["entries"][0]["decrypted_path"])).parent)
                    for _ in [0]
                    if args.write_decrypted
                    and payload.get("entries")
                    and payload["entries"][0].get("decrypted_path")
                ]
            ),
            notes=[
                "KakaoTalk secrets are intentionally redacted from the audit log.",
                "Message previews are included only when --include-message-preview is set.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk decrypt JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Chat DBs: {summary['chat_database_count']}  "
                f"SQLite opened: {summary['sqlite_open_count']}  "
                f"Messages: {summary['message_row_count']}"
            )
            if "postpatch_memory_carve" in payload:
                print(
                    "Post-patch memory carve: "
                    f"SQLite headers {summary.get('postpatch_memory_carve_sqlite_header_count', 0)}  "
                    f"DB fragments {summary.get('postpatch_memory_carve_database_count', 0)}  "
                    f"chat-relevant tables {summary.get('postpatch_memory_carve_chat_relevant_table_count', 0)}  "
                    f"message residues {summary.get('postpatch_memory_chat_message_residue_count', 0)}"
                )
        return 0



def handle_kakaotalk_macos_report(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        previous_user_id_file = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE")
        if args.user_id_file:
            os.environ["RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE"] = str(Path(args.user_id_file).expanduser().resolve())
        try:
            payload = run_kakaotalk_macos_report(
                root,
                output_dir=output_dir,
                include_message_text=args.include_message_text,
                max_messages=args.max_messages,
                max_context_rows=args.max_context_rows,
                sqlcipher_bin=args.sqlcipher_bin,
            )
        except (KakaoTalkMacOsReportError, OSError, ValueError) as exc:
            parser.error(str(exc))
        finally:
            if args.user_id_file:
                if previous_user_id_file is None:
                    os.environ.pop("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE", None)
                else:
                    os.environ["RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE"] = previous_user_id_file
        outputs = payload.get("outputs") if isinstance(payload.get("outputs"), dict) else {}
        report_json = Path(str(outputs.get("report_json", output_dir / "kakaotalk_macos_report.json")))
        audit_output = audit_path_for(report_json)
        output_files = [
            (str(label), Path(str(path)))
            for label, path in outputs.items()
            if isinstance(path, str)
        ]
        write_audit_record(
            audit_output,
            command="kakaotalk-macos-report",
            options={
                "output_dir": str(output_dir),
                "include_message_text": args.include_message_text,
                "max_messages": args.max_messages,
                "max_context_rows": args.max_context_rows,
                "user_id_file": str(Path(args.user_id_file).expanduser().resolve()) if args.user_id_file else None,
                "sqlcipher_bin": args.sqlcipher_bin,
                "raw_user_id_exported": False,
                "sqlcipher_key_exported": False,
            },
            input_root=root,
            output_files=output_files,
            notes=[
                "macOS KakaoTalk SQLCipher stores are opened read-only with -ifexists when sqlcipher is required.",
                "Raw Kakao UserID and SQLCipher key values are kept in memory and are not written to report or audit JSON.",
                "Message text is exported only when --include-message-text is explicitly set.",
            ],
        )
        payload["audit_output"] = str(audit_output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved macOS KakaoTalk report JSON: {outputs.get('report_json')}")
            print(f"Saved macOS KakaoTalk viewer HTML: {outputs.get('viewer_html')}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Databases: {summary['processed_database_count']}/{summary['database_count']}  "
                f"SQLCipher opened: {summary['sqlcipher_opened_count']}  "
                f"Plain SQLite opened: {summary['plain_sqlite_opened_count']}  "
                f"Messages: {summary['message_count']}  "
                f"Media refs: {summary['media_reference_count']}  "
                f"Context truncated: {summary.get('context_truncated_table_count', 0)}"
            )
        return 0



def handle_kakaotalk_collect_windows(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        output_root = Path(args.output_root).expanduser().resolve()
        kakao_root = Path(args.kakao_root).expanduser().resolve() if args.kakao_root else None
        try:
            payload = run_kakaotalk_windows_collect(
                output_root=output_root,
                kakao_root=kakao_root,
                include_memory_dump=args.include_memory_dump,
                analyze=args.analyze,
                sqlcipher_bin=args.sqlcipher_bin,
                timeout_seconds=args.timeout_seconds,
                max_message_residues=args.max_message_residues,
                no_xlsx=args.no_xlsx,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        collection_zip = Path(str(payload["summary"]["collection_zip"]))
        audit_output = audit_path_for(collection_zip)
        output_files = [("kakaotalk-collection-zip", collection_zip)]
        if payload["summary"].get("report_dir"):
            output_files.append(("kakaotalk-collection-report-dir", Path(str(payload["summary"]["report_dir"]))))
        write_audit_record(
            audit_output,
            command="kakaotalk-collect-windows",
            options={
                "output_root": str(output_root),
                "kakao_root": str(kakao_root) if kakao_root else None,
                "include_memory_dump": args.include_memory_dump,
                "analyze": args.analyze,
                "sqlcipher_bin": args.sqlcipher_bin,
                "timeout_seconds": args.timeout_seconds,
                "max_message_residues": args.max_message_residues,
                "sensitive_keys_exported": False,
            },
            output_files=output_files,
            notes=[
                "Collect only systems and accounts within authorized legal scope.",
                "Memory dumps are collected only when explicitly requested.",
                "Sensitive key material is not exported by the collection workflow.",
            ],
        )
        payload["audit_output"] = str(audit_output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk collection ZIP: {summary['collection_zip']}")
            print(f"Saved audit JSON: {audit_output}")
            if summary.get("report_dir"):
                print(f"Saved KakaoTalk report directory: {summary['report_dir']}")
            print(
                f"Files hashed: {summary['hash_manifest_count']}  "
                f"Registry exports: {summary['registry_export_count']}  "
                f"Memory dumps: {summary['memory_dump_count']}  "
                f"status: {summary['status']}"
            )
        return 0



def handle_kakaotalk_memory_carve(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        carve_dir = Path(args.carve_dir).expanduser().resolve() if args.carve_dir else None
        message_csv = Path(args.message_csv).expanduser().resolve() if args.message_csv else None
        try:
            payload = run_kakaotalk_memory_carve(
                root,
                output=output,
                carve_dir=carve_dir,
                max_hits=args.max_hits,
                max_carve_bytes=args.max_carve_bytes,
                include_row_preview=args.include_row_preview,
                max_rows_per_table=args.max_rows_per_table,
                max_message_residues=args.max_message_residues,
                include_message_preview=args.include_message_preview or args.include_row_preview or bool(message_csv),
                write_carves=args.write_carves,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        if message_csv is not None:
            write_kakaotalk_message_residue_csv(payload, message_csv)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-memory-carve",
            options={
                "output": str(output),
                "carve_dir": str(carve_dir) if carve_dir else None,
                "message_csv": str(message_csv) if message_csv else None,
                "write_carves": args.write_carves,
                "max_hits": args.max_hits,
                "max_carve_bytes": args.max_carve_bytes,
                "include_row_preview": args.include_row_preview,
                "include_message_preview": args.include_message_preview,
                "max_rows_per_table": args.max_rows_per_table,
                "max_message_residues": args.max_message_residues,
                "secrets_redacted": not (args.include_row_preview or args.include_message_preview or bool(message_csv)),
            },
            output_files=[("kakaotalk-memory-carve-json", output)]
            + ([("kakaotalk-message-residue-csv", message_csv)] if message_csv else [])
            + ([("kakaotalk-memory-carve-dir", carve_dir)] if args.write_carves and carve_dir else []),
            notes=[
                "Memory-carved SQLite fragments are post-patch triage evidence and require manual validation.",
                "Row previews are included only when --include-row-preview is set.",
                "Message body previews are included only when --include-message-preview or --message-csv is set.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk memory carve JSON: {output}")
            if message_csv is not None:
                print(f"Saved KakaoTalk message residue CSV: {message_csv}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Memory sources: {summary['memory_source_count']}  "
                f"SQLite headers: {summary['sqlite_header_count']}  "
                f"DB fragments: {summary['carved_database_count']}  "
                f"chat-relevant tables: {summary['chat_relevant_table_count']}  "
                f"message residues: {summary['chat_message_residue_count']}  "
                f"reverse indicators: {summary.get('reverse_indicator_count', 0)}  "
                f"SQLCipher key residues: {summary.get('sqlcipher_key_residue_count', 0)}"
            )
        return 0



def handle_kakaotalk_sqlcipher_probe(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        export_opened_dir = Path(args.export_opened_dir).expanduser().resolve() if args.export_opened_dir else None
        try:
            payload = run_kakaotalk_sqlcipher_probe(
                root,
                output=output,
                sqlcipher_bin=args.sqlcipher_bin,
                max_keys=args.max_keys,
                max_databases=args.max_databases,
                max_message_residues=args.max_message_residues,
                include_message_preview=args.include_message_preview,
                timeout_seconds=args.timeout_seconds,
                export_opened_dir=export_opened_dir,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-sqlcipher-probe",
            options={
                "output": str(output),
                "sqlcipher_bin": args.sqlcipher_bin,
                "max_keys": args.max_keys,
                "max_databases": args.max_databases,
                "max_message_residues": args.max_message_residues,
                "include_message_preview": args.include_message_preview,
                "timeout_seconds": args.timeout_seconds,
                "export_opened_dir": str(export_opened_dir) if export_opened_dir else None,
                "raw_keys_redacted": True,
            },
            output_files=[("kakaotalk-sqlcipher-probe-json", output)]
            + ([("kakaotalk-opened-edb-export-dir", export_opened_dir)] if export_opened_dir else []),
            notes=[
                "SQLCipher probes run only against temporary EDB copies.",
                "Memory key literals are redacted in output and require manual validation.",
                "Plaintext SQLite exports are produced only for EDBs whose memory literal salt matches the file header.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk SQLCipher probe JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Chat DBs: {summary['chat_database_count']}  "
                f"key candidates: {summary['key_candidate_count']}  "
                f"variants: {summary['variant_count']}  "
                f"attempts: {summary['probe_attempt_count']}  "
                f"opened: {summary['opened_database_count']}  "
                f"openable EDBs: {summary.get('openable_edb_count', 0)}  "
                f"exported EDBs: {summary.get('exported_edb_count', 0)}  "
                f"rooms: {summary.get('postpatch_room_evidence_count', 0)}  "
                f"memory messages: {summary.get('postpatch_message_residue_count', 0)}  "
                f"media attachments: {summary.get('postpatch_media_attachment_count', 0)}  "
                f"local media files: {summary.get('postpatch_media_local_file_count', 0)}  "
                f"status: {summary['status']}"
            )
        return 0



def handle_kakaotalk_key_store_inspect(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_kakaotalk_key_store_inspect(
                root,
                output=output,
                max_memory_sources=args.max_memory_sources,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-key-store-inspect",
            options={
                "output": str(output),
                "max_memory_sources": args.max_memory_sources,
                "raw_wrapped_deks_redacted": True,
                "unwrapped_deks_not_exported": True,
            },
            output_files=[("kakaotalk-key-store-json", output)],
            notes=[
                "appstate.dat wrapped DEKs are hashed and length-counted only; raw wrapped key bytes are not exported.",
                "This maps post-patch EDB key-store state but does not yet unwrap DEKs.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk key-store JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Key stores: {summary['parsed_key_store_count']}/{summary['key_store_file_count']}  "
                f"wrapped DEKs: {summary['wrapped_dek_entry_count']}  "
                f"chatLog keys: {summary['chatlog_wrapped_dek_entry_count']}  "
                f"chatLog file matches: {summary['chat_database_key_store_match_count']}  "
                f"status: {summary['method_status']}"
            )
        return 0



def handle_kakaotalk_userdir_bruteforce(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_kakaotalk_userdir_bruteforce(
                root,
                output=output,
                userdir_home=args.userdir_home,
                userdir=args.userdir,
                pragma=args.pragma,
                pragma_key_hex=args.pragma_key_hex,
                sys_uuid=args.sys_uuid,
                hdd_model=args.hdd_model,
                hdd_serial=args.hdd_serial,
                start_id=args.start_id,
                end_id=args.end_id,
                chunk_size=args.chunk_size,
                compiler=args.compiler,
                openssl_bin=args.openssl_bin,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-userdir-bruteforce",
            options={
                "output": str(output),
                "userdir": args.userdir,
                "userdir_home": args.userdir_home,
                "start_id": args.start_id,
                "end_id": args.end_id,
                "chunk_size": args.chunk_size,
                "compiler": args.compiler,
                "secrets_redacted": True,
            },
            output_files=[("kakaotalk-userdir-bruteforce-json", output)],
            notes=[
                "KakaoTalk pragma values are redacted from the audit log.",
                "A matched userId is sensitive and should be used only within authorized scope.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk userDir brute force JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Status: {summary['status']}  "
                f"Searched through: {summary['searched_end_id']}  "
                f"Matched: {summary['matched']}"
            )
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "kakaotalk-decrypt": handle_kakaotalk_decrypt,
    "kakaotalk-macos-report": handle_kakaotalk_macos_report,
    "kakaotalk-collect-windows": handle_kakaotalk_collect_windows,
    "kakaotalk-memory-carve": handle_kakaotalk_memory_carve,
    "kakaotalk-sqlcipher-probe": handle_kakaotalk_sqlcipher_probe,
    "kakaotalk-key-store-inspect": handle_kakaotalk_key_store_inspect,
    "kakaotalk-userdir-bruteforce": handle_kakaotalk_userdir_bruteforce,
}
