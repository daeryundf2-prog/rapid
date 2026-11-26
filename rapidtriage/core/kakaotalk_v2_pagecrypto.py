"""Opt-in post-patch v2 chatLogs decryption: raw AES-256-CBC pages gated by a real SQLite open.

SQLCipher-keyed inputs keep using ``kakaotalk-sqlcipher-probe``; this path only
accepts a database when the rebuilt image opens in sqlite3 and bounded counts run.
Databases are decrypted page by page into a temporary file, so memory use does not
grow with the database size.
"""

from __future__ import annotations

import datetime as dt
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from .docs import write_result
from .kakaotalk import (
    KakaoTalkDecryptError,
    derive_kakaotalk_postpatch_v2_dek_candidates,
    find_memory_dump_candidates,
    redact_postpatch_v2_derived_key,
    safe_export_name,
)
from .kakaotalk_algorithms import (
    KakaoTalkAlgorithmError,
    decrypt_postpatch_v2_file,
    validate_decrypted_sqlite_file,
)

KAKAOTALK_V2_PAGE_DECRYPT_VERSION = "kakaotalk-windows-v2-page-decrypt-v1"


def run_kakaotalk_v2_page_decrypt(
    root: Path,
    *,
    output: Path,
    export_dir: Path | None = None,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise KakaoTalkDecryptError("kakaotalk-v2-page-decrypt expects an extracted KakaoTalk folder")
    resolved_export_dir = export_dir.expanduser().resolve() if export_dir is not None else None
    if resolved_export_dir is not None:
        resolved_export_dir.mkdir(parents=True, exist_ok=True)

    sources = find_memory_dump_candidates(root)
    key_confirmation_attempts: list[dict[str, object]] = []
    derived = derive_kakaotalk_postpatch_v2_dek_candidates(
        root=root, memory_sources=sources, include_raw=True, diagnostics=key_confirmation_attempts
    )
    databases: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    chatlogs_row_count = 0
    with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-v2-") as temp_dir:
        for candidate in derived:
            if candidate.get("role") != "chatlog" or not candidate.get("database") or not candidate.get("key_hex"):
                continue
            database = Path(str(candidate["database"]))
            # Several key stores (backups, copies) can wrap the same key for one database.
            identity = (str(database), str(candidate.get("derived_key_sha256") or ""))
            if identity in seen:
                continue
            seen.add(identity)
            entry: dict[str, object] = {
                "database": str(database),
                "database_name": database.name,
                "decryption": "raw-v2-page-aes-256-cbc",
                "key_store_path": candidate.get("key_store_path", ""),
                "key_confirmation_method": candidate.get("key_confirmation_method", ""),
                "key_confirmation_fallback_reason": candidate.get("key_confirmation_fallback_reason", ""),
                "derived_key_sha256": candidate.get("derived_key_sha256", ""),
            }
            plaintext_path = Path(temp_dir) / f"candidate-{len(databases):04d}.sqlite"
            try:
                decrypted = decrypt_postpatch_v2_file(
                    database, plaintext_path, dek=bytes.fromhex(str(candidate["key_hex"]))
                )
            except OSError as exc:
                entry["status"] = "read-error"
                entry["error"] = str(exc)
                databases.append(entry)
                plaintext_path.unlink(missing_ok=True)
                continue
            except KakaoTalkAlgorithmError as exc:
                entry["status"] = "invalid-page-geometry"
                entry["error"] = str(exc)
                databases.append(entry)
                plaintext_path.unlink(missing_ok=True)
                continue
            gate = validate_decrypted_sqlite_file(plaintext_path)
            entry["page_count"] = decrypted["page_count"]
            entry["validation_gate"] = gate
            if not gate["accepted"]:
                entry["status"] = "rejected-by-sqlite-gate"
                databases.append(entry)
                plaintext_path.unlink(missing_ok=True)
                continue
            entry["status"] = "decrypted"
            gate_rows = gate["chatlogs_row_count"]
            chatlogs_row_count += gate_rows if isinstance(gate_rows, int) else 0
            entry["plaintext_sha256"] = decrypted["plaintext_sha256"]
            if resolved_export_dir is not None:
                export_path = resolved_export_dir / f"{safe_export_name(root, database)}.sqlite"
                shutil.copyfile(plaintext_path, export_path)
                entry["export_path"] = str(export_path)
            plaintext_path.unlink(missing_ok=True)
            databases.append(entry)

    statuses = Counter(str(entry["status"]) for entry in databases)
    payload: dict[str, object] = {
        "command": "kakaotalk-v2-page-decrypt",
        "parser": KAKAOTALK_V2_PAGE_DECRYPT_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "raw_keys_redacted": True,
            "original_edb_untouched": True,
            "plaintext_exports_requested": resolved_export_dir is not None,
        },
        "summary": {
            "memory_source_count": len(sources),
            "derived_key_count": len(derived),
            "chatlog_database_count": len(databases),
            "decrypted_count": statuses["decrypted"],
            "rejected_by_sqlite_gate_count": statuses["rejected-by-sqlite-gate"],
            "invalid_page_geometry_count": statuses["invalid-page-geometry"],
            "read_error_count": statuses["read-error"],
            "key_confirmation_methods": dict(Counter(str(c.get("key_confirmation_method") or "") for c in derived)),
            "chatlogs_row_count": chatlogs_row_count,
            "status": "decrypted" if statuses["decrypted"] else ("no-v2-chatlog-key" if not databases else "not-decrypted"),
        },
        "key_confirmation_attempts": key_confirmation_attempts,
        "derived_keys": [redact_postpatch_v2_derived_key(candidate) for candidate in derived],
        "databases": databases,
    }
    write_result(payload, output)
    return payload
