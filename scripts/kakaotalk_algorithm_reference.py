#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.kakaotalk import (  # noqa: E402
    derive_kakaotalk_postpatch_v2_dek_candidates,
    find_memory_dump_candidates,
    redact_postpatch_v2_derived_key,
)
from rapidtriage.core.kakaotalk_algorithms import (  # noqa: E402
    build_sqlcipher_raw_key_with_salt,
    decrypt_legacy_file,
    derive_legacy_key_iv,
    derive_postpatch_v2_database_key,
    derive_postpatch_v2_profile_material,
)


RAW_KEY_DISCLOSURE_ENV = "RAPIDTRIAGE_KAKAO_ALLOW_RAW_KEYS"
RAW_KEY_DISCLOSURE_VALUE = "I_UNDERSTAND_RAW_KEY_DISCLOSURE"


def require_raw_key_disclosure_gate(include_raw: bool) -> None:
    if not include_raw:
        return
    if os.environ.get(RAW_KEY_DISCLOSURE_ENV) == RAW_KEY_DISCLOSURE_VALUE:
        return
    raise SystemExit(
        "--include-raw can expose KakaoTalk database keys. "
        f"Set {RAW_KEY_DISCLOSURE_ENV}={RAW_KEY_DISCLOSURE_VALUE} in a controlled lab to continue."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone reference runner for the two KakaoTalk PC algorithms observed in the test samples."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    legacy = sub.add_parser("legacy", help="Sample #1/pre-patch: pragma+userId AES-CBC page decrypt")
    legacy.add_argument("--edb", required=True, help="chatLogs_*.edb path")
    legacy.add_argument("--pragma", required=True, help="Authorized pragma value")
    legacy.add_argument("--user-id", required=True, help="Authorized KakaoTalk userId")
    legacy.add_argument("--output", help="Optional plaintext SQLite output path")

    v2 = sub.add_parser("postpatch-v2-summary", help="Sample #2/post-patch: profile/appstate/memory key derivation summary")
    v2.add_argument("--root", required=True, help="Extracted KakaoTalk root containing appstate.dat/profile.dat/chatLogs/memory")
    v2.add_argument("--include-raw", action="store_true", help="Include raw key_hex in JSON. Use only in a controlled lab.")

    primitive = sub.add_parser("postpatch-v2-primitives", help="Run only the primitive derivation formulas from hex inputs")
    primitive.add_argument("--object-key-hex", required=True)
    primitive.add_argument("--entropy-hex", required=True)
    primitive.add_argument("--wrapped-profile-hex", required=True)
    primitive.add_argument("--appstate-salt-hex", required=True)
    primitive.add_argument("--info-prefix", default="v2:")
    primitive.add_argument("--relative-path", required=True)
    primitive.add_argument("--wrapped-dek-hex", required=True)
    primitive.add_argument("--edb-salt-hex", help="Optional first 16 bytes of EDB for SQLCipher raw-key-with-salt hex")
    primitive.add_argument("--include-raw", action="store_true", help="Include raw key hex. Use only in a controlled lab.")

    args = parser.parse_args()
    require_raw_key_disclosure_gate(bool(getattr(args, "include_raw", False)))
    if args.command == "legacy":
        edb = Path(args.edb).expanduser().resolve()
        output = Path(args.output).expanduser().resolve() if args.output else None
        result = decrypt_legacy_file(edb, pragma=args.pragma, user_id=args.user_id, output_path=output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "postpatch-v2-summary":
        root = Path(args.root).expanduser().resolve()
        memory_sources = find_memory_dump_candidates(root)
        candidates = derive_kakaotalk_postpatch_v2_dek_candidates(
            root=root,
            memory_sources=memory_sources,
            include_raw=args.include_raw,
        )
        payload = {
            "algorithm": "postpatch-v2-profile-appstate-memory-sqlcipher",
            "root": str(root),
            "memory_source_count": len(memory_sources),
            "derived_key_count": len(candidates),
            "chatlog_key_count": sum(1 for item in candidates if item.get("role") == "chatlog"),
            "raw_keys_included": bool(args.include_raw),
            "candidates": candidates if args.include_raw else [redact_postpatch_v2_derived_key(item) for item in candidates],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "postpatch-v2-primitives":
        material = derive_postpatch_v2_profile_material(
            object_key=bytes.fromhex(args.object_key_hex),
            entropy=bytes.fromhex(args.entropy_hex),
            wrapped_profile=bytes.fromhex(args.wrapped_profile_hex),
        )
        raw_key = derive_postpatch_v2_database_key(
            object_key=material.object_key,
            ikm=material.ikm,
            appstate_salt=bytes.fromhex(args.appstate_salt_hex),
            info_prefix=args.info_prefix,
            relative_path=args.relative_path,
            wrapped_dek=bytes.fromhex(args.wrapped_dek_hex),
        )
        payload = {
            "algorithm": "postpatch-v2-primitives",
            "profile_material": material.redacted_summary(),
            "database_key_sha256": __import__("hashlib").sha256(raw_key).hexdigest(),
            "database_key_length": len(raw_key),
        }
        if args.edb_salt_hex:
            payload["sqlcipher_raw_key_with_salt_length"] = 48
            payload["sqlcipher_raw_key_with_salt_sha256"] = __import__("hashlib").sha256(
                bytes.fromhex(build_sqlcipher_raw_key_with_salt(raw_key=raw_key, edb_salt=bytes.fromhex(args.edb_salt_hex)))
            ).hexdigest()
        if args.include_raw:
            payload["database_key_hex"] = raw_key.hex()
            if args.edb_salt_hex:
                payload["sqlcipher_raw_key_with_salt_hex"] = build_sqlcipher_raw_key_with_salt(
                    raw_key=raw_key,
                    edb_salt=bytes.fromhex(args.edb_salt_hex),
                )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
