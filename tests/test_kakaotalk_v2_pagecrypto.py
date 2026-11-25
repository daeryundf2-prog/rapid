from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.kakaotalk import derive_kakaotalk_postpatch_v2_dek_candidates
from rapidtriage.core.kakaotalk_algorithms import (
    V2_PAGE_PAYLOAD_SIZE,
    V2_PAGE_SIZE,
    KakaoTalkAlgorithmError,
    decrypt_postpatch_v2_pages,
    find_postpatch_v2_bound_ikm_by_salt_locality,
    validate_decrypted_sqlite_bytes,
)
from tests.kakaotalk_v2_pagecrypto_fixtures import (
    build_reserved_sqlite,
    encrypt_v2_pages,
)
from tests.test_rapidtriage_kakaotalk_decrypt import (
    cbor_array_bytes,
    cbor_map,
    cbor_pair_array,
)

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
except ImportError:  # pragma: no cover - optional KakaoTalk post-patch dependency
    AES = None

MESSAGES = ["first synthetic line", "second synthetic line", "third synthetic line"]
APP_SALT = hashlib.sha256(b"synthetic-appstate-salt").digest()
BOUND_IKM = hashlib.sha256(b"synthetic-bound-ikm").digest()
DEK = hashlib.sha256(b"synthetic-dek").digest()
WRONG_DEK = hashlib.sha256(b"some-other-dek").digest()
CHAT_RELATIVE = b"chat_data\\chatLogs_42.edb"
CHAT_INFO = b"v2:" + CHAT_RELATIVE
ENTROPY = b"2xU78xUIRNKi4z7N74Kg5KKHvjopoFmNEMcNJQn9xxCcEX9Q/BMXbBn1/BCaQ89+sYzoZGLNgIUdPA4AOtZhhQ=="


def wrap_dek(bound_ikm: bytes, dek: bytes) -> bytes:
    kek = HKDF(bound_ikm, 32, APP_SALT, SHA256, context=CHAT_INFO)
    return AES.new(kek, AES.MODE_KW).seal(dek)


def locality_dump() -> bytes:
    decoy = b"\x11" * 32 + APP_SALT
    real = BOUND_IKM + APP_SALT
    return b"\x00" * 0x200 + decoy + b"\x00" * 0x100 + real + b"\x00" * 0x200


def write_case(root: Path, *, page_key: bytes, dump: bytes) -> Path:
    user = root / "KakaoTalk" / "users" / ("d" * 40)
    chat_dir = user / "chat_data"
    chat_dir.mkdir(parents=True)
    chat_db = chat_dir / "chatLogs_42.edb"
    chat_db.write_bytes(encrypt_v2_pages(build_reserved_sqlite(MESSAGES), dek=page_key))
    (user / "appstate.dat").write_bytes(
        cbor_map(
            {
                "info_prefix": cbor_array_bytes(b"v2:"),
                "salt": cbor_array_bytes(APP_SALT),
                "wrapped_dek_map": [cbor_pair_array(CHAT_RELATIVE, wrap_dek(BOUND_IKM, DEK))],
            }
        )
    )
    (root / "KakaoTalk.DMP").write_bytes(dump)
    return chat_db


@unittest.skipIf(AES is None, "pycryptodome is required for KakaoTalk v2 page decrypt tests")
class KakaoTalkV2PageCryptoTests(unittest.TestCase):
    def test_correct_key_rebuilds_sqlite_that_passes_open_and_count_gate(self) -> None:
        plaintext = build_reserved_sqlite(MESSAGES)
        decrypted = decrypt_postpatch_v2_pages(encrypt_v2_pages(plaintext, dek=DEK), dek=DEK)

        self.assertEqual(decrypted, plaintext)
        gate = validate_decrypted_sqlite_bytes(decrypted)
        self.assertTrue(gate["accepted"])
        self.assertEqual(gate["sqlite_master_count"], 2)
        self.assertEqual(gate["chatlogs_row_count"], len(MESSAGES))

    def test_wrong_key_cbc_succeeds_with_header_but_gate_rejects(self) -> None:
        encrypted = encrypt_v2_pages(build_reserved_sqlite(MESSAGES), dek=DEK)

        decrypted = decrypt_postpatch_v2_pages(encrypted, dek=WRONG_DEK)

        self.assertEqual(len(decrypted), len(encrypted))
        self.assertTrue(decrypted.startswith(b"SQLite format 3\x00"))
        gate = validate_decrypted_sqlite_bytes(decrypted)
        self.assertTrue(gate["sqlite_header_ok"])
        self.assertFalse(gate["accepted"])
        self.assertIsNone(gate["chatlogs_row_count"])
        self.assertTrue(gate["error"])

    def test_omitting_reserved_zero_fill_is_malformed(self) -> None:
        decrypted = decrypt_postpatch_v2_pages(encrypt_v2_pages(build_reserved_sqlite(MESSAGES), dek=DEK), dek=DEK)
        unpadded = b"".join(
            decrypted[offset : offset + V2_PAGE_PAYLOAD_SIZE] for offset in range(0, len(decrypted), V2_PAGE_SIZE)
        )

        gate = validate_decrypted_sqlite_bytes(unpadded)

        self.assertFalse(gate["accepted"])
        self.assertIn("malformed", str(gate["error"]))

    def test_odd_and_short_inputs_are_rejected(self) -> None:
        for size in (0, 16, V2_PAGE_SIZE - 1, V2_PAGE_SIZE + 1):
            with self.subTest(size=size), self.assertRaises(KakaoTalkAlgorithmError):
                decrypt_postpatch_v2_pages(b"\x00" * size, dek=DEK)
        with self.assertRaises(KakaoTalkAlgorithmError):
            decrypt_postpatch_v2_pages(b"\x00" * V2_PAGE_SIZE, dek=DEK[:16])
        self.assertEqual(validate_decrypted_sqlite_bytes(b"")["error"], "sqlite-header-mismatch")
        self.assertFalse(validate_decrypted_sqlite_bytes(b"SQLite format 3\x00")["accepted"])
        wrapped = wrap_dek(BOUND_IKM, DEK)
        self.assertIsNone(
            find_postpatch_v2_bound_ikm_by_salt_locality(
                APP_SALT + BOUND_IKM, appstate_salt=APP_SALT, info=CHAT_INFO, wrapped_dek=wrapped
            )
        )
        with self.assertRaises(KakaoTalkAlgorithmError):
            find_postpatch_v2_bound_ikm_by_salt_locality(
                locality_dump(), appstate_salt=APP_SALT[:16], info=CHAT_INFO, wrapped_dek=wrapped
            )

    def test_salt_locality_rule_skips_decoy_and_confirms_bound_ikm(self) -> None:
        dump = locality_dump()

        hit = find_postpatch_v2_bound_ikm_by_salt_locality(
            dump, appstate_salt=APP_SALT, info=CHAT_INFO, wrapped_dek=wrap_dek(BOUND_IKM, DEK)
        )

        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit["bound_ikm"], BOUND_IKM)
        self.assertEqual(hit["salt_hits_tested"], 2)
        self.assertEqual(hit["bound_ikm_offset"], dump.rindex(APP_SALT) - 0x20)

    def test_derivation_uses_locality_rule_without_profile_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_case(root, page_key=DEK, dump=locality_dump())

            candidates = derive_kakaotalk_postpatch_v2_dek_candidates(
                root=root, memory_sources=[root / "KakaoTalk.DMP"], include_raw=True
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["key_confirmation_method"], "salt-locality-0x20")
            self.assertEqual(candidates[0]["key_hex"], DEK.hex())
            self.assertNotIn(BOUND_IKM.hex(), json.dumps(candidates))

    def test_locality_miss_falls_back_to_hmac_unwrap_chain(self) -> None:
        object_key = b"k" * 32
        ikm = b"i" * 32
        chain_bound_ikm = hmac.new(object_key, ikm + b"entropy-bound-kek", hashlib.sha256).digest()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            memory = bytearray(4096)
            memory[0x100 + 0x68 : 0x100 + 0x88] = object_key
            memory[0x100 + 0x88 : 0x100 + 0x90] = (0x500).to_bytes(8, "little")
            memory[0x500 : 0x500 + len(ENTROPY)] = ENTROPY
            write_case(root, page_key=DEK, dump=bytes(memory))
            user = root / "KakaoTalk" / "users" / ("d" * 40)
            appstate = user / "appstate.dat"
            appstate.write_bytes(
                cbor_map(
                    {
                        "info_prefix": cbor_array_bytes(b"v2:"),
                        "salt": cbor_array_bytes(APP_SALT),
                        "wrapped_dek_map": [cbor_pair_array(CHAT_RELATIVE, wrap_dek(chain_bound_ikm, DEK))],
                    }
                )
            )
            ikm_wrap_kek = hmac.new(object_key, ENTROPY + b"ikm-wrap", hashlib.sha256).digest()
            (user / "profile.dat").write_bytes(AES.new(ikm_wrap_kek, AES.MODE_KW).seal(ikm))

            candidates = derive_kakaotalk_postpatch_v2_dek_candidates(
                root=root, memory_sources=[root / "KakaoTalk.DMP"], include_raw=True
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["key_confirmation_method"], "hmac-unwrap-chain")
            self.assertEqual(candidates[0]["key_hex"], DEK.hex())

    def test_cli_exports_only_gate_accepted_databases(self) -> None:
        for page_key, expected_status in ((DEK, "decrypted"), (WRONG_DEK, "rejected-by-sqlite-gate")):
            with self.subTest(status=expected_status), tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir) / "case"
                chat_db = write_case(root, page_key=page_key, dump=locality_dump())
                original = chat_db.read_bytes()
                output = Path(tmp_dir) / "v2.json"
                export_dir = Path(tmp_dir) / "export"

                exit_code = main(
                    ["kakaotalk-v2-page-decrypt", str(root), "--output", str(output), "--export-dir", str(export_dir)]
                )

                self.assertEqual(exit_code, 0)
                self.assertEqual(chat_db.read_bytes(), original)
                payload = json.loads(output.read_text(encoding="utf-8"))
                self.assertNotIn(DEK.hex(), json.dumps(payload))
                self.assertNotIn(BOUND_IKM.hex(), json.dumps(payload))
                entry = payload["databases"][0]
                self.assertEqual(entry["status"], expected_status)
                self.assertEqual(entry["key_confirmation_method"], "salt-locality-0x20")
                exports = list(export_dir.glob("*.sqlite"))
                if expected_status == "decrypted":
                    self.assertEqual(payload["summary"]["chatlogs_row_count"], len(MESSAGES))
                    self.assertEqual(len(exports), 1)
                    with closing(sqlite3.connect(exports[0])) as connection:
                        rows = [row[0] for row in connection.execute("SELECT message FROM chatLogs ORDER BY logId")]
                    self.assertEqual(rows, MESSAGES)
                else:
                    self.assertEqual(payload["summary"]["decrypted_count"], 0)
                    self.assertTrue(entry["validation_gate"]["sqlite_header_ok"])
                    self.assertEqual(exports, [])


if __name__ == "__main__":
    unittest.main()
