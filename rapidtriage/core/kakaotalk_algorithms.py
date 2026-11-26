from __future__ import annotations

import base64
import hashlib
import hmac
import mmap
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

LEGACY_PAGE_SIZE = 4096
LEGACY_BLOCK_SIZE = 16
POSTPATCH_V2_INFO_PREFIX = "v2:"
SQLITE_MAGIC = b"SQLite format 3\x00"
# Post-patch v2 chatLogs page geometry (raw AES-256-CBC per page, not SQLCipher):
# every 4096-byte page carries 4016 bytes of ciphertext followed by a 16-byte IV;
# page 0 keeps its first 16 bytes as a plaintext header, so only 4000 bytes are
# encrypted there. The remaining 80 bytes are the SQLite reserved region, which
# must be zero-filled on output or SQLite reports a malformed image.
V2_PAGE_SIZE = 4096
V2_PAGE_HEADER_SIZE = 16
V2_PAGE_PAYLOAD_SIZE = 4016
V2_PAGE_IV_SIZE = 16
V2_PAGE_RESERVED_SIZE = V2_PAGE_SIZE - V2_PAGE_PAYLOAD_SIZE
V2_BOUND_IKM_SALT_DISTANCE = 0x20
V2_SALT_LOCALITY_MAX_HITS = 4096
V2_SQLITE_GATE_MAX_PROGRESS_CALLS = 100_000


class KakaoTalkAlgorithmError(ValueError):
    """Raised when a standalone KakaoTalk algorithm input is invalid."""


@dataclass(frozen=True)
class LegacyKeyIv:
    key: bytes
    iv: bytes

    def redacted_summary(self) -> dict[str, object]:
        return {
            "algorithm": "legacy-md5-pragma-userid-aes-cbc-page",
            "key_length": len(self.key),
            "iv_length": len(self.iv),
            "key_sha256": hashlib.sha256(self.key).hexdigest(),
            "iv_sha256": hashlib.sha256(self.iv).hexdigest(),
        }


@dataclass(frozen=True)
class PostPatchV2Material:
    object_key: bytes
    entropy: bytes
    ikm: bytes

    def redacted_summary(self) -> dict[str, object]:
        return {
            "algorithm": "postpatch-v2-profile-ikm",
            "object_key_length": len(self.object_key),
            "entropy_length": len(self.entropy),
            "ikm_length": len(self.ikm),
            "object_key_sha256": hashlib.sha256(self.object_key).hexdigest(),
            "entropy_sha256": hashlib.sha256(self.entropy).hexdigest(),
            "ikm_sha256": hashlib.sha256(self.ikm).hexdigest(),
        }


def derive_legacy_key_iv(pragma: str, user_id: str) -> LegacyKeyIv:
    """KakaoTalk sample #1/pre-patch PC DB key derivation.

    Observed flow:
    1. pk = pragma + user_id
    2. repeat pk bytes until 512 bytes, then truncate to 512
    3. AES key = MD5(pk512)
    4. IV = MD5(Base64(AES key))
    5. decrypt each 4096-byte EDB page with AES-128-CBC, no padding removal
    """

    return derive_legacy_key_iv_from_pk(f"{pragma}{user_id}", repeat_to_512=True)


def derive_legacy_key_iv_from_pk(pk_value: str, *, repeat_to_512: bool = True) -> LegacyKeyIv:
    seed = pk_value.encode("utf-8")
    if repeat_to_512:
        while len(seed) < 512:
            seed += seed
        seed = seed[:512]
    key = hashlib.md5(seed).digest()
    iv = hashlib.md5(base64.b64encode(key)).digest()
    return LegacyKeyIv(key=key, iv=iv)


def decrypt_legacy_pages(encrypted: bytes, *, key_iv: LegacyKeyIv, page_size: int = LEGACY_PAGE_SIZE) -> bytes:
    """Decrypt legacy KakaoTalk EDB bytes page-by-page with AES-CBC."""

    if len(key_iv.key) != 16 or len(key_iv.iv) != 16:
        raise KakaoTalkAlgorithmError("Legacy KakaoTalk key and IV must both be 16 bytes")
    if page_size <= 0 or page_size % LEGACY_BLOCK_SIZE != 0:
        raise KakaoTalkAlgorithmError("Legacy page size must be a positive AES block multiple")
    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
    except ImportError:
        AES = None  # type: ignore[assignment]
    output = bytearray()
    for offset in range(0, len(encrypted), page_size):
        page = encrypted[offset : offset + page_size]
        if len(page) % LEGACY_BLOCK_SIZE != 0:
            raise KakaoTalkAlgorithmError("Legacy encrypted page is not AES-block aligned")
        if AES is not None:
            output.extend(AES.new(key_iv.key, AES.MODE_CBC, key_iv.iv).decrypt(page))
        else:
            output.extend(decrypt_aes_128_cbc_with_openssl(page, key_iv=key_iv))
    return bytes(output)


def decrypt_aes_128_cbc_with_openssl(page: bytes, *, key_iv: LegacyKeyIv) -> bytes:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise KakaoTalkAlgorithmError("pycryptodome or openssl is required for legacy KakaoTalk AES-CBC decrypt")
    command = [
        openssl,
        "enc",
        "-aes-128-cbc",
        "-d",
        "-K",
        key_iv.key.hex(),
        "-iv",
        key_iv.iv.hex(),
        "-nopad",
    ]
    result = subprocess.run(command, input=page, capture_output=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise KakaoTalkAlgorithmError(f"openssl legacy AES-CBC decrypt failed: {stderr}")
    return result.stdout


def decrypt_legacy_file(
    edb_path: Path,
    *,
    pragma: str,
    user_id: str,
    output_path: Path | None = None,
) -> dict[str, object]:
    key_iv = derive_legacy_key_iv(pragma, user_id)
    plaintext = decrypt_legacy_pages(edb_path.read_bytes(), key_iv=key_iv)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(plaintext)
    return {
        "algorithm": "legacy-md5-pragma-userid-aes-cbc-page",
        "input": str(edb_path.resolve()),
        "output": str(output_path.resolve()) if output_path is not None else "",
        "sqlite_header": plaintext[:16].decode("ascii", errors="replace"),
        "sqlite_header_confirmed": plaintext.startswith(b"SQLite format 3"),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "key_material": key_iv.redacted_summary(),
    }


def derive_postpatch_v2_profile_material(
    *,
    object_key: bytes,
    entropy: bytes,
    wrapped_profile: bytes,
) -> PostPatchV2Material:
    """KakaoTalk sample #2/post-patch profile.dat IKM unwrap step."""

    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency guard
        raise KakaoTalkAlgorithmError("pycryptodome is required: pip install pycryptodome") from exc
    if len(object_key) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 object_key must be 32 bytes")
    if not entropy:
        raise KakaoTalkAlgorithmError("Post-patch v2 entropy must not be empty")
    if len(wrapped_profile) < 24 or len(wrapped_profile) % 8:
        raise KakaoTalkAlgorithmError("profile.dat must be AES-KW wrapped data")
    ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
    try:
        ikm = AES.new(ikm_wrap_kek, AES.MODE_KW).unseal(wrapped_profile)
    except (KeyError, ValueError) as exc:
        raise KakaoTalkAlgorithmError("profile.dat unwrap failed for supplied object_key/entropy") from exc
    if len(ikm) != 32:
        raise KakaoTalkAlgorithmError("Unwrapped post-patch v2 IKM must be 32 bytes")
    return PostPatchV2Material(object_key=object_key, entropy=entropy, ikm=ikm)


def derive_postpatch_v2_database_key(
    *,
    object_key: bytes,
    ikm: bytes,
    appstate_salt: bytes,
    info_prefix: str,
    relative_path: str,
    wrapped_dek: bytes,
) -> bytes:
    """Derive one post-patch v2 SQLCipher raw DB key from appstate.dat data."""

    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
        from Crypto.Hash import SHA256  # type: ignore[import-not-found]
        from Crypto.Protocol.KDF import HKDF  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency guard
        raise KakaoTalkAlgorithmError("pycryptodome is required: pip install pycryptodome") from exc
    if len(object_key) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 object_key must be 32 bytes")
    if len(ikm) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 IKM must be 32 bytes")
    if len(appstate_salt) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 appstate salt must be 32 bytes")
    if len(wrapped_dek) != 40:
        raise KakaoTalkAlgorithmError("Post-patch v2 wrapped DEK must be 40 bytes")
    normalized_path = normalize_postpatch_relative_path(relative_path)
    info = info_prefix.encode("utf-8") + normalized_path.replace("/", "\\").encode("utf-8")
    bound_ikm = hmac.new(object_key, ikm + b"entropy-bound-kek", hashlib.sha256).digest()
    kek = HKDF(bound_ikm, 32, appstate_salt, SHA256, context=info)
    try:
        raw_key = AES.new(kek, AES.MODE_KW).unseal(wrapped_dek)
    except (KeyError, ValueError) as exc:
        raise KakaoTalkAlgorithmError("wrapped DEK unwrap failed for supplied appstate entry") from exc
    if len(raw_key) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 SQLCipher raw key must be 32 bytes")
    return raw_key


def build_sqlcipher_raw_key_with_salt(*, raw_key: bytes, edb_salt: bytes) -> str:
    """Return SQLCipher x'raw_key||salt' hex used with PRAGMA cipher_salt."""

    if len(raw_key) != 32:
        raise KakaoTalkAlgorithmError("SQLCipher raw key must be 32 bytes")
    if len(edb_salt) != 16:
        raise KakaoTalkAlgorithmError("SQLCipher EDB salt must be first 16 bytes of the database")
    return (raw_key + edb_salt).hex()


def normalize_postpatch_relative_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def unwrap_postpatch_v2_dek_with_bound_ikm(
    *,
    bound_ikm: bytes,
    appstate_salt: bytes,
    info: bytes,
    wrapped_dek: bytes,
) -> bytes | None:
    """HKDF-SHA256(bound_ikm, salt, info) -> AES-KW unwrap; None when the KW integrity check fails."""

    from Crypto.Cipher import AES  # type: ignore[import-not-found]
    from Crypto.Hash import SHA256  # type: ignore[import-not-found]
    from Crypto.Protocol.KDF import HKDF  # type: ignore[import-not-found]

    kek = HKDF(bound_ikm, 32, appstate_salt, SHA256, context=info)
    try:
        dek = AES.new(kek, AES.MODE_KW).unseal(wrapped_dek)
    except (KeyError, ValueError):
        return None
    return dek if len(dek) == 32 else None


def find_postpatch_v2_bound_ikm_by_salt_locality(
    data: bytes | mmap.mmap,
    *,
    appstate_salt: bytes,
    info: bytes,
    wrapped_dek: bytes,
    max_hits: int = V2_SALT_LOCALITY_MAX_HITS,
) -> dict[str, object]:
    """Fast v2 key confirmation: bound_ikm sits 0x20 bytes before the appstate salt in memory.

    Each salt hit yields one 32-byte candidate at ``hit - 0x20``; the first candidate that
    unwraps ``wrapped_dek`` through HKDF + AES-KW (whose 8-byte integrity check rejects
    wrong keys) is confirmed. ``data`` may be ``bytes`` or an ``mmap``. The result always
    carries ``salt_hits_tested`` and ``salt_hits_truncated`` (``max_hits`` reached) so a
    miss can be recorded; ``confirmed`` is False and ``bound_ikm`` None on a miss.
    """

    if len(appstate_salt) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 appstate salt must be 32 bytes")
    if len(wrapped_dek) != 40:
        raise KakaoTalkAlgorithmError("Post-patch v2 wrapped DEK must be 40 bytes")
    hits_tested = 0
    position = data.find(appstate_salt)
    while position >= 0 and hits_tested < max_hits:
        hits_tested += 1
        start = position - V2_BOUND_IKM_SALT_DISTANCE
        if start >= 0:
            bound_ikm = bytes(data[start:position])
            if bound_ikm != b"\x00" * 32:
                dek = unwrap_postpatch_v2_dek_with_bound_ikm(
                    bound_ikm=bound_ikm,
                    appstate_salt=appstate_salt,
                    info=info,
                    wrapped_dek=wrapped_dek,
                )
                if dek is not None:
                    return {
                        "confirmed": True,
                        "bound_ikm": bound_ikm,
                        "salt_hit_offset": position,
                        "bound_ikm_offset": start,
                        "salt_hits_tested": hits_tested,
                        "salt_hits_truncated": False,
                    }
        position = data.find(appstate_salt, position + 1)
    return {
        "confirmed": False,
        "bound_ikm": None,
        "salt_hits_tested": hits_tested,
        "salt_hits_truncated": position >= 0,
    }


def _v2_page_aes(dek: bytes) -> object:
    if len(dek) != 32:
        raise KakaoTalkAlgorithmError("Post-patch v2 DEK must be 32 bytes")
    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency guard
        raise KakaoTalkAlgorithmError("pycryptodome is required: pip install pycryptodome") from exc
    return AES


def _check_v2_geometry(size: int) -> None:
    if not size or size % V2_PAGE_SIZE:
        raise KakaoTalkAlgorithmError(
            f"Post-patch v2 chatLogs must be a whole number of {V2_PAGE_SIZE}-byte pages (got {size} bytes)"
        )


def _decrypt_postpatch_v2_page(page: bytes, *, first: bool, dek: bytes, aes_module: object) -> bytes:
    iv = page[V2_PAGE_PAYLOAD_SIZE : V2_PAGE_PAYLOAD_SIZE + V2_PAGE_IV_SIZE]
    cipher = aes_module.new(dek, aes_module.MODE_CBC, iv)  # type: ignore[attr-defined]
    if first:
        body = page[:V2_PAGE_HEADER_SIZE] + cipher.decrypt(page[V2_PAGE_HEADER_SIZE:V2_PAGE_PAYLOAD_SIZE])
    else:
        body = cipher.decrypt(page[:V2_PAGE_PAYLOAD_SIZE])
    return body + b"\x00" * V2_PAGE_RESERVED_SIZE


def decrypt_postpatch_v2_pages(encrypted: bytes, *, dek: bytes) -> bytes:
    """Rebuild a v2 chatLogs SQLite image: raw AES-256-CBC per page with a trailing per-page IV.

    page 0: [0:16] plaintext header (kept), [16:4016] ciphertext, [4016:4032] IV
    page N: [0:4016] ciphertext, [4016:4032] IV
    Each decrypted 4016-byte page is padded with 80 zero bytes (SQLite reserved region).
    """

    aes_module = _v2_page_aes(dek)
    _check_v2_geometry(len(encrypted))
    return b"".join(
        _decrypt_postpatch_v2_page(
            encrypted[offset : offset + V2_PAGE_SIZE], first=offset == 0, dek=dek, aes_module=aes_module
        )
        for offset in range(0, len(encrypted), V2_PAGE_SIZE)
    )


def decrypt_postpatch_v2_file(source: Path, destination: Path, *, dek: bytes) -> dict[str, object]:
    """``decrypt_postpatch_v2_pages`` streamed page by page from ``source`` to ``destination``.

    Memory stays at one page whatever the database size; the plaintext SHA-256 is
    computed on the way.
    """

    aes_module = _v2_page_aes(dek)
    _check_v2_geometry(source.stat().st_size)
    digest = hashlib.sha256()
    page_count = 0
    with source.open("rb") as reader, destination.open("wb") as writer:
        while page := reader.read(V2_PAGE_SIZE):
            if len(page) != V2_PAGE_SIZE:
                raise KakaoTalkAlgorithmError(f"Post-patch v2 chatLogs ends with a partial {len(page)}-byte page")
            plain = _decrypt_postpatch_v2_page(page, first=page_count == 0, dek=dek, aes_module=aes_module)
            writer.write(plain)
            digest.update(plain)
            page_count += 1
    return {"page_count": page_count, "plaintext_sha256": digest.hexdigest()}


def validate_decrypted_sqlite_file(candidate: Path) -> dict[str, object]:
    """Anti-false-positive gate: accept only if SQLite opens the image and bounded counts succeed.

    A raw CBC decrypt never fails on a wrong key and the v2 page-0 header is kept in
    plaintext, so the magic alone proves nothing. The image is opened read-only and
    ``count(*)`` runs on sqlite_master and, if present, chatLogs.
    """

    with candidate.open("rb") as handle:
        header = handle.read(len(SQLITE_MAGIC))
    result: dict[str, object] = {
        "accepted": False,
        "sqlite_header_ok": header == SQLITE_MAGIC,
        "sqlite_master_count": None,
        "chatlogs_table": "",
        "chatlogs_row_count": None,
        "error": "",
    }
    if not result["sqlite_header_ok"]:
        result["error"] = "sqlite-header-mismatch"
        return result
    progress_calls = 0

    def abort_when_unbounded() -> int:
        nonlocal progress_calls
        progress_calls += 1
        return 1 if progress_calls > V2_SQLITE_GATE_MAX_PROGRESS_CALLS else 0

    try:
        with closing(sqlite3.connect(f"{candidate.as_uri()}?mode=ro", uri=True)) as connection:
            connection.set_progress_handler(abort_when_unbounded, 1000)
            result["sqlite_master_count"] = int(connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0])
            tables = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            chatlogs = next((name for name in tables if name.lower() == "chatlogs"), "")
            if chatlogs:
                quoted = '"' + chatlogs.replace('"', '""') + '"'
                result["chatlogs_table"] = chatlogs
                result["chatlogs_row_count"] = int(connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])
    except sqlite3.DatabaseError as exc:
        result["error"] = str(exc)
        return result
    result["accepted"] = True
    return result


def validate_decrypted_sqlite_bytes(plaintext: bytes) -> dict[str, object]:
    """``validate_decrypted_sqlite_file`` for an in-memory image (written to a temp file first)."""

    with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-v2-gate-") as temp_dir:
        candidate = Path(temp_dir) / "candidate.sqlite"
        candidate.write_bytes(plaintext)
        return validate_decrypted_sqlite_file(candidate)
