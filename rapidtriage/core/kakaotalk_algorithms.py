from __future__ import annotations

import base64
import hashlib
import hmac
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


LEGACY_PAGE_SIZE = 4096
LEGACY_BLOCK_SIZE = 16
POSTPATCH_V2_INFO_PREFIX = "v2:"


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
