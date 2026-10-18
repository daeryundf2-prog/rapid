"""BitLocker recovery key files -> ``bitlocker-recovery-key-file`` rows (plan r3-os-depth §3.1 O1).

* ``BitLocker Recovery Key <GUID>.TXT`` / ``BitLocker 복구 키 <GUID>.TXT`` (the "save to a
  file" option of manage-bde / the BitLocker wizard; UTF-16LE text with an identifier
  and the 48-digit recovery password).
* ``<GUID>.BEK`` startup-key files (binary FVE external-key metadata: identifier GUID at
  offset 16, creation FILETIME at offset 40).

**The key is never stored.** A row carries the key identifier, a masked key
(``XXXXXX-…-XXXXNN``: only the last two digits), the SHA-256 of the normalized key
(for matching against escrow exports without disclosing it), a format check
(8 groups, each ≤ 720885 and divisible by 11) and the file's SHA-256. ``.BEK`` key
material is not read beyond the metadata header.

The anti-forensics *tool* signatures (VeraCrypt, CCleaner, sdelete …) are not parsed
here: they are catalogue rule params (``catalog/antiforensics.yaml``) applied by the
``antiforensics.*`` triage rules to installed-program / Prefetch / Amcache / service /
file-name rows.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable
from pathlib import Path

from ...core.models import ArtifactRecord
from .._walk import iter_evidence_paths

BITLOCKER_PARSER = "windows-bitlocker-recovery-key-file"
BITLOCKER_PARSER_VERSION = "bitlocker-key-file-v1"
MAX_KEY_TEXT_BYTES = 64 * 1024
MAX_BEK_BYTES = 64 * 1024
GUID_TEXT = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
KEY_TEXT_NAME = re.compile(rf"^bitlocker (?:recovery key|복구 키)\s*({GUID_TEXT})?.*\.txt$", re.IGNORECASE)
BEK_NAME = re.compile(rf"^\{{?({GUID_TEXT})\}}?\.bek$", re.IGNORECASE)
RECOVERY_PASSWORD = re.compile(r"(?<!\d)(\d{6}(?:-\d{6}){7})(?!\d)")
IDENTIFIER = re.compile(rf"(?<![0-9A-Fa-f-])({GUID_TEXT})(?![0-9A-Fa-f-])")


def mask_recovery_password(value: str) -> str:
    """``XXXXXX-XXXXXX-…-XXXXNN``: the format and the last two digits only."""
    groups = value.split("-")
    masked = ["XXXXXX"] * (len(groups) - 1) + ["XXXX" + groups[-1][-2:]]
    return "-".join(masked)


def recovery_password_valid(value: str) -> bool:
    groups = value.split("-")
    return len(groups) == 8 and all(group.isdigit() and int(group) <= 720885 and int(group) % 11 == 0 for group in groups)


def decode_key_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if len(data) > 1 and data[1:2] == b"\x00":
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp949", errors="replace")


def parse_key_text(data: bytes, file_name: str) -> dict[str, object]:
    text = decode_key_text(data)
    passwords = RECOVERY_PASSWORD.findall(text)
    identifiers = [match.upper() for match in IDENTIFIER.findall(text)]
    name_match = KEY_TEXT_NAME.match(file_name)
    name_guid = (name_match.group(1) or "").upper() if name_match else ""
    identifier = identifiers[0] if identifiers else name_guid
    key = passwords[0] if passwords else ""
    return {
        "key_file_kind": "recovery-password-text",
        "key_file_kind_label": "복구 키 텍스트 파일",
        "key_identifier": identifier,
        "file_name_identifier": name_guid,
        "identifier_matches_file_name": bool(identifier and name_guid and identifier == name_guid),
        "key_present": bool(key),
        "key_masked": mask_recovery_password(key) if key else "",
        "key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest() if key else "",
        "key_format_valid": recovery_password_valid(key) if key else False,
        "key_count": len(set(passwords)),
        "key_value_stored": False,
        "language": "ko" if "복구 키" in text else ("en" if "Recovery Key" in text or "recovery key" in text else ""),
    }


def parse_bek(data: bytes, file_name: str) -> dict[str, object]:
    from .registry import filetime_to_iso_ticks

    name_match = BEK_NAME.match(file_name)
    name_guid = name_match.group(1).upper() if name_match else ""
    identifier = ""
    created = ""
    header_valid = False
    if len(data) >= 48:
        size = int.from_bytes(data[0:4], "little")
        version = int.from_bytes(data[4:8], "little")
        header_size = int.from_bytes(data[8:12], "little")
        header_valid = version == 1 and header_size == 0x30 and 48 <= size <= len(data)
        identifier = str(uuid.UUID(bytes_le=data[16:32])).upper()
        created = filetime_to_iso_ticks(int.from_bytes(data[40:48], "little"))
    return {
        "key_file_kind": "startup-key-bek",
        "key_file_kind_label": "시동 키 파일(.BEK)",
        "key_identifier": identifier or name_guid,
        "file_name_identifier": name_guid,
        "identifier_matches_file_name": bool(identifier and name_guid and identifier == name_guid),
        "bek_header_valid": header_valid,
        "key_created_at": created if header_valid else "",
        "key_present": header_valid,
        "key_masked": "(외부 키 — 값 저장 안 함)" if header_valid else "",
        "key_sha256": "",
        "key_format_valid": header_valid,
        "key_count": 1 if header_valid else 0,
        "key_value_stored": False,
    }


def collect_bitlocker_recovery_key_files(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        name = path.name
        lowered = name.lower()
        if not (lowered.endswith(".bek") or (lowered.endswith(".txt") and lowered.startswith("bitlocker"))):
            continue
        is_text = bool(KEY_TEXT_NAME.match(name))
        if not is_text and not BEK_NAME.match(name):
            continue
        try:
            if not path.is_file() or path.stat().st_size > (MAX_KEY_TEXT_BYTES if is_text else MAX_BEK_BYTES):
                continue
            data = path.read_bytes()
            stat_result = path.stat()
        except OSError:
            continue
        try:
            fields = parse_key_text(data, name) if is_text else parse_bek(data, name)
        except (ValueError, UnicodeError) as exc:  # corrupt file: inventory row only
            fields = {"key_file_kind": "unparsed", "parse_error": f"{type(exc).__name__}: {exc}"[:200], "key_value_stored": False}
        resolved = str(path.resolve())
        created = str(fields.get("key_created_at") or "")
        yield ArtifactRecord(
            provider=provider,
            artifact_type="bitlocker-recovery-key-file",
            path=resolved,
            supported=True,
            details={
                "parser": BITLOCKER_PARSER,
                "parser_version": BITLOCKER_PARSER_VERSION,
                "recovery_method": "parsed",
                "source_path": resolved,
                "source_offset": 0,
                "source_format": "bitlocker-key-file",
                "source_hashes": {"sha256": hashlib.sha256(data).hexdigest()},
                "file_name": name,
                "size": stat_result.st_size,
                **fields,
                "timestamp": created,
                "timestamp_label": "bek_created" if created else "",
                "label": "BitLocker 복구 키 파일",
                "risk_flags": ["bitlocker-recovery-key-file"] if fields.get("key_present") else [],
                "sensitive_content_warning": True,
                "evidence_note": "복구 키 값은 저장하지 않습니다(가린 값·식별자·해시만). 원본 파일은 증거 매체에서 확인하십시오.",
                "raw_preview": f"{name} 식별자 {fields.get('key_identifier') or '-'}",
            },
        )
