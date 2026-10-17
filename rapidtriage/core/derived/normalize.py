r"""Value normalisation of the 통합 보기 tables (plan axiom-adoption §3.2 "정규화").

``normalize(table, raw)`` returns the grouping key of one identifier value, or ``None``
when the value is a placeholder (``-``, ``N/A``, ``0`` …) and is not counted:

* people -- an e-mail address (also inside ``Name <addr>``) lower-cased; a phone number
  as E.164 when it can be read (``+`` / ``00`` prefix, or a Korean ``0``-prefixed national
  number, ``+82``); a SID upper-cased; anything else NFC, whitespace collapsed, casefolded
  (Windows account names are case-insensitive);
* devices -- MAC ``AA:BB:CC:DD:EE:FF``, IP addresses in their canonical text, GUIDs lower
  case without braces, everything else casefolded;
* paths -- ``\\?\`` / ``file:///`` prefixes removed, ``/`` → ``\\``, repeated separators
  collapsed (a leading UNC ``\\\\`` kept), trailing separator removed, casefolded;
* attachments -- the file name (last path part), casefolded;
* urls -- the host (lower case, no port / credentials / trailing dot / leading dot of a
  cookie domain); a bare host is accepted;
* credentials -- never normalised from the clear value: :func:`credential_record` gives the
  masked text, length and SHA-256 and the key is ``sha256:<hex>``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

PLACEHOLDERS = frozenset(
    {"", "-", "--", "—", "n/a", "na", "none", "null", "(null)", "nil", "unknown", "0", "?", "(none)", "undefined", "\\"}
)
MAX_VALUE_CHARS = 2048

EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
PHONE_CHARS = re.compile(r"^\+?[\d\s().-]{7,24}$")
SID = re.compile(r"^s-1-[0-9-]+$", re.IGNORECASE)
MAC = re.compile(r"^[0-9a-f]{2}(?:[:-]?[0-9a-f]{2}){5}$", re.IGNORECASE)
GUID = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.IGNORECASE)
HOST = re.compile(r"^[a-z0-9_.-]+\.[a-z0-9-]{2,}\.?$|^localhost$", re.IGNORECASE)
WHITESPACE = re.compile(r"\s+")


def clean(raw: object) -> str | None:
    """The display text of a scalar value (``None`` for placeholders, booleans, containers)."""
    if raw is None or isinstance(raw, bool) or isinstance(raw, (dict, list, tuple, set)):
        return None
    text = unicodedata.normalize("NFC", str(raw)).strip().strip("\x00")
    if text.casefold() in PLACEHOLDERS:
        return None
    return text[:MAX_VALUE_CHARS]


def _text_key(text: str) -> str:
    return WHITESPACE.sub(" ", text).strip().casefold()


def phone_e164(text: str) -> str | None:
    """E.164 form of a phone number (``None`` when the text is not one); Korean national numbers get +82."""
    if not PHONE_CHARS.fullmatch(text):
        return None
    digits = re.sub(r"\D", "", text)
    if len(digits) < 7 or len(digits) > 15:
        return None
    stripped = text.lstrip()
    if stripped.startswith("+"):
        return f"+{digits}"
    if digits.startswith("00"):
        return f"+{digits[2:]}"
    if digits.startswith("0") and len(digits) in (9, 10, 11):
        return f"+82{digits[1:]}"
    return digits


def person_key(text: str) -> str:
    email = EMAIL.search(text)
    if email:
        return email.group(0).lower()
    phone = phone_e164(text)
    if phone:
        return phone
    if SID.fullmatch(text):
        return text.upper()
    return _text_key(text)


def device_key(text: str) -> str:
    compact = text.strip()
    if MAC.fullmatch(compact):
        hexdigits = re.sub(r"[^0-9a-fA-F]", "", compact).upper()
        return ":".join(hexdigits[index : index + 2] for index in range(0, 12, 2))
    try:
        return str(ipaddress.ip_address(compact.strip("[]")))
    except ValueError:
        pass
    if GUID.fullmatch(compact):
        return compact.strip("{}").lower()
    return _text_key(compact)


def path_key(text: str) -> str:
    value = text.strip()
    if value.lower().startswith("file:///"):
        value = unquote(value[len("file:///") :])
    elif value.lower().startswith("file://"):
        value = "\\\\" + unquote(value[len("file://") :])
    for prefix in ("\\\\?\\UNC\\", "\\\\?\\", "\\??\\"):
        if value.startswith(prefix):
            value = ("\\\\" if prefix.endswith("UNC\\") else "") + value[len(prefix) :]
            break
    value = value.replace("/", "\\")
    unc = value.startswith("\\\\")
    body = re.sub(r"\\{2,}", r"\\", value.lstrip("\\") if unc else value)
    value = ("\\\\" + body) if unc else body
    if len(value) > 3 and value.endswith("\\"):
        value = value.rstrip("\\")
    return value.casefold()


def attachment_key(text: str) -> str:
    name = re.split(r"[\\/]", text.strip())[-1]
    return _text_key(name or text)


def url_host(text: str) -> str | None:
    """Host of a URL or bare host name (lower case); ``None`` when there is none."""
    value = text.strip()
    if "://" in value:
        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            return None
    else:
        host = value.split("/", 1)[0].rsplit("@", 1)[-1]
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]
        host = host.lower().lstrip(".")
        if not HOST.fullmatch(host):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return None
    host = host.lower().strip(".")
    return host or None


def normalize(table: str, text: str) -> str | None:
    """Grouping key of a cleaned value for ``table`` (``credentials`` are keyed by :func:`credential_record`)."""
    if table == "people":
        return person_key(text)
    if table == "devices":
        return device_key(text)
    if table == "paths":
        key = path_key(text)
        return key if key.strip("\\") else None
    if table == "attachments":
        return attachment_key(text)
    if table == "urls":
        return url_host(text)
    raise ValueError(f"no normalisation for table {table!r}")


MASK = "•"


def mask_secret(text: str) -> str:
    """Masked display form, applied to every value (also one its parser already masked): a value
    shorter than 10 characters is all ``•``; a longer one keeps its first two and last character."""
    if len(text) < 10:
        return MASK * len(text)
    return f"{text[:2]}{MASK * min(len(text) - 3, 12)}{text[-1]}"


def credential_record(text: str, *, sha256: str | None = None, length: int | None = None) -> dict[str, object]:
    """``{masked, length, sha256}`` of a secret; the clear text is never returned.

    ``sha256`` / ``length`` given by the parser (computed over the clear value it saw) win over
    the ones computed here, which are over ``text`` as stored.
    """
    digest = sha256.lower() if isinstance(sha256, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha256) else None
    if digest is None:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    size = length if isinstance(length, int) and not isinstance(length, bool) and length >= 0 else len(text)
    return {"masked": mask_secret(text), "length": size, "sha256": digest}
