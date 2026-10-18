"""Shared redaction of credential-like query values (and URL userinfo) in URLs emitted by parsers.

HTTP caches, upload candidates and cloud sync logs routinely contain signed or
token-bearing URLs (Discord CDN ``ex/is/hm``, SharePoint ``tempauth``, S3 / GCS
signatures, OAuth ``code`` / ``access_token``).  Rows keep the key name so an
examiner can see that a token was present, replace the value with ``[가림]`` and
carry the sha256 of the raw URL in a sibling field so the same URL can still be
matched across sources without storing the secret.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

REDACTED_VALUE = "[가림]"

SENSITIVE_QUERY_KEYS = frozenset(
    key.lower()
    for key in (
        "tempauth",
        "access_token",
        "token",
        "sig",
        "signature",
        "X-Amz-Signature",
        "X-Amz-Credential",
        "X-Amz-Security-Token",
        "X-Goog-Signature",
        "X-Goog-Credential",
        "code",
        "upload_id",
        "key",
        "auth",
        "session",
        "sid",
        "ex",
        "is",
        "hm",
        # R5 review: credentials passed as query values (login callbacks, API links, share links).
        "password",
        "passwd",
        "pwd",
        "pass",
        "passkey",
        "refresh_token",
        "id_token",
        "client_secret",
        "api_key",
        "apikey",
        "secret",
        "resourcekey",
        "otp",
    )
)

# key=value pairs inside a query string or fragment.  Separators: ? & ; #
_PAIR_RE = re.compile(r"(?P<lead>[?&;#])(?P<key>[^=&;#?\s]+)=(?P<value>[^&;#\s]*)")


# ``scheme://user:password@host`` userinfo (FTP/HTTP basic credentials embedded in a URL).  The userinfo
# may not contain ``/ ? # @`` or whitespace, so ``https://www.google.com/maps/@37.5,127`` is untouched.
_USERINFO_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]{0,15}://)(?P<userinfo>[^/?#@\s]+)@")

# Values that are credentials whatever their key is called (Slack ``url_private``
# links carry ``?t=xoxe-...``; ``t`` itself is too generic to list as a key).
_SENSITIVE_VALUE_RE = re.compile(r"xox[a-z]-", re.IGNORECASE)


def _replace_pair(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value")
    if not value or (key.lower() not in SENSITIVE_QUERY_KEYS and not _SENSITIVE_VALUE_RE.match(value)):
        return match.group(0)
    return f"{match.group('lead')}{key}={REDACTED_VALUE}"


def redact_url(value: Any) -> Any:
    """Return ``value`` with sensitive query/fragment values and URL userinfo replaced.

    Non-strings are returned unchanged.  Strings without ``=`` or ``@`` are returned
    as-is, which keeps the helper cheap for plain paths and host names.  Works on bare
    URLs, cache keys such as ``1/0/_dk_https://a https://a https://b/x?sig=...``
    and log lines that embed URLs.  ``https://user:pass@host`` becomes
    ``https://[가림]@host`` (the user name may itself be an identifier worth keeping out
    of shared rows; the raw URL's sha256 still matches across sources).
    """
    if not isinstance(value, str):
        return value
    if "@" in value and "://" in value:
        value = _USERINFO_RE.sub(lambda match: f"{match.group('scheme')}{REDACTED_VALUE}@", value)
    if "=" not in value:
        return value
    return _PAIR_RE.sub(_replace_pair, value)


def url_sha256(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def redact_url_fields(row: dict[str, Any], fields: tuple[str, ...] | list[str]) -> dict[str, Any]:
    """Redact ``fields`` of ``row`` in place.

    For every field whose value changed, ``<field>_sha256`` holds the sha256 of
    the raw value (UTF-8) so matching across sources still works.  Returns the row.
    """
    for field in fields:
        raw = row.get(field)
        if not isinstance(raw, str) or not raw:
            continue
        redacted = redact_url(raw)
        if redacted != raw:
            row[field] = redacted
            row[f"{field}_sha256"] = url_sha256(raw)
            row["url_tokens_redacted"] = True
    return row


def redact_text_urls(values: list[Any]) -> tuple[list[Any], bool]:
    """Redact a list of log strings; returns ``(new_list, any_changed)``."""
    changed = False
    out: list[Any] = []
    for item in values:
        new = redact_url(item)
        changed = changed or new != item
        out.append(new)
    return out, changed
