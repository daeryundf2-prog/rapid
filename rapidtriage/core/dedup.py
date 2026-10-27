"""항목 단위 중복 제거 (R7 갈래 A, Nuix R2 item sets) over a run's items.

Items and their keys:

* files rows with a content SHA-256 (``hashes.sha256``), email-attachment rows (``details.sha256``),
  an EML / MBOX message's embedded attachments (virtual ``#attachment:<i>`` items),
  android-backup-member files and carved rows (``details.sha256``): ``sha256:<hex>`` -- the same
  bytes are one item wherever they were found (a file on disk and the same mail attachment);
* email-message rows: ``mail:<hex>`` = SHA-256 of ``normalized subject | date (UTC, minute) | from |
  sorted to+cc | body_sha256`` (the Message-ID when the body hash is missing). Subjects are
  NFC + case-folded with whitespace collapsed; addresses are the lower-cased addresses only.

Archive inventory and android-backup rows are not items of their own (the archive is already
its files row); in ``family`` mode they are top-level items keyed by their source SHA-256
(:func:`container_key`). Listed archive entries carry no content digest (ZIP CRC-32 only): they
are never deduplicated on their own and enter a family key by their title.

Modes (``DEDUP_MODES``):

* ``item`` -- every item on its own key; the original is the first in item order
  (:func:`families.ref_order`).
* ``family`` -- only top-level items are compared, on a family key = SHA-256 of the item's own
  key and the sorted keys of all its descendants (a descendant without a key counts by its
  title); every descendant takes its top-level item's status. A top-level item without an own
  key is never a duplicate.
* ``custodian`` -- like ``item``, but the original of a group is the item of the best-ranked
  custodian (``custodian_rank``; without custodian assignments -- R7 갈래 D -- every item ranks by
  its evidence, i.e. the run's single evidence source: the result equals ``item``).

``rapidtriage-dedup.json`` holds the groups of every mode (original + duplicate refs).
"""

from __future__ import annotations

import datetime as dt
import email.utils
import hashlib
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from .families import ATTACHMENT_MARK, FamilyIndex, SourceRow, details_of, ref_order

DEDUP_FILE_NAME = "rapidtriage-dedup.json"
DEDUP_FORMAT = "rapidtriage-dedup-v1"
DEDUP_MODES = ("item", "family", "custodian")
DEDUP_MODE_LABELS = {"item": "항목별", "family": "계열별", "custodian": "보관자 순위별"}
DEDUP_STATUSES = ("original", "duplicate", "any")
CONTENT_ITEM_TYPES = frozenset({"email-attachment", "android-backup-member"})
CONTAINER_TYPES = frozenset({"archive-file-inventory", "android-backup"})
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SPACE = re.compile(r"\s+")

CustodianRank = Callable[[str], tuple[int, str]]


def sha256_value(value: object) -> str:
    text = str(value or "").strip()
    return text.lower() if _SHA256.match(text) else ""


def normalize_subject(value: object) -> str:
    return _SPACE.sub(" ", unicodedata.normalize("NFC", str(value or ""))).strip().casefold()


def addresses(*values: object) -> list[str]:
    """Lower-cased e-mail addresses of header values (display names dropped), sorted, unique."""
    found: set[str] = set()
    for value in values:
        items = value if isinstance(value, list) else [value]
        texts = [str(item) for item in items if isinstance(item, str) and item.strip()]
        for _name, address in email.utils.getaddresses(texts):
            address = address.strip().lower()
            if address:
                found.add(address)
    return sorted(found)


def minute_utc(value: object) -> str:
    """``YYYY-MM-DDTHH:MM`` (UTC) of an RFC 2822 or ISO-8601 date; ``""`` when unparseable."""
    text = str(value or "").strip()
    if not text:
        return ""
    moment: dt.datetime | None = None
    try:
        moment = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        moment = None
    if moment is None:
        candidate = text.replace("Z", "+00:00").replace(" ", "T", 1) if len(text) > 10 else text
        try:
            moment = dt.datetime.fromisoformat(candidate)
        except ValueError:
            return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    try:
        return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M")
    except (OverflowError, ValueError):
        return ""


def mail_key(details: Mapping[str, object]) -> str:
    """``mail:<sha256>`` of a message (module doc); ``""`` when the message has neither a body hash
    nor a Message-ID (nothing identifies its content)."""
    body = sha256_value(details.get("body_sha256")) or str(details.get("message_id") or "").strip()
    if not body:
        return ""
    material = "|".join(
        (
            normalize_subject(details.get("subject")),
            minute_utc(details.get("date")),
            ",".join(addresses(details.get("from"))),
            ",".join(addresses(details.get("to"), details.get("cc"))),
            body,
        )
    )
    return "mail:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def item_keys(source: SourceRow) -> list[tuple[str, str]]:
    """``(ref, key)`` of the dedup items one row contributes (module doc)."""
    row, details = source.row, details_of(source.row)
    ref = source.ref
    if source.collection == "files":
        hashes = row.get("hashes")
        digest = sha256_value(hashes.get("sha256")) if isinstance(hashes, Mapping) else ""
        return [(ref, f"sha256:{digest}")] if digest else []
    if source.collection == "analysis":
        digest = sha256_value(details.get("sha256")) if details.get("recovery_method") == "carved" else ""
        return [(ref, f"sha256:{digest}")] if digest else []
    artifact_type = str(row.get("artifact_type") or "")
    if artifact_type == "email-message":
        out: list[tuple[str, str]] = []
        key = mail_key(details)
        if key:
            out.append((ref, key))
        embedded = details.get("attachments")
        if isinstance(embedded, list):
            for position, item in enumerate(embedded):
                digest = sha256_value(item.get("sha256")) if isinstance(item, Mapping) else ""
                if digest:
                    out.append((f"{ref}{ATTACHMENT_MARK}{position}", f"sha256:{digest}"))
        return out
    if artifact_type in CONTENT_ITEM_TYPES:
        digest = sha256_value(details.get("sha256"))
        return [(ref, f"sha256:{digest}")] if digest else []
    return []


def container_key(source: SourceRow) -> str:
    """Family-mode key of an archive / backup row (its source SHA-256), ``""`` for other rows."""
    if source.collection != "artifacts" or str(source.row.get("artifact_type") or "") not in CONTAINER_TYPES:
        return ""
    hashes = details_of(source.row).get("source_hashes")
    digest = sha256_value(hashes.get("sha256")) if isinstance(hashes, Mapping) else ""
    return f"sha256:{digest}" if digest else ""


@dataclass
class DedupGroup:
    key: str
    original: str
    duplicates: list[str]

    @property
    def size(self) -> int:
        return 1 + len(self.duplicates)


@dataclass
class DedupMode:
    groups: list[DedupGroup] = field(default_factory=list)
    # ref -> (status, group position); status "original" | "duplicate"
    status: dict[str, tuple[str, int]] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        duplicates = sum(1 for status, _position in self.status.values() if status == "duplicate")
        return {
            "items": len(self.status),
            "groups": len(self.groups),
            "originals": len(self.status) - duplicates,
            "duplicates": duplicates,
            "groups_with_duplicates": sum(1 for group in self.groups if group.duplicates),
        }

    def lookup(self, ref: str) -> tuple[str, int] | None:
        """``(status, group size)`` of ``ref`` (``None``: not an item of this mode)."""
        found = self.status.get(ref)
        if found is None:
            return None
        return found[0], self.groups[found[1]].size

    def matches(self, ref: str, wanted: str) -> bool:
        found = self.status.get(ref)
        if found is None:
            return False
        if wanted == "any":
            return bool(self.groups[found[1]].duplicates)
        return found[0] == wanted


@dataclass
class DedupIndex:
    modes: dict[str, DedupMode]
    keys: dict[str, str]

    def mode(self, name: str) -> DedupMode:
        return self.modes[name]


def _group(items: Iterable[tuple[str, str]], order: Callable[[str], tuple[object, ...]]) -> DedupMode:
    by_key: dict[str, list[str]] = {}
    for ref, key in items:
        by_key.setdefault(key, []).append(ref)
    mode = DedupMode()
    ordered = sorted(by_key.items(), key=lambda pair: min(order(ref) for ref in pair[1]))
    for key, refs in ordered:
        refs.sort(key=order)
        position = len(mode.groups)
        mode.groups.append(DedupGroup(key, refs[0], refs[1:]))
        mode.status[refs[0]] = ("original", position)
        for ref in refs[1:]:
            mode.status[ref] = ("duplicate", position)
    return mode


def evidence_rank(_ref: str) -> tuple[int, str]:
    """Default custodian rank: the run's single evidence source (every item ranks the same)."""
    return (0, "")


def compute_dedup(
    keys: Mapping[str, str],
    families: FamilyIndex,
    *,
    custodian_rank: CustodianRank | None = None,
    container_keys: Mapping[str, str] | None = None,
) -> DedupIndex:
    """Groups of the three modes from ``keys`` (ref -> item key); ``container_keys`` (archive /
    backup rows -> source key) are used for top-level items in ``family`` mode only."""
    item_mode = _group(keys.items(), ref_order)
    rank = custodian_rank or evidence_rank
    custodian_mode = _group(keys.items(), lambda ref: (rank(ref), ref_order(ref)))
    # Family mode: top-level items only, on the family key; descendants follow their top.
    containers = dict(container_keys or {})
    tops = sorted({families.top(ref) for ref in [*keys, *containers]}, key=ref_order)
    family_keys: list[tuple[str, str]] = []
    for top in tops:
        own = keys.get(top) or containers.get(top)
        if not own:
            continue
        parts = []
        for child in families.descendants(top):
            key = keys.get(child)
            if key:
                parts.append(key)
            else:
                info = families.info(child)
                parts.append(f"title:{info.title if info else child.rpartition(':')[2]}")
        material = own + "|" + "|".join(sorted(parts))
        family_keys.append((top, "family:" + hashlib.sha256(material.encode("utf-8")).hexdigest()))
    family_mode = _group(family_keys, ref_order)
    for top, (status, position) in list(family_mode.status.items()):
        for child in families.descendants(top):
            family_mode.status.setdefault(child, (status, position))
    return DedupIndex(modes={"item": item_mode, "family": family_mode, "custodian": custodian_mode}, keys=dict(keys))


def dedup_document(index: DedupIndex) -> dict[str, object]:
    """``rapidtriage-dedup.json`` body (without the stamp the caller adds)."""
    modes: dict[str, object] = {}
    for name in DEDUP_MODES:
        mode = index.modes[name]
        modes[name] = {
            "label": DEDUP_MODE_LABELS[name],
            "summary": mode.summary(),
            "groups": [
                {"key": group.key, "original": group.original, "duplicates": group.duplicates, "count": group.size}
                for group in mode.groups
            ],
            # Descendants that follow their top-level item (family mode only): ref -> [status, group].
            "inherited": {
                ref: [status, position]
                for ref, (status, position) in mode.status.items()
                if mode.groups[position].original != ref and ref not in mode.groups[position].duplicates
            },
        }
    return {"format": DEDUP_FORMAT, "keys": index.keys, "modes": modes}


def dedup_index_from_document(document: Mapping[str, object]) -> DedupIndex:
    """Rebuild the index from a stored document (``ValueError`` when it does not validate)."""
    raw_keys = document.get("keys")
    raw_modes = document.get("modes")
    if not isinstance(raw_keys, dict) or not isinstance(raw_modes, dict):
        raise ValueError("dedup document shape")
    keys = {str(ref): str(key) for ref, key in raw_keys.items()}
    modes: dict[str, DedupMode] = {}
    for name in DEDUP_MODES:
        raw = raw_modes.get(name)
        if not isinstance(raw, dict) or not isinstance(raw.get("groups"), list):
            raise ValueError(f"dedup mode {name}")
        mode = DedupMode()
        for item in raw["groups"]:
            if not isinstance(item, dict) or not isinstance(item.get("original"), str) or not isinstance(item.get("duplicates"), list):
                raise ValueError("dedup group shape")
            position = len(mode.groups)
            duplicates = [str(ref) for ref in item["duplicates"]]
            mode.groups.append(DedupGroup(str(item.get("key") or ""), item["original"], duplicates))
            mode.status[item["original"]] = ("original", position)
            for ref in duplicates:
                mode.status[ref] = ("duplicate", position)
        inherited = raw.get("inherited") or {}
        if not isinstance(inherited, dict):
            raise ValueError("dedup inherited shape")
        for ref, value in inherited.items():
            if (
                not isinstance(value, list)
                or len(value) != 2
                or value[0] not in ("original", "duplicate")
                or type(value[1]) is not int
                or not 0 <= value[1] < len(mode.groups)
            ):
                raise ValueError("dedup inherited entry")
            mode.status.setdefault(str(ref), (value[0], value[1]))
        modes[name] = mode
    return DedupIndex(modes=modes, keys=keys)

