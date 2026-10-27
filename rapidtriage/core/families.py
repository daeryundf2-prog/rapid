"""계열(family) — parent / child item relations derived from a run's outputs (R7 갈래 A, Nuix R1).

Nothing is re-parsed: the relations come from fields the parsers already wrote.

* email-message → email-attachment rows (PST normalizer: same mailbox ``path``, ``message_id``,
  ``export_item`` and ``folder``); an EML / MBOX message's own ``details.attachments`` become
  *virtual* children ``<message locator>#attachment:<i>`` (i = position in that list) when no
  attachment row names the message.
* email-mailbox / email-container-inventory row → the email-message rows of the same mailbox
  ``path`` (a *container* relation: a message stays a top-level item, as in Nuix).
* archive-file-inventory row → its listed entries as virtual children
  ``<archive locator>#entry:<i>`` (i = position in ``archive_inventory_profile.sample_entries``,
  the search index's archive-entry locator form).
* android-backup row → android-backup-member rows of the same ``.ab``; a member → the app rows
  parsed from it (``details.container_backup_path`` + ``container_member``).
* chat-message → chat-attachment rows of the same source row (``path``, ``conversation_id``,
  ``timestamp``, ``sender``; messages with ``attachment_count`` > 0 only).
* carved rows (``recovery_method = carved``: carve analysis rows, carved files candidates) → the
  files row of the source file; a source that is no row is a virtual ``source::<path>`` parent.

An *item reference* (``ref``) is ``<collection>:<kind>:<locator>`` -- ``artifacts:email:/artifacts/3``,
``files::/candidates/12``, ``analysis:<analysis id>:/rows/0``,
``artifacts:generic-documents:/artifacts/5#entry:2``, ``source::<path>``.

*Top-level item* (Nuix): climb parents except across a container relation (mailbox → message).
*Family*: a top-level item and all its descendants. *Material*: inline / signature attachments
and archive folder entries are immaterial (``material = false``).
"""

from __future__ import annotations

import ntpath
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

FAMILIES_FILE_NAME = "rapidtriage-families.jsonl"
FAMILIES_FORMAT = "rapidtriage-families-v1"

COLLECTIONS = ("files", "artifacts", "analysis", "source")
_COLLECTION_RANK = {name: rank for rank, name in enumerate(COLLECTIONS)}
ENTRY_MARK = "#entry:"
ATTACHMENT_MARK = "#attachment:"
# Relations (child side): Korean labels for the console.
RELATION_LABELS: dict[str, str] = {
    "attachment": "첨부",
    "message": "메시지",
    "member": "압축 항목",
    "backup-member": "백업 항목",
    "extracted": "백업에서 추출",
    "chat-attachment": "대화 첨부",
    "carved": "카빙",
}
# Relations whose parent is a container: the child stays a top-level item (Nuix: mail stores).
CONTAINER_RELATIONS = frozenset({"message"})
TITLE_LIMIT = 160

MAILBOX_TYPES = frozenset({"email-mailbox", "email-container-inventory"})
ARCHIVE_TYPE = "archive-file-inventory"
BACKUP_TYPE = "android-backup"
BACKUP_MEMBER_TYPE = "android-backup-member"

_LOCATOR = {
    "artifacts": re.compile(r"^/artifacts/(\d+)(?:(#entry:|#attachment:)(\d+))?$"),
    "files": re.compile(r"^/(candidates|inventory)/(\d+)$"),
    "analysis": re.compile(r"^/rows/(\d+)$"),
}
_KIND = re.compile(r"^[A-Za-z0-9._-]{0,128}$")
MAX_REF_CHARS = 2048


def make_ref(collection: str, kind: str, locator: str) -> str:
    return f"{collection}:{kind}:{locator}"


def parse_ref(text: object) -> tuple[str, str, str] | None:
    """``(collection, kind, locator)`` of a well-formed ref, else ``None``."""
    if not isinstance(text, str) or not text or len(text) > MAX_REF_CHARS:
        return None
    collection, sep, rest = text.partition(":")
    kind, sep2, locator = rest.partition(":")
    if not sep or not sep2 or collection not in _COLLECTION_RANK:
        return None
    if collection == "source":
        return (collection, "", locator) if locator and not kind else None
    if not _KIND.match(kind) or not _LOCATOR[collection].match(locator):
        return None
    if collection in ("artifacts", "analysis") and not kind:
        return None
    if collection == "files" and kind:
        return None
    return collection, kind, locator


def base_ref(ref: str) -> str:
    """The row a virtual entry / attachment ref belongs to (other refs unchanged)."""
    for mark in (ENTRY_MARK, ATTACHMENT_MARK):
        head, found, tail = ref.partition(mark)
        if found and tail.isdigit():
            return head
    return ref


def is_virtual(ref: str) -> bool:
    return ref.startswith("source::") or base_ref(ref) != ref


def ref_order(ref: str) -> tuple[object, ...]:
    """Deterministic item order: files (candidates, inventory), artifacts by kind, analyses, sources;
    record order inside each, virtual children after their row."""
    parsed = parse_ref(ref)
    if parsed is None:
        return (99, ref)
    collection, kind, locator = parsed
    numbers = [int(part) for part in re.findall(r"\d+", locator)] if collection != "source" else []
    sub = numbers[1] if len(numbers) > 1 else -1
    head = numbers[0] if numbers else 0
    lane = 1 if "/inventory/" in locator else 0
    return (_COLLECTION_RANK[collection], kind, lane, head, sub, locator if collection == "source" else "")


@dataclass(slots=True)
class SourceRow:
    """One run row handed to the derivations (``row`` is the expanded record)."""

    collection: str
    kind: str
    locator: str
    row: Mapping[str, object]

    @property
    def ref(self) -> str:
        return make_ref(self.collection, self.kind, self.locator)


@dataclass(slots=True)
class NodeInfo:
    title: str
    artifact_type: str
    material: bool = True


@dataclass
class FamilyIndex:
    """Parent / child relations of a run (only items that have a relation are held)."""

    parent: dict[str, tuple[str, str]] = field(default_factory=dict)  # child -> (parent, relation)
    children: dict[str, list[str]] = field(default_factory=dict)
    nodes: dict[str, NodeInfo] = field(default_factory=dict)

    def add(self, parent: str, child: str, relation: str) -> bool:
        """Link ``child`` under ``parent`` (first parent wins; a link closing a cycle is refused)."""
        if parent == child or child in self.parent:
            return False
        cursor: str | None = parent
        seen = 0
        while cursor is not None and seen < 10_000:
            if cursor == child:
                return False
            link = self.parent.get(cursor)
            cursor = link[0] if link else None
            seen += 1
        self.parent[child] = (parent, relation)
        self.children.setdefault(parent, []).append(child)
        return True

    def finish(self) -> None:
        for refs in self.children.values():
            refs.sort(key=ref_order)

    @property
    def edge_count(self) -> int:
        return len(self.parent)

    def ancestors(self, ref: str) -> list[str]:
        """Parent, grandparent, … (nearest first)."""
        out: list[str] = []
        cursor = self.parent.get(ref)
        while cursor is not None and len(out) < 10_000:
            out.append(cursor[0])
            cursor = self.parent.get(cursor[0])
        return out

    def top(self, ref: str) -> str:
        """The top-level item of ``ref``: climb parents, never across a container relation."""
        current = ref
        for _ in range(10_000):
            link = self.parent.get(current)
            if link is None or link[1] in CONTAINER_RELATIONS:
                return current
            current = link[0]
        return current

    def descendants(self, ref: str, *, family_only: bool = True) -> list[str]:
        """Children, grandchildren, … in tree order (``family_only``: not below a container edge)."""
        out: list[str] = []
        stack = list(reversed(self.children.get(ref, [])))
        while stack and len(out) < 1_000_000:
            child = stack.pop()
            if family_only and self.parent.get(child, ("", ""))[1] in CONTAINER_RELATIONS:
                continue
            out.append(child)
            stack.extend(reversed(self.children.get(child, [])))
        return out

    def family(self, ref: str) -> list[str]:
        """Top-level item of ``ref`` and its descendants (``ref`` alone when it has no relation)."""
        top = self.top(ref)
        return [top, *self.descendants(top)]

    def relation(self, ref: str) -> str | None:
        link = self.parent.get(ref)
        return link[1] if link else None

    def info(self, ref: str) -> NodeInfo | None:
        return self.nodes.get(ref)


# --- row helpers --------------------------------------------------------------------------------


def details_of(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    return details if isinstance(details, Mapping) else {}


def text_of(value: object, limit: int = TITLE_LIMIT) -> str:
    if value is None or isinstance(value, (Mapping, list, bool)):
        return ""
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def norm_path(value: object) -> str:
    """Comparable form of an evidence path (case-folded, back slashes, no trailing separator)."""
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.strip().replace("/", "\\").rstrip("\\").casefold()


def base_name(value: object) -> str:
    text = str(value or "")
    return ntpath.basename(text.replace("/", "\\")) or text


def row_title(source: SourceRow) -> str:
    row, details = source.row, details_of(source.row)
    kind = str(row.get("artifact_type") or "")
    if source.collection == "files":
        return text_of(row.get("name") or base_name(row.get("path")))
    if kind == "email-message":
        return text_of(details.get("subject")) or "(제목 없음)"
    if kind in ("email-attachment",):
        return text_of(details.get("filename")) or "(이름 없는 첨부)"
    if kind == "chat-attachment":
        return text_of(details.get("file_name") or details.get("file_path")) or "(이름 없는 첨부)"
    if kind == "chat-message":
        return text_of(details.get("message_text_preview"), 80) or "(본문 없음)"
    if kind == BACKUP_MEMBER_TYPE:
        return text_of(details.get("member_path") or details.get("member_name"))
    if source.collection == "analysis":
        signature = text_of(details.get("signature_kind")) or "카빙"
        offset = details.get("offset")
        return f"{signature} @ 0x{int(offset):x}" if isinstance(offset, int) and not isinstance(offset, bool) else signature
    return text_of(base_name(row.get("path") or details.get("source_path"))) or kind


def _entry_material(entry: Mapping[str, object]) -> bool:
    return not entry.get("is_dir") and not str(entry.get("name") or "").endswith(("/", "\\"))


def _attachment_material(item: Mapping[str, object]) -> bool:
    return not bool(item.get("inline"))


# --- derivation ---------------------------------------------------------------------------------


@dataclass
class _Collector:
    messages: dict[tuple[str, ...], str] = field(default_factory=dict)
    messages_by_id: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    message_rows: dict[str, tuple[str, str, list[tuple[int, Mapping[str, object]]]]] = field(default_factory=dict)
    attachments: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    mailboxes: dict[tuple[str, str], str] = field(default_factory=dict)
    mail_in_box: list[tuple[str, tuple[str, str]]] = field(default_factory=list)
    backups: dict[str, str] = field(default_factory=dict)
    backup_members: dict[tuple[str, str], str] = field(default_factory=dict)
    member_rows: list[tuple[str, str]] = field(default_factory=list)
    extracted: list[tuple[str, tuple[str, str]]] = field(default_factory=list)
    chat_messages: dict[tuple[str, ...], str] = field(default_factory=dict)
    chat_attachments: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    files_by_path: dict[str, str] = field(default_factory=dict)
    carved: list[tuple[str, str, str]] = field(default_factory=list)  # (ref, source norm path, source path)


def _mail_key(source: SourceRow, details: Mapping[str, object]) -> tuple[str, ...]:
    return (
        source.kind,
        norm_path(source.row.get("path")),
        text_of(details.get("message_id"), 1000),
        text_of(details.get("export_item"), 1000),
        text_of(details.get("folder"), 1000),
    )


def _chat_key(source: SourceRow, details: Mapping[str, object]) -> tuple[str, ...]:
    return (
        source.kind,
        norm_path(source.row.get("path")),
        text_of(details.get("conversation_id"), 1000),
        text_of(details.get("timestamp"), 100),
        text_of(details.get("sender"), 1000),
    )


class FamilyBuilder:
    """Streaming derivation: :meth:`add` every row once (any order), then :meth:`finish`."""

    def __init__(self) -> None:
        self.index = FamilyIndex()
        self._c = _Collector()

    def _node(self, ref: str, title: str, artifact_type: str, material: bool = True) -> None:
        if ref not in self.index.nodes:
            self.index.nodes[ref] = NodeInfo(title, artifact_type, material)

    def add(self, source: SourceRow) -> None:
        row = source.row
        details = details_of(row)
        ref = source.ref
        artifact_type = str(row.get("artifact_type") or "")
        c = self._c
        if source.collection == "files":
            key = norm_path(row.get("path"))
            if key and key not in c.files_by_path:
                c.files_by_path[key] = ref
            recovery = row.get("recovery") if isinstance(row.get("recovery"), Mapping) else {}
            source_path = recovery.get("source_path") if isinstance(recovery, Mapping) else None
            if (
                isinstance(recovery, Mapping)
                and recovery.get("candidate_kind") == "carved"
                and norm_path(source_path)
                and norm_path(source_path) != key
            ):
                c.carved.append((ref, norm_path(source_path), str(source_path)))
                self._remember(source, ref)
            return
        if source.collection == "analysis":
            if details.get("recovery_method") == "carved":
                path = details.get("source_path") or row.get("path")
                if norm_path(path):
                    c.carved.append((ref, norm_path(path), str(path)))
                    self._remember(source, ref)
            return
        if artifact_type == "email-message":
            key = _mail_key(source, details)
            c.messages.setdefault(key, ref)
            c.messages_by_id.setdefault((key[0], key[1], key[2]), []).append(ref)
            embedded = details.get("attachments")
            items = [(i, item) for i, item in enumerate(embedded) if isinstance(item, Mapping)] if isinstance(embedded, list) else []
            c.message_rows[ref] = (key[0], key[1], items)
            c.mail_in_box.append((ref, (source.kind, norm_path(row.get("path")))))
            self._remember(source, ref)
        elif artifact_type == "email-attachment":
            c.attachments.append((ref, _mail_key(source, details)))
            self._remember(source, ref, material=not bool(details.get("inline")))
        elif artifact_type in MAILBOX_TYPES:
            c.mailboxes.setdefault((source.kind, norm_path(row.get("path"))), ref)
            self._remember(source, ref)
        elif artifact_type == ARCHIVE_TYPE:
            profile = details.get("archive_inventory_profile")
            entries = profile.get("sample_entries") if isinstance(profile, Mapping) else None
            if isinstance(entries, list) and entries:
                self._remember(source, ref)
                for position, entry in enumerate(entries):
                    if not isinstance(entry, Mapping):
                        continue
                    child = f"{ref}{ENTRY_MARK}{position}"
                    self._node(child, text_of(entry.get("name")) or f"항목 {position + 1}", "archive-entry", _entry_material(entry))
                    self.index.add(ref, child, "member")
        elif artifact_type == BACKUP_TYPE:
            c.backups.setdefault(norm_path(row.get("path")), ref)
            self._remember(source, ref)
        elif artifact_type == BACKUP_MEMBER_TYPE:
            path = norm_path(row.get("path"))
            c.member_rows.append((ref, path))
            member = text_of(details.get("member_name"), 1000)
            if member:
                c.backup_members.setdefault((path, member), ref)
            self._remember(source, ref, material=details.get("member_type") != "directory")
        elif artifact_type == "chat-message":
            if isinstance(details.get("attachment_count"), int) and int(details.get("attachment_count") or 0) > 0:
                c.chat_messages.setdefault(_chat_key(source, details), ref)
                self._remember(source, ref)
        elif artifact_type == "chat-attachment":
            c.chat_attachments.append((ref, _chat_key(source, details)))
            self._remember(source, ref)
        if details.get("container_member") and details.get("container_backup_path"):
            c.extracted.append((ref, (norm_path(details.get("container_backup_path")), text_of(details.get("container_member"), 1000))))
            self._remember(source, ref)

    def _remember(self, source: SourceRow, ref: str, *, material: bool = True) -> None:
        self._node(ref, row_title(source), str(source.row.get("artifact_type") or ""), material)

    def finish(self) -> FamilyIndex:
        c = self._c
        index = self.index
        linked_messages: set[str] = set()
        for child, key in c.attachments:
            parent = c.messages.get(key)
            if parent is None:
                candidates = c.messages_by_id.get((key[0], key[1], key[2])) or []
                parent = candidates[0] if len(candidates) == 1 and key[2] else None
            if parent is not None and index.add(parent, child, "attachment"):
                linked_messages.add(parent)
        for message, (_kind, _path, items) in c.message_rows.items():
            if message in linked_messages:
                continue  # the attachment rows are the children
            for position, item in items:
                child = f"{message}{ATTACHMENT_MARK}{position}"
                self._node(child, text_of(item.get("filename")) or f"첨부 {position + 1}", "email-attachment", _attachment_material(item))
                index.add(message, child, "attachment")
        for message, box_key in c.mail_in_box:
            box = c.mailboxes.get(box_key)
            if box is not None:
                index.add(box, message, "message")
        for member, path in c.member_rows:
            backup = c.backups.get(path)
            if backup is not None:
                index.add(backup, member, "backup-member")
        for child, key in c.extracted:
            parent = c.backup_members.get(key) or c.backups.get(key[0])
            if parent is not None and parent != child:
                index.add(parent, child, "extracted")
        for child, key in c.chat_attachments:
            parent = c.chat_messages.get(key)
            if parent is not None:
                index.add(parent, child, "chat-attachment")
        for child, source_key, source_path in c.carved:
            parent = c.files_by_path.get(source_key)
            if parent is None:
                parent = make_ref("source", "", source_path)
                self._node(parent, text_of(base_name(source_path)) or source_path, "source-file")
            elif parent not in index.nodes:
                self._node(parent, text_of(base_name(source_path)), "file")
            index.add(parent, child, "carved")
        # Drop node infos of rows that ended up without any relation.
        linked = set(index.parent) | set(index.children)
        index.nodes = {ref: info for ref, info in index.nodes.items() if ref in linked}
        index.finish()
        return index


def derive_families(rows: Iterable[SourceRow]) -> FamilyIndex:
    builder = FamilyBuilder()
    for source in rows:
        builder.add(source)
    return builder.finish()


# --- file ----------------------------------------------------------------------------------------


def iter_family_records(index: FamilyIndex) -> Iterator[dict[str, object]]:
    """``rapidtriage-families.jsonl`` edge records (parent order, then child order)."""
    for parent in sorted(index.children, key=ref_order):
        parent_info = index.nodes.get(parent)
        for child in index.children[parent]:
            relation = index.parent[child][1]
            info = index.nodes.get(child)
            yield {
                "parent_locator": parent,
                "child_locator": child,
                "relation": relation,
                "material": bool(info.material) if info else True,
                "parent_title": parent_info.title if parent_info else "",
                "parent_type": parent_info.artifact_type if parent_info else "",
                "child_title": info.title if info else "",
                "child_type": info.artifact_type if info else "",
            }


def family_index_from_records(records: Iterable[Mapping[str, object]]) -> FamilyIndex:
    """Rebuild the index from stored edge records (``ValueError`` on a malformed record)."""
    index = FamilyIndex()
    for record in records:
        parent, child, relation = record.get("parent_locator"), record.get("child_locator"), record.get("relation")
        if not isinstance(parent, str) or not isinstance(child, str) or not isinstance(relation, str):
            raise ValueError("family edge shape")
        if parse_ref(parent) is None or parse_ref(child) is None:
            raise ValueError("family edge ref")
        if parent not in index.nodes:
            index.nodes[parent] = NodeInfo(str(record.get("parent_title") or ""), str(record.get("parent_type") or ""))
        index.nodes[child] = NodeInfo(str(record.get("child_title") or ""), str(record.get("child_type") or ""), record.get("material") is not False)
        if not index.add(parent, child, relation):
            raise ValueError("family edge duplicates a child or closes a cycle")
    index.finish()
    return index
