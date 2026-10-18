"""E-mail indicators: EML / MBOX / PST / OST / MSG (catalogue: apps §2)."""

from __future__ import annotations

import datetime as dt
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import NamedTuple

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    as_list,
    email_domain,
    evidence,
    extension,
    org_domain,
    parse_time,
    register,
    select,
)

MESSAGES = select(types={"email-message", "cloud-mail"})
EXECUTABLE_ATTACHMENTS = frozenset({"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "pif", "hta", "jar", "ps1", "lnk", "iso", "img", "msi", "wsf", "cpl", "dll"})
ARCHIVE_ATTACHMENTS = frozenset({"zip", "7z", "rar", "alz", "egg", "gz", "tar", "cab"})
_DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|hwpx?|jpe?g|png|gif|txt|rtf|csv|zip)[\s._-]*\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|hta|jar|ps1|lnk|wsf)$",
    re.IGNORECASE,
)
_AUTH_VERDICT = {name: re.compile(rf"\b{name}\s*=\s*([a-z]+)", re.IGNORECASE) for name in ("spf", "dkim", "dmarc")}
# Magic bytes by family for the attachment preview check.
MAGIC = (
    ("25504446", "pdf"),
    ("504b0304", "zip"),
    ("d0cf11e0", "ole"),
    ("4d5a", "exe"),
    ("ffd8ff", "jpeg"),
    ("89504e47", "png"),
    ("47494638", "gif"),
    ("377abcaf", "7z"),
    ("52617221", "rar"),
)
EXTENSION_FAMILY = {
    "pdf": {"pdf"},
    "docx": {"zip"},
    "xlsx": {"zip"},
    "pptx": {"zip"},
    "hwpx": {"zip"},
    "zip": {"zip"},
    "doc": {"ole"},
    "xls": {"ole"},
    "ppt": {"ole"},
    "hwp": {"ole"},
    "msg": {"ole"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "png": {"png"},
    "gif": {"gif"},
    "7z": {"7z"},
    "rar": {"rar"},
    "exe": {"exe"},
    "dll": {"exe"},
}


def header(row: RowView, *names: str) -> str:
    """Header value from a flat key (``reply_to``), a ``headers`` map or the raw source row (case-insensitive)."""
    for name in names:
        flat = name.lower().replace("-", "_")
        value = row.get(flat, name)
        if value in (None, ""):
            headers = row.get("headers")
            if isinstance(headers, Mapping):
                value = next((item for key, item in headers.items() if str(key).lower() == name.lower()), None)
        if value in (None, ""):
            value = row.raw(name)
        if isinstance(value, list):
            value = "\n".join(str(item) for item in value)
        if value not in (None, ""):
            return str(value)
    return ""


def auth_verdict(row: RowView, mechanism: str) -> str:
    text = header(row, "Authentication-Results", "ARC-Authentication-Results")
    match = _AUTH_VERDICT[mechanism].search(text)
    if match:
        return match.group(1).lower()
    if mechanism == "spf":
        received_spf = header(row, "Received-SPF").strip().lower()
        return received_spf.split()[0] if received_spf else ""
    return ""


def attachments(row: RowView) -> list[Mapping[str, object]]:
    return [item for item in as_list(row.get("attachments")) if isinstance(item, Mapping)]


def attachment_name(item: Mapping[str, object]) -> str:
    return str(item.get("filename") or item.get("name") or item.get("file_name") or "")


def preview_family(item: Mapping[str, object]) -> str:
    preview = str(item.get("bounded_preview_hex") or item.get("header_hex") or "").lower()
    return next((family for magic, family in MAGIC if preview.startswith(magic)), "")


def zip_encrypted(item: Mapping[str, object]) -> bool:
    """ZIP local header general-purpose flag bit 0 (encrypted) from the attachment preview."""
    preview = str(item.get("bounded_preview_hex") or "").lower()
    if not preview.startswith("504b0304") or len(preview) < 16:
        return False
    flags = int(preview[14:16] + preview[12:14], 16)
    return bool(flags & 1)


def received_times(row: RowView) -> list[dt.datetime]:
    """Dates of the Received chain (top hop first)."""
    times: list[dt.datetime] = []
    for line in re.split(r"\n(?=\S)|\r?\n(?=from\s)", header(row, "Received")):
        if ";" not in line:
            continue
        try:
            moment = parsedate_to_datetime(line.rsplit(";", 1)[1].strip())
        except (TypeError, ValueError, IndexError):
            continue
        if moment is not None:
            times.append(moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc))
    return times


def header_date(row: RowView) -> dt.datetime | None:
    text = header(row, "Date")
    if not text:
        return None
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return parse_time(text)  # ISO-8601 (normalised PST rows)
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def sender_address(row: RowView) -> str:
    """SMTP address of the sender, lower-cased; an Exchange X.500 ``From`` falls back to ``sender_smtp_address``."""
    _display, address = parseaddr(header(row, "From"))
    if "@" in address:
        return address.strip().lower()
    _display, address = parseaddr(row.text("sender_smtp_address", "sent_representing_smtp_address"))
    return address.strip().lower() if "@" in address else ""


def from_domain(row: RowView) -> str:
    """Sender domain; an Exchange X.500 sender (``/O=EXCHANGELABS/...``) uses the SMTP sender property instead."""
    return email_domain(header(row, "From")) or email_domain(row.text("sender_smtp_address", "sent_representing_smtp_address"))


def recipients(row: RowView) -> list[str]:
    values = [header(row, name) for name in ("To", "Cc", "Bcc")]
    return [address.lower() for _name, address in getaddresses([value for value in values if value]) if "@" in address]


class _AuthRule(Rule):
    mechanism = ""
    verdicts: frozenset[str] = frozenset()
    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        verdict = auth_verdict(row, self.mechanism)
        if verdict not in self.verdicts:
            return None
        return RuleResult(evidence(**{self.mechanism: verdict, "from": header(row, "From"), "subject": header(row, "Subject")}))


@register("email.spf_fail")
class SpfFail(_AuthRule):
    """Authentication-Results / Received-SPF: spf=fail or softfail."""

    mechanism = "spf"
    verdicts = frozenset({"fail", "softfail"})


@register("email.dkim_fail")
class DkimFail(_AuthRule):
    """Authentication-Results: dkim=fail or none."""

    mechanism = "dkim"
    verdicts = frozenset({"fail", "none", "permerror"})


@register("email.dmarc_fail")
class DmarcFail(_AuthRule):
    """Authentication-Results: dmarc=fail."""

    mechanism = "dmarc"
    verdicts = frozenset({"fail"})


@register("email.display_name_spoof")
class DisplayNameSpoof(Rule):
    """From display name carries an address of another domain than the real sender."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        display, address = parseaddr(header(row, "From"))
        shown = email_domain(display)
        real = email_domain(address)
        if not shown or not real or org_domain(shown) == org_domain(real):
            return None
        return RuleResult(evidence(display_name=display, address=address))


class _DomainMismatch(Rule):
    header_names: tuple[str, ...] = ()
    selector = MESSAGES

    def other_domain(self, row: RowView) -> str:
        return email_domain(header(row, *self.header_names))

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        sender = from_domain(row)
        other = self.other_domain(row)
        if not sender or not other or org_domain(sender) == org_domain(other):
            return None
        return RuleResult(evidence(from_domain=sender, other_domain=other, header=self.header_names[0]))


@register("email.reply_to_differs")
class ReplyToDiffers(_DomainMismatch):
    """Reply-To domain differs from the From domain (reply hijack / BEC)."""

    header_names = ("Reply-To",)


@register("email.returnpath_from_mismatch")
class ReturnPathMismatch(_DomainMismatch):
    """Return-Path (envelope sender) domain differs from the From domain."""

    header_names = ("Return-Path",)


@register("email.msgid_domain_mismatch")
class MessageIdMismatch(_DomainMismatch):
    """Message-ID domain part differs from the From domain."""

    header_names = ("Message-ID",)

    def other_domain(self, row: RowView) -> str:
        value = header(row, "Message-ID").strip().strip("<>")
        domain = value.rsplit("@", 1)[-1].lower() if "@" in value else ""
        return domain if "." in domain else ""


@register("email.attach_double_ext")
class AttachDoubleExtension(Rule):
    """Attachment named like ``invoice.pdf.exe`` (document extension followed by an executable one)."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        for item in attachments(row):
            name = attachment_name(item)
            if _DOUBLE_EXTENSION.search(name.strip()):
                return RuleResult(evidence(attachment=name, subject=header(row, "Subject")))
        return None


@register("email.attach_ext_mime_mismatch")
class AttachMimeMismatch(Rule):
    """Attachment whose content magic (bounded preview) contradicts its extension."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        for item in attachments(row):
            name = attachment_name(item)
            expected = EXTENSION_FAMILY.get(extension(name))
            actual = preview_family(item)
            if expected and actual and actual not in expected:
                return RuleResult(evidence(attachment=name, content_type=item.get("content_type"), detected=actual))
        return None


@register("email.attach_exec_or_archive_enc")
class AttachExecutable(Rule):
    """Executable/script/disk-image attachment, or an encrypted archive attachment."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        for item in attachments(row):
            name = attachment_name(item)
            ext = extension(name)
            if ext in EXECUTABLE_ATTACHMENTS or preview_family(item) == "exe":
                return RuleResult(evidence(attachment=name, reason="실행형 첨부"))
            if ext in ARCHIVE_ATTACHMENTS and (as_bool(item.get("encrypted")) is True or zip_encrypted(item)):
                return RuleResult(evidence(attachment=name, reason="암호화 압축 첨부"))
        return None


@register("email.date_vs_received_skew")
class DateReceivedSkew(Rule):
    """Date header more than ``max_skew_hours`` away from the receiving server's (top) Received time."""

    selector = MESSAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        date = header_date(row)
        received = received_times(row)
        if date is None or not received:
            return None
        skew = abs((received[0] - date).total_seconds())
        if skew <= float(self.param("max_skew_hours", 24)) * 3600:
            return None
        return RuleResult(evidence(date=date, received=received[0], skew_hours=round(skew / 3600, 1)))


class _OwnerDomainRule(Rule):
    """Rules that need the mailbox owner's domain (most common From domain of the mailbox)."""

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.domains: dict[str, Counter[str]] = defaultdict(Counter)
        self.messages: list[tuple[RowRef, str, str, list[str]]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        mailbox = row.text("source_path") or row.path()
        sender = org_domain(from_domain(row))
        if sender:
            self.domains[mailbox][sender] += 1
        self.messages.append((row.ref, mailbox, sender, recipients(row)))
        return None

    def owner(self, mailbox: str) -> str:
        counts = self.domains.get(mailbox)
        return counts.most_common(1)[0][0] if counts else ""


@register("email.external_forward_auto")
class ExternalForward(_OwnerDomainRule):
    """≥ ``min_count`` messages from the owner's domain to one external address (auto/bulk forwarding)."""

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        sent: dict[tuple[str, str], list[RowRef]] = defaultdict(list)
        for ref, mailbox, sender, targets in self.messages:
            owner = self.owner(mailbox)
            if not owner or sender != owner:
                continue
            for target in set(targets):
                if org_domain(target.rsplit("@", 1)[-1]) != owner:
                    sent[(mailbox, target)].append(ref)
        for (_mailbox, target), refs in sent.items():
            if len(refs) >= int(self.param("min_count", 20)):
                for ref in refs:
                    yield ref, RuleResult(evidence(external_recipient=target, messages=len(refs)))


@register("email.bcc_self_or_personal")
class PersonalRecipient(_OwnerDomainRule):
    """Message from the owner's domain to a personal webmail address (``personal_domains``)."""

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        personal = {str(item).lower() for item in self.param("personal_domains", [])}
        for ref, mailbox, sender, targets in self.messages:
            owner = self.owner(mailbox)
            if not owner or sender != owner or owner in personal:
                continue
            hits = sorted({target for target in targets if target.rsplit("@", 1)[-1] in personal})
            if hits:
                yield ref, RuleResult(evidence(owner_domain=owner, personal_recipients=hits))


# --- r2 M2: Outlook PST/OST rows (pffexport/readpst) ------------------------------------

# Folder names (one path segment, casefolded) of deleted / recoverable mail. Shared with
# ``rapidtriage.artifacts.email_pst`` (the parser's ``deleted_state``) -- single source of truth.
DELETED_FOLDER_NAMES = frozenset(
    {
        "deleted items",
        "deleted messages",
        "deleted",
        "recoverable items",
        "trash",
        "bin",
        "지운 편지함",
        "지운편지함",
        "삭제된 항목",
        "휴지통",
        "削除済みアイテム",
        "ごみ箱",
        "已删除邮件",
        "已删除项目",
        "已刪除的郵件",
        "已刪除郵件",
        "gelöschte elemente",
        "papierkorb",
        "éléments supprimés",
        "corbeille",
        "elementos eliminados",
        "papelera",
    }
)
SENT_FOLDER_NAMES = frozenset(
    {
        "sent items",
        "sent",
        "sent mail",
        "sent messages",
        "보낸 편지함",
        "보낸편지함",
        "送信済みアイテム",
        "已发送邮件",
        "已傳送的郵件",
        "gesendete elemente",
        "éléments envoyés",
        "elementos enviados",
    }
)
DELETED_STATES = frozenset({"deleted", "deleted-folder", "recovered", "orphan"})
_ACCOUNT_IN_NAME = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_MAILBOX_SUFFIXES = (".pst", ".ost", ".nst", ".mbox", ".msg", ".eml")
# Times later than "now" + this are clock errors / spam with forged dates, not the mailbox's last activity.
FUTURE_TOLERANCE = dt.timedelta(days=1)


def folder_segments(folder: str) -> list[str]:
    """Casefolded, NFC-normalised path segments of a mail folder (``/`` or ``\\`` separated)."""
    text = unicodedata.normalize("NFC", str(folder or ""))
    return [" ".join(part.split()).casefold() for part in re.split(r"[\\/]+", text) if part.strip()]


def folder_is_deleted(folder: str) -> bool:
    """Exact segment match (``Inbox/Undeleted`` and ``Projects/deleted-reports`` are not deleted folders)."""
    return any(segment in DELETED_FOLDER_NAMES for segment in folder_segments(folder))


def folder_is_sent(folder: str) -> bool:
    return any(segment in SENT_FOLDER_NAMES for segment in folder_segments(folder))


def account_address(mailbox: str) -> str:
    """Account address in the container file name (Outlook names OSTs ``alice@example.com.ost``)."""
    name = re.split(r"[\\/]", mailbox)[-1]
    lowered = name.lower()
    for suffix in _MAILBOX_SUFFIXES:
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    match = _ACCOUNT_IN_NAME.search(name)
    return match.group(0).lower() if match else ""


def message_time(row: RowView) -> dt.datetime | None:
    """Submit / delivery time of a normalised PST row, else the Date header."""
    return row.time("submit_time", "delivery_time") or header_date(row) or row.time("date")


def mailbox_time(row: RowView, now: dt.datetime) -> dt.datetime | None:
    """Delivery / submit time only (the sender-controlled Date header is not used); future-dated values are dropped."""
    moment = row.time("delivery_time", "submit_time")
    if moment is None or moment > now + FUTURE_TOLERANCE:
        return None
    return moment


def attachment_inline(item: Mapping[str, object]) -> bool:
    """Inline body part (signature / embedded image): ``inline`` flag, ``Content-Disposition: inline`` or an image with a Content-ID."""
    if as_bool(item.get("inline")) is True:
        return True
    if str(item.get("content_disposition") or "").strip().lower() == "inline":
        return True
    return bool(item.get("content_id")) and str(item.get("content_type") or "").lower().startswith("image/")


def attachment_total(row: RowView) -> int:
    """Attachments without inline parts. Rows carrying ``inline_attachment_count`` already exclude them."""
    items = attachments(row)
    inline = sum(1 for item in items if attachment_inline(item))
    count = row.number("attachment_count")
    if count is None:
        return len(items) - inline
    if row.get("inline_attachment_count") is not None:
        return int(count)
    return max(0, int(count) - inline)


def message_key(row: RowView) -> str:
    return row.text("message_id", "Message-ID").strip().strip("<>").strip().lower()


class _BulkFact(NamedTuple):
    ref: RowRef
    mailbox: str
    sender: str
    in_sent: bool
    targets: list[str]
    count: int
    moment: dt.datetime
    key: str
    live: bool


@register("email.external_bulk_attachments")
class ExternalBulkAttachments(Rule):
    """≥ ``min_attachments`` attachments *sent by the mailbox owner* to external-domain recipients on one (local) day.

    Owner: the most common sender of the Sent folder, else the account address in the container name.
    Direction: Sent folder, or From == owner. One copy per Message-ID (live preferred over recovered / orphan /
    Deleted Items copies); inline parts (signature images) are not counted.
    """

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.sent_senders: dict[str, Counter[str]] = defaultdict(Counter)
        self.messages: list[_BulkFact] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        mailbox = row.text("source_path") or row.path()
        folder = row.text("folder", "mailbox_folder")
        sender = sender_address(row)
        in_sent = folder_is_sent(folder)
        if in_sent and sender:
            self.sent_senders[mailbox][sender] += 1
        count = attachment_total(row)
        moment = message_time(row)
        if count > 0 and moment is not None:
            live = row.text("deleted_state").lower() not in DELETED_STATES and not folder_is_deleted(folder)
            self.messages.append(_BulkFact(row.ref, mailbox, sender, in_sent, recipients(row), count, moment, message_key(row), live))
        return None

    def owner(self, mailbox: str) -> str:
        counts = self.sent_senders.get(mailbox)
        return counts.most_common(1)[0][0] if counts else account_address(mailbox)

    def deduplicated(self) -> list[_BulkFact]:
        """One fact per (mailbox, Message-ID): the live copy wins over recovered / deleted copies."""
        kept: list[_BulkFact] = []
        unique: dict[tuple[str, str], _BulkFact] = {}
        for fact in self.messages:
            if not fact.key:
                kept.append(fact)
                continue
            previous = unique.get((fact.mailbox, fact.key))
            if previous is None or (fact.live and not previous.live):
                unique[(fact.mailbox, fact.key)] = fact
        return kept + list(unique.values())

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        offset = dt.timedelta(hours=float(self.param("tz_offset_hours", 9)))
        days: dict[tuple[str, dt.date], list[tuple[RowRef, int, list[str]]]] = defaultdict(list)
        for fact in self.deduplicated():
            owner = self.owner(fact.mailbox)
            if not (fact.in_sent or (owner and fact.sender == owner)):
                continue
            reference = owner or fact.sender
            owner_org = org_domain(reference.rsplit("@", 1)[-1]) if "@" in reference else ""
            if not owner_org:
                continue
            external = sorted({target for target in fact.targets if org_domain(target.rsplit("@", 1)[-1]) != owner_org})
            if external:
                days[(fact.mailbox, (fact.moment + offset).date())].append((fact.ref, fact.count, external))
        threshold = int(self.param("min_attachments", 10))
        for (_mailbox, day), items in days.items():
            total = sum(count for _ref, count, _external in items)
            if total < threshold:
                continue
            for ref, count, external in items:
                yield ref, RuleResult(
                    evidence(day=day.isoformat(), attachments_that_day=total, attachments=count, external_recipients=external[:5])
                )


@register("email.deleted_folder_recent")
class DeletedFolderRecent(Rule):
    """Message in Deleted Items / Recoverable Items (or recovered by the tool) within ``recent_days`` of the mailbox's newest message.

    Only delivery / submit times count, and times later than the acquisition time (else now) + 1 day
    (forged / broken dates) are ignored,
    so one future-dated spam message does not push the mailbox's "newest" time out of reach.
    """

    selector = MESSAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.now = dt.datetime.now(dt.timezone.utc)
        self.latest: dict[str, dt.datetime] = {}
        self.candidates: list[tuple[RowRef, str, dt.datetime, str, str]] = []

    def reference_time(self, ctx: FlagContext) -> dt.datetime:
        """Acquisition time when the run provides one (``ctx.shared["acquisition_time"]``), else now."""
        return parse_time(ctx.shared.get("acquisition_time")) or self.now

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        moment = mailbox_time(row, self.reference_time(ctx))
        if moment is None:
            return None
        mailbox = row.text("source_path") or row.path()
        if mailbox not in self.latest or moment > self.latest[mailbox]:
            self.latest[mailbox] = moment
        folder = row.text("folder", "mailbox_folder")
        state = row.text("deleted_state").lower()
        if state in DELETED_STATES or folder_is_deleted(folder):
            self.candidates.append((row.ref, mailbox, moment, folder, state))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(days=float(self.param("recent_days", 30)))
        for ref, mailbox, moment, folder, state in self.candidates:
            latest = self.latest[mailbox]
            if latest - moment <= window:
                yield ref, RuleResult(evidence(folder=folder, deleted_state=state, time=moment, mailbox_latest=latest))
