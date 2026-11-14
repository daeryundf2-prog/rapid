#!/usr/bin/env python3
"""Compare RapidTriage mail messages with a mailbox tool's message export (T-212).

    python scripts/mail-reference-diff.py --ours <run>/artifacts/<per-kind .json or JSONL> \\
        --reference <messages.csv> --output <report.json> --json

Key = Message-ID (angle brackets dropped, case-insensitive); a message
without one is keyed by sender + subject + date (UTC whole seconds; RFC 2822
dates are read too). Compared per message: attachment count and subject.
The report adds message and attachment totals on each side and ``match``
(true only when counts, keys and fields all agree).

Ours: ``email-message`` rows (``message_id``, ``attachment_count`` or the
``attachments`` list, ``subject``, ``from``, ``date``). Reference: one row
per message from a mailbox tool export (``Message-ID``/``InternetMessageId``,
``AttachmentCount`` or an ``Attachments`` name list separated by ``;``,
``Subject``, ``From``, ``Date``).

Shared loader/diff/report: rapidtriage/validation/reference_diff.py.
Exit 0 clean, 1 differences, 2 input error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from email.utils import parsedate_to_datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

MAIL_ARTIFACT_TYPES = ("email-message",)
REF_MSGID = ("messageid", "internetmessageid")
REF_FROM = ("from", "sender", "senderemail")
REF_SUBJECT = ("subject",)
REF_DATE = ("date", "sent", "sentdate", "deliverytime")
REF_ATTACH_COUNT = ("attachmentcount", "numattachments")
REF_ATTACH_LIST = ("attachments",)


def attachment_count(value: object) -> int:
    """Count from a number, a list, or a ``;``-separated name list; empty means 0."""
    if isinstance(value, (list, tuple)):
        return len(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value if value is not None else "").strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    return len([part for part in text.split(";") if part.strip()])


def mail_time(value: object, default_tz: dt.tzinfo, warnings: list[str], context: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if text and "," in text[:5]:  # RFC 2822: "Mon, 03 Jun 2024 09:00:00 +0900"
        try:
            stamp = parsedate_to_datetime(text)
            return (stamp if stamp.tzinfo else stamp.replace(tzinfo=default_tz)).astimezone(dt.timezone.utc)
        except (TypeError, ValueError, IndexError):
            pass
    return rd.safe_timestamp(value, default_tz, warnings, context)


def message_row(message_id: object, sender: object, subject: object, date: object, count: int) -> rd.KeyedRow:
    mid = rd.normalize_text(str(message_id or "").strip().strip("<>"))
    key = mid or "no-message-id|" + "|".join(
        (rd.normalize_text(sender), rd.normalize_text(subject), rd.format_timestamp(date))  # type: ignore[arg-type]
    )
    fields = {"attachment_count": count, "subject": rd.normalize_text(subject)}
    return rd.KeyedRow(keys=[key], fields=fields, label={"message_id": mid, **fields})


def build_mail_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, message_id_or_subject=(*REF_MSGID, *REF_SUBJECT))
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        count_text = rd.pick(row, *REF_ATTACH_COUNT)
        count = attachment_count(count_text if count_text else rd.pick(row, *REF_ATTACH_LIST))
        date = mail_time(rd.pick(row, *REF_DATE), args.reference_tzinfo, warnings, f"기준 {line}행")
        reference.append(
            message_row(rd.pick(row, *REF_MSGID), rd.pick(row, *REF_FROM), rd.pick(row, *REF_SUBJECT), date, count)
        )
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, MAIL_ARTIFACT_TYPES, warnings):
        count_value = rd.rapid_field(row, "attachment_count")
        count = attachment_count(count_value if count_value is not None else rd.rapid_field(row, "attachments"))
        date = mail_time(rd.rapid_field(row, "date", "sent_at"), args.ours_tzinfo, warnings, "우리 메일 행")
        ours.append(
            message_row(
                rd.rapid_field(row, "message_id", "internet_message_id"),
                rd.rapid_field(row, "from", "sender"),
                rd.rapid_field(row, "subject"),
                date,
                count,
            )
        )

    def totals(result: rd.DiffResult) -> dict[str, object]:
        ours_attachments = sum(int(item.fields["attachment_count"]) for item in ours)  # type: ignore[call-overload]
        ref_attachments = sum(int(item.fields["attachment_count"]) for item in reference)  # type: ignore[call-overload]
        return {
            "messages": {"ours": len(ours), "reference": len(reference)},
            "attachments": {
                "ours": ours_attachments,
                "reference": ref_attachments,
                "missing": max(ref_attachments - ours_attachments, 0),
            },
            "match": (
                len(ours) == len(reference)
                and ours_attachments == ref_attachments
                and not result.missing
                and not result.extra
                and not result.mismatched
            ),
        }

    if not reference:
        rd.add_warning(warnings, "기준 파일에 메시지 행이 없습니다")
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool="mailbox tool message export (CSV)",
        key_fields=["message_id"],
        compared_fields=["attachment_count", "subject"],
        extra_sections=totals,
    )


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="mail",
        description="Diff RapidTriage email-message rows against a mailbox tool export (key = Message-ID).",
        build=build_mail_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
