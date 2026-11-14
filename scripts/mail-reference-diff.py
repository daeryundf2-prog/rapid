#!/usr/bin/env python3
"""Compare RapidTriage mail messages with a mailbox tool's message export (T-212).

    python scripts/mail-reference-diff.py --ours <records.jsonl> \\
        --reference <messages.csv> --output <report.json> --json

Key = Message-ID (angle brackets dropped, case-insensitive); a message
without one is keyed by sender + subject + date (UTC seconds). Compared per
message: attachment count and subject. Totals: message count and attachment
count on each side.

Ours: ``email-message`` records (``message_id``, ``attachment_count`` or the
``attachments`` list, ``subject``, ``from``, ``date``). Reference: one row
per message from a mailbox tool export (``Message-ID``/``InternetMessageId``,
``AttachmentCount`` or an ``Attachments`` name list separated by ``;``,
``Subject``, ``From``, ``Date``).

Report keys: recall, matched, missing, mismatched, reference_tool (+ extra,
counts, messages, attachments, match). Exit 2 when an input is missing.
"""

from __future__ import annotations

import sys
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

OURS_TYPES = {"email-message"}
MSGID_OURS = ("message_id", "internet_message_id")
MSGID_REF = ("Message-ID", "MessageId", "Message ID", "InternetMessageId", "Internet Message ID", "message_id")
FROM_OURS = ("from", "sender", "from_address")
FROM_REF = ("From", "Sender", "SenderEmail", "Sender Email", "from")
SUBJECT_OURS = ("subject",)
SUBJECT_REF = ("Subject", "subject")
DATE_OURS = ("date", "sent_at", "timestamp")
DATE_REF = ("Date", "Sent", "SentDate", "Sent Date", "DeliveryTime", "Delivery Time", "date")
ATTACH_OURS = ("attachment_count", "attachments")
ATTACH_REF = ("AttachmentCount", "Attachment Count", "NumAttachments", "attachment_count", "Attachments")


def attachment_count(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return str(len(value))
    text = str(value if value is not None else "").strip()
    if not text:
        return "0"  # an empty attachment cell means none
    if text.isdigit():
        return str(int(text))
    return str(len([part for part in text.split(";") if part.strip()]))


def key_fn(msgid, sender, subject, date, naive_tz):
    def key(row) -> str:
        message_id = str(H.pick(row, msgid) or "").strip().strip("<>").strip().casefold()
        if message_id:
            return message_id
        parts = (H.norm_text(H.pick(row, sender)), H.norm_text(H.pick(row, subject)),
                 H.norm_ts(H.pick(row, date), naive_tz))
        return "no-message-id|" + "|".join(parts) if any(parts) else ""

    return key


def compare(ours_rows, reference_rows, naive_tz) -> dict[str, object]:
    ours_rows = [row for row in ours_rows if str(row.get("artifact_type") or "") in OURS_TYPES]
    result = H.diff_keyed(
        ours_rows,
        reference_rows,
        ours_key=key_fn(MSGID_OURS, FROM_OURS, SUBJECT_OURS, DATE_OURS, timezone.utc),
        reference_key=key_fn(MSGID_REF, FROM_REF, SUBJECT_REF, DATE_REF, naive_tz),
        fields=[
            H.FieldSpec("attachment_count", ATTACH_OURS, ATTACH_REF, attachment_count),
            H.FieldSpec("subject", SUBJECT_OURS, SUBJECT_REF, H.norm_text),
        ],
    )
    ours_attachments = sum(int(attachment_count(H.pick(row, ATTACH_OURS)) or 0) for row in ours_rows)
    ref_attachments = sum(int(attachment_count(H.pick(row, ATTACH_REF)) or 0) for row in reference_rows)
    result["messages"] = {"ours": len(ours_rows), "reference": len(reference_rows)}
    result["attachments"] = {
        "ours": ours_attachments,
        "reference": ref_attachments,
        "missing": max(ref_attachments - ours_attachments, 0),
    }
    result["match"] = (
        len(ours_rows) == len(reference_rows)
        and ours_attachments == ref_attachments
        and not result["missing"]
        and not result["extra"]
        and not result["mismatched"]
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(__doc__.splitlines()[0], "mailbox-tool-export-csv")

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference})
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare(H.load_ours(args.ours), H.load_csv(args.reference), naive_tz)
        report = H.envelope("mail", args.reference_tool, {"ours": args.ours, "reference": args.reference}, result)
        summary = (
            f"match={result['match']} messages={result['messages']} attachments={result['attachments']} "
            + H.summary_line(report)
        )
        return H.emit(report, args.output, args.json, summary)

    return H.run_cli(body)


if __name__ == "__main__":
    raise SystemExit(main())
