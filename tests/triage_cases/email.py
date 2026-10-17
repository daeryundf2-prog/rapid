"""Fixtures of ``rapidtriage.core.triage_rules.email`` (see ``tests.triage_cases``)."""

from __future__ import annotations

MAILBOX = r"C:\Users\alice\AppData\Local\Microsoft\Outlook\alice@example.com.ost"


def message(mailbox: str = MAILBOX, **details: object) -> dict[str, object]:
    base: dict[str, object] = {
        "source_path": mailbox,
        "from": "Alice Kim <alice@example.com>",
        "to": "Bob Lee <bob@example.com>",
        "subject": "Quarterly report",
        "date": "Wed, 01 May 2024 10:00:00 +0000",
        "message_id": "<20240501100000.1234@mail.example.com>",
    }
    base.update(details)
    return {"kind": "email", "row": {"artifact_type": "email-message", "path": mailbox, "details": base}}


def attachment(filename: str, preview_hex: str, content_type: str = "application/octet-stream") -> dict[str, object]:
    return {"filename": filename, "content_type": content_type, "size": 2048, "bounded_preview_hex": preview_hex}


# ZIP local file header: version 2.0, general-purpose flag 0x0001 (encrypted) / 0x0000.
ZIP_ENCRYPTED = "504b0304" + "1400" + "0100" + "0800"
ZIP_PLAIN = "504b0304" + "1400" + "0000" + "0800"
PDF = "255044462d312e370a"
MZ = "4d5a90000300000004000000"


def outbound(count: int, to: str, mailbox: str = MAILBOX, sender: str = "alice@example.com") -> list[dict[str, object]]:
    return [message(mailbox, **{"from": sender, "to": to, "subject": f"update {index}"}) for index in range(count)]


CASES = {
    "email.spf_fail": {
        "positive": {
            "rows": [message(authentication_results="mx.example.com; spf=softfail smtp.mailfrom=example.net; dkim=none; dmarc=fail header.from=example.com")],
            "flagged": [0],
        },
        # Mailing-list delivery: the list rewrites the envelope (SPF passes for the list) but alters the body (DKIM breaks).
        "negative": {
            "rows": [message(authentication_results="mx.example.com; spf=pass smtp.mailfrom=lists.example.org; dkim=fail header.d=example.org; dmarc=pass")],
            "flagged": [],
        },
    },
    "email.dkim_fail": {
        "positive": {
            "rows": [message(authentication_results="mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=fail (body hash did not verify) header.d=example.com")],
            "flagged": [0],
        },
        "negative": {
            "rows": [message(authentication_results="mx.example.com; spf=softfail smtp.mailfrom=example.org; dkim=pass header.d=example.com; dmarc=pass")],
            "flagged": [],
        },
    },
    "email.dmarc_fail": {
        "positive": {
            "rows": [message(authentication_results="mx.example.com; spf=pass smtp.mailfrom=example.net; dkim=none; dmarc=fail (p=reject) header.from=example.com")],
            "flagged": [0],
        },
        # Third-party sender (marketing SaaS) aligned through DKIM: SPF is for the ESP but DMARC passes.
        "negative": {
            "rows": [message(authentication_results="mx.example.com; spf=pass smtp.mailfrom=bounce.example.net; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")],
            "flagged": [],
        },
    },
    "email.display_name_spoof": {
        "positive": {"rows": [message(**{"from": '"ceo@example.com" <ceo.office@example.net>'})], "flagged": [0]},
        # Personal alias: the display name shows the primary address, the real address is a subdomain of the same organisation.
        "negative": {"rows": [message(**{"from": '"alice@example.com" <alice@mail.example.com>'})], "flagged": []},
    },
    "email.reply_to_differs": {
        "positive": {"rows": [message(reply_to="Alice Kim <alice.kim.finance@example.net>")], "flagged": [0]},
        # Mailing list: Reply-To is the list address on the sender organisation's list server.
        "negative": {
            "rows": [message(**{"from": "Carol Park <carol@example.org>", "reply_to": "dev-team@lists.example.org"})],
            "flagged": [],
        },
    },
    "email.returnpath_from_mismatch": {
        "positive": {"rows": [message(return_path="<payments@example.net>")], "flagged": [0]},
        # VERP bounce address on the sender's own mail subdomain.
        "negative": {"rows": [message(return_path="<bounces+alice=example.com@em.example.com>")], "flagged": []},
    },
    "email.msgid_domain_mismatch": {
        "positive": {"rows": [message(message_id="<5f2c9a.77@relay.example.net>")], "flagged": [0]},
        "negative": {"rows": [message(message_id="<CAF8x7Q@outbound.mail.example.com>")], "flagged": []},
    },
    "email.attach_double_ext": {
        "positive": {"rows": [message(attachments=[attachment("invoice_2024.pdf.exe", MZ)])], "flagged": [0]},
        # Dots in a version/date name, ending in a document extension.
        "negative": {"rows": [message(attachments=[attachment("minutes.2024.05.v2.pdf", PDF, "application/pdf")])], "flagged": []},
    },
    "email.attach_ext_mime_mismatch": {
        "positive": {"rows": [message(attachments=[attachment("statement.pdf", MZ, "application/pdf")])], "flagged": [0]},
        # A .docx is a ZIP container: PK magic is expected.
        "negative": {
            "rows": [message(attachments=[attachment("contract.docx", ZIP_PLAIN, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])],
            "flagged": [],
        },
    },
    "email.attach_exec_or_archive_enc": {
        "positive": {
            "rows": [
                message(attachments=[attachment("scan_0501.js", "76617220", "application/javascript")]),
                message(attachments=[attachment("payroll.zip", ZIP_ENCRYPTED, "application/zip")]),
            ],
            "flagged": [0, 1],
        },
        # Ordinary unencrypted archive of documents.
        "negative": {"rows": [message(attachments=[attachment("photos_may.zip", ZIP_PLAIN, "application/zip")])], "flagged": []},
    },
    "email.date_vs_received_skew": {
        "positive": {
            "rows": [
                message(
                    date="Mon, 01 Apr 2024 09:00:00 +0000",
                    received=[
                        "from mail.example.net (mail.example.net [192.0.2.10]) by mx.example.com; Wed, 01 May 2024 10:00:05 +0000",
                        "from client.example.net by mail.example.net; Wed, 01 May 2024 10:00:01 +0000",
                    ],
                )
            ],
            "flagged": [0],
        },
        # Sender clock in KST (+0900), receiving server logs UTC, plus a few minutes of queueing: same instant.
        "negative": {
            "rows": [
                message(
                    date="Wed, 01 May 2024 19:00:00 +0900",
                    received=["from mail.example.net (mail.example.net [192.0.2.10]) by mx.example.com; Wed, 01 May 2024 10:07:30 +0000"],
                )
            ],
            "flagged": [],
        },
    },
    "email.external_forward_auto": {
        "positive": {"rows": outbound(20, "drop.box@example.net"), "flagged": list(range(20))},
        # Many messages to one colleague in the organisation, plus a newsletter the owner receives from outside.
        "negative": {
            "rows": outbound(22, "team-lead@example.com")
            + [message(**{"from": "news@example.net", "to": "alice@example.com", "subject": f"weekly {index}"}) for index in range(20)],
            "flagged": [],
        },
    },
    "email.bcc_self_or_personal": {
        "positive": {
            "rows": [
                message(),
                message(bcc="alice.private@example.net", subject="customer list"),
            ],
            "flagged": [1],
            "params": {"personal_domains": ["example.net"]},
        },
        # The mailbox itself is a personal webmail account: mail between personal addresses is not a leak indicator.
        "negative": {
            "rows": [
                message(r"C:\Users\alice\Documents\personal.mbox", **{"from": "alice.home@example.net", "to": "friend@example.net"}),
                message(r"C:\Users\alice\Documents\personal.mbox", **{"from": "alice.home@example.net", "to": "family@example.net"}),
            ],
            "flagged": [],
            "params": {"personal_domains": ["example.net"]},
        },
    },
    # r2 M2: PST rows normalised from pffexport/readpst (submit_time, attachment_count, folder, deleted_state).
    "email.external_bulk_attachments": {
        "positive": {
            "rows": [
                message(to="buyer@partner.example.net", attachment_count=4, submit_time=f"2024-03-05T0{hour}:00:00Z")
                for hour in (1, 2, 3)
            ]
            + [message(to="bob@example.com", attachment_count=5, submit_time="2024-03-05T04:00:00Z")],
            "flagged": [0, 1, 2],
        },
        # Same 12 attachments to the same partner, but split over two local (KST) days: 23:00 and 01:00.
        "negative": {
            "rows": [
                message(to="buyer@partner.example.net", attachment_count=6, submit_time="2024-03-05T14:00:00Z"),
                message(to="buyer@partner.example.net", attachment_count=6, submit_time="2024-03-05T16:00:00Z"),
            ],
            "flagged": [],
        },
    },
    "email.deleted_folder_recent": {
        "positive": {
            "rows": [
                message(folder="Top of Personal Folders/Inbox", submit_time="2024-03-10T00:00:00Z"),
                message(folder="Top of Personal Folders/Deleted Items", submit_time="2024-03-01T00:00:00Z"),
                message(folder="", deleted_state="recovered", submit_time="2024-03-05T00:00:00Z"),
                message(folder="Personal Folders/지운 편지함", submit_time="2024-03-09T00:00:00Z"),
            ],
            "flagged": [1, 2, 3],
        },
        # Routine clean-up long ago: the deleted message is a year older than the newest mail of the mailbox.
        "negative": {
            "rows": [
                message(folder="Top of Personal Folders/Inbox", submit_time="2024-03-10T00:00:00Z"),
                message(folder="Top of Personal Folders/Deleted Items", submit_time="2023-01-01T00:00:00Z"),
            ],
            "flagged": [],
        },
    },
}
