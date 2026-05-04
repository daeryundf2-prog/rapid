# RapidTriage #31-#40 Internal Validation

This package records internal fixture evidence for messenger, email, cloud export, and cloud API acquisition items #31 through #40.

Run:

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-031-040 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-031-040-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-031-040/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-031-040 \
  --json
```

The internal fixtures assert that RapidTriage emits reviewable rows with source hashes, source IDs, parser versions, redaction/legal gates, validation matrices, `forensic_review`, commercial blockers, and `core_accuracy_gates` for the implemented messenger, mailbox, cloud export, and cloud API evidence surfaces.

The #31~#35 messenger rows now also emit explicit reportability decisions in `chat_app_commercial_uplift_evidence`. KakaoTalk rows remain `kakaotalk-export-or-inventory-triage-pivot` until post-2025-08 BigBang behavior, schema-specific decoding, deleted/encrypted store handling, and known-answer comparison are attached. WhatsApp rows remain `whatsapp-export-or-db-inventory-triage-pivot` until crypt backup/key workflow, contacts/calls/media databases, and deleted rows are validated. Telegram rows remain `telegram-export-or-cache-triage-pivot` until local encrypted stores, cache/media recovery, and account attribution are validated. Signal rows remain `signal-export-or-inventory-triage-pivot` until SQLCipher/key handling, encrypted backups, attachments, and deleted rows are validated. Extended messenger rows remain `extended-messenger-export-triage-pivot` until service-specific schemas, read-state/reaction completeness, media recovery, and ephemeral/deleted behavior are proven.

Validated item mapping:

| Item | Fixture evidence | Remaining commercial blockers |
| --- | --- | --- |
| #31 KakaoTalk | Authorized export rows preserve service/profile detection, message/media pivots, BigBang compatibility metadata, encrypted/deleted warnings, and source/legal provenance. | Post-2025-08 KakaoTalk corpus, schema-specific parser mapping, deleted/encrypted store validation. |
| #32 WhatsApp | Export/database inventory rows preserve service/profile detection, chat/contact/media pivots, crypt authority warnings, and deleted-row limitations. | Crypt backup workflow, contacts/calls/media database validation, deleted rows. |
| #33 Telegram | Export rows preserve service/profile detection, chat/user/media attribution, account/cache provenance, and encrypted/deleted limitations. | Desktop encrypted stores, cache/media recovery, account attribution. |
| #34 Signal | Export rows preserve service/profile detection, thread/recipient/message inventory, SQLCipher authority gate, attachment/deleted warnings, and secret-safe provenance. | SQLCipher/key handling, encrypted backups, attachment/deleted validation. |
| #35 Extended messengers | LINE/Discord/Instagram/Facebook-style exports preserve service detection, message/media/reaction normalization, schema registry evidence, and encrypted/ephemeral warnings. | Service-specific encrypted stores, reaction/read-state completeness, ephemeral/deleted validation. |
| #36 Email | EML/MBOX/Maildir/PST/OST/MSG rows preserve source profile, message/body/attachment inventory, PST/OST limitations, threading warnings, and privilege boundary. | Native PST/OST/MSG object decoding, folder/deleted recovery, broad mailbox corpus. |
| #37 Google | Google/Gmail/Takeout rows preserve provider profile, Gmail/Drive/Activity/Location normalization, export-scope warnings, and schema/timezone warnings. | Full Takeout product matrix, Gmail threading, Photos sidecar/EXIF merge. |
| #38 iCloud | Apple/iCloud rows preserve provider profile, account/file/photo normalization, ADP/shared-album warnings, and retention/schema warnings. | ADP limits, shared-album fidelity, third-party iCloud containers. |
| #39 Microsoft 365 | OneDrive/Teams/Audit rows preserve provider profile, file/message/audit normalization, eDiscovery warnings, and permission/retention limitations. | Graph/eDiscovery diff, Teams reactions/attachments, SharePoint permission graph. |
| #40 Cloud API | Cloud collection payloads preserve manifest validation, credential redaction, response hashes, API limitation warnings, and OAuth/scope/legal warnings. | Provider OAuth/device flow, pagination/delta corpus, legal hold workflow. |

Boundary: passing this package means `implemented + usable + validated` for internal fixture claims. It is not commercial-grade parity with AXIOM/WISDOM/EnCase until external corpora, provider/vendor-tool diffs, original acquisition metadata, and independent reviewer sign-off are attached.
