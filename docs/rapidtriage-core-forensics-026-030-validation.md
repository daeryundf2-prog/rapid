# RapidTriage #26-#30 Internal Validation

This package records the internal fixture evidence for mobile/vendor export, iOS backup/keychain, Android app-data, and APK/package triage items #26 through #30.

Run:

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-026-030 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-026-030-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-026-030/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-026-030 \
  --json
```

The internal fixtures assert that RapidTriage emits reviewable rows with source hashes, source IDs, parser versions, redaction/legal gates, validation matrices, `forensic_review`, commercial blockers, and `core_accuracy_gates` for the implemented mobile and Android evidence surfaces.

The #26~#30 rows also emit explicit reportability decisions in their commercial-uplift evidence. Vendor mobile exports remain `vendor-mobile-export-triage-pivot` until export settings, source acquisition hashes, vendor schema versions, and deleted-row semantics are validated. iOS backup rows remain `ios-backup-inventory-triage-pivot` until encrypted backups, app databases, and deleted rows are independently validated. iOS keychain rows remain `ios-keychain-redacted-inventory-pivot` until protected-data decryption, access-group semantics, legal authority, and audit evidence are attached. Android app-data rows remain `android-app-data-inventory-triage-pivot` until app-specific databases, encrypted/deleted stores, and backup payloads are decoded with known-answer fixtures. APK rows remain `android-apk-risk-inventory-triage-pivot` until binary manifest decoding, signature-chain trust, DEX/control-flow, and malware-behavior validation exist.

Validated item mapping:

| Item | Fixture evidence | Remaining commercial blockers |
| --- | --- | --- |
| #26 Vendor mobile exports | Cellebrite/XRY/GrayKey/AXIOM-style CSV/JSON rows normalize messages, contacts, calls, apps, files, accounts, media, browser rows, source IDs, hashes, and schema warnings. | Vendor-version schema matrix, deleted-record semantics, original acquisition hash logs, and cross-tool diff. |
| #27 iOS backup | Manifest.db and Info/Status plist fixtures preserve domain/fileID mapping, plist metadata, encrypted-backup authority gates, app DB candidates, and deleted-record warnings. | Encrypted backup unlock, app DB decoding, deleted rows, and independent iOS backup corpus. |
| #28 iOS keychain | Keychain SQLite inventory records table counts, redacted-default policy, protected-data labels, and controlled-reveal audit gates. | Protected-data decryption, access group semantics, and legal authority package. |
| #29 Android artifacts | Android app-data export files preserve package/path attribution, communication/browser/media hints, encrypted-store limitations, and schema tracking. | Android backup payload decoding, app-specific schemas, encrypted/deleted stores. |
| #30 Android APK/app data | APK rows preserve manifest/permission/component normalization, certificate inventory/limitation, bounded DEX/native pivots, and secret-handling warnings. | Binary manifest decoding, signature-chain trust, DEX control-flow, malware behavior validation. |

Boundary: passing this package means `implemented + usable + validated` for internal fixture claims. It is not commercial-grade parity with AXIOM/WISDOM/EnCase until external corpora, vendor-tool diffs, original acquisition metadata, and independent reviewer sign-off are attached.
