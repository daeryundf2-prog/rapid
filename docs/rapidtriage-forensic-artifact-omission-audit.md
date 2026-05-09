# RapidForensic Forensic Artifact Omission Audit

This audit is intentionally strict. It compares the current RapidForensic implementation against a Maestro/WISDOM-style
single-case forensic workbench expectation and marks items that are absent, shallow, or not yet independently validated.

## Current Implementation Evidence

- Artifact collectors discovered from `rapidtriage.artifacts.artifact_collectors()`: 21.
- Static and registry-declared `artifact_type` values discovered by `taxonomy-audit`: 130.
- Main collector families:
  - `android-apk`
  - `browser`
  - `cloud-export`
  - `email`
  - `eventlog`
  - `kakaotalk-windows`
  - `linux-system`
  - `macos-system`
  - `media-image`
  - `memory-volatility`
  - `mobile-export`
  - `recent-files`
  - `windows-execution`
  - `windows-filesystem`
  - `windows-os-account`
  - `windows-prefetch`
  - `windows-registry`
  - `windows-remote-access`
  - `windows-search-index`
  - `windows-shellbags`
  - `windows-system`

## Previously Fully Missing Or Not Practical Yet

These were identified by the strict audit pass as missing or not practical enough. The current taxonomy guardrail now has
collector/artifact-type bindings for the listed targets, but many remain triage-grade rather than commercial-grade deep
parsers.

1. Direct E01 partition browser in the GUI, including partition table display, selected offset, and multi-partition queue.
2. Direct Volume Shadow Copy discovery and mount from E01/RAW, not only comparison of already-mounted folders.
3. Full USB/removable-device timeline view with device serial, user, mount point, first/last seen, volume GUID, and file activity correlation.
4. Browser cookies, sessions, local storage, extension data, sync data, and password/DPAPI/keychain-gated secret workflows.
5. Browser cache object reconstruction with request/response metadata and deleted-cache validation.
6. Dedicated IIS/Apache/Nginx/webroot/webshell collector with server log parsing and suspicious source-code rules.
7. Dedicated ADS anti-forensics collector beyond `Zone.Identifier`, including stream inventory and suspicious stream scoring.
8. Thumbnail cache, icon cache, and Windows Explorer thumbnail evidence parser.
9. Recycle Bin `$I`/`$R` deep parser with original path, deletion time, SID/user mapping, and source citation.
10. Windows Notifications, Clipboard, ActivitiesCache, Timeline, and ConnectedDevicesPlatform artifacts.
11. Windows Store/UWP package and app activity artifacts.
12. DPAPI masterkey, credential vault, browser secret inventory, and certificate/private-key inventory with strict legal gates.
13. Dedicated archive/encrypted-file workflow with password-candidate management, recursive archive policy, and safe extraction sandbox.
14. Password cracking queue/workflow for supported evidence containers; only detection/metadata is currently practical.
15. Native OCR execution pipeline with Korean OCR quality calibration; current support is closer to queue/sidecar/search than full OCR analysis.
16. Video/audio playback, waveform, transcript cue review, and subtitle/transcript evidence citation.
17. Perceptual image/video similarity clustering and gallery triage.
18. Dedicated SQLite/DB table viewer with deleted-row module and large table paging.
19. Full PST/OST mailbox parser with deleted items, MAPI properties, threading, and attachment viewer.
20. Native Teams/Slack/Discord desktop database parsers; cloud/export heuristics exist but not deep app-native parsing.
21. WhatsApp, Telegram, Signal, LINE, WeChat, Instagram, Discord native mobile/desktop schema-matrix parsers with fixture validation.
22. iOS full backup parser depth: Manifest.db domains, app DB mapping, media, SMS, encrypted-backup lawful key workflow.
23. Android full artifact parser depth: SMS/call/contact/browser/media/app DB schemas, not only APK/app-data inventory.
24. Google Takeout complete product matrix with Gmail, Drive, Photos, Activity, Location, and device/account attribution.
25. iCloud export parser with Photos albums/shares/devices/account attribution.
26. Microsoft 365/OneDrive/Teams/eDiscovery deep import with permissions, reactions, attachments, and SharePoint context.
27. Native cloud API acquisition workflows with OAuth device flow, pagination, backoff, delta sync, and audit.
28. STIX/TAXII/offline signed TI feed ingestion with confidence decay and local-only policy.
29. Full Volatility-style memory process/network/module/handle/credential-yield inventory; current memory support is triage-level.
30. Remote/live acquisition agent workflow; documented as missing/out of scope until safe authorization design exists.
31. External-tool import wizard for EvtxECmd, Hayabusa, RECmd, MFTECmd, JLECmd, ShellBagsExplorer, PECmd, and SRUM/ESE exports.
32. Dedicated CDR/phone call/SMS/contact unified mobile view with entity resolution.
33. Vehicle/dashcam/IoT parser families; file categories exist but no real collector depth.
34. Full report exhibit bundle with manifest, hashes, source offsets, parser versions, limitations, and signing slot for every selected item.
35. Artifact taxonomy registry that fails tests when a target Maestro-style artifact has no collector, artifact type, viewer, test, or documentation.

## Present But Too Shallow For Commercial Claims

These features exist, but should remain `partial` until trusted-tool diffing, fixtures, and source-level validation are complete.

1. EVTX: event parsing exists, but full native BinXML grammar, provider message rendering, and corrupt/deleted recovery validation are incomplete.
2. Registry: hive parsing exists, but LOG1/LOG2 transaction replay, deleted allocator validation, and full NTUSER/UsrClass activity coverage are incomplete.
3. SAM/SECURITY/SYSTEM: account/group/service/mounted-device pivots exist, but deep alias/LSA/privilege completeness is not proven.
4. Amcache/ShimCache/BAM/SRUM: execution artifacts exist, but OS-version-specific binary semantics and trusted diff validation are still needed.
5. Windows.edb: ESE/header/string/table pivots exist, but full ESE catalog/table/row/deleted-state decoding is not complete.
6. MFT: records and timestamps exist, but attribute-list, nonresident runlist, full parent path reconstruction, and deleted proof need deeper validation.
7. USN: records exist, but full FRN path-cache replay, rename/delete replay, and huge-journal pagination validation are not done.
8. LNK/JumpList/recent files: recent shortcut/Jumplist-like evidence exists, but full ShellLink and DestList decoder coverage is not proven.
9. ShellBags: native candidates exist, but full binary shell item decode and transaction-log/deleted validation remain incomplete.
10. Prefetch: inventory exists, but full version 17/23/26/30/31 section coverage and compressed PF validation are incomplete.
11. Browser/AI usage: history/downloads/AI pivots exist, but service-specific transcript Q/A pairing and deleted/session/cache validation are incomplete.
12. KakaoTalk: strong progress exists for PC KakaoTalk legacy and post-patch research paths, but schema/version corpus and Windows packaging need hardened validation.
13. Email/cloud/mobile: import heuristics exist, but deep native-parser correctness and version matrices are insufficient.
14. Search: run-output scan and SQLite FTS exist, but Lucene/Tantivy/Elasticsearch-grade indexing, saved keyword packs, proximity/fuzzy/stemming, and source-verification UX are incomplete.
15. GUI workbench: improving, but the left artifact tree, virtualized table, preview/detail, evidence tray, and report citation workflow are not yet mature enough for large analyst workloads.

## Highest-Risk Omissions For A Windows 11 E01 Case

If a Windows 11 E01 is the benchmark, these missing or shallow items matter most.

1. Direct E01 partition/VSC workflow in the GUI.
2. EVTX native BinXML/message/recovery validation.
3. Registry transaction replay and deleted key/value validation.
4. MFT/USN large-volume path reconstruction and rename/delete replay.
5. Browser cache/session/cookie/extension/deleted history.
6. Windows.edb/SRUM full ESE table decode.
7. USB timeline and device correlation.
8. Recycle Bin, thumbnail cache, ActivitiesCache, notifications, and UWP app artifacts.
9. Deep source viewers for EVTX, registry, hex, SQLite, email, image/video, and timeline.
10. Trusted-tool diff corpus and known-answer fixtures.

## Implemented Guardrail

Do not claim commercial-grade parity from feature count alone. A feature should be called commercial-grade only when all of
the following exist:

1. A collector or parser produces usable rows.
2. A viewer can inspect the row and its source evidence.
3. A report citation records source path, hash, parser version, offset or stable row locator, and limitation text.
4. Tests cover normal, corrupt, deleted/slack, and large-case behavior where applicable.
5. At least one known-answer or trusted-tool diff validates the parser output.

RapidForensic now includes a machine-readable taxonomy guardrail:

```bash
rapidtriage taxonomy-audit --output rapidtriage-taxonomy-audit.json
rapidtriage taxonomy-audit --strict
```

The audit compares target forensic artifact families against actual collectors, static `artifact_type` rows, viewer
markers, tests, documentation markers, and external blockers. The default mode writes a report; `--strict` returns a
non-zero exit code while any taxonomy target remains incomplete.

Current guardrail status after the first closure pass:

- Taxonomy targets: 48.
- Covered bindings: 48.
- Partial bindings: 0.
- Missing bindings: 0.
- Collector families: 21.
- Static and registry-declared artifact types: 130.

## Recommended Next Implementation Step

Use `taxonomy-audit` as the queue generator. Pick the highest-priority `missing` or `partial` target, add the real
collector/parser/viewer/test/documentation bindings, rerun the audit, and only then promote the target's status.
