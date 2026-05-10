# RapidForensic QC-Prep Detailed Gap Checklist

Last updated: 2026-05-11

This file expands `rapidforensic-qc-prep-implementation-list.md` into a more actionable checklist. It is intentionally detailed because formal QC should start only after the product can be exercised as an analyst workflow, not merely as separate CLI features.

Status baseline from the latest local review:

- Readiness score: `79`
- Commercial claim allowed: `false`
- Maturity gates: implemented `120/120`, usable `120/120`, validated `0/120`, commercial-grade `0/120`
- Taxonomy audit: `48/48` covered, partial `0`, missing `0`, strict pass `true`, artifact type literals `146`

## Completion Categories

- `Build`: implementation needed before QC.
- `QC evidence`: what must be produced to prove the feature works.
- `Blocker`: what still prevents report-grade or commercial-grade claims.

## Detailed Checklist

| # | Area | Build | QC evidence | Blocker to keep visible |
|---:|---|---|---|---|
| 1 | E01 intake | Show image filename, size, segment set, source signature, hash feasibility, and read-only posture before processing. | `e01-known-answer` JSON plus GUI screenshot or API response for a real/synthetic E01. | Full-image hashing may be bounded for huge images. |
| 2 | E01 dependency check | Report `ewfmount`, `mmls`, `tsk_recover`, version attempts, install hints, Windows/WSL guidance, and fallback route. | Preflight JSON with available/missing tools and remediation text. | Fresh Windows/macOS tool-matrix smoke still required. |
| 3 | E01 partition browser | Render partition number, start sector, byte offset, filesystem guess, size, boot flag, recommended flag, and manual override. | Partition-selection JSON and GUI/API fixture with multi-partition example. | Real multi-partition Windows 11 E01 fixture needed. |
| 4 | E01 stage workflow | One command/API flow should run preflight, selected partition extraction, artifact run, search index, review summary, and report bundle. | End-to-end smoke output folder with stage status files. | Real E01 run with libewf/SleuthKit or trusted export needed. |
| 5 | E01 resume | Reuse completed mount/recovery/run stages when rerun with the same source/output fingerprint. | Resume test that skips completed stages and records reuse reasons. | Interrupted external tool recovery needs real process tests. |
| 6 | E01 failure UX | Classify missing tool, corrupt image, encrypted volume, unsupported FS, permission, partition ambiguity, and external-tool failure. | Fixture tests for each failure category and GUI text snapshot. | Real encrypted/corrupt image corpus needed. |
| 7 | E01 provenance | Link source image, segment set, selected partition, extraction root, tool commands, tool versions, and output hashes. | Provenance manifest with stable hash and audit sidecar. | Chain-of-custody signoff remains external. |
| 8 | VSC workflow | Discover, list, compare, and extract Volume Shadow Copy snapshots from image or recovered Windows roots. | VSC fixture with current vs snapshot deleted-file comparison. | Direct image-level VSC mount may require platform tooling. |
| 9 | GUI start screen | Reduce entry choices to E01, folder/export, recent case, sample case, and validation/QC tools. | Browser smoke contract verifies selectors and primary actions. | Fresh Windows packaged GUI smoke needed. |
| 10 | GUI workbench layout | Implement artifact tree, virtualized result table, preview/detail panel, evidence tray, and report tray as the default workbench. | UI contract JSON plus screenshot or Playwright trace. | Real browser performance trace still required. |
| 11 | GUI artifact tree | Group Windows, Browser/AI, Mail, Messenger, Mobile, Media/OCR, Timeline, Search, Reports, Validation. | Tree snapshot with counts and selected artifact filters. | Counts depend on parser output quality. |
| 12 | GUI table controls | Add bounded pagination/windowing, sort, filters, column show/hide, time filter, source filter, and keyboard navigation. | 100k synthetic row UI evidence plus DOM/latency metrics. | Real browser memory profile required. |
| 13 | GUI preview | Collapse verbose metadata by default and show analyst-first summary, source locator, warning, hash, and review controls. | Source preview visual smoke and JSON contract. | Full visual QA on Windows/macOS needed. |
| 14 | GUI history | Preserve navigation stack for result A to result B back-and-forth review. | Browser smoke clicking two evidence items and returning to the first. | Stateful browser e2e required. |
| 15 | GUI persistence | Restore selected case, current search, filters, selected row, review tray, and compare tray after refresh. | Browser smoke refresh test with persisted state. | Multi-user conflict handling not in scope yet. |
| 16 | Search-to-source | Every search result should expose a source action and locator type when possible. | Search JSON shows source-verifiable hit count and locator coverage. | Some derived artifacts may need parser-specific locators. |
| 17 | SQLite source locator | Connect CLI SQLite row locator to GUI source viewer and review note/report citation actions. | GUI/API opens SQLite row and stores row hash/citation in review note. | WAL/deleted row recovery remains separate. |
| 18 | EVTX source locator | Add event log source locator with file, channel, record ID, provider, event ID, timestamp, record offset if available. | EVTX viewer payload and current-file hit citation. | Native EVTX offset accuracy needs trusted diff. |
| 19 | Registry source locator | Add hive, key path, value name, value type, cell offset, deleted/allocation state, transaction replay status. | Registry viewer payload and citation copied to review note. | LOG replay and allocator validation still required. |
| 20 | MFT locator | Add record number, sequence, attribute type, parent FRN, path confidence, record offset, and hash context. | MFT locator fixture and report citation row. | Full volume parent reconstruction remains incomplete. |
| 21 | USN locator | Add USN, FRN, parent FRN, reason flags, timestamp, path confidence, replay transition ID. | USN replay locator fixture with rename/delete transitions. | Full FRN cache and huge journal validation needed. |
| 22 | Email locator | Add mailbox, folder, message ID, subject hash, attachment index/name/hash, and bounded attachment preview. | EML/MBOX/PST-style fixture for message and attachment citation. | PST/OST deep parser still required. |
| 23 | Hex citation | Allow byte range selection with SHA256, offset, length, copied hex/ASCII, and report citation text. | Hex range fixture with stable range hash. | Large binary rendering must remain bounded. |
| 24 | Image viewer | Show dimensions, EXIF summary, hashes, OCR sidecar, perceptual hash, similar images, tags, and report warning. | Image gallery fixture with OCR and EXIF sidecar. | Native similarity corpus still needed. |
| 25 | Media viewer | Show safe media metadata, transcript sidecars, cue timestamps, cue citations, and no-exec playback policy. | VTT/SRT cue fixture with report citation. | Safe playback and waveform are not fully implemented. |
| 26 | OCR viewer | Show OCR queue state, language, confidence, Korean OCR hints, translation sidecar, and original/translated text hashes. | OCR queue fixture with Korean sidecar and translation sidecar. | Native OCR engine quality calibration still external. |
| 27 | Review note citation | Add current-file hit, source locator, snippet, hash, warning, and analyst note into review item. | Case DB review export includes cited hit fields. | Multi-reviewer conflict handling still needed. |
| 28 | Evidence tray | Persist selected evidence, pinned evidence, compare targets, report candidates, tags, and notes. | Case DB reopen shows same tray state. | Role-based collaboration not complete. |
| 29 | Report candidate state | Make include-in-report depend on review status, source locator, hash status, confidence, and limitation presence. | Report export blocks or warns incomplete candidates. | Legal wording review remains external. |
| 30 | EVTX BinXML grammar | Decode full record/chunk structures, System, EventData, UserData, TemplateInstance, typed values, substitutions. | Record-level fixture and EvtxECmd/Hayabusa row diff. | Provider/version corpus needed. |
| 31 | EVTX message rendering | Resolve provider manifest/resource DLL messages and preserve unresolved template warnings. | Rendered-message diff against trusted export. | Windows DLL/resource matrix required. |
| 32 | EVTX recovery | Recover corrupt/slack/deleted candidates with offset, chunk context, confidence, and recovery reason. | Corrupt/deleted EVTX known-answer corpus. | Report-grade recovery needs independent validation. |
| 33 | Registry transaction replay | Implement or externally prove LOG1/LOG2 transaction replay equivalence. | Hive plus LOG1/LOG2 fixture compared to RECmd/Registry Explorer. | Native replay correctness is critical. |
| 34 | Registry deleted recovery | Validate free-cell allocator state, parent chain, key/value structure, false-positive score. | Deleted key/value corpus with expected positives/negatives. | Slack recovery must default non-reportable. |
| 35 | NTUSER activity | Parse UserAssist, RunMRU, RecentDocs, TypedURLs, ComDlg32, MountPoints2, network shares, shell open/save. | NTUSER fixture with expected normalized user activity rows. | Transaction log replay still needed. |
| 36 | UsrClass/ShellBags | Correlate NTUSER and UsrClass BagMRU/Bags trees, shell item decoding, deleted/slack candidates. | ShellBagsExplorer diff fixture. | Full binary shell item coverage needed. |
| 37 | SAM parser | Decode SAM F/V users, RID, disabled/admin state, last login, password metadata, aliases and group membership. | SAM fixture with known accounts/groups. | Domain/SID contexts require broad corpus. |
| 38 | SECURITY parser | Parse LSA policy, privilege assignments, secret metadata, and legal-gated secret handling. | SECURITY fixture with redacted inventory and gate audit. | Secret decryption needs lawful key workflow. |
| 39 | SYSTEM parser | Parse ControlSets, services, mounted devices, timezone, last boot, BAM/DAM roots, USBSTOR. | SYSTEM fixture with expected service/device/time rows. | Cross-hive correlation needed. |
| 40 | Amcache | Implement versioned schema map, file/program entries, SHA1, install/execution timestamp semantics. | AmcacheParser/RECmd trusted diff. | OS version matrix needed. |
| 41 | ShimCache | Decode AppCompatCache layouts across Windows versions and label as not direct execution proof. | AppCompatCacheParser diff plus UX warning test. | Broad Windows version coverage needed. |
| 42 | BAM/DAM | Decode binary FILETIME/SID/path values and correlate with SYSTEM ControlSet. | BAM/DAM fixture with expected SID/path/timestamp rows. | Interpretation varies by version. |
| 43 | Prefetch | Decode compressed PF and versions 17/23/26/30/31, run count, last runs, volumes, file metrics. | PECmd diff corpus. | MAM decompression validation needed. |
| 44 | LNK | Decode ShellLinkHeader, LinkInfo, StringData, ExtraData, TrackerDataBlock, target metadata. | LEcmd/JLECmd diff fixture. | Shell item edge cases remain. |
| 45 | JumpList | Decode CFB/OLE, DestList, AppID mapping, embedded LNK, deleted/unlinked entries. | JLECmd diff fixture. | Deleted entry recovery needs corpus. |
| 46 | SRUM ESE | Decode ESE catalog/page/tagged columns, SRUDB tables, app/user/network counters. | SrumECmd/libesedb diff fixture. | Full ESE native parser required. |
| 47 | Windows.edb | Decode ESE properties, search index rows, content/path/URL fields, deleted-state candidates. | WinSearchDBAnalyzer/libesedb diff fixture. | Deleted long-value handling needed. |
| 48 | MFT deep parser | Decode attribute list, resident/nonresident attributes, runlists, timestamps, deleted records, parent paths. | MFTECmd/analyzeMFT diff fixture. | Full-volume scale validation needed. |
| 49 | USN replay | Decode v2/v3/v4 records, build FRN path cache, replay rename/delete/create lifecycle. | UsnJrnl2Csv plus known-answer replay CSV. | Huge journal cursor proof needed. |
| 50 | Recycle Bin | Decode `$I`/`$R`, original path, deletion time, SID/user mapping, source hash, report citation. | Recycle fixture with deleted files and user SID. | Edge cases for missing `$R` needed. |
| 51 | ADS | Inventory all alternate data streams, Zone.Identifier, suspicious streams, hashes, and source citations. | ADS fixture with multiple streams. | Platform extraction support varies. |
| 52 | Browser cache | Reconstruct cache objects with URL, request/response metadata, content hash, deleted/cache warnings. | Chrome/Edge/Firefox cache fixture. | Browser version matrix needed. |
| 53 | Browser storage | Decode session storage, local storage, extension DBs, IndexedDB, sync data, profile attribution. | Browser profile fixture with expected storage rows. | Secret stores must remain gated. |
| 54 | Browser secrets | Add opt-in legal gate, DPAPI/keychain status, redaction, controlled reveal, and audit event. | Secret inventory fixture with redacted output. | Decryption requires authority and keys. |
| 55 | AI transcripts | Pair Q/A for ChatGPT, Claude, Gemini, Perplexity, Copilot exports and browser artifacts. | Service export fixtures with expected conversations. | Schemas change frequently. |
| 56 | KakaoTalk | Stabilize legacy/post-patch schema matrix, Windows package, media attachment mapping, memory-assisted notes. | Two sample ZIP regressions plus Windows execution smoke. | Sensitive key handling must stay redacted. |
| 57 | WhatsApp | Parse export/native msgstore/contact/call/media with crypt/key workflow separated. | WhatsApp export fixture and lawful key workflow test. | Native encrypted DB requires key. |
| 58 | Telegram | Parse desktop/mobile exports, cache/media/account attribution, encrypted local-store warning. | Telegram export fixture. | Secret local stores remain limited. |
| 59 | Signal | Parse export or lawful SQLCipher workflows with attachment/deleted limitations. | Signal fixture with separate secure key input. | Key handling must be secure and audited. |
| 60 | LINE/Discord/Instagram/WeChat | Add service-specific schema mappers for exports first, native DBs second. | Per-service export fixtures and schema version registry. | Native encrypted stores often blocked. |
| 61 | PST/OST | Integrate libpff or equivalent for folders, messages, attachments, deleted items, MAPI properties. | PST/OST fixture with attachment citation. | External dependency/package validation needed. |
| 62 | Google Takeout | Parse Gmail MBOX, Drive, Photos, Activity, Location, account/device context. | Takeout fixture with product matrix. | Product exports vary widely. |
| 63 | iCloud | Parse Photos, albums, shares, devices, EXIF, account context. | iCloud export fixture. | Native cloud API acquisition not included. |
| 64 | M365/Teams/OneDrive | Parse eDiscovery/Graph exports, Teams messages/reactions, files, permissions, SharePoint context. | M365 export fixture with permissions. | Live Graph acquisition needs credentials. |
| 65 | iOS backup | Parse Manifest.db, domains, SMS, media, app DBs, encrypted backup legal workflow. | iOS backup fixture with expected rows. | Encrypted backups need lawful key material. |
| 66 | Android artifacts | Parse SMS, calls, contacts, browser, media, app DBs, APK signatures/permissions. | Android backup/app fixture. | App schemas are versioned and broad. |
| 67 | Search backend | Add backend abstraction with consistent query, paging, highlighting, source locator, and index stats. | Backend contract tests. | External engines optional only. |
| 68 | SQLite FTS backend | Formalize default local FTS limits, query plans, row counts, and truncation disclosure. | Large SQLite search fixture. | Not Lucene-scale by itself. |
| 69 | Tantivy/Lucene candidate | Prototype local inverted index for million-row text/artifact search. | 1M synthetic benchmark and parity test. | New dependency requires packaging review. |
| 70 | OpenSearch/Elasticsearch adapter | Optional lab/server adapter with config, health, bulk ingest, and no-default network posture. | Adapter contract with mocked server. | Deployment/security evidence required. |
| 71 | Unified index schema | Normalize docs, files, EVTX, Registry, OCR, email, messenger, browser, AI, and timeline rows. | Schema snapshot and migration test. | Parser-specific locators required. |
| 72 | Benchmarks | Generate 100k/1M/10M synthetic cases with manifest, p50/p95 latency, memory, row counts. | Benchmark outputs with threshold status. | Real hardware runs still required. |
| 73 | Cursor APIs | Use cursor/offset consistently across files, docs, artifacts, search, timeline, report, review queues. | API contract tests for every list route. | GUI must use cursors too. |
| 74 | UI virtualization | Enforce DOM window, keyboard navigation, persisted viewport, and row count disclosure. | Browser trace with 100k rows. | Real browser memory profile needed. |
| 75 | Current-file search | Remove silent scan caps; add resume, searched rows, total rows, truncated tables, and warnings. | Large SQLite/text file source-search fixture. | Very large binary search must stay bounded. |
| 76 | Hash cache | Persist file/content hash cache with invalidation by size/mtime/inode/content fingerprint. | Rerun fixture proving cache hit/miss behavior. | Cross-platform inode semantics vary. |
| 77 | Dedup grouping | Add exact hash, fuzzy text, perceptual image/video duplicate groups. | Fixture with duplicate and near-duplicate families. | Perceptual video may require native/dependency support. |
| 78 | Parser isolation | Run high-risk parsers in subprocesses with timeout, crash quarantine, partial output cleanup. | Crash fixture showing main run survives. | OS sandboxing is separate. |
| 79 | Memory caps | Add hard caps where possible and clear cooperative warnings elsewhere. | RSS/cap fixture and warning output. | Job Object/cgroup support differs by OS. |
| 80 | Validation package | Export commands, tool versions, source hashes, output hashes, parser versions, warnings, diffs, reviewer state. | Per-run validation package fixture. | Real trusted diffs still needed. |
| 81 | Trusted-tool import wizard | Guide users through EvtxECmd, Hayabusa, RECmd, MFTECmd, JLECmd, PECmd, ShellBagsExplorer, SrumECmd, libesedb outputs. | Wizard fixture importing multiple trusted outputs. | Operators must provide real exports. |
| 82 | Mismatch dashboard | Show missing rows, extra rows, field mismatches, truncation, severity, and recommended parser fix. | Cross-tool diff fixture with deliberate mismatch. | Human review still required. |
| 83 | FP/FN recording | Let reviewers mark false positive/false negative and export parser-specific FP/FN notes. | Case DB review fixture with FP/FN export. | Needs corpus-wide statistics later. |
| 84 | Confidence scoring | Calibrate parser confidence and reportability status per artifact family. | Confidence dashboard fixture. | External validation required for calibration. |
| 85 | Legal limitations | Attach limitation text and report wording guardrails to every artifact family. | Report fixture showing limitation coverage. | Legal review remains external. |
| 86 | Chain of custody | Capture acquisition metadata, transfers, write-blocker info, analyst actions, and export events. | Chain-of-custody report section with hashes. | Real operator records required. |
| 87 | Audit hash chain | Maintain append-only audit rows and export tamper-evident bundle. | Audit chain verification fixture. | External signing remains separate. |
| 88 | Court exhibit bundle | Package selected evidence, report, manifests, hashes, provenance, limitations, and signing slot. | Exhibit ZIP fixture and manifest verifier. | Signed exhibit package requires external signing. |
| 89 | QC checklist | Generate pass/fail/blocked checklist from run outputs, validation package, trusted diffs, warnings, and blockers. | QC checklist fixture with blocked and passed rows. | Final QC depends on real evidence. |
| 90 | Final QC report | Produce final QC summary with pass/fail/blocked/needs-external-evidence per feature and parser family. | End-to-end QC report generated from a sample case. | Real Windows 11 E01 QC remains the decisive test. |

## First Implementation Recommendation

Start with items `16` through `23`: search-to-source and source locator wiring. This gives analysts a concrete way to verify every hit before adding it to a report, and it creates the foundation needed for QC to be meaningful.

After that, work in this order:

1. Items `1` through `8`: E01 workflow and provenance.
2. Items `30` through `49`: Windows core parser depth.
3. Items `67` through `79`: large-case search/performance.
4. Items `80` through `90`: validation, mismatch, QC, and report packages.

## QC Acceptance Rule

Do not start formal QC with "feature exists" as the criterion. Start formal QC only when the feature has:

1. A source locator or explicit reason why no source locator can exist.
2. Source hash or explicit hash limitation.
3. Parser/version/provenance metadata.
4. Review state and reportability warning.
5. Fixture or trusted-tool diff evidence.
6. Large-case behavior disclosure when applicable.
