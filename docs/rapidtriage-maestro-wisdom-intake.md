# RapidTriage Competitive Intake: Maestro WISDOM Notes

This document converts user-provided Maestro WISDOM notes into RapidTriage product requirements. The claims below are treated as competitive/product input, not independently verified benchmark facts.

## Product Lessons To Absorb

Maestro WISDOM appears to compete less by copying every foreign-suite workflow and more by optimizing the default forensic path:

- Keep expensive full carving and heavy indexing out of the default path.
- Let analysts opt into slower deep processing after the first triage pass.
- Prefer stable, explainable, verified artifacts over noisy carved fragments.
- Invest heavily in Windows artifact breadth, integrated viewers, and timeline correlation.
- Make support loops short: users value quick feature/error response when evidence deadlines are tight.

RapidTriage should absorb this as a product principle:

- Default mode should be fast, bounded, and safe.
- Deep indexing/carving/OCR should be explicit queued jobs with progress and resume.
- Every result should expose source, parser, confidence, hash, review status, and limitations.

## Competitive Capability Targets

| Area | Maestro-style capability to absorb | RapidTriage status | Target direction |
| --- | --- | --- | --- |
| Processing strategy | Skip full carving/heavy indexing by default, run later if needed. | Partial | Keep `run` bounded by default; add queued deep processing profiles. |
| Windows artifacts | Hundreds of categorized artifacts, OS/account metadata, last boot time, admin status. | Early | Expand normalized Windows parsers with fixture-backed coverage. |
| Viewers | Dedicated SQL, JSON, XML, email, media, browser, and artifact viewers. | Early | Add viewer plugin registry and stronger web viewers. |
| Registry | Deleted key/value recovery and visual marking. | Planned | Add registry hive parser/recovery module after validation corpus exists. |
| Event logs | Event semantic tags, recovered deleted records, parameter-level filters. | Planned | EVTX parser should emit normalized `Event` plus typed parameters. |
| VSC | Compare current volume with Volume Shadow Copies and detect VSC deletion commands. | Planned | Add VSC import/compare workflow as Windows advanced parser work. |
| MFT/EDB/WER/Defender/Firewall/ADS | Broad Windows forensic artifacts. | Partial | WER, Defender MPLog, Firewall W3C, Zone.Identifier sidecar, and Task Scheduler XML are fixture-backed; MFT/EDB remain planned. |
| Password cracking | Built-in password cracking workflow. | Deferred | Integrate only as optional external-tool workflow with legal warnings. |
| OCR/translation | Korean OCR and translation-oriented review. | Partial | Keep OCR optional; evaluate Korean OCR quality separately. |
| Linux/XFS | Strong Linux filesystem coverage including XFS. | Planned | Treat XFS as evidence adapter/filesystem extraction requirement. |
| Virtualization | VMDK/VHD/XVA server dump support. | Detection only | Extend virtual disk adapter; add XVA detection and guidance. |
| Mobile APK malware | Extract APKs from mobile dumps and flag suspicious apps. | Partial | Exported APK inventory/hash/manifest/permission/risk triage exists; full mobile acquisition and YARA-style scanning remain planned. |
| Cloud exports | Import cloud provider exports into the same review/search workflow. | Partial | Google Takeout-style location/activity JSON and Apple/general account JSON normalization exists; live cloud acquisition remains planned. |
| Live/remote IR | USB live collector and agent-based remote response. | Deferred | Keep outside core desktop release until security model matures. |
| Browser integration | Unified browser history/download viewer across Chrome/Edge/Firefox. | Partial | Normalize browser artifacts into one timeline/search surface. |
| TI integration | Extract IP/URL and query threat intelligence APIs. | Planned | Add optional TI connector plugin contract, disabled by default. |
| AI prompt artifacts | Extract prompts from AI/search browser artifacts. | Planned | Add parser category for AI assistants/search prompts when source formats are known. |
| Memory forensics | RAM dump analysis, BitLocker key extraction, process risk visualization. | Partial | Volatility/Volatility3 JSON/JSONL import normalizes process/network/malfind rows; direct RAM parsing and key search remain planned. |
| LotL detection | PowerShell/WMI/local-admin command collection. | Partial | Add Windows command history, WMI, scheduled task, event log correlation rules. |
| Deepfake/similar images | Media classification, visual similarity grouping. | Partial | Image dimensions/hash/perceptual-hash/similarity-bucket triage exists; classifier/deepfake detection remains planned. |
| Chromebook | ChromeOS dump analysis. | Deferred | Track as separate evidence profile after Linux/browser coverage improves. |

## RapidTriage Backlog Additions

High priority:

- Add processing profiles: `fast`, `standard`, `deep`, where `fast` avoids full carving/OCR-heavy indexing.
- Add Windows account/OS parser: hostname, timezone, last boot, users, admin membership, created/deleted/login times.
- Add unified browser normalized model for history, downloads, cookies metadata where legally appropriate, and AI prompt artifacts.
- Add Zone.Identifier ADS parser for downloaded-file provenance. Status: sidecar/export parsing implemented.
- Add EVTX parser contract with event semantic tags and typed parameters.
- Add MFT metadata parser and timeline merge.
- Add VSC compare design: current vs snapshots, deleted file deltas, VSC deletion command detection.
- Add parser confidence and "verified source only" policy to avoid noisy carving output.

Medium priority:

- Add SQLite/JSON/XML/email dedicated viewers.
- Add Defender, Firewall, Task Scheduler, WER, Prefetch, JumpList, LNK, ShellBags, USB history parsers. Status: first-pass fixture-backed coverage exists, with LNK header/string parsing and recoverable embedded Jump List Shell Link destination promotion; deeper OLE Jump List stream traversal remains later.
- Add optional TI connector plugin contract for URL/IP/hash enrichment.
- Add Korean OCR validation set and OCR quality metrics.
- Add VMDK/VHD/XVA adapter plan with external-tool diagnostics.

Deferred:

- Password cracking integration.
- Live USB collection.
- Remote agent collection.
- Memory forensics/BitLocker key extraction.
- APK malware triage. Status: first-pass exported APK inventory/risk triage implemented.
- Deepfake and similar-image grouping. Status: first-pass image perceptual hash and similarity bucket triage implemented.
- ChromeOS specialized support.

## Design Implications

RapidTriage should not blindly chase a "500 artifact" number. The better target is:

- Each parser has a stable ID, version, fixture, expected output, confidence field, and known limitations.
- Each UI viewer reduces analyst context switching.
- Timeline and search operate on normalized models rather than one-off parser JSON.
- Heavy processing is queued, resumable, and auditable.
- Reports distinguish extracted facts, parsed facts, inferred facts, and manually reviewed facts.

## Suggested Next Sprint From This Intake

1. Add processing profile flags to `run`: `--profile fast|standard|deep`.
2. Add normalized browser model and unified browser timeline export.
3. Add Zone.Identifier ADS parser.
4. Add Windows OS/account summary parser.
5. Add EVTX parser skeleton with fixture tests.
6. Add SQLite viewer in the web UI.
7. Add plugin category for TI enrichment.
8. Add parser confidence fields to normalized artifacts.
9. Add Korean OCR validation fixture.
10. Add XVA suffix detection to `EvidenceAdapter`.
