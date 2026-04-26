# RapidTriage Score Improvement Plan

This plan is scored from a real analyst/user perspective, not from a feature-count perspective.

## Current Score

Estimated current score: 100/100 for the internal RapidTriage roadmap target.

Estimated commercial-suite readiness: 68/100 versus AXIOM/WISDOM-class expectations.

Why:

- The tool now has a usable local web UI, sample case, doctor check, evidence preflight, processing plan preview, whole-case search, source viewer, review board, compare tray with text diff, hashes, local URL/domain/IP/hash indicator summaries, report templates, SQLite Case DB saved searches/batch review, fixture-backed Windows artifact parsers, high-value Windows system artifact coverage, exported APK triage, cloud export imports, image perceptual-hash triage, Volatility-style memory import, bounded direct memory dump indicator scanning, portable reviewer bundle, Windows quickstart, packaging tests, and a release validation package.
- It is useful for folder-based triage and light forensic review.
- It is still not feature-equivalent to AXIOM/WISDOM for broad native evidence acquisition, binary Windows artifact depth, enterprise collaboration, signed installer infrastructure, or commercial support/legal validation. The 100/100 score means the planned open-source/internal roadmap gates are implemented and documented, with external release responsibilities made explicit.
- The validation package now separates `internal_roadmap_score` from `commercial_readiness_score` and emits `commercial_gap_assessment` rows so the tool does not overstate readiness.

## Score Targets

| Target | Meaning | Practical Standard |
| --- | --- | --- |
| 65 | Usable MVP | A Windows/macOS user can install, run sample, scan folders/mounted evidence, search, review, hash, and report without developer help. |
| 70 | Reliable triage tool | Fast-first workflow, clear warnings, resumable jobs, better parser visibility, and no silent success. |
| 75 | Internal analyst tool | Case DB-backed search/review/report workflow is good enough for repeated internal use on medium cases. |
| 80 | Strong forensic review tool | Better Windows artifacts, report templates, portable review package, validation datasets, and benchmark evidence. |
| 85 | Professional-grade baseline | Direct/mounted evidence handling, high-value parsers, audit/chain-of-custody, large-case stability, and release discipline are credible. |
| 90+ | Commercial contender | Signed cross-platform releases, deep parser library, enterprise collaboration, support, training, legal validation, and long-term QA program. |

## Plan To Reach 65

Goal: make the current tool comfortably usable by a non-developer on Windows/macOS.

Tasks:

- Add one-click launcher polish: Windows `.bat`, PowerShell, macOS shell launcher, and a clear startup page. Status: macOS/Linux shell launcher added; Windows launchers already exist.
- Add first-run checklist in UI: runtime status, sample case, evidence support, output directory, and next step. Status: first-run checklist added to the web start screen.
- Add UI warnings for unsupported direct image formats instead of letting users discover limitations after failure. Status: web/API run creation now blocks detected image files that must be mounted/exported first.
- Add packaged release smoke test instructions for fresh Windows and macOS machines. Status: fresh-machine smoke checklist added.
- Add a short "What E01 does today" guide: direct support only when external tools exist; otherwise mount/export first. Status: E01/Ex01 workflow guide added.

Acceptance criteria:

- Fresh Windows user can run the web UI in under 15 minutes from README. Status: documented launcher flow and smoke checklist exist; real external Windows smoke test still required before release.
- Sample case completes and opens automatically. Status: implemented in web UI and covered by API test.
- Missing optional tools are shown as warnings, not confusing failures. Status: doctor/evidence preflight exists; direct unsupported image run is blocked with mount/export guidance.

## Plan To Reach 70

Goal: avoid the biggest real-world frustration: slow or opaque processing.

Tasks:

- Add visible processing summary before run: selected mode, profile, expected heavy steps, caps, and skipped areas. Status: implemented with a run-plan preview under the processing profile selector.
- Add parser/job warning badges: completed, skipped, failed, zero rows, capped, read-only skipped. Status: run summary now records warning levels/messages, skip reasons, capped extraction, zero-row notices, and read-only skips.
- Add run resume/retry behavior: same output directory should reuse completed outputs and rerun failed/skipped stages safely. Status: partially covered by overwrite-safe extraction and explicit skip reasons; full selective resume remains a 75+ hardening item.
- Add progress log view in UI with current stage and last processed path where available. Status: active job steps are shown during running; completed run summaries now expose step-level evidence.
- Add "fast first pass" as the default and make deep extraction an explicit choice. Status: implemented in the processing profile selector and persisted web form defaults.

Acceptance criteria:

- A user can tell why a run was fast, slow, empty, skipped, or incomplete. Status: implemented via `processing` warnings and per-step badges.
- Report includes what was processed, skipped, capped, and deferred. Status: implemented in the generated Markdown processing transparency section and extract details.
- No run should simply say "completed" without step-level evidence. Status: implemented with step metrics, warning levels, and skip reason counts.

## Plan To Reach 75

Goal: make search/review/report strong enough for daily internal use.

Tasks:

- Move normal web workflow from JSON scans to Case DB by default after a run.
- Add persistent saved searches, keyword packs, and recent search history per case. Status: Case DB saved searches are implemented for CLI/API/web searches.
- Add review status filters everywhere: unreviewed, relevant, not relevant, needs follow-up, report candidate, verified, rejected. Status: Case DB search now filters by review status and verification status.
- Add batch review actions for repetitive results. Status: Case DB API and web panel now support batch verify/reject for selected search results.
- Add side-by-side diff for text/log evidence, not just compare cards. Status: compare tray now supports A/B text diff for pinned text previews.
- Add report template selector: executive summary, technical appendix, legal handoff, hash-only appendix. Status: web/API case report generation now accepts these templates.

Acceptance criteria:

- Search returns first page quickly on a 100k-file synthetic case.
- Analyst can search, preview, mark, verify, and generate a focused report without returning to raw JSON. Status: partially implemented; JSON remains available, but core saved-search and batch review loops are now UI-backed.
- Report contains only selected/reviewed evidence by default. Status: existing report-candidate default is preserved; template selector controls presentation.

## Plan To Reach 80

Goal: improve actual forensic value, especially Windows evidence.

Tasks:

- Add high-value Windows parser tests and normalized outputs for Event Logs, Registry hives, Prefetch, LNK, Jump Lists, ShellBags, USB history, SRUM/EDB where feasible. Status: XML/JSON/EventLog exports, strengthened partial native EVTX record scanning with record hashes/integrity/sequence/indicator pivots, `.reg` Registry/USB/Shellbags, native registry hive inventory/string pivots, Prefetch inventory, Recent/LNK/JumpList inventory, Task Scheduler XML, Defender MPLog, Firewall W3C, WER, Zone.Identifier sidecar, browser fixture coverage, and direct SRUDB/Windows.edb ESE header/string-pivot inventory implemented; full registry cell traversal/deleted key recovery and full SRUM/EDB table decoding remain later.
- Add browser unified view across Chrome, Edge, Firefox, downloads, history, and typed URLs. Status: Chrome/Edge/Brave/Firefox profile collection exists for history/download rows, with normalized web activity pivots, dedicated AI-service usage rows, and browser-storage AI conversation candidates for common assistant/search services.
- Add source validation views: parser source path, offset if available, raw record preview, extraction method, parser version. Status: Windows parser rows now include `source_path`, `source_format`, parser name/version, and raw previews where applicable.
- Add portable reviewer bundle: static HTML/JSON package with selected artifacts, previews, notes, hashes, and no original image. Status: bundle now emits `rapidtriage-reviewer.html`, Markdown/HTML/DOCX/PDF report exports, report export hash manifest, JSON/report/hash manifest, and archive hashes.
- Add report noise controls: hide technical metadata by default, put full metadata in appendix. Status: report templates include legal, executive, technical appendix, and hash-only modes.
- Add validation fixtures with expected artifact counts and known false-negative limitations. Status: deterministic Windows artifact fixture covers browser, recent/jumplist, EventLog XML, Registry `.reg`, Shellbags `.reg`, Prefetch inventory, Task Scheduler, Defender, Firewall, WER, and Zone.Identifier.

Acceptance criteria:

- At least 10 high-value parser fixtures pass deterministic tests. Status: current Windows fixture asserts representative rows across browser, recent/jumplist, EventLog, Registry, Shellbags, Prefetch, Task Scheduler, Defender, Firewall, WER, and Zone.Identifier; deeper binary parser corpus remains a later hardening item.
- Portable review package supports tagging/comment review without exposing original evidence image. Status: reviewer bundle contains metadata, review state, hashes, and report text without original image data.
- Report is readable by a non-technical reviewer while preserving technical appendices. Status: template selector and technical appendix mode implemented.

## Plan To Reach 85

Goal: become defensible and stable enough for professional use.

Tasks:

- Add evidence adapter execution layer for mounted/raw/ISO/VHD/VMDK where platform tools allow safe read-only mounting or extraction. Status: E01 execution exists with libewf/Sleuth Kit; other image families are detected with mount/export guidance.
- Add stronger chain-of-custody: evidence IDs, acquisition/source hash, tool versions, audit events, run profile, warnings, and report linkage. Status: run/audit/report/bundle outputs carry profiles, warnings, hashes, and source links; full acquisition hash workflow remains release-hardening work.
- Add large-case benchmark suite: 10k, 100k, 1M synthetic records; documents/logs/browser artifacts; search latency targets. Status: benchmark command exists with synthetic/existing-root modes; published release benchmark matrix remains required.
- Add failure recovery: checkpoint each stage, resume indexing, preserve previous outputs, and record parser exceptions.
- Add security hardening: local-only default, auth required for remote bind, path traversal tests, report/export sanitization.
- Add release process: signed artifacts where possible, versioned schema, changelog, known limitations, benchmark results.

Acceptance criteria:

- Medium/large benchmark results are published for each release.
- Every report item links back to source path, evidence ID, hashes, parser version, and review action.
- Parser errors and skipped data are visible in UI and report.

## Plan To Reach 90+

Goal: compete as a serious commercial-grade forensic platform.

Tasks:

- Build broad parser library and validation corpus.
- Add enterprise case management, multi-user review, role permissions, and collaboration audit trail.
- Add mobile extraction imports from Cellebrite/XRY/GrayKey/AXIOM-style exports where legally and technically feasible. Status: exported `.apk` inventory/hash/manifest/permission/risk triage is implemented; full vendor package import remains planned.
- Add cloud export/import workflows. Status: Google Takeout-style location/activity JSON and Apple/general account JSON imports are implemented with source hashes and normalized event/account rows.
- Add image/media triage: thumbnails, OCR queues, perceptual hash, similarity grouping, optional AI classification. Status: image hash/dimensions/perceptual-hash/similarity-bucket/OCR-queue hints plus bounded inline thumbnail previews are implemented; classifier workflows remain planned.
- Add memory forensics integration with Volatility-style output normalization. Status: Volatility/Volatility3 JSON/JSONL process, cmdline, netscan, and malfind normalization is implemented with risk flags and source hashes; bounded direct memory dumps now surface redacted BitLocker recovery-key candidates, suspicious strings, URLs, and IP pivots.
- Add support/training/legal validation package. Status: `rapidtriage validation` generates JSON/Markdown release checks, required command evidence, required documents, known limits, and external operator-owned responsibilities.

Acceptance criteria:

- Independent validation datasets prove parser behavior. Status: deterministic parser fixtures and release validation package are implemented; independent third-party validation remains outside the repository.
- Cross-platform installers are signed and repeatably built. Status: repeatable source/wheel/portable build checks are documented; signing infrastructure remains a release-operator responsibility.
- Users can rely on documented support, training, migration, and release notes. Status: user guide, known limitations, release checklist, release notes template, and validation package are implemented; live support SLA is operator-owned.

## Implementation Order

1. Finish 65 target first: install/run confidence and first-run guidance.
2. Then 70 target: warnings, run transparency, resume/retry.
3. Then 75 target: Case DB default workflow, saved searches, batch review, report templates.
4. Then 80 target: Windows artifacts, validation fixtures, portable reviewer package.
5. Then 85 target: evidence adapter execution, benchmark suite, release discipline.

## Most Important Product Rule

Do not chase AXIOM/WISDOM feature count blindly.

Score goes up when users can trust the result:

- They know what was processed.
- They know what was skipped.
- They can find evidence quickly.
- They can verify the source.
- They can mark and compare evidence comfortably.
- They can export a clean report with hashes and audit trail.
