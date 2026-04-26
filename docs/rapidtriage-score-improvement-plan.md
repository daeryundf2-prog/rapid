# RapidTriage Score Improvement Plan

This plan is scored from a real analyst/user perspective, not from a feature-count perspective.

## Current Score

Estimated current score: 60/100.

Why:

- The tool now has a usable local web UI, sample case, doctor check, evidence preflight, whole-case search, source viewer, review board, compare tray, hashes, report draft, SQLite Case DB alpha, Windows quickstart, and packaging tests.
- It is useful for folder-based triage and light forensic review.
- It is not yet comparable to AXIOM/WISDOM for direct evidence ingestion, deep Windows artifact coverage, validated parsers, large-case indexing, polished reporting, portable reviewer workflows, or commercial trust.

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
- Add UI warnings for unsupported direct image formats instead of letting users discover limitations after failure.
- Add packaged release smoke test instructions for fresh Windows and macOS machines.
- Add a short "What E01 does today" guide: direct support only when external tools exist; otherwise mount/export first.

Acceptance criteria:

- Fresh Windows user can run the web UI in under 15 minutes from README.
- Sample case completes and opens automatically.
- Missing optional tools are shown as warnings, not confusing failures.

## Plan To Reach 70

Goal: avoid the biggest real-world frustration: slow or opaque processing.

Tasks:

- Add visible processing summary before run: selected mode, profile, expected heavy steps, caps, and skipped areas.
- Add parser/job warning badges: completed, skipped, failed, zero rows, capped, read-only skipped.
- Add run resume/retry behavior: same output directory should reuse completed outputs and rerun failed/skipped stages safely.
- Add progress log view in UI with current stage and last processed path where available.
- Add "fast first pass" as the default and make deep extraction an explicit choice.

Acceptance criteria:

- A user can tell why a run was fast, slow, empty, skipped, or incomplete.
- Report includes what was processed, skipped, capped, and deferred.
- No run should simply say "completed" without step-level evidence.

## Plan To Reach 75

Goal: make search/review/report strong enough for daily internal use.

Tasks:

- Move normal web workflow from JSON scans to Case DB by default after a run.
- Add persistent saved searches, keyword packs, and recent search history per case.
- Add review status filters everywhere: unreviewed, relevant, not relevant, needs follow-up, report candidate, verified, rejected.
- Add batch review actions for repetitive results.
- Add side-by-side diff for text/log evidence, not just compare cards.
- Add report template selector: executive summary, technical appendix, legal handoff, hash-only appendix.

Acceptance criteria:

- Search returns first page quickly on a 100k-file synthetic case.
- Analyst can search, preview, mark, verify, and generate a focused report without returning to raw JSON.
- Report contains only selected/reviewed evidence by default.

## Plan To Reach 80

Goal: improve actual forensic value, especially Windows evidence.

Tasks:

- Add high-value Windows parser tests and normalized outputs for Event Logs, Registry hives, Prefetch, LNK, Jump Lists, ShellBags, USB history, SRUM/EDB where feasible.
- Add browser unified view across Chrome, Edge, Firefox, downloads, history, and typed URLs.
- Add source validation views: parser source path, offset if available, raw record preview, extraction method, parser version.
- Add portable reviewer bundle: static HTML/JSON package with selected artifacts, previews, notes, hashes, and no original image.
- Add report noise controls: hide technical metadata by default, put full metadata in appendix.
- Add validation fixtures with expected artifact counts and known false-negative limitations.

Acceptance criteria:

- At least 10 high-value parser fixtures pass deterministic tests.
- Portable review package supports tagging/comment review without exposing original evidence image.
- Report is readable by a non-technical reviewer while preserving technical appendices.

## Plan To Reach 85

Goal: become defensible and stable enough for professional use.

Tasks:

- Add evidence adapter execution layer for mounted/raw/ISO/VHD/VMDK where platform tools allow safe read-only mounting or extraction.
- Add stronger chain-of-custody: evidence IDs, acquisition/source hash, tool versions, audit events, run profile, warnings, and report linkage.
- Add large-case benchmark suite: 10k, 100k, 1M synthetic records; documents/logs/browser artifacts; search latency targets.
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
- Add mobile extraction imports from Cellebrite/XRY/GrayKey/AXIOM-style exports where legally and technically feasible.
- Add cloud export/import workflows.
- Add image/media triage: thumbnails, OCR queues, perceptual hash, similarity grouping, optional AI classification.
- Add memory forensics integration with Volatility-style output normalization.
- Add support/training/legal validation package.

Acceptance criteria:

- Independent validation datasets prove parser behavior.
- Cross-platform installers are signed and repeatably built.
- Users can rely on documented support, training, migration, and release notes.

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
