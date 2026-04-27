# RapidTriage User Convenience Principles

RapidTriage should be designed for analysts who are tired, under time pressure, and handling large evidence sets.

## UX Rules

- Start with a safe default. If the user is unsure, recommend `fraud` mode, read-only processing, and sample-case practice first.
- Never make users remember output paths. Show import, Case DB, report, and bundle actions close to the run summary.
- Keep the first pass fast. Full carving, heavy OCR, and deep indexing should be explicit follow-up jobs.
- Always show "what next". Every completed run should point to search, review, and report-candidate actions.
- Make failures actionable. Show the failed step, not just a generic error.
- Preserve context. Analysts should move between search, viewer, compare, review, and report without losing selected evidence.
- Reduce noise. Prefer verified source artifacts by default, and clearly label inferred, carved, or low-confidence data.
- Keep evidence defensible. Source path, parser, hash, review status, and audit trail should stay visible near report actions.

## Convenience Backlog

- One-click sample case launch from the web UI is available through `Run sample case`.
- First-run runtime checks are available through `Check runtime`.
- Evidence preflight is available through `Check evidence support` so users can see whether a folder/image scans directly or needs mounting/export first.
- Processing profiles are available in the web UI so the first pass can stay fast instead of accidentally enabling deep extraction on a huge case.
- Whole-case search supports source, extension, and path filters so analysts can narrow noisy cases before opening rows.
- The evidence viewer computes MD5/SHA1/SHA256 only on demand, avoiding accidental slowdowns on very large files.
- Completed run summaries now show direct actions for Case DB preparation, whole-case search, review decisions, and report/submission workflow.
- Evidence preflight warns when the selected source looks like a host drive, user home, or common analyst-machine folder instead of a deliberate exhibit.
- Processing summaries now expose parser warning badges for warning steps, zero-row parser outputs, and reused outputs.
- The evidence viewer supports keyboard shortcuts for review decisions: `Alt+R` saves relevant, `Alt+X` saves not relevant, and `Alt+I` toggles report inclusion.
- Whole-case search remembers recent keyword sets per run, and Case DB search can reload saved searches/recent DB keywords from the web panel.
- The evidence viewer supports `Alt+[` and `Alt+]` for previous/next search hit navigation.
- Case DB batch review supports selecting visible rows or low-priority rows before verify/reject actions.
- The review board can build a portable reviewer ZIP with static HTML, selected evidence JSON, report exports, hashes, and no original image.
- Add progressive processing profiles: fast first pass, then standard/deep enrichment.
