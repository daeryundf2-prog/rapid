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
- Add "send to Case DB" and "make submission bundle" actions directly from the completed run summary.
- Add saved searches and recent keywords per case.
- Add viewer-specific shortcuts for next hit, previous hit, mark relevant, reject, and include in report.
- Add batch review for repeated low-value hits.
- Add progressive processing profiles: fast first pass, then standard/deep enrichment.
