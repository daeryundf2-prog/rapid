# RapidTriage macOS Live Smoke

- Generated: `2026-05-19T00:14:54.789962+00:00`
- Local smoke score: `85.71`
- Passed checks: `6/7`
- Live artifact records: `212`
- Large-case readiness: `needs-large-case-evidence`
- Largest FTS benchmark: `5000` rows
- Redaction: `Live smoke stores counts and source hashes by default; rerun with --include-path-details only for authorized local debugging.`

## Failed Checks
- `forensic-cross-tool-ready`

## Commercial Blockers
- `forensic-cross-tool-ready`
- `independent-lab-signoff-not-attached`
- `large-case-1tb-10tb-hardware-run-not-run`
- `trusted-forensic-cross-tool-output-missing`
- `windows-e01-real-image-validation-not-run`

## Readiness Attachment
- Claim effect: `preparatory-only; does not satisfy commercial-grade validation gates by itself`
- CLI: `rapidtriage commercial-readiness --mac-first-evidence '/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/macos-live-smoke' --output-dir ./commercial-readiness --json`
- API: `/api/commercial-readiness?mac_first_evidence=/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/macos-live-smoke`
- GUI note: Open the readiness dashboard and paste this QC folder path into Mac evidence/QC folder; the Mac evidence rows should show attached evidence while commercial gates remain blocked until trusted validation packages are supplied.
- Required follow-up:
  - Attach trusted parser/cross-tool validation packages for the relevant backlog items.
  - Run larger SQLite FTS benchmarks on target Mac hardware before million-row or commercial-scale claims.
  - Attach independent review, signed package, and real hardware stress evidence before commercial-grade release claims.
