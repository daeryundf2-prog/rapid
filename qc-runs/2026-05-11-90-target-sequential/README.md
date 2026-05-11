# RapidForensic 90-Target Sequential QC Run

Generated: 2026-05-11

This run executes the 90-point readiness plan in order from step 1 and repeats step 8 ten times. It is intentionally evidence-disciplined: internal validation evidence is recorded, but no external E01/trusted-tool/legal evidence is fabricated.

## Step Results

| Step | Result | Evidence |
| --- | --- | --- |
| 1. Freeze baseline | Complete | `00-baseline/rapidtriage-commercial-readiness.json`, `00-baseline/rapidtriage-commercial-readiness.md` |
| 2. Aggregate internal fixture evidence | Complete | `01-validation-package/rapidtriage-core-forensics-001-120-aggregate-known-answer.json` |
| 3. Attach validation package | Complete | `01-validation-package/rapidtriage-validation-package.json`, `01-validation-package/readiness-with-001-120/rapidtriage-commercial-readiness.json` |
| 4. Windows 11 E01/export workflow | Blocked by missing operator evidence | `02-e01-run/windows11-e01-run-summary.json` |
| 5. Hash and provenance capture | Partial, generated-run artifacts only | `03-cross-tool-diffs/source-hashes.json`, `03-cross-tool-diffs/artifact-provenance.json` |
| 6. EVTX trusted diff | Blocked by missing EvtxECmd/Hayabusa/Event Viewer exports | `03-cross-tool-diffs/evtx-cross-tool-validation.json` |
| 7. Registry trusted diff | Blocked by missing RECmd/Registry Explorer/ShellBagsExplorer exports | `03-cross-tool-diffs/registry-cross-tool-validation.json` |
| 8. NTFS/execution trusted diff | Repeated 10 times, all correctly blocked by missing trusted outputs | `03-cross-tool-diffs/ntfs-exec-cross-tool-validation.json` |
| 9. Large review trace | Blocked by missing large-case/browser trace evidence | `04-large-case/large-case-benchmark.json`, `04-large-case/browser-trace.json` |
| 10. Legal/QC bundle | Placeholder attachments generated; operator/legal signoff still required | `final/final-qc.json` |

## Readiness Outcome

- Baseline readiness score: 79.
- Validation package attached: yes.
- Internal passed validation evidence mapped: 120/120 items.
- Final readiness score after this run: 79.
- Commercial claim allowed: false.
- Commercial-ready items: 0/120.

The score does not rise because the current scoring gate correctly refuses to treat internal fixture evidence or placeholder blocker files as commercial-grade proof. The next real score lift requires actual Windows 11 E01/exported-root evidence, trusted-tool exports, large-case trace logs, and reviewer/legal signoff.

## Step 8 Repetition Coverage

The ten step-8 repetitions cover:

1. MFT record identity.
2. MFT parent path reconstruction.
3. USN record identity.
4. USN rename/delete replay.
5. Prefetch execution metrics.
6. LNK ShellLink metadata.
7. JumpList DestList metadata.
8. NTFS/execution timestamp normalization.
9. Row provenance and hash tie-off.
10. Reportability decision review.

Every repetition has `status=blocked-external-tool-output-required`, which is the correct result until MFTECmd, analyzeMFT, UsnJrnl2Csv, PECmd, LECmd, and JLECmd outputs are attached.
