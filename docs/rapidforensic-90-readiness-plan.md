# RapidForensic 90-Point Readiness Plan

Last verified: 2026-05-11

## Current Baseline

Fresh `commercial-readiness` evidence after the scoring correction shows:

| Gate | Result |
| --- | --- |
| Readiness score without validation package | 88 |
| Readiness score with #1-#120 internal validation package | 90 |
| Commercial claim allowed | false |
| Implemented | 120/120 |
| Usable | 120/120 |
| Internal validation evidence mapped | 120/120 when the package is attached |
| Commercial-grade | 0/120 |

Interpretation: the product now reaches the internal 90-point readiness target when the #1-#120 validation package is attached. This still does not permit commercial-grade wording because external E01 evidence, trusted-tool diffs, large-case traces, legal/reviewer signoff, and release operations evidence remain blockers.

Fresh verification command:

```bash
/Users/shinyoohag/rapidforensic/repo/.venv/bin/rapidtriage commercial-readiness \
  --output-dir /tmp/rapidtriage-90-plan-readiness \
  --json

/Users/shinyoohag/rapidforensic/repo/.venv/bin/rapidtriage commercial-readiness \
  --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json \
  --output-dir /tmp/rapidtriage-90-plan-readiness-validated \
  --json
```

Observed blocking release-evidence classes:

1. Core parser known-answer corpus.
2. Mobile/cloud schema validation.
3. Large-case stress results.
4. Legal validation package.
5. Commercial release operations.

## 90-Point Target

The 90-point target means:

- The score calculation recognizes deeper `Partial+++` and higher maturity states instead of undercounting them as unknown statuses.
- The #1-#120 internal validation package maps passing evidence to all backlog items.
- Final QC can hash and summarize validation, custody, audit, exhibit, performance, browser, and reviewer evidence paths.
- Commercial-grade remains blocked unless external lab/legal/release evidence is attached.

The 90-point target does not mean AXIOM/WISDOM parity, court acceptance, signed installer readiness, or independent validation completion.

## Stage 1: Aggregate Internal Known-Answer Evidence

Target score lift: 88 -> 90

Objective: prove all internal fixture-backed claims are attached through one validation package.

Actions:

1. Build an aggregate manifest that references all existing batch manifests from `docs/validation/rapidtriage-core-forensics-001-005-known-answer.json` through `docs/validation/rapidtriage-core-forensics-101-120-known-answer.json`.
2. Run `rapidtriage commercial-readiness --validation-package <aggregate> --json`.
3. Record mapped items, validated gate count, missing trusted-diff blockers, and remaining commercial blockers.
4. Store output under `logs/readiness/` or another controlled validation folder.

Required evidence:

- Aggregate known-answer manifest.
- Commercial-readiness JSON.
- Human-readable summary of validated items and remaining blockers.

Acceptance criteria:

- All #1-#120 internal fixture claims are mapped.
- The report explicitly separates internal fixture validation from commercial-grade validation.
- No item is described as commercial-grade from internal fixtures alone.

## Stage 2: Windows 11 E01 Single-Case End-To-End QC

Target score impact: does not increase the internal 90 score by itself; it removes the real-case blocker needed before any report-grade claim.

Objective: prove one analyst workflow works from evidence selection to report bundle.

Actions:

1. Select a real Windows 11 E01, Ex01, or trusted exported evidence folder.
2. Run `rapidtriage e01-known-answer <case.E01> --output windows11-e01-known-answer.json`.
3. Run `rapidtriage e01-smoke <case.E01> --output-dir e01-smoke --case-id <case-id>`.
4. Run the standard analysis workflow or scan the trusted export folder when image extraction tools are unavailable.
5. Generate search, review, report, validation package, runner matrix, and final QC outputs.
6. Attach all outputs to `rapidtriage final-qc-report`.

Required evidence:

- Source evidence hash or segment-set hashes.
- Dependency/preflight transcript.
- Partition or exported-root selection proof.
- Run summary and artifact outputs.
- Search/review/report outputs.
- Final QC report JSON.

Acceptance criteria:

- The case can be re-run from documented commands.
- Final QC has no missing attachment checks except trusted-tool exports that are explicitly unavailable.
- Failure modes are classified instead of silent.

## Stage 3: Trusted-Tool Diff For Core Windows Artifacts

Target score impact: does not increase the internal 90 score by itself; it removes core parser trusted-diff blockers needed before commercial-grade review.

Objective: validate high-value artifact rows against established tools.

Priority order:

1. EVTX: EvtxECmd and Hayabusa.
2. Registry/NTUSER/UsrClass: RECmd, Registry Explorer, ShellBagsExplorer or SBECmd.
3. NTFS: MFTECmd, analyzeMFT, UsnJrnl2Csv.
4. Execution artifacts: PECmd, JLECmd, LECmd.
5. ESE/SRUM/Windows.edb: SrumECmd, libesedb, Windows Search DB Analyzer.

Actions:

1. Run `rapidtriage validation-diff-runners --output runner-matrix.json --json`.
2. Generate trusted-tool exports with captured command lines and versions.
3. Run `rapidtriage cross-tool-validate` with `--source-evidence`, `--tool-version`, `--tool-command`, `--independent-report`, and `--corpus-scope`.
4. Triage mismatch dashboard rows into RapidForensic bug, trusted-tool difference, schema limitation, or human-review-required.
5. Re-run readiness with passing validation package evidence.

Required evidence:

- Trusted-tool output files.
- Tool version and command transcripts.
- Cross-tool validation JSON.
- Mismatch dashboard with severity and triage notes.
- Reviewer signoff.

Acceptance criteria:

- EVTX, Registry, MFT/USN, Prefetch, JumpList, and ShellBags each have at least one trusted-diff result or explicit external blocker.
- Missing/extra/field mismatch rows are visible and not silently ignored.
- Report wording remains validation-required when diffs are absent or failing.

## Stage 4: Large-Case And GUI Trace Evidence

Target score impact: does not increase the internal 90 score by itself; it removes large-data usability blockers.

Objective: prove large-result usability and bounded resource behavior.

Actions:

1. Run synthetic benchmark scenarios for 100k and 1M records.
2. Run a real exported case folder where legally available.
3. Capture GUI/browser trace for large result table, source viewer open, review tagging, and report selection.
4. Record DOM count, p95 interaction latency, memory usage, skipped/truncated counts, and failure count.
5. Attach benchmark and trace outputs to final QC.

Required evidence:

- Benchmark JSON and markdown.
- Browser trace, screenshot, or equivalent UI evidence.
- Peak memory and latency metrics.
- Large-case limitations and safe operating envelope.

Acceptance criteria:

- 100k+ result review remains usable without browser lockup.
- Source viewer and review tagging work from large result rows.
- Truncation, caps, and pagination are disclosed.

## Stage 5: Legal Submission Evidence Package

Target score impact: does not increase the internal 90 score by itself; it makes the 90-point evidence package reviewable and blocks false commercial-grade claims.

Objective: make the QC bundle reviewable by a forensic lead without searching scattered files.

Actions:

1. Prepare chain-of-custody record.
2. Generate audit hash chain or tamper-evident bundle.
3. Generate court exhibit bundle or exhibit manifest.
4. Write reviewer signoff.
5. Run:

```bash
rapidtriage final-qc-report \
  --validation-package ./validation/rapidtriage-validation-package.json \
  --runner-matrix ./runner-matrix.json \
  --chain-of-custody ./custody.json \
  --audit-bundle ./tamper-bundle.json \
  --exhibit-bundle ./exhibit.zip \
  --performance-run ./benchmark.json \
  --browser-trace ./trace.json \
  --reviewer-signoff ./review.md \
  --output ./final-qc.json \
  --json
```

Required evidence:

- Chain-of-custody JSON or signed note.
- Audit/tamper bundle.
- Court exhibit bundle or manifest.
- Reviewer signoff.
- Final QC report.

Acceptance criteria:

- `final-qc-report` failed checks are empty.
- Every attached evidence file has SHA-256 in the report.
- Remaining blockers are explicit and do not permit commercial-grade claims.

## Score Gate Expectations

| Stage | Expected score | Main blocker after stage |
| --- | ---: | --- |
| Baseline | 88 | No validation package attached |
| Stage 1 | 90 | Internal fixtures only; commercial-grade still blocked |
| Stage 2 | 90 | Needs trusted-tool diffs |
| Stage 3 | 90 | Needs large-case and UI trace evidence |
| Stage 4 | 90 | Needs legal submission package |
| Stage 5 | 90 | Needs external lab/legal/release evidence for commercial-grade |

## Ten-Step Execution Ladder

This is the operational order for reaching and defending the internal 90-point score. Each step must create files that can be attached to `commercial-readiness` or `final-qc-report`; notes alone do not count.

| Step | Target | Output that must exist | Pass signal | If it fails |
| --- | --- | --- | --- | --- |
| 1 | Freeze baseline | `rapidtriage-commercial-readiness.json` and `.md` | Score/gates reproducible from clean command | Fix command/runtime path before touching feature code |
| 2 | Aggregate internal fixture evidence | `rapidtriage-core-forensics-001-120-aggregate-known-answer.json` | All intended item IDs mapped, no missing evidence path | Split by batch and identify missing fixture file |
| 3 | Attach validation package | `rapidtriage-validation-package.json` | `validation_evidence_mapped_count` increases | Fix validation schema or path references |
| 4 | Run Windows 11 E01/export workflow | `windows11-e01-run-summary.json` | Ingest, artifact scan, search, review, report run are linked | Fall back to trusted exported root and mark E01 dependency blocker |
| 5 | Hash and provenance capture | `source-hashes.json`, `artifact-provenance.json` | Source path/hash/parser/version/index present for selected evidence | Block report inclusion for provenance-missing rows |
| 6 | EVTX trusted diff | `evtx-cross-tool-validation.json` | EvtxECmd/Hayabusa export compared at record level | Classify as tool missing, parser bug, or schema limitation |
| 7 | Registry trusted diff | `registry-cross-tool-validation.json` | RECmd/ShellBagsExplorer/SBECmd rows compared | Add parser fixture or mark unsupported hive/cell feature |
| 8 | NTFS/execution trusted diff | `ntfs-exec-cross-tool-validation.json` | MFT/USN/Prefetch/LNK/JumpList row diff exists | Prioritize row identity and timestamp normalization bugs |
| 9 | Large review trace | `large-case-benchmark.json`, `browser-trace.json` | 100k+ review/search/source-view/report selection usable | Add cursor/virtualization/cap disclosure fixes |
| 10 | Legal/QC bundle | `final-qc.json`, custody/audit/exhibit/signoff files | `failed_checks` empty for attached evidence set | Do not claim commercial-grade; fix missing attachment or signoff |

## Evidence Directory Layout

Use one immutable run folder per score-lift attempt:

```text
qc-runs/
  2026-05-11-windows11-e01-90-target/
    00-baseline/
    01-validation-package/
    02-e01-run/
    03-cross-tool-diffs/
    04-large-case/
    05-legal-qc/
    final/
```

Required naming rule: every generated JSON/CSV/HTML/ZIP must include the case ID, tool/version when relevant, and SHA-256 in either the file itself or the final QC manifest.

## Readiness Promotion Rules

Do not promote the score target unless the corresponding evidence exists:

| Promotion | Minimum evidence |
| --- | --- |
| 88 -> 90 | Baseline reproduced and #1-#120 internal validation package attached |
| 90 -> report-grade blocker reduction | One Windows 11 E01/exported-root workflow produces artifact, search, review, and report outputs |
| 90 -> core parser blocker reduction | EVTX, Registry, NTFS/execution trusted-tool diff outputs are attached |
| 90 -> large-data blocker reduction | Large-case benchmark plus GUI/source-view/review trace is attached |
| 90 -> legal/QC blocker reduction | Final QC has validation, runner matrix, custody, audit/tamper, exhibit, performance, trace, and reviewer signoff |

Commercial-grade remains separate from the 90-point internal target. Even at 90, the product must still block commercial-grade wording unless independent validation, real release operations, and external/legal signoff evidence are attached.

## Concrete Next Implementation Tasks

1. Add or generate the #1-#120 aggregate validation package and test that `commercial-readiness --validation-package` maps the expected item IDs.
2. Add a `qc-runs` README/template so analysts know exactly where to place E01, trusted-tool, benchmark, custody, audit, exhibit, and signoff outputs.
3. Add a smoke test that fails if the 90-point plan references a command or evidence filename that no longer exists.
4. Run final QC with synthetic attachments to keep the command path tested, while clearly labeling it as non-commercial synthetic evidence.
5. When the operator provides a real Windows 11 E01 or trusted export, replace synthetic artifacts with real run outputs and re-run readiness.

## Execution Order

1. Create aggregate #1-#120 validation package.
2. Run one real Windows 11 E01/exported-folder case end-to-end.
3. Attach EVTX, Registry, and NTFS trusted-tool diffs first.
4. Capture large-result GUI/browser trace.
5. Attach custody, audit, exhibit, and reviewer signoff.
6. Re-run `commercial-readiness`.
7. Compare score, gate counts, and blocker deltas.
8. Repeat only on the blocker class that still limits the score.

## Stop Conditions

Stop calling the product 90-ready if any of these are true:

- No real Windows 11 case or trusted export has been run.
- Trusted-tool diffs are missing for core Windows artifact claims.
- Final QC report has failed attachment checks.
- Report package lacks custody, audit/tamper, exhibit, or reviewer signoff evidence.
- `commercial-readiness` still shows no validated gate improvement.

## Immediate Next Command Set

```bash
rapidtriage validation-diff-runners --output ./qc/runner-matrix.json --json
rapidtriage validation --output-dir ./qc/validation --overwrite --json
rapidtriage final-qc-report --runner-matrix ./qc/runner-matrix.json --validation-package ./qc/validation/rapidtriage-validation-package.json --output ./qc/final-qc.json --json
rapidtriage commercial-readiness --validation-package ./qc/validation/rapidtriage-validation-package.json --output-dir ./qc/readiness --json
```

Those commands establish the evidence baseline and the internal 90-point package when the #1-#120 validation manifest is attached. Commercial-grade wording still requires real E01, trusted-tool, performance, browser, custody, audit, exhibit, and reviewer files.
