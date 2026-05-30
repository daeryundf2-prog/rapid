# RapidForensic Review Recovery Plan - 2026-05-30

## Requirements Summary

The current repository was developed on macOS, tested on Windows, then received back on macOS. The immediate goal is to restore a clean, reproducible baseline before adding new recovery-engine work. The plan prioritizes failing verification, Windows/macOS parity, E01 workflow honesty, large-case stability, and viewer/extraction readiness.

## Decision Principles

1. Fix red tests before adding features.
2. Keep E01 and commercial-grade claims honest; never mark preflight complete unless the required extraction path is actually usable.
3. Make Windows/macOS setup deterministic for fresh machines.
4. Make samples and fixtures reproducible; no current-time fields in golden outputs.
5. Refactor only after behavior is locked by tests.

## Decision Drivers

1. CI currently fails: `.github/workflows/rapidtriage-ci.yml:37` runs `python -m unittest discover -s tests`.
2. User target includes Windows and macOS, E01 workflows, 10TB-scale cases, resumability, fast review, and clean viewer UX.
3. Forensic credibility depends on provenance, validation blockers, and repeatable evidence rather than optimistic UI claims.

## Plan Revision History

| Revision | Date | Git authority | Summary |
| --- | --- | --- | --- |
| R0 | 2026-05-30 | draft history in containing commit | Initial recovery review roadmap drafted from macOS/Windows review findings. |
| R1 | 2026-05-30 | containing commit | Converted roadmap into a canonical execution program with waves, governance gates, quantitative release gates, DB migration contract, legal/operator gate, and git authority rules. |

Rule:
- This document becomes execution authority only after it is committed in git.
- Execution records must cite the committed plan revision and commit hash.
- Any untracked or locally modified copy is a draft and cannot authorize implementation.

## Change Log

R1 changes:
- Added one authoritative execution order.
- Split all work into independently executable waves.
- Moved recovery, indexing, viewer, and performance work behind recovery governance.
- Added pass/fail quantitative release gates.
- Added database migration and schema deletion controls.
- Replaced legal overclaiming language with report-defensible wording.
- Added git governance and release scorecard requirements.

## Git Governance

1. The plan document must be committed before any execution wave starts.
2. Every execution branch, issue, PR, work log, and validation report must reference:
   - plan path
   - plan revision id
   - git commit hash
   - wave id
   - milestone ids being executed
3. Plan revision history is mandatory. New plan changes require a new row in `Plan Revision History`.
4. A change log is mandatory. Each plan revision must summarize material changes.
5. Untracked plans cannot be used as execution authority.
6. Modified-but-uncommitted plans cannot be used as execution authority unless the active work is explicitly "revise the plan".
7. If the plan changes during execution, stop the affected wave, commit the revised plan, then resume with the new committed revision.

## Canonical Execution Sequence

This section is the single authoritative execution order. Numbered sections below are reference milestones, not chronological authority. If any milestone text conflicts with this sequence, this sequence wins and the milestone must be interpreted as backlog, design, or validation scope for its assigned wave.

Authoritative order:
1. Baseline validation.
2. Static analysis cleanup.
3. Security review.
4. DB audit.
5. Code review.
6. Refactor.
7. Feature implementation.
8. Validation.
9. Release.

Milestone mapping:

| Sequence | Wave | Execution phase | Primary milestone references | Hard gate |
| --- | --- | --- | --- | --- |
| 1 | Wave 0 | Baseline validation | 0-7 | macOS baseline repair is green or explicitly blocked with evidence. |
| 2 | Wave 1 | Static analysis cleanup | 43, 46 | Ruff selected rules pass and Vulture findings are triaged. |
| 3 | Wave 2 | Security review | 38, 44 security lane | Security findings are recorded, severity-ranked, and blockers are fixed or accepted with rationale. |
| 4 | Wave 2 | DB audit | 45 plus Database Migration Contract | Schema/index inventory is complete; no deletion is allowed without validation evidence. |
| 5 | Wave 2 | Code review | 44 | Accepted review findings are converted to tracked fix items. |
| 6 | Wave 3 | Refactor | 8 | Behavior is locked by tests before module movement. |
| 7 | Wave 4 | Feature implementation | Recovery Backlog, 47-54 | PRD, test specification, and recovery architecture review are approved first. |
| 8 | Wave 5 | Validation | 22, 42, 55-63 plus Quantitative Validation Matrix | All pass/fail gates meet numeric thresholds. |
| 9 | Wave 6 | Release | 24, 64 plus Updated Release Scorecard | Release scorecard has no failing blocker. |

Milestone authority rule:
- Every milestone in this document must be executed only through the wave and phase assigned in `Canonical Execution Sequence`.
- Section numbers are stable references for tracking and review, not permission to execute in numeric order.
- Recovery, indexing, viewer, and performance implementation items are candidates only until Wave 4 entry criteria are met.

## Wave-Based Execution Model

Wave summary table:

| Wave | Objective | Scope | Entry criteria | Completion criteria | Deliverables | Blocking conditions |
| --- | --- | --- | --- | --- | --- | --- |
| Wave 0 - Baseline Validation | Restore a reproducible baseline | sections 0-7 | committed plan or active plan revision task; status and failures recorded | macOS tests, compileall, JS syntax, Rust checks, E01 honesty, Windows checklist pass | baseline repair commit, transcripts, blocker list | unexplained red tests, dishonest E01 status, nondeterminism, unsupported Python |
| Wave 1 - Static Cleanup | Remove static/dead-code risk | sections 43, 46 | Wave 0 complete; tool versions recorded | Ruff selected rules pass; Vulture triaged; full tests pass | static report, Ruff config, whitelist, cleanup commit | output schema drift, unclear forensic impact, unreproducible tooling |
| Wave 2 - Security and Audit | Prove safety and DB correctness | sections 38, 44, 45 | Wave 1 complete; security and DB templates ready | security blockers resolved; schema/index inventory complete; code review report exists | security report, DB inventory, query plans, code review report | unsafe extraction, unvalidated schema deletion, missing migration backup, premature code review |
| Wave 3 - Refactor | Reduce module risk without behavior change | section 8 | Wave 2 complete; characterization tests ready | public behavior stable; focused and full checks pass | refactor plan, tests, commits, transcript | red baseline, missing characterization tests, feature work mixed in |
| Wave 4 - Recovery MVP | Ship governed recovery MVP scope | sections 47-54 | PRD, test spec, and architecture review approved | MVP feature tests pass; every recovery output has provenance and limits | PRD, test spec, architecture record, corpus, implementation commits | missing governance approval, missing provenance, unsupported source implementation |
| Wave 5 - Validation | Prove claims with numbers | sections 22, 42, 55-63 | Wave 4 complete; corpora and benchmark schemas exist | all quantitative gates pass | accuracy, reproducibility, performance, UI, large-case, trusted-tool, report-defensible, and operational reports | missing numeric evidence, failed thresholds, missing trusted-tool evidence |
| Wave 6 - Release Readiness | Release only evidence-backed scope | sections 24, 64 | Wave 5 complete; legal/operator review complete | Updated Release Scorecard has no failures | release checklist, release notes, limitations, final validation bundle | scorecard failure, uncommitted evidence, overclaiming |

### Wave 0 - Baseline Validation

Objective:
- Restore and prove a clean, reproducible macOS baseline before cleanup, refactor, or recovery feature work.

Scope:
- Sections 0-7.
- Failing README/docs tests.
- Windows manifest deterministic sample.
- E01 smoke honesty.
- launcher Python version parity.
- local macOS CI parity.
- Windows handoff checklist.

Entry criteria:
- Plan revision is committed or the active task is only plan revision.
- Current branch and working tree status are recorded.
- Existing failing tests are captured with command transcripts.

Completion criteria:
- `python3.12 -m unittest discover -s tests` passes on macOS.
- `python3.12 -m compileall -q rapidtriage tests scripts` passes.
- Web JS syntax checks pass.
- Rust fmt/check/test pass where the Rust workspace is present.
- E01 dummy smoke remains blocked with explicit blocker evidence.
- Windows revalidation checklist exists with exact commands.

Deliverables:
- Baseline repair commit.
- macOS verification transcript.
- Windows revalidation checklist.
- Known blocker list.

Blocking conditions:
- Unexplained failing tests.
- E01 preflight reporting ready when extraction path is blocked.
- nondeterministic golden samples.
- unsupported Python accepted by launchers.

### Wave 1 - Static Cleanup

Objective:
- Remove static-analysis noise and dead-code risk before audit, review, and refactor.

Scope:
- Sections 43 and 46.
- Ruff selected-rule cleanup.
- Vulture advisory triage.
- duplicate definitions.
- import shadowing.
- unused locals classified as delete, keep, or output-contract candidates.

Entry criteria:
- Wave 0 is complete.
- Static tool versions and commands are recorded.
- Current test baseline is green.

Completion criteria:
- Ruff selected rules pass with documented per-file ignores.
- Vulture high-confidence findings are fixed or documented in a whitelist.
- No duplicate function definitions remain unless explicitly justified.
- No unused manifest/profile locals remain unless emitted, renamed `_`, or documented as pending contract work.
- Full macOS unittest and compileall pass after cleanup.

Deliverables:
- Static analysis evidence report.
- Ruff configuration or documented static runner.
- Vulture triage whitelist.
- cleanup commit.

Blocking conditions:
- Any cleanup changes output schema without tests.
- Any deleted code has unclear forensic impact.
- Static tooling cannot be repeated from documented commands.

### Wave 2 - Security and Audit

Objective:
- Prove security posture, database safety, and review readiness before refactoring.

Scope:
- Section 38 parser/evidence safety.
- Section 44 security and code review lanes.
- Section 45 DB schema/index audit.
- Database Migration Contract.
- path traversal, parser sandboxing, redaction, local web exposure, export safety, case DB migrations, and index evidence.

Entry criteria:
- Wave 1 is complete.
- Security review checklist and DB schema inventory template exist.
- Review scope cites the committed plan revision.

Completion criteria:
- Security findings are severity-ranked and all release blockers are fixed or accepted with written rationale.
- Schema inventory covers tables, columns, indexes, FTS tables, triggers, and schema version.
- Every unused table/column is classified as an unused candidate, not deleted.
- Query-plan evidence exists for index additions/removals.
- Formal code review report exists after security and DB audit.

Deliverables:
- security review report.
- DB schema inventory.
- DB usage inventory.
- query-plan evidence.
- code review report.
- fix plan for accepted findings.

Blocking conditions:
- path traversal or unsafe extraction findings without a fix plan.
- schema deletion proposed without validation evidence.
- migrations lack rollback/backup strategy.
- code review starts before security and DB audit are complete.

### Wave 3 - Refactor

Objective:
- Reduce module size and isolate boundaries while preserving behavior.

Scope:
- Section 8 only.
- API router split.
- Case DB module split.
- JS workbench split.
- characterization tests.

Entry criteria:
- Wave 2 is complete.
- Accepted security, DB, and review blockers that affect refactor boundaries are resolved.
- Characterization tests exist for routes, DB behavior, UI flows, and export/report contracts being moved.

Completion criteria:
- Public CLI commands, API routes, output schemas, and UI behavior remain stable.
- Full macOS verification passes after each narrow extraction batch.
- Browser smoke passes for moved UI code.
- No recovery implementation is included in refactor commits.

Deliverables:
- refactor plan per module.
- characterization tests.
- refactor commits.
- post-refactor verification transcript.

Blocking conditions:
- red baseline.
- missing characterization tests for moved behavior.
- refactor mixed with recovery feature implementation.

### Wave 4 - Recovery MVP

Objective:
- Implement the first governed recovery product slice after product, test, and architecture gates are approved.

Scope:
- Sections 47-54.
- Existing-file export.
- checkpoint/resume/job-state foundation.
- index/search/fast review MVP.
- NTFS recovery MVP.
- signature carving MVP.
- recovery viewer/review UX MVP.

Entry criteria:
- Wave 3 is complete.
- Recovery PRD is approved.
- Recovery test specification is approved.
- Recovery architecture review is approved.
- Known-answer corpus exists for every MVP claim.

Completion criteria:
- Existing-file export, resume, search, NTFS recovery, carving, and viewer MVP tests pass for approved scope.
- Every recovered output has hash, source citation, confidence, limitation, and validation status.
- Recovery outputs use a stable manifest contract shared with existing-file export.
- No unsupported source type is silently treated as supported.

Deliverables:
- approved PRD.
- approved test specification.
- architecture review record.
- recovery data model.
- known-answer corpus.
- MVP implementation commits.
- feature verification transcript.

Blocking conditions:
- PRD, test specification, or architecture review missing.
- recovery output lacks provenance or limitation fields.
- no known-answer corpus for the claimed recovery path.
- implementation attempts a source type not covered by the approved scope.

### Wave 5 - Validation

Objective:
- Convert accuracy, reproducibility, performance, UI, large-scale, external-tool, and operational claims into pass/fail evidence.

Scope:
- Sections 22, 42, and 55-63.
- Quantitative Validation Matrix.
- trusted-tool diff.
- report-defensible package.
- Windows real-evidence validation where available.

Entry criteria:
- Wave 4 is complete.
- Benchmark commands and schemas exist.
- Validation corpus and negative-control corpus exist for claimed scope.
- Windows validation environment is defined or blocked with evidence.

Completion criteria:
- Every quantitative release gate is pass/fail and has attached evidence.
- Accuracy, reproducibility, performance, UI latency, and large dataset survival meet thresholds.
- External trusted-tool comparisons exist for every strong source-type claim.
- Report-defensible package passes citation, chain-of-custody, limitation, and hash checks.

Deliverables:
- accuracy report.
- reproducibility report.
- performance report.
- UI latency report.
- large dataset survival report.
- trusted-tool diff report.
- report-defensible evidence package.
- operational readiness report.

Blocking conditions:
- any release gate missing numeric evidence.
- any strong claim lacks trusted-tool or known-answer evidence.
- large-scale or UI tests fail thresholds.
- Windows validation is required for a claim but not executed or explicitly blocked.

### Wave 6 - Release Readiness

Objective:
- Package an honest release whose claims match validation evidence.

Scope:
- Sections 24 and 64.
- Updated Release Scorecard.
- release notes.
- known limitations.
- installer/startup smoke.

Entry criteria:
- Wave 5 is complete.
- Legal and Operator Review Gate is complete.
- Release claims are mapped to validation evidence.

Completion criteria:
- Updated Release Scorecard has no blocker failures.
- Release notes list supported scope, unsupported scope, and known limitations.
- Windows and macOS startup smoke evidence is attached.
- The release does not claim legal suitability, universal recovery rate, or unsupported source coverage.

Deliverables:
- release checklist.
- release notes.
- known limitations update.
- signed or packaged artifact if in scope.
- final validation bundle.

Blocking conditions:
- failing release scorecard item.
- missing legal/operator review.
- uncommitted plan or validation evidence.
- release wording exceeds measured evidence.

## Recovery Feature Governance

Recovery functionality must not be implemented before all three gates are complete:
1. PRD approved.
2. Test specification approved.
3. Recovery architecture reviewed.

Governance rules:
- Recovery, indexing, viewer, carving, checkpoint/resume, performance worker, and export implementation items are backlog or design candidates until Wave 4 entry criteria are met.
- Sections 9-25 and 47-54 are not implementation authorization before Wave 4.
- Design work may refine scope, interfaces, tests, and risk controls before Wave 4, but must not add product recovery behavior.
- Any code change that creates, recovers, carves, indexes, displays, or exports recovery candidates is feature implementation and is blocked until Wave 4.
- Existing baseline fixes, static cleanup, security fixes, DB audit work, and behavior-preserving refactor are allowed in earlier waves only when they do not add recovery functionality.

## Recovery Design Candidates

These sections are design candidates until Wave 4 entry criteria are met:

| Candidate area | Section references | Allowed before Wave 4 | Blocked before Wave 4 |
| --- | --- | --- | --- |
| Recovery architecture | 9, 13, 14, 15, 21, 22, 23 | PRD/test spec/architecture design, fixture design, schema drafts | implementing recovery, carving, worker scans, adapters that change product behavior |
| Large-case behavior | 10, 17, 21 | benchmark design, checkpoint schema design, failure-mode modeling | production resume/checkpoint behavior for recovery jobs |
| Viewer and export UX | 11, 18, 19, 20 | wireframes, API contracts, i18n test design | recovery viewer/export implementation |
| Intake and coverage | 12, 25, 27 | coverage matrix, limitation wording, failure registry | claiming unsupported source support |
| Broader forensic roadmap | 28-42 | research, scope notes, validation planning | shipping new analysis modules without wave authorization |

## Recovery Backlog

These implementation milestones are held in backlog until Wave 4:

| Backlog item | Section references | First executable wave |
| --- | --- | --- |
| Recovery PRD and test spec | 47 | Wave 4 entry preparation after Wave 3 |
| Known-answer corpus | 48 | Wave 4 entry preparation after Wave 3 |
| Existing-file export MVP | 49 | Wave 4 |
| Checkpoint, resume, and job-state foundation | 50 | Wave 4 |
| Index, search, and fast review MVP | 51 | Wave 4 |
| NTFS file-level recovery MVP | 52 | Wave 4 |
| Signature carving MVP | 53 | Wave 4 |
| Recovery viewer and review UX MVP | 54 | Wave 4 |
| Recovery accuracy benchmark and report | 55 | Wave 5 |
| Windows real-evidence validation | 56 | Wave 5 |
| Post-MVP hardening | 57 | After Wave 6 or next committed plan |

## Quantitative Validation Matrix

All release gates are pass/fail. No gate may be satisfied by subjective wording.

| Gate | Metric | MVP pass threshold | Evidence artifact |
| --- | --- | --- | --- |
| Accuracy | precision target | >= 0.995 on the approved CI known-answer corpus; 1.000 for complete allocated existing-file export | `recovery-accuracy.json` |
| Accuracy | recall target | >= 0.990 on the approved CI known-answer corpus; 1.000 for complete allocated existing-file export | `recovery-accuracy.json` |
| Accuracy | maximum false positive rate | <= 0.005 on recovery candidates; 0 false positives in negative-control fixtures | `false-positive-report.csv` |
| Accuracy | complete recovered-file hash match | 100% for candidates marked complete | per-file diff table |
| Reproducibility | deterministic rerun equivalence | 100% normalized material equivalence for two same-machine runs | `reproducibility-diff.json` |
| Reproducibility | acceptable diff threshold | 0 material diffs; only approved dynamic fields may differ | `normalized-output-manifest.json` |
| Performance | maximum RSS memory | <= 4 GiB for 100k-file local profile and 1M-row metadata profile | `resource-usage.csv` |
| Performance | maximum CPU utilization target | <= 90% sustained system CPU over a 5-minute window unless user selects an explicit high-performance mode | performance report |
| Performance | throughput target | >= 20 MB/s sequential scan on local SSD for hashing/indexing profile, or >= 5,000 metadata rows/sec for metadata-only profile | benchmark JSON |
| UI | p95 latency | <= 2.0s for search/filter/page load on 100k-row case | browser timing report |
| UI | p99 latency | <= 5.0s for search/filter/page load on 100k-row case | browser timing report |
| Large dataset survival | target corpus size | 100k real/synthetic files and 1M metadata rows for MVP; 10TB remains blocked until representative evidence exists | `large-case-benchmark.json` |
| Large dataset survival | required completion rate | 100% job completion for 100k-file profile; >= 99.9% item completion for 1M-row metadata profile with failed items isolated | `resume-validation.json` |
| Resume | duplicate outputs after resume | 0 duplicate completed outputs | checkpoint audit |
| Report-defensible output | citation completeness | 100% report/export items have source citation or explicit approved exception | citation completeness report |
| External validation | trusted-tool comparison | required for each strong source-type claim | `trusted-tool-diff.json` |

Approved dynamic diff fields:
- `generated_at`
- elapsed/runtime fields such as `elapsed_ms`, `duration_ms`, and `runtime_seconds`
- absolute temp paths
- machine hostname
- OS username
- randomized job ids only when an id mapping file proves equivalence
- ordering only where the schema declares the collection unordered

Any other normalized output difference is a release failure.

## Database Migration Contract

The Case DB is forensic evidence infrastructure. Schema changes are release-blocking unless they follow this contract.

Schema version rule:
- Every schema change must migrate `schema_info.schema_version` from `N` to `N+1`.
- No schema behavior may change without a migration test from the previous fixture version.
- Multiple unrelated schema changes must not be hidden under one unreviewed version bump.

Migration ownership:
- The wave owner for Wave 2 owns schema inventory and migration design.
- The implementation owner for a later wave owns the migration code only after Wave 2 approves the schema change.
- The verifier owns old-fixture migration tests and post-migration validation.

Migration naming convention:
- Python migration functions must use `_migrate_schema_N_to_Nplus1_<short_slug>`.
- SQL/script artifacts, if introduced, must use `schema_N_to_Nplus1_<short_slug>.sql`.
- Validation notes must use `docs/validation/case-db/schema_N_to_Nplus1_<short_slug>.md`.

Rollback strategy:
- Every migration must either provide an automated rollback or state that rollback is unsupported and require restoring the pre-migration backup.
- Irreversible migrations are release blockers unless the review record approves the irreversibility.

Backup requirements:
- Before migration, create a byte-for-byte backup of the original database.
- Store and verify SHA-256 for both original and migrated DB.
- Migration must never overwrite the only copy of a case DB.

Fixture database locations:
- Previous-version fixture DBs: `tests/fixtures/case_db/schema_vN/*.sqlite`.
- Current expected fixture DBs: `tests/fixtures/case_db/schema_vNplus1/*.sqlite`.
- Migration expected outputs: `tests/fixtures/case_db/migrations/N_to_Nplus1/`.
- If these directories do not exist, creating them is part of Wave 2 before destructive schema work.

Migration verification procedure:
1. Run schema inventory before migration.
2. Back up the DB and record SHA-256.
3. Run migration from `N` to `N+1`.
4. Verify `schema_info.schema_version` equals `N+1`.
5. Run `PRAGMA integrity_check`.
6. Run FTS integrity/rebuild checks where FTS tables are affected.
7. Run export/import compatibility tests.
8. Run representative query-plan tests.
9. Run full Case DB tests.
10. Verify migrated output hashes and row counts against expected fixtures.

Post-migration validation checklist:
- schema version incremented exactly once.
- table list matches expected inventory.
- column list matches expected inventory.
- index list matches expected inventory.
- FTS tables and triggers are synchronized.
- row counts for preserved tables match expectations.
- exported case package remains readable.
- old fixture DB migrates successfully.
- rollback or backup-restore path is documented.

Deletion policy:
- No schema deletion without validation evidence.
- All removals must be treated as unused candidates until usage inventory, tests, query-plan evidence, migration tests, and review approval prove deletion is safe.
- "Unused by `rg`" is not sufficient evidence for deletion.

## Legal and Operator Review Gate

The product may produce report-defensible technical evidence packages, but it must not claim legal suitability without review completion.

Required release reviews:
1. Technical review.
2. Forensic methodology review.
3. Operator review.
4. Legal review.

Release blockers:
- Any missing required review.
- Any unresolved review finding marked blocker.
- Any marketing, README, UI, report, or release note wording that claims legal suitability, legal acceptance, universal recovery rate, or unsupported source coverage.
- Any report/export item lacking source citation, hash, limitation, or review status unless an explicit approved exception exists.

Required output:
- `legal-operator-review-checklist.md`
- `forensic-methodology-review.md`
- `operator-review-notes.md`
- `release-claims-map.md`

Claim policy:
- Allowed: "report-defensible technical package" when the review gate passes.
- Allowed: corpus-scoped accuracy statements with measured thresholds and limitations.
- Forbidden: any claim that a result is legally sufficient, admissible, or universally accepted.

## Updated Release Scorecard

Each scorecard row is pass/fail. A single fail blocks release.

| Area | Pass criterion | Status source |
| --- | --- | --- |
| Plan authority | committed plan revision and commit hash cited by execution records | git log and execution transcript |
| Baseline | Wave 0 completion criteria pass | macOS verification transcript |
| Static cleanup | Wave 1 completion criteria pass | static analysis report |
| Security | no unresolved blocker findings | security review report |
| DB audit | schema inventory, migration contract, and query-plan evidence complete | DB audit report |
| Code review | accepted findings tracked or fixed | code review report |
| Refactor | behavior-preserving tests pass | refactor verification transcript |
| Recovery governance | PRD, test spec, and architecture review approved | Wave 4 entry package |
| Feature MVP | Wave 4 completion criteria pass | feature verification transcript |
| Accuracy | Quantitative Validation Matrix accuracy thresholds pass | accuracy report |
| Reproducibility | 100% normalized material equivalence | reproducibility report |
| Performance | memory, CPU, and throughput thresholds pass | performance report |
| UI | p95 and p99 latency thresholds pass | browser timing report |
| Large dataset survival | corpus size and completion thresholds pass | large-case report |
| External validation | trusted-tool diff exists for each strong claim | trusted-tool report |
| Report-defensible package | citation, chain-of-custody, limitations, hashes pass | report package verification |
| Legal/operator | all required reviews complete | legal/operator checklist |
| Release wording | claims match evidence and limitations | release claims map |

## Final Deliverable Map

This revision produces the required execution artifacts inside this master plan:

1. Revised master plan: this document.
2. Canonical execution sequence: `Canonical Execution Sequence`.
3. Wave table: `Wave-Based Execution Model`.
4. Quantitative validation matrix: `Quantitative Validation Matrix`.
5. Database migration contract: `Database Migration Contract`.
6. Legal review gate: `Legal and Operator Review Gate`.
7. Updated release scorecard: `Updated Release Scorecard`.

## External Feature Baseline

The feature roadmap should be compared against mature DFIR patterns:

1. Sleuth Kit and Autopsy set the baseline for disk image support, file/volume analysis, deleted filename listing, NTFS attributes/ADS, hash databases, keyword search, image integrity, and case management: https://www.sleuthkit.org/sleuthkit/desc.php
2. dfVFS sets a useful model for read-only virtual filesystem access across EWF/E01, RAW, QCOW, sparse/UDIF and other storage media formats: https://forensics.wiki/dfvfs/
3. Plaso/log2timeline sets the baseline for supertimeline generation across many artifact sources: https://plaso.readthedocs.io/
4. Volatility 3 sets the baseline for memory image triage across Windows, Linux, and macOS symbol/plugin workflows: https://volatility3.readthedocs.io/en/latest/
5. Velociraptor sets the baseline for artifact collection workflows, favorites, notebooks, and optional endpoint/hunt-style collection: https://docs.velociraptor.app/docs/hunting/
6. YARA and Sigma set the baseline for file/memory pattern detection and generic log-event detection rules: https://yara.readthedocs.io/ and https://sigmahq.io/docs/guide/about

## Alternatives Considered

1. Patch only README and rerun tests.
   - Pros: fastest way to reduce failures.
   - Cons: leaves E01 preflight semantics and sample nondeterminism unresolved.
   - Decision: rejected as incomplete.
2. Refactor the large modules first.
   - Pros: improves long-term maintainability.
   - Cons: too risky while current tests are red.
   - Decision: defer until baseline is green.
3. Stabilize tests and platform contracts first, then refactor behind tests.
   - Pros: produces a trusted baseline and lowers regression risk.
   - Cons: slower than a cosmetic cleanup.
   - Decision: chosen.

## Numbered Implementation Plan

### 0. Baseline Freeze

Purpose: make the current state auditable before changes.

Work:
- Confirm branch and cleanliness with `git status --short --branch`.
- Record failing test list from `/tmp/rapid-unittest.log` or a fresh unittest run.
- Create a small tracking note in `.omx/plans/` or issue-style checklist if needed.

Verification:
- `git status --short --branch` is known before edits.
- Failure list is stable: 5 unittest failures, no hidden running sessions.

Exit:
- We know exactly what will be fixed and can compare after each step.

### 1. Restore README Documentation Contract

Problem:
- `tests/test_rapidtriage_documentation_contract.py:31` expects README to link schemas/sample JSON files.
- `tests/test_rapidtriage_documentation_contract.py:44` expects README to separate Implemented, Experimental, and Planned contracts.
- `tests/test_rapidtriage_rule_engine_docs.py:28` expects README to link the rule engine doc and rule sample.

Files:
- `README.md`
- `docs/rapidtriage-output-schema.md`
- `docs/rapidtriage-rule-engine.md`
- `docs/samples/rapidtriage-*.json`
- `docs/samples/rapidtriage-rules.sample.yaml`
- `rapidtriage/schemas/*.schema.json`

Work:
1. Add an "Output Contracts" section near README document map.
2. Link `rapidtriage/schemas/manifest.schema.json`.
3. Link all required sample JSON files:
   - `docs/samples/rapidtriage-manifest.sample.json`
   - `docs/samples/rapidtriage-docs.sample.json`
   - `docs/samples/rapidtriage-files.sample.json`
   - `docs/samples/rapidtriage-extract.sample.json`
   - `docs/samples/rapidtriage-artifacts.sample.json`
   - `docs/samples/rapidtriage-run-summary.sample.json`
4. Add the required CLI examples:
   - `rapidtriage run . --mode fraud --output-dir ./rapidtriage-run-fraud`
   - `rapidtriage artifacts . --kind browser`
5. Add explicit contract maturity bullets:
   - `Implemented:`
   - `Experimental:`
   - `Planned:`
6. Preserve the exact tested phrase about bookmarks from implemented outputs.
7. Add `compare` contract wording and `rapidtriage/schemas/compare.schema.json`.
8. Add `docs/samples/rapidtriage-rules.sample.yaml` to the rule engine link area.

Verification:
- `python3.12 -m unittest tests.test_rapidtriage_documentation_contract tests.test_rapidtriage_rule_engine_docs -v`

Exit:
- Both README contract modules pass.

### 2. Make Windows Manifest Golden Sample Deterministic

Problem:
- `tests/test_rapidtriage_output_samples.py:624` compares generated Windows manifest output to `docs/samples/manifest-windows-artifacts.json`.
- Current generated output has new `windows-execution` `native_depth_profile` fields missing from the golden sample.
- Some `windows-filesystem` `modified_at` values use current mtime from files created during fixture setup.

Files:
- `tests/test_rapidtriage_output_samples.py`
- `docs/samples/manifest-windows-artifacts.json`
- possibly Windows collector modules under `rapidtriage/artifacts/windows/`

Work:
1. Reproduce the diff with the focused test.
2. Decide whether `native_depth_profile` is intended public contract.
3. If intended, update `docs/samples/manifest-windows-artifacts.json`.
4. If not intended, remove or gate it from manifest sample output.
5. Fix fixture setup so all created files have stable mtimes.
6. Confirm canonicalization masks only truly dynamic values, not meaningful evidence.

Verification:
- `python3.12 -m unittest tests.test_rapidtriage_output_samples.RapidTriageOutputSamplesTests.test_manifest_windows_sample_matches_fixture -v`
- Re-run the full output samples module.

Exit:
- Golden sample comparison passes without current-time drift.

### 3. Correct E01 Smoke Stage Semantics

Problem:
- `tests/test_rapidtriage_e01.py:152` expects dummy E01 preflight to be blocked.
- `rapidtriage/core/e01_smoke.py:131` marks `evidence-preflight` complete when `identify_evidence(...).supported` is true.
- This conflates "format recognized" with "extraction dependencies and workflow are ready".

Files:
- `rapidtriage/core/e01_smoke.py`
- `rapidtriage/core/evidence.py`
- `rapidtriage/core/e01.py`
- `tests/test_rapidtriage_e01.py`

Work:
1. Define stage semantics:
   - `recognized`: adapter detected the source type.
   - `preflight-ready`: dependencies and validation prerequisites are ready enough to attempt extraction.
   - `blocked`: source is recognized but required tools/validation are missing.
2. Update E01 smoke stage status to use `preflight_summary.status` or missing-tool information, not only `supported`.
3. Keep dummy E01 smoke report blocked and commercially not ready.
4. Preserve honest blocker details in `stage_status.blocked_stage_ids`.
5. Add or adjust tests for three cases:
   - dummy E01 without tools -> blocked
   - mocked tool-ready E01 -> complete/ready preflight
   - plan-only -> skipped run but complete planning artifacts

Verification:
- `python3.12 -m unittest tests.test_rapidtriage_e01.RapidTriageE01Tests.test_e01_smoke_records_known_answer_preflight_and_blocked_run -v`
- Run the entire E01 module if time permits.

Exit:
- E01 smoke status is deterministic and semantically honest.

### 4. Fix Python Version Selection in macOS and Windows Launchers

Problem:
- `pyproject.toml:10` requires Python `>=3.10`.
- `README.md:71` recommends 3.12 and says 3.9 is unsupported.
- `scripts/windows/start-rapidtriage.ps1:23` and `scripts/windows/smoke-test-rapidtriage.ps1:26` call `py -3`.
- `scripts/start-rapidtriage.sh:49` and `scripts/smoke-test-rapidtriage.sh:74` call first `python3`/`python` and still mention `3.9+`.

Files:
- `scripts/windows/start-rapidtriage.ps1`
- `scripts/windows/smoke-test-rapidtriage.ps1`
- `scripts/start-rapidtriage.sh`
- `scripts/smoke-test-rapidtriage.sh`
- tests covering launcher/static script contracts, likely `tests/test_rapidtriage_ops.py` or new static test module.

Work:
1. Implement interpreter selection order:
   - Windows: `py -3.12`, `py -3.11`, `py -3.10`, then `python` only if version check passes.
   - macOS/Linux: `python3.12`, `python3.11`, `python3.10`, then `python3`/`python` only if version check passes.
2. Add an explicit version probe before creating `.venv`.
3. Change error messages from `3.9+` to `3.10+`, preferably recommending 3.12.
4. Ensure existing `.venv` created by unsupported Python is detected or fails clearly.
5. Add static tests that grep launcher scripts for `3.9+` absence and 3.10+ enforcement.

Verification:
- `python3.12 -m unittest` for the static launcher tests.
- Manual macOS run of `sh scripts/start-rapidtriage.sh --doctor-only` if supported.
- Windows manual verification later.

Exit:
- Fresh machine setup cannot silently create a 3.9 venv.

### 5. Full Local CI Parity Pass on macOS

Purpose: prove the Mac baseline is green before Windows handoff.

Commands:
1. `python3.12 -m unittest discover -s tests`
2. `python3.12 -m compileall -q rapidtriage tests scripts`
3. `node --check rapidtriage/web/static/app_workbench_config.js`
4. `node --check rapidtriage/web/static/app_state.js`
5. `node --check rapidtriage/web/static/app.js`
6. `cargo fmt --all -- --check` in `engines/rust`
7. `cargo check --workspace --all-targets --locked` in `engines/rust`
8. `cargo test --workspace --locked` in `engines/rust`

Exit:
- All commands pass on macOS.
- `git status` shows only intentional changes.

### 6. Windows Revalidation Checklist

Purpose: create the exact Windows work list after Mac fixes.

Windows Commands:
1. `py -3.12 -m venv .venv`
2. `.\\.venv\\Scripts\\Activate.ps1`
3. `python -m pip install -U pip build`
4. `python -m pip install -e ".[web,test,kakaotalk,columnar]"`
5. `python -m unittest discover -s tests`
6. `python -m compileall -q rapidtriage tests scripts`
7. `.\\scripts\\windows\\start-rapidtriage.ps1 -DoctorOnly`
8. `.\\scripts\\windows\\smoke-test-rapidtriage.ps1`
9. If available, run Windows E01 smoke with real/trusted source and external tools.

Windows-specific checks:
- Hangul paths and filenames.
- Long paths over 260 chars if Windows long-path support is enabled.
- PowerShell execution policy guidance.
- NTFS alternate data stream inventory.
- E01 external tool discovery.
- Browser opens local UI without remote auth regression.

Exit:
- Windows produces a pass/fail evidence note with logs and blocker list.

### 7. Commit the Baseline Repair

Purpose: make the restored state easy to revert and review.

Work:
1. Stage only files touched by this repair.
2. Review diff for accidental generated output.
3. Commit with Lore protocol.

Suggested commit intent:
`Restore cross-platform verification baseline`

Required commit body points:
- Constraint: current CI runs unittest, compileall, JS syntax, release evidence, Rust checks.
- Rejected: feature work before green baseline.
- Tested: list exact commands.
- Not-tested: Windows real E01 if not yet available.

Exit:
- Clean git status after commit.

### 8. Wave 3 Refactor Preparation

Canonical sequence reference: Wave 3 - Refactor.

Purpose: reduce risk before adding recovery-engine features after Wave 0, Wave 1, and Wave 2 are complete.

Execution rule:
- Do not execute this immediately after baseline validation.
- Execute only after static cleanup, security review, DB audit, and code review pass according to `Canonical Execution Sequence`.
- This milestone is behavior-preserving refactor only; it must not implement recovery features.

Target modules:
- `rapidtriage/api/app.py`
- `rapidtriage/core/case_db.py`
- `rapidtriage/core/run.py`
- `rapidtriage/cli.py`
- `rapidtriage/web/static/app.js`

Work:
1. Add characterization tests around current behavior before moving code.
2. Split API into routers by domain:
   - health/jobs
   - evidence/preflight
   - case DB/search
   - viewer/source-read
   - export/bundle/report
3. Split Case DB into schema, migrations, ingest, query, review-state, export.
4. Split `app.js` into state, API client, table/viewer renderers, progress panel, extraction panel.
5. Keep public routes and CLI command names stable.

Verification:
- Full unittest after each narrow extraction.
- Browser smoke for UI after JS split.

Exit:
- No user-visible behavior changes, but modules are small enough for future recovery-engine work.

### 9. Recovery Design Candidate - Recovery Engine Design Gate

Canonical sequence reference: Recovery Design Candidates, then Wave 4 after governance approval.

Purpose: define recovery design only; file-level recovery implementation starts only after PRD approval, test specification approval, and recovery architecture review.

Execution rule:
- Before Wave 4, this section authorizes design, test planning, and architecture review only.
- It does not authorize implementation of recovery, indexing, viewer, carving, checkpoint/resume, or performance-worker behavior.

Work:
1. Define recovery source types:
   - existing files
   - deleted filesystem entries
   - file carving by signature
   - E01/Ex01 via external tools
   - raw/split/virtual disk via adapters
2. Define checkpoint model:
   - source hash
   - image segment inventory
   - stage id
   - cursor/offset
   - output manifest hash
   - retry count
3. Define extraction model:
   - original preserved
   - recovered copy
   - metadata sidecar
   - confidence and limitation text
   - source offset/path when known
4. Define viewer model:
   - by file type
   - by extension
   - by source app/path
   - by recovery confidence
   - by review status
5. Define progress model:
   - total bytes/files when known
   - current stage
   - rate
   - ETA when meaningful
   - resumable checkpoint path

Verification:
- Write PRD and test spec before implementation.
- Add synthetic tiny images/fixtures before real large-case work.

Exit:
- Recovery implementation begins from a written contract, not ad hoc carving.

### 10. Recovery Design Candidate - Large-Case Stability and Performance Gate

Purpose: support million-file and 10TB-class workflows without dying mid-run.

Work:
1. Add resumable stage checkpoints to every long-running stage.
2. Use streaming manifests instead of loading full JSON in memory where possible.
3. Add pagination/cursors for Case DB and viewer APIs.
4. Add memory caps and disk-space preflight.
5. Add cancellation-safe writes using temp files and atomic rename.
6. Add benchmark profiles:
   - 10k files
   - 100k synthetic entries
   - 1M metadata rows
   - large sparse file smoke

Verification:
- Benchmark command writes machine-readable metrics.
- Resume test interrupts and restarts from checkpoint.
- Viewer test loads large result sets through paging.

Exit:
- Progress, resume, and memory behavior are measurable.

### 11. Recovery Design Candidate - UX and Viewer Hardening Gate

Purpose: make results easy to review and export.

Work:
1. Add result grouping:
   - documents
   - images/media
   - archives
   - browser/AI
   - Windows artifacts
   - recovered/deleted/carved
2. Add fast filters:
   - extension
   - app path
   - common user folders
   - review status
   - confidence
3. Add bulk export:
   - selected results
   - current filtered view
   - all reviewed relevant
4. Preserve Hangul and multilingual filenames in UI/export manifests.
5. Add progress panel for active recovery/indexing/carving jobs.

Verification:
- Browser UI smoke with Korean filenames.
- Export manifest round-trip test.
- JS syntax and web static tests.

Exit:
- Analyst can find, review, and extract important results without reading raw JSON.

### 12. Recovery Design Candidate - Evidence Intake and Acquisition UX

Purpose: make the first screen guide analysts into the correct workflow without hiding limitations.

Features:
1. Source intake wizard for folder, mounted image, E01/Ex01, RAW/split, VHD/VHDX/VMDK/VDI/QCOW, DMG/ISO/WIM, ZIP/TAR, DB, and existing run output.
2. Read-only safety preflight with source hash, size, filesystem hints, segment inventory, dependency status, and disk-space estimate.
3. "Fast first pass" option for huge sources: metadata/hash/category only before deep content extraction.
4. Case profile presets:
   - fraud
   - hacking
   - insider
   - malware/IR
   - document review
   - deleted-file recovery
5. Korean/English UI labels from the start, with locale fallback.

Files likely involved:
- `rapidtriage/api/app.py`
- `rapidtriage/core/evidence.py`
- `rapidtriage/core/run.py`
- `rapidtriage/web/static/app.js`
- `rapidtriage/web/static/index.html`
- `rapidtriage/web/static/styles.css`

Verification:
- API tests for each input kind.
- Browser smoke for the intake wizard.
- Korean path fixture such as `증거/사건자료/문서.txt`.

Exit:
- Analyst can choose a source and immediately see whether the tool can safely proceed.

### 13. Recovery Design Candidate - File-Level Recovery Engine

Purpose: recover files from supported sources while preserving provenance and limitations.

Features:
1. Recovery job model:
   - source id
   - stage id
   - checkpoint id
   - source hash
   - byte offset or filesystem record id
   - output manifest path
   - confidence
   - limitation text
2. Recovery modes:
   - existing allocated file extraction
   - deleted-entry recovery
   - orphan record recovery
   - signature carving
   - slack/unallocated candidate extraction
3. Output structure:
   - recovered file
   - metadata sidecar JSON
   - source citation
   - hash manifest
   - validation warnings
4. Safe extraction defaults:
   - never modify evidence
   - write to case output only
   - atomic temp file then rename
   - path traversal defense
   - duplicate-name collision handling

Candidate implementation lanes:
- Python orchestration for correctness and UI integration.
- Rust worker for hot-path scanning and carving.
- External-tool adapter for libewf/Sleuth Kit outputs where available.

Verification:
- Tiny synthetic fixture with known deleted/recovered candidates.
- Resume test that interrupts after one recovered file.
- Hash and citation round-trip test.

Exit:
- Recovery output is reviewable, reproducible, and not just dumped files.

### 14. Recovery Design Candidate - Deleted File and Metadata Reconstruction

Purpose: recover not only bytes, but enough metadata to decide whether the result is useful.

Features:
1. NTFS-focused first path:
   - `$MFT` record parsing
   - filename attributes
   - timestamps
   - parent reference
   - resident/non-resident data distinction
   - deleted flag
   - runlist confidence
2. FAT/exFAT path:
   - directory entry recovery
   - cluster chain confidence
   - deleted first-character handling
3. APFS/HFS+ path as staged future work:
   - snapshot awareness
   - catalog metadata
   - xattr/resource fork handling
4. Metadata confidence scoring:
   - high: complete record and content hash
   - medium: metadata complete but content partial
   - low: carved or orphan candidate

Verification:
- Known-answer fixtures per filesystem.
- Compare generated metadata to trusted parser exports when available.

Exit:
- Viewer can distinguish "real deleted file candidate" from "raw carved blob".

### 15. Recovery Design Candidate - Signature Carving Engine

Purpose: recover content when filesystem metadata is missing or damaged.

Features:
1. Carving profiles:
   - documents: PDF, DOCX/XLSX/PPTX, HWPX, TXT/log/config
   - images: JPG, PNG, GIF, HEIC where feasible
   - archives: ZIP, 7z, RAR inventory where feasible
   - databases: SQLite headers and WAL/SHM adjacency
   - browser/AI traces: SQLite, LevelDB/log fragments
2. Boundary detection:
   - header/footer
   - length fields
   - container validation
   - entropy/false-positive filters
3. Chunked scanning:
   - fixed-size block reads
   - overlap windows
   - checkpoint by byte offset
   - memory cap
4. Carved result classification:
   - complete
   - partial
   - corrupt but inspectable
   - false-positive rejected

Verification:
- Synthetic unallocated byte stream with embedded known files.
- Corrupt/footer-missing fixtures.
- False-positive control corpus.

Exit:
- Carving can be enabled selectively and does not flood the UI with junk.

### 16. Recovery Design Candidate - Indexing and Search Engine Upgrade

Purpose: let the analyst output only the wanted results instead of waiting for everything.

Features:
1. Unified index over:
   - filenames
   - paths
   - hashes
   - extracted text
   - artifact details
   - timestamps
   - recovery confidence
   - review state
2. Query filters:
   - extension
   - path prefix
   - app location
   - date range
   - size range
   - file category
   - recovered/deleted/carved/existing
   - language/encoding
3. Saved quick-review lanes:
   - Desktop/Downloads/Documents
   - browser profiles
   - KakaoTalk/messenger locations
   - email containers
   - cloud sync folders
   - executable/script locations
4. Incremental indexing:
   - new stage writes are indexed as they appear
   - UI can review partial results while scan continues.

Verification:
- Case DB query tests.
- Million-row synthetic index benchmark.
- UI filter smoke.

Exit:
- Analyst can search early and export a filtered subset without waiting for deep recovery completion.

### 17. Recovery Design Candidate - Progress, Resume, Cancel, and Crash Recovery

Purpose: survive 10TB sources, million-file jobs, and accidental interruption.

Features:
1. Job control:
   - start
   - pause
   - cancel
   - resume
   - retry failed stage
2. Progress model:
   - current stage
   - current path or offset
   - files seen
   - bytes read
   - bytes written
   - recovered candidates
   - rate
   - ETA only when meaningful
3. Checkpoints:
   - per-stage checkpoint file
   - Case DB job table
   - worker checkpoint for Rust scanner
   - output manifest checkpoint
4. Crash recovery:
   - detect incomplete temp outputs
   - verify completed output hashes
   - resume from last safe checkpoint
   - mark suspect partials for review

Verification:
- Kill-and-resume integration test.
- Partial temp-file cleanup test.
- Progress API monotonicity test.

Exit:
- Long jobs can be stopped and continued without starting over.

### 18. Recovery Design Candidate - Viewer System Expansion

Purpose: make recovered and existing evidence easy to inspect by type.

Features:
1. Viewer panes:
   - table/list viewer
   - text viewer
   - hex/source viewer
   - image viewer
   - document preview
   - SQLite/table viewer
   - browser history viewer
   - timeline viewer
   - recovery candidate viewer
2. Grouping:
   - existing files
   - deleted files
   - carved files
   - artifacts
   - documents
   - browser/AI
   - media
   - archives
3. Review controls:
   - relevant
   - needs-review
   - excluded
   - include-in-report
   - export selected
4. Evidence detail panel:
   - source path
   - recovered path
   - hash
   - offset/record id
   - parser
   - confidence
   - limitation
   - related artifacts

Verification:
- Browser smoke with sample case.
- Korean filename visual check.
- Large table virtualization test.

Exit:
- The UI feels like a forensic review workstation, not a raw JSON browser.

### 19. Recovery Design Candidate - Extraction and Export Workbench

Purpose: make both recovered and existing-file extraction easy and auditable.

Features:
1. Export modes:
   - selected rows
   - current filtered results
   - reviewed relevant items
   - source folder subset
   - recovered-only
   - existing-only
2. Export package:
   - files
   - manifest
   - hashes
   - review states
   - citations
   - limitations
   - optional HTML/CSV summary
3. Collision handling:
   - preserve original relative path when safe
   - sanitize unsafe names
   - add stable suffix for duplicates
4. Chain-of-custody support:
   - export generated time
   - tool version
   - case id
   - source hash
   - operator note field

Verification:
- Export manifest round-trip test.
- Path traversal fixture.
- Duplicate filename fixture.

Exit:
- Analyst can hand off selected evidence without manual file hunting.

### 20. Recovery Design Candidate - Hangul, Unicode, and Multi-Language Safety

Purpose: prevent broken Korean filenames/content and prepare for multi-language UI.

Features:
1. Filename normalization:
   - NFC/NFD awareness on macOS
   - Windows path encoding
   - ZIP filename encoding handling
2. Text extraction encoding detection:
   - UTF-8
   - UTF-16LE/BE
   - CP949/EUC-KR
   - Shift-JIS/GBK as future profiles
3. UI i18n:
   - Korean
   - English
   - language toggle
   - fallback keys visible in dev mode only
4. Export safety:
   - manifest stores original name
   - export path stores safe normalized name
   - hash links original to exported copy

Verification:
- Korean filename fixtures.
- Korean document text search fixture.
- macOS NFD path fixture.
- Windows CP949 path/content test during Windows validation.

Exit:
- Korean does not break in scan, search, viewer, or export.

### 21. Recovery Design Candidate - Performance Worker Strategy

Purpose: keep Python orchestration while moving hot paths to faster workers.

Features:
1. Rust worker lanes:
   - streaming file inventory
   - hash calculation
   - byte scanning/carving
   - EVTX/structured binary parsing
2. Python lanes:
   - job orchestration
   - API/UI integration
   - plugin adapters
   - report/export composition
3. Data exchange:
   - NDJSON streaming
   - stable schema per worker command
   - backpressure and cancellation
4. Benchmark metrics:
   - files/sec
   - MB/sec
   - memory peak
   - checkpoint interval
   - UI update latency

Verification:
- Rust worker unit tests.
- Python worker smoke.
- Benchmark regression threshold.

Exit:
- Speed improvements are measurable, not just perceived.

### 22. Recovery Design Candidate - Recovery Accuracy and Validation Matrix

Purpose: measure recovery quality against known-answer corpora and trusted tools.

Features:
1. Known-answer fixture matrix:
   - allocated files
   - deleted files
   - carved files
   - corrupted files
   - multilingual paths
2. Metrics:
   - recovered count
   - true positive
   - false positive
   - false negative
   - byte-identical hash match
   - metadata match
   - partial recovery ratio
3. Trusted-tool comparison:
   - Sleuth Kit
   - libewf/ewfmount workflow
   - X-Ways/EnCase exported report comparison when user supplies outputs
4. Report:
   - per-source score
   - blocker list
   - unsupported cases
   - do-not-claim wording

Verification:
- `rapidtriage recovery-benchmark` command.
- Fixture expected JSON.
- Diff report tests.

Exit:
- "Recovery rate" becomes a measured result per corpus, not a marketing claim.

### 23. Recovery Design Candidate - Plugin and External Tool Adapter Layer

Purpose: use best available external engines without locking the product to one tool.

Features:
1. Adapter contracts:
   - tool discovery
   - version capture
   - command transcript
   - output parser
   - limitation mapping
2. Initial adapters:
   - Sleuth Kit
   - libewf/ewfmount
   - qemu-img
   - 7-Zip
   - optional user-provided commercial export importers
3. Safety:
   - read-only commands by default
   - no destructive mount
   - command preview
   - transcript saved in case evidence

Verification:
- Adapter discovery tests with mocked tools.
- Transcript schema tests.
- Missing-tool blocker tests.

Exit:
- The product can improve recovery by integrating proven engines while keeping its own review/index/export layer.

### 24. Recovery Design Candidate - Packaging, Installer, and Desktop App Path

Purpose: make Windows and macOS use practical for non-developer operation.

Features:
1. Windows:
   - PowerShell launcher hardening
   - optional packaged executable
   - signed installer backlog
   - Start Menu shortcut backlog
2. macOS:
   - app launcher or `.command`
   - codesign/notarization backlog
   - quarantine guidance
3. Local web UI:
   - auto-open browser
   - port conflict handling
   - crash log location
4. Offline mode:
   - local-only operation
   - no external network requirement
   - dependency bundle investigation

Verification:
- Clean Windows smoke.
- Clean macOS smoke.
- Install/uninstall checklist.

Exit:
- Analysts do not need to understand Python internals to start the tool.

### 25. Recovery Design Candidate - Community Feedback and Failure Registry

Purpose: track the problems other forensic users actually hit.

Features:
1. Failure registry:
   - source type
   - filesystem
   - symptom
   - root cause
   - workaround
   - fixed version
2. Community review package:
   - sanitized sample outputs
   - limitation list
   - benchmark method
   - request-for-feedback checklist
3. Regression labels:
   - Windows-only
   - macOS-only
   - E01 dependency
   - Unicode
   - huge-case
   - viewer
   - export

Verification:
- `docs/rapidtriage-known-limitations.md` updated from real failures.
- Each serious failure gets a fixture or explicit test gap.

Exit:
- Repeated pain points become tracked engineering work, not memory.

### 26. Feature Prioritization Order

Canonical sequence reference: `Canonical Execution Sequence`.

Purpose: prevent feature sprawl by routing every feature through the authoritative wave model.

Order:
1. Wave 0 - Baseline Validation.
2. Wave 1 - Static Cleanup.
3. Wave 2 - Security and Audit.
4. Wave 3 - Refactor.
5. Wave 4 - Recovery MVP.
6. Wave 5 - Validation.
7. Wave 6 - Release Readiness.

Rule:
- Do not start a later wave if an earlier wave is red, unless the later-wave item is explicitly required to unblock the earlier wave and is recorded as an exception.
- Recovery, indexing, viewer, and performance implementation remain in `Recovery Backlog` until Wave 4 entry criteria are satisfied.
- Validation and release claims must use the `Quantitative Validation Matrix` and `Updated Release Scorecard`.

### 27. Recovery Design Candidate - Filesystem and Disk Image Coverage Matrix

Purpose: avoid claiming broad image support when only a few paths are actually validated.

Features:
1. Coverage matrix by source container:
   - E01/Ex01/EWF
   - RAW/dd
   - split RAW
   - VHD/VHDX
   - VMDK
   - VDI
   - QCOW/QCOW2
   - DMG/UDIF
   - sparse image/sparsebundle
   - ISO/UDF
   - WIM/SWM
   - AFF/AFF4 as research/backlog
2. Coverage matrix by filesystem:
   - NTFS
   - FAT/exFAT
   - APFS
   - HFS+
   - EXT2/3/4
   - UFS
   - ISO9660/UDF
3. Per-format support states:
   - detected
   - mounted externally
   - parsed natively
   - extracted safely
   - deleted recovery supported
   - carving supported
   - trusted-tool validated

Verification:
- One tiny fixture or documented blocker per matrix row.
- UI must show support state before a run starts.

Exit:
- The user sees exactly what is supported, blocked, or experimental.

### 28. Recovery Design Candidate - Hash Intelligence, Dedup, and Known-Good Filtering

Purpose: reduce review volume and identify known files quickly.

Features:
1. Hash sets:
   - MD5/SHA1/SHA256 import
   - NSRL-style known-good
   - custom known-bad
   - case-local hash set
2. Dedup:
   - exact hash dedup
   - same-name different-hash warnings
   - same-hash different-path grouping
3. Fuzzy/similarity hashing backlog:
   - ssdeep/TLSH-style matching
   - perceptual image hash
   - near-duplicate document clustering
4. Performance:
   - streaming hash worker
   - hash cache keyed by source id, size, mtime, and source offset

Verification:
- Hash-set import tests.
- Dedup grouping tests.
- Large synthetic hash benchmark.

Exit:
- Known-good files can be suppressed and suspicious known-bad hits can be prioritized.

### 29. Recovery Design Candidate - Super Timeline and Event Correlation Workbench

Purpose: make the tool explain what happened, not just list files.

Features:
1. Timeline event model:
   - timestamp
   - timezone/source timezone
   - parser/source
   - event type
   - actor/account
   - object/path/url
   - confidence
   - citation
2. Sources:
   - filesystem MACB
   - browser history/downloads
   - Windows Event Logs
   - registry user activity
   - LNK/JumpList/ShellBags
   - Prefetch/Amcache/ShimCache
   - messenger/email/cloud exports
   - recovery events
3. Correlation:
   - same user/path/url grouping
   - clock skew warning
   - time bucket view
   - narrative builder
4. Export:
   - CSV
   - JSONL
   - HTML timeline
   - report-ready selected events

Verification:
- Known timeline fixture.
- Timezone and clock-skew tests.
- UI timeline smoke.

Exit:
- Analyst can reconstruct event sequence across files, artifacts, and recovered data.

### 30. Recovery Design Candidate - Windows Deep Artifact Parser Expansion

Purpose: match real Windows forensic expectations beyond basic file inventory.

Features:
1. Core Windows artifacts:
   - EVTX BinXML deep parsing
   - Registry hives and transaction logs
   - `$MFT`
   - `$UsnJrnl`
   - SRUM
   - Windows.edb
   - Prefetch
   - LNK
   - JumpList
   - ShellBags
   - Amcache
   - ShimCache/AppCompatCache
   - BAM/DAM
   - Scheduled Tasks
   - WMI persistence
   - Defender/Firewall/WER
2. Deleted/recovered metadata:
   - MFT orphan files
   - registry deleted cells
   - USN path reconstruction
3. Validation:
   - parser output profile
   - trusted-tool diff adapter
   - per-artifact limitation text

Verification:
- Fixture per artifact family.
- Known-answer diff where available.

Exit:
- Windows review is artifact-rich enough to compete with serious triage workflows.

### 31. Recovery Design Candidate - Browser, AI, Cloud, and Messenger Recovery

Purpose: target user-relevant evidence, not only OS-level traces.

Features:
1. Browser:
   - Chrome/Edge/Firefox/Safari history
   - downloads
   - cookies inventory with secret redaction
   - cache inventory
   - LocalStorage/SessionStorage
   - IndexedDB/LevelDB
   - extensions
   - deleted SQLite/WAL candidates
2. AI service traces:
   - ChatGPT
   - Claude
   - Gemini
   - Copilot
   - Perplexity
   - local LLM app traces
3. Messenger:
   - KakaoTalk Windows/macOS
   - Telegram Desktop
   - Signal Desktop
   - Discord
   - LINE
   - WhatsApp Desktop/export
4. Cloud/sync:
   - Google Takeout
   - iCloud exports
   - OneDrive/Dropbox/Google Drive local metadata
   - Teams/Slack exports where authorized

Verification:
- Authorized sample exports only.
- Secret redaction tests.
- Browser SQLite/WAL merge tests.

Exit:
- User activity evidence can be reviewed by app/service, not just by raw file path.

### 32. Recovery Design Candidate - Email, Archive, and Nested Container Processing

Purpose: handle common evidence containers without manual unpacking chaos.

Features:
1. Email:
   - EML
   - MBOX
   - MSG
   - PST/OST inventory and adapter workflow
   - attachments
   - header/authentication fields
2. Archives:
   - ZIP
   - TAR/GZ
   - 7z
   - RAR inventory/adapters
   - nested archives
   - password-protected archive detection
3. Safety:
   - extraction depth limit
   - decompression bomb limits
   - filename encoding handling
   - path traversal defense
4. Indexing:
   - container path notation
   - attachment hash
   - parent-child relationships

Verification:
- Nested archive fixture.
- Decompression bomb guard test.
- Email attachment round-trip test.

Exit:
- Containers become searchable evidence trees with safe extraction.

### 33. Recovery Design Candidate - Media, OCR, EXIF, and Geolocation Workbench

Purpose: make image/video/audio evidence useful for review.

Features:
1. Metadata:
   - EXIF
   - GPS
   - camera/device
   - created/modified timestamps
   - thumbnail extraction
2. OCR:
   - image OCR queue
   - PDF OCR backlog
   - Korean OCR profile
   - OCR confidence
3. Media:
   - video metadata
   - keyframe thumbnail generation
   - audio metadata
   - transcription backlog
4. Map view backlog:
   - GPS point clustering
   - timeline plus map
   - redaction before export

Verification:
- EXIF fixture.
- OCR text search fixture.
- Media thumbnail smoke.

Exit:
- Media evidence is searchable, previewable, and reportable.

### 34. Recovery Design Candidate - Memory and Incident Response Module

Purpose: cover cases where disk evidence is not enough.

Features:
1. Memory image intake:
   - raw memory dump
   - crash dump
   - hiberfil/pagefile inventory
2. Volatility-compatible adapter:
   - process list
   - network connections
   - DLL/module list
   - command line
   - handles
   - malfind-style suspicious memory
   - dumpfiles workflow
3. Memory carving:
   - strings
   - URLs/domains/IPs
   - credentials redacted by default
4. Correlation:
   - process to file path
   - process to network
   - memory hit to timeline

Verification:
- Small memory fixture or mocked Volatility output.
- Adapter transcript test.
- Redaction test.

Exit:
- The product can triage memory evidence without pretending to be a full memory suite.

### 35. Recovery Design Candidate - Detection Rules, IOC, and Threat Intelligence

Purpose: support threat hunting and incident response workflows.

Features:
1. YARA-style file scanning:
   - rule import
   - namespace/tag display
   - match offsets
   - timeout/memory cap
2. Sigma-style log detection:
   - Sigma YAML import
   - normalized event matching
   - unsupported logsource warning
3. IOC matching:
   - hash
   - domain
   - URL
   - IP
   - email
   - file path
   - registry path
4. Rule management:
   - enabled/disabled
   - severity
   - source
   - version
   - false-positive notes

Verification:
- YARA test rule fixture.
- Sigma log fixture.
- IOC match and false-positive suppression tests.

Exit:
- Detection output is explainable and tied to source evidence.

### 36. Recovery Design Candidate - Case Management, Chain of Custody, and Audit Log

Purpose: make the workflow defensible.

Features:
1. Case model:
   - case id
   - evidence items
   - operators
   - notes
   - tags
   - review states
2. Chain of custody:
   - source hash
   - acquisition note
   - tool version
   - stage transcript
   - immutable event log
3. Evidence sealing:
   - manifest hash
   - package hash
   - signed summary backlog
4. Audit:
   - who reviewed
   - status changes
   - exports
   - deleted/hidden redaction actions

Verification:
- Audit event append-only test.
- Case export/import test.
- Review state history test.

Exit:
- A case can be reopened and defended without relying on memory.

### 37. Recovery Design Candidate - Reporting, Redaction, and Report-Defensible Output

Purpose: turn reviewed evidence into useful deliverables.

Features:
1. Reports:
   - HTML
   - PDF backlog
   - DOCX backlog
   - CSV/JSON evidence tables
2. Report builder:
   - selected evidence
   - timeline snippets
   - screenshots/previews
   - citations
   - limitations
   - reviewer notes
3. Redaction:
   - manual redaction notes
   - secret masking
   - PII masking profiles
   - export-safe filenames
4. Review workflow:
   - draft
   - reviewed
   - approved
   - exported

Verification:
- Report snapshot test.
- Citation completeness test.
- Redaction fixture.

Exit:
- Results can leave the tool in a controlled, reviewable package.

### 38. Wave 2 Security Review Candidate - Parser Sandbox and Evidence Safety

Purpose: protect the analyst machine from malicious evidence.

Features:
1. Parser isolation:
   - subprocess boundaries
   - timeout
   - memory cap
   - crash capture
2. File preview safety:
   - no active content execution
   - HTML/script sanitization
   - Office macro warning
   - archive bomb detection
3. Secret handling:
   - opt-in reveal
   - redaction by default
   - audit log for reveal/export
4. Quarantine:
   - suspicious executable preview disabled by default
   - hash-only display unless explicitly extracted

Verification:
- Malicious HTML fixture.
- Parser timeout test.
- Secret reveal audit test.

Exit:
- Opening a case does not accidentally execute or leak evidence.

### 39. Recovery Design Candidate - Collaboration and Analyst Workflow

Purpose: support real review sessions, even if local-first.

Features:
1. Tags and labels.
2. Comments per evidence item.
3. Review assignments backlog.
4. Saved searches.
5. Bookmarks.
6. Triage queues:
   - urgent
   - high-confidence
   - needs-human
   - export-ready
7. Keyboard shortcuts and bulk actions.

Verification:
- Case DB tests for tags/comments/bookmarks.
- UI smoke for saved searches.

Exit:
- Analysts can work through large result sets systematically.

### 40. Recovery Design Candidate - Plugin SDK and Artifact Exchange Path

Purpose: let new parsers and workflows be added without growing the monolith forever.

Features:
1. Plugin contract:
   - input source declaration
   - output schema
   - parser version
   - limitation declaration
   - test fixture requirement
2. Plugin types:
   - artifact parser
   - file carver
   - external tool adapter
   - report exporter
   - viewer panel
3. Safety:
   - plugin permission manifest
   - sandbox option
   - deterministic tests required
4. Community exchange backlog:
   - import local plugin
   - validate plugin
   - disable plugin
   - plugin provenance display

Verification:
- Example plugin.
- Plugin schema validation.
- Plugin failure isolation test.

Exit:
- New forensic targets do not require editing one giant core file.

### 41. Recovery Design Candidate - Remote and Live Endpoint Collection Backlog

Purpose: support future IR workflows without compromising local-first evidence handling.

Features:
1. Live local collection:
   - running processes
   - network connections
   - autoruns
   - event logs
   - browser profiles
2. Remote collection backlog:
   - agentless collection research
   - endpoint artifact package import
   - Velociraptor/DFIR-ORC/KAPE output import adapters
3. Hunt-style backlog:
   - run same artifact query across multiple imported endpoint packages
   - compare hosts
   - collect failures and retry list
4. Guardrails:
   - explicit live mode
   - no stealth behavior
   - audit transcript
   - legal authority warning

Verification:
- Imported endpoint package fixture.
- Live local dry-run test.
- Multi-host comparison sample.

Exit:
- RapidForensic can grow toward IR collection while preserving forensic transparency.

### 42. Wave 5 Validation Candidate - Validation Corpus and Benchmark Lab

Purpose: prove recovery rate and performance with repeatable data.

Features:
1. Synthetic corpus generator:
   - allocated files
   - deleted files
   - fragmented files
   - nested archives
   - Korean filenames
   - corrupted headers/footers
2. Known-answer registry:
   - expected recovered files
   - expected missing files
   - expected false-positive controls
   - expected metadata
3. Benchmark profiles:
   - small developer corpus
   - CI corpus
   - 100GB local stress
   - 1TB/10TB external stress backlog
4. Score outputs:
   - recovery precision
   - recovery recall
   - hash match rate
   - metadata match rate
   - runtime
   - memory peak

Verification:
- `rapidtriage recovery-benchmark --profile ci`
- JSON score schema.
- Historical benchmark comparison.

Exit:
- Recovery quality can be discussed with numbers and evidence.

### 43. Dead-Code Deletion and Static Hygiene Gate

Canonical sequence reference: Wave 1 - Static Cleanup.

Purpose: remove unused code safely while preserving forensic behavior and evidence contracts.

Initial static analysis evidence:
- `ruff` was not installed in the project environment, so it was installed temporarily under `/tmp/rapid-static-tools` for read-only inspection.
- Command used: `PYTHONPATH=/tmp/rapid-static-tools python3.12 -m ruff check rapidtriage tests scripts --output-format=concise`
- Result: 67 Ruff findings.
- Main categories:
  - `F401` unused imports.
  - `F841` assigned but unused local variables.
  - `F811` duplicate/redefined function in `rapidtriage/core/kakaotalk.py:5528`.
  - `F541` f-string without placeholders.
  - `F402` import shadowed by loop variable in `rapidtriage/core/e01.py:2683`.
  - `E402` module-level imports not at top, mostly tests/scripts with path bootstrapping.
- `vulture` was also installed temporarily under `/tmp/rapid-static-tools`.
- Command used: `PYTHONPATH=/tmp/rapid-static-tools python3.12 -m vulture rapidtriage tests scripts --min-confidence 80`
- Result: 4 high-confidence unused-variable findings:
  - `rapidtriage/artifacts/media.py:182`
  - `rapidtriage/core/artifact_store.py:83`
  - `tests/test_rapidtriage_cloud_collect.py:755`
  - `tests/test_rapidtriage_media_image.py:40`

Work:
1. Split findings into four buckets:
   - Safe automatic cleanup: unused imports, placeholder-free f-strings.
   - Manual cleanup: unused locals that might represent unfinished manifest/profile output.
   - Bug-risk cleanup: duplicate function, import shadowing, silently ignored variables.
   - Intentional exceptions: test/script `E402` path setup that should be configured, not churned.
2. Do not delete variables like `apk_profile`, `mailbox_manifest`, `message_profile`, or validation-plan locals until confirming whether they were meant to be emitted in output payloads.
3. Fix `F811` duplicate function only after reading both definitions and adding or running KakaoTalk focused tests.
4. Fix `F402` by renaming the loop variable or import target without changing dataclass behavior.
5. Add a small Ruff configuration with selected rules and per-file ignores for intentional test bootstrapping.
6. Keep Vulture advisory at first; do not gate CI on Vulture until a whitelist exists.

Verification:
- `python3.12 -m compileall -q rapidtriage tests scripts`
- Focused tests for each touched module.
- `python3.12 -m unittest discover -s tests` after the cleanup batch.
- Ruff selected rules pass or only approved ignores remain.

Exit:
- Dead code is removed in small commits with no behavior drift.

### 44. Wave 2 Post-Audit Code Review Gate

Canonical sequence reference: Wave 2 - Security and Audit, after security review and DB audit.

Purpose: run a formal review after static cleanup, security review, and DB audit, before refactor or feature work.

Execution rule:
- The security review lane in this section executes before DB audit completion only when it is explicitly scoped as security review.
- General code review starts after security review and DB audit are complete.
- Review findings must reference `Canonical Execution Sequence` and the committed plan revision.

Review lanes:
1. Correctness review:
   - E01 smoke state semantics.
   - Windows manifest deterministic sample.
   - Recovery/citation output contracts.
2. Platform review:
   - Windows launcher and PowerShell behavior.
   - macOS/Linux launcher behavior.
   - Korean/Unicode path handling.
3. Database review:
   - Case DB schema usage.
   - migrations/backward compatibility.
   - index coverage for common queries.
4. Security/safety review:
   - path traversal.
   - parser sandboxing.
   - secret redaction.
   - remote web auth.
5. Performance review:
   - huge result pagination.
   - FTS/index query plans.
   - checkpoint/resume hot paths.

Work:
1. Review findings first, ordered by severity, with file/line references.
2. For every finding, record:
   - impact
   - affected files
   - proposed fix
   - test evidence required
   - whether it blocks feature work
3. Convert accepted review findings into numbered plan updates.
4. Do not mix review-only findings with implementation commits.

Verification:
- Review report exists.
- Every accepted finding has a linked fix step or explicit rejection rationale.

Exit:
- Cleanup and schema work proceeds from reviewed findings, not guesses.

### 45. Case DB Unused Table, Column, and Index Maintenance Gate

Canonical sequence reference: Wave 2 - Security and Audit, DB audit phase.

Purpose: remove or deprecate unused schema safely and improve query performance without breaking existing cases.

Current schema anchor:
- `rapidtriage/core/case_db.py:13911` starts the Case DB schema.
- Existing tables include `schema_info`, `case_record`, `citation_sequence`, `evidence_source`, `file_record`, `hash_record`, `acquisition_metadata`, `artifact`, `event`, `indexed_document`, `review_mark`, `review_mark_history`, `saved_search`, `audit_event`, `report_item`, `job`, and `job_step`.
- Existing FTS tables include `file_record_fts`, `artifact_fts`, `event_fts`, and `indexed_document_fts`.
- Existing indexes are declared around `rapidtriage/core/case_db.py:14300`.

Work:
1. Build a schema inventory:
   - table names
   - columns
   - indexes
   - FTS tables
   - triggers if any
   - migration/schema version
2. Build a usage inventory:
   - `rg` references by table and column name.
   - SQL statement extraction from Case DB code.
   - API and CLI call paths using each table.
   - test coverage touching each table.
3. Classify tables/columns:
   - actively used
   - write-only
   - read-only legacy
   - migration-only
   - unused but reserved for planned feature
   - safe candidate for deprecation
4. Do not drop immediately on first pass.
   - First mark deprecated in schema notes.
   - Add export/import compatibility tests.
   - Add migration from previous schema to new schema.
5. Index review:
   - collect common queries for search, review board, timeline, report export, jobs, and saved searches.
   - run `EXPLAIN QUERY PLAN` on representative databases.
   - add missing composite indexes only when a query plan proves it.
   - remove redundant indexes only after checking write overhead and query coverage.
6. FTS maintenance:
   - verify insert/update/delete synchronization.
   - plan `rebuild`, `optimize`, `integrity-check`, and `VACUUM/ANALYZE` maintenance commands.
7. Add a `case-db doctor` or `case-db maintenance` command backlog:
   - schema check
   - index check
   - FTS rebuild
   - orphan row check
   - database backup before migration
8. Apply `Database Migration Contract` to every schema change:
   - `schema_info.schema_version` must move from `N` to `N+1`.
   - migration owner, verifier, backup path, rollback strategy, and fixture DB paths must be recorded.
   - old fixture DB migration tests must pass before merging.
9. Treat every proposed table, column, trigger, FTS object, or index removal as an unused candidate until evidence proves safe deletion.
10. Do not drop schema objects based only on text search. Require usage inventory, query-plan evidence, fixture migration tests, export/import compatibility tests, and code review approval.

Verification:
- New schema inventory test.
- Migration test from old fixture DB.
- Query plan test for key search/review/report paths.
- Full Case DB module tests.
- `PRAGMA integrity_check` after migration.
- FTS rebuild/integrity verification when FTS tables are affected.

Exit:
- Unused schema is removed only through a reversible migration path, and indexes are updated with query-plan evidence.

### 46. Static Analysis Toolchain Integration Gate

Canonical sequence reference: Wave 1 - Static Cleanup.

Purpose: make static checks repeatable instead of ad hoc `/tmp` runs.

Work:
1. Add dev/static tooling without bloating runtime dependencies:
   - optional `dev` extra or documented temp install command.
   - Ruff as first mandatory tool.
   - Vulture as advisory until whitelist is mature.
   - MyPy/Pyright as later staged work due current large dynamic code surface.
   - Bandit/security scanner only after exclusions are explicit for forensic file handling.
2. Add `pyproject.toml` Ruff config:
   - select `F`, key `E`, and targeted bug-prone rules first.
   - ignore `E402` in tests/scripts where path bootstrapping is intentional.
   - expand rule set only after baseline passes.
3. Add CI step after tests or before tests:
   - start non-blocking locally in plan.
   - make blocking once current findings are fixed or ignored intentionally.
4. Store static-analysis evidence:
   - command
   - tool version
   - result count
   - accepted ignores
   - remaining findings
   - plan revision and commit hash
   - evidence path such as `docs/validation/static-analysis-YYYY-MM-DD.md`
5. Create a static cleanup checklist:
   - no unused imports in product code.
   - no duplicate function definitions.
   - no unused manifest/profile locals unless explicitly named `_`.
   - no placeholder-free f-strings.

Verification:
- `python3.12 -m ruff check rapidtriage tests scripts`
- `python3.12 -m vulture rapidtriage tests scripts --min-confidence 80` advisory run.
- CI/static check documentation updated.

Exit:
- Future dead-code and lint regressions are caught before they become thousand-line cleanup work.

### 47. Recovery Backlog - Post-Baseline Recovery PRD and Test Spec

Canonical sequence reference: Wave 4 entry governance.

Purpose: after the repository is green, define the recovery product contract before writing recovery code.

Inputs:
- Current baseline repair results.
- Existing E01/evidence/run/case-db behavior.
- User requirements: Windows/macOS, 10TB-class sources, million-file scale, resume, speed, accuracy, clean viewer, easy extraction, Korean/multilingual support.

Deliverables:
1. PRD: `docs/plans/rapidforensic-recovery-engine-prd.md`
2. Test spec: `docs/plans/rapidforensic-recovery-engine-test-spec.md`
3. Recovery data model draft:
   - source id
   - source hash
   - source container type
   - filesystem type
   - candidate id
   - candidate kind
   - source path when known
   - byte offset or filesystem record id
   - recovered output path
   - hash set
   - confidence
   - limitation
   - validation status
4. MVP scope statement:
   - existing-file export
   - resumable job model
   - NTFS deleted-file MVP
   - signature carving MVP for a small file-type set
   - viewer/export integration
   - benchmark report

Decisions to lock:
1. Recovery candidate classes:
   - existing
   - deleted-entry
   - orphan-record
   - carved
   - partial/corrupt
2. First target filesystem:
   - NTFS first because Windows E01/SSD recovery is the user pain point.
3. First carving types:
   - PDF
   - JPG
   - PNG
   - ZIP/OOXML
   - SQLite
4. First validation metric:
   - hash-identical recovery for complete files.
   - metadata match where filesystem metadata exists.
   - partial recovery ratio for incomplete files.

Verification:
- PRD has acceptance criteria for every MVP feature.
- Test spec maps every acceptance criterion to a unit/integration/e2e test.
- Recovery architecture review is completed and approved.
- No recovery code starts until PRD, test spec, and architecture review are approved.

Exit:
- Implementation can begin without guessing what "recovery rate" or "accurate" means.

### 48. Recovery Backlog - Known-Answer Corpus Buildout

Canonical sequence reference: Wave 4 entry governance.

Purpose: create evidence where the correct answer is known, so recovery quality can be measured.

Corpus profiles:
1. Tiny developer corpus:
   - a few allocated files
   - a few deleted candidates
   - one carved byte stream
   - Korean filenames
   - SQLite/WAL sample
2. CI corpus:
   - deterministic, small enough for Git/CI
   - no personal data
   - expected JSON checked into repo
3. Local stress corpus:
   - generated outside Git
   - 10k/100k/1M file metadata profiles
   - sparse large files
4. External validation corpus backlog:
   - real Windows E01/Ex01
   - trusted-tool exports
   - commercial-tool comparison outputs supplied by operator.

Fixture content:
1. Filenames:
   - ASCII
   - Korean NFC/NFD
   - spaces
   - long names
   - duplicate names
2. File types:
   - TXT
   - PDF
   - DOCX/XLSX/PPTX
   - JPG/PNG
   - ZIP
   - SQLite DB and WAL
3. Damage states:
   - intact
   - deleted but recoverable
   - fragmented
   - missing footer
   - corrupt header
   - false-positive byte sequence.

Expected-answer schema:
- expected file id
- expected path
- expected source state
- expected hash
- expected size
- expected metadata
- expected recovery outcome
- expected confidence
- allowed partial range

Verification:
- `rapidtriage recovery-benchmark --profile tiny`
- Expected-answer JSON schema test.
- Corpus generator reproducibility test.

Exit:
- Recovery work can be measured with precision, recall, hash match, and metadata match.

### 49. Recovery Backlog - Existing-File Export MVP

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: complete the easier extraction/export workflow before deleted recovery.

Features:
1. Export selected files.
2. Export current filtered result set.
3. Export reviewed relevant files.
4. Export existing-only vs recovered-only distinction.
5. Preserve original relative path when safe.
6. Sanitize unsafe names.
7. Handle duplicate names with stable suffixes.
8. Write export manifest:
   - case id
   - source id
   - original path
   - exported path
   - hashes
   - size
   - review state
   - citation
   - limitation.

Implementation likely touches:
- `rapidtriage/core/case_db.py`
- `rapidtriage/core/extract.py`
- `rapidtriage/api/app.py`
- `rapidtriage/web/static/app.js`
- CLI export command surface.

Tests:
1. Path traversal fixture.
2. Duplicate filename fixture.
3. Korean filename fixture.
4. Filtered export fixture.
5. Reviewed-only export fixture.

Exit:
- Analysts can extract useful existing evidence before deeper recovery is ready.

### 50. Recovery Backlog - Checkpoint, Resume, and Job-State Foundation

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: make every long-running recovery/index/export operation restartable.

Job model:
1. job id
2. case id
3. source id
4. stage id
5. checkpoint version
6. started/updated/completed timestamps
7. current offset/path/cursor
8. completed output hashes
9. failed item list
10. retry count
11. cancellation request flag.

Stage priorities:
1. evidence preflight
2. file inventory
3. hashing
4. indexing
5. existing-file export
6. NTFS recovery
7. carving
8. report/export package.

Implementation rules:
1. Use temp files and atomic rename.
2. Never mark a stage complete until output hash is written.
3. Treat unknown partial output as suspect.
4. Resume must verify previous output before skipping work.
5. Cancel must stop at checkpoint boundaries.

Tests:
1. Interrupt after N files.
2. Resume from checkpoint.
3. Corrupt partial output detection.
4. Cancel then resume.
5. Crash log records failing stage.

Exit:
- 10TB-class work can be paused, killed, and continued without starting over.

### 51. Recovery Backlog - Index, Search, and Fast Review MVP

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: let analysts find the important subset before deep processing finishes.

Index fields:
1. filename
2. normalized path
3. extension
4. category
5. source app/path profile
6. hash
7. size
8. timestamps
9. extracted text
10. artifact details
11. recovery kind
12. confidence
13. review state.

Fast filters:
1. extension
2. category
3. user folder
4. app location
5. date range
6. size range
7. existing/deleted/carved
8. confidence
9. reviewed/unreviewed
10. include-in-report.

Quick-review lanes:
1. Desktop
2. Downloads
3. Documents
4. browser profiles
5. messenger paths
6. email containers
7. cloud sync folders
8. executable/script locations
9. recovered candidates
10. high-confidence hits.

Tests:
- Case DB query tests.
- 100k/1M synthetic row benchmark.
- UI filter smoke.
- Search while indexing integration test.

Exit:
- The tool feels fast even when the full scan is still running.

### 52. Recovery Backlog - NTFS File-Level Recovery MVP

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: solve the first serious deleted-file recovery path for Windows evidence.

Scope:
1. Parse `$MFT` records or consume trusted-tool MFT export as adapter input.
2. Identify deleted file candidates.
3. Recover resident data when possible.
4. Recover non-resident data only when runlist confidence is sufficient.
5. Preserve parent reference, filename attributes, timestamps, allocation state, and source record id.
6. Mark fragmented or overwritten candidates clearly.

Candidate fields:
- record number
- sequence number
- filename
- parent reference
- allocated/deleted state
- resident/non-resident
- logical size
- allocated size
- data runs
- source offset
- recovered hash
- confidence
- blocker list.

Tests:
1. Tiny NTFS known-answer fixture or mocked MFT record fixture.
2. Deleted resident file recovery.
3. Non-resident runlist candidate with confidence.
4. Overwritten/partial candidate warning.
5. Trusted-tool diff when export is available.

Exit:
- The first deleted-file workflow exists and is honest about what it can and cannot recover.

### 53. Recovery Backlog - Signature Carving MVP

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: recover files when filesystem metadata is gone.

First carving types:
1. PDF
2. JPG
3. PNG
4. ZIP/OOXML
5. SQLite

Engine behavior:
1. Stream source bytes in chunks.
2. Use overlap windows to avoid missing signatures at chunk boundaries.
3. Detect header/footer or length-based boundaries.
4. Validate container structure where possible.
5. Reject common false positives.
6. Save carved candidates with source offset and confidence.
7. Support resume by byte offset.

Output classes:
- complete-carved
- partial-carved
- corrupt-inspectable
- false-positive-rejected

Tests:
1. Embedded known files in byte stream.
2. Boundary across chunk edge.
3. Missing footer.
4. False-positive control.
5. Resume mid-carve.

Exit:
- Carving produces useful candidates without overwhelming the viewer.

### 54. Recovery Backlog - Recovery Viewer and Review UX MVP

Canonical sequence reference: Wave 4 - Recovery MVP, after governance approval.

Purpose: make recovered results understandable.

Views:
1. all results
2. existing files
3. deleted candidates
4. carved candidates
5. partial/corrupt
6. high-confidence
7. needs-review
8. export-ready.

Detail panel:
1. original path when known
2. recovered output path
3. source offset/record id
4. file type
5. hash
6. confidence
7. limitation
8. related artifact/timeline events
9. validation status
10. export action.

Preview support:
1. text
2. image
3. PDF/document metadata
4. SQLite/table summary
5. hex/source preview
6. unsupported binary safe summary.

Tests:
- Browser smoke with recovered fixtures.
- Korean filename display test.
- Large table virtualization test.
- Export selected recovered item test.

Exit:
- Analyst can decide what recovered results matter without leaving the UI.

### 55. Recovery Accuracy Benchmark and Report

Canonical sequence reference: Wave 5 - Validation.

Purpose: turn recovery quality into a measurable report.

Metrics:
1. true positives
2. false positives
3. false negatives
4. precision
5. recall
6. hash-identical matches
7. metadata matches
8. partial recovery ratio
9. corrupt-but-detected count
10. runtime
11. memory peak.

Report outputs:
1. JSON
2. CSV
3. HTML summary
4. per-file diff
5. blocker list
6. recommendation list.

Comparison inputs:
1. internal known-answer JSON
2. Sleuth Kit output
3. libewf/Sleuth Kit extraction transcript
4. X-Ways/EnCase exported CSV or report when operator supplies it.

Tests:
- Benchmark command schema.
- Known-answer pass/fail fixture.
- False-positive fixture.
- Trusted export diff parser fixture.

Exit:
- Recovery rate can be discussed as measured evidence, not a guess.

### 56. Windows Real-Evidence Validation Round

Canonical sequence reference: Wave 5 - Validation.

Purpose: prove the MVP on the platform and data type that matters most.

Environment:
1. Clean Windows 11 machine or VM.
2. Python 3.12.
3. Sleuth Kit/libewf/qemu-img/7-Zip where available.
4. Test source stored read-only where possible.
5. Separate output drive with enough free space.

Scenarios:
1. Folder source with Korean names.
2. Mounted/exported E01 folder.
3. Real or trusted E01/Ex01.
4. Large folder with 100k+ files.
5. Deleted-file known-answer source.
6. Carving byte stream.
7. Interrupted job and resume.
8. Export reviewed evidence.

Evidence to save:
1. command transcript
2. tool versions
3. run summary
4. benchmark JSON
5. recovery report
6. screenshots of viewer/progress
7. limitations/blockers.

Exit:
- Windows validation produces a reproducible evidence package and an updated blocker list.

### 57. Post-MVP Hardening Backlog

Canonical sequence reference: after Wave 6 or a later committed plan revision.

Purpose: define what comes after the first recovery MVP.

Backlog:
1. FAT/exFAT deleted recovery.
2. APFS/HFS+ recovery research.
3. EXT recovery research.
4. Fragmented file recovery improvements.
5. More carving signatures.
6. Fuzzy hash and near-duplicate detection.
7. OCR and media review integration.
8. Memory artifact correlation.
9. Multi-case comparison.
10. Portable case viewer.
11. Signed installer.
12. Public validation package.

Exit:
- The next phase is already scoped after MVP validation.

### 58. Accuracy Measurement Gate

Canonical sequence reference: Wave 5 - Validation.

Purpose: answer "how accurate is it?" with measured evidence rather than confidence wording.

Measurement dimensions:
1. File recovery accuracy:
   - true positive recovered files
   - false positive recovered files
   - false negative missed files
   - exact hash match rate
   - partial recovery ratio
   - corrupt-but-correctly-flagged count
2. Metadata accuracy:
   - original filename match
   - original path/parent match
   - timestamp match
   - size match
   - filesystem record id match
   - source offset/runlist match
3. Artifact parser accuracy:
   - expected rows found
   - unexpected rows emitted
   - missing rows
   - field-level match rate
   - timestamp normalization accuracy
4. Search/index accuracy:
   - keyword hit recall
   - false hit rate
   - Unicode/Hangul hit accuracy
   - FTS/tokenization consistency

Required datasets:
1. Tiny known-answer corpus for CI.
2. Medium local known-answer corpus.
3. Real Windows E01/Ex01 validation source when available.
4. External trusted-tool exports.
5. Negative-control corpus with false-positive traps.

Required outputs:
1. `recovery-accuracy.json`
2. `recovery-accuracy.csv`
3. per-file diff table
4. per-parser diff table
5. false positive/false negative list
6. unsupported/unmeasured scope list
7. final accuracy summary with "claim allowed" flags.

Pass/fail release criteria for MVP:
- Precision is >= 0.995 on the approved CI known-answer recovery corpus.
- Recall is >= 0.990 on the approved CI known-answer recovery corpus.
- Maximum false positive rate is <= 0.005 for recovery candidates.
- Negative-control fixtures produce 0 accepted false-positive recovered files.
- Complete allocated existing-file export has precision 1.000 and recall 1.000.
- 100% of candidates marked complete have byte-identical hash matches.
- 100% of partial recovery candidates are marked partial or corrupt with limitation text.
- 100% of unsupported filesystems and source types are listed in unsupported scope.
- Any recovery-rate statement names the corpus, source type, tool versions, and limitations.
- Any metric below threshold fails the release gate.

Verification:
- `rapidtriage recovery-benchmark --profile ci --output-dir <out>`
- Trusted-tool diff parser test.
- Accuracy report schema test.

Exit:
- The tool can say "on this corpus, for this source type, with these limitations, accuracy was X" and prove it.

### 59. Reproducibility and Determinism Gate

Canonical sequence reference: Wave 5 - Validation.

Purpose: prove that the same input produces the same material output across repeated runs.

Measurement dimensions:
1. Run determinism:
   - same input hash
   - same command
   - same config
   - same tool versions
   - same output hashes after dynamic fields are normalized
2. Cross-platform reproducibility:
   - macOS run
   - Windows run
   - normalized path differences accounted for
   - Unicode normalization differences accounted for
3. Resume reproducibility:
   - full uninterrupted run
   - interrupted/resumed run
   - output equivalence after normalization
4. Dependency reproducibility:
   - Python version
   - package lock/report
   - external tool version
   - Rust worker version

Required controls:
1. Dynamic field normalization:
   - generated_at
   - elapsed/runtime fields such as elapsed_ms, duration_ms, and runtime_seconds
   - absolute temp paths
   - machine hostname
   - OS username
   - randomized job ids only when an id mapping file proves equivalence
   - ordering only where the schema declares the collection unordered
2. Output hash manifest:
   - every JSON/CSV/exported file
   - normalized hash where needed
   - raw hash where needed
3. Reproduction transcript:
   - command
   - environment
   - source hash
   - tool versions
   - git commit.

Required outputs:
1. `reproducibility-run-a.json`
2. `reproducibility-run-b.json`
3. `reproducibility-diff.json`
4. `normalized-output-manifest.json`
5. `environment-transcript.txt`

Pass/fail release criteria for MVP:
- Two consecutive runs on the same machine produce 100% normalized material equivalence.
- Interrupted/resumed run produces 100% normalized material equivalence with uninterrupted run for the same fixture.
- Acceptable material diff threshold is 0.
- Only approved dynamic diff fields may differ.
- Cross-platform normalized output has 100% material equivalence for claimed cross-platform profiles.
- Any unapproved normalized output difference fails the release gate.

Verification:
- `rapidtriage reproducibility-check --profile ci`
- Resume equivalence test.
- macOS/Windows normalized output diff.

Exit:
- A third party can rerun the same case profile and reproduce material findings.

### 60. Report Defensibility Gate

Canonical sequence reference: Wave 5 - Validation and Legal and Operator Review Gate.

Purpose: determine whether output is report-defensible in a technical reporting context without claiming legal suitability.

Defensibility dimensions:
1. Provenance:
   - source evidence hash
   - source path/container
   - parser/tool version
   - command transcript
   - source offset/record id when applicable
2. Chain of custody:
   - case id
   - evidence item id
   - acquisition notes
   - operator notes
   - export package hash
   - immutable audit events
3. Citation completeness:
   - every report item links to source evidence
   - every recovered file has source citation
   - every limitation is preserved in report/export
4. Review workflow:
   - reviewer status
   - reviewer note
   - inclusion decision
   - report approval state
5. Limitation honesty:
   - commercial-grade blockers
   - trusted-tool diff status
   - unsupported parser warnings
   - partial/corrupt recovery warnings
   - SSD/TRIM impossibility notes where applicable.

Required outputs:
1. `case-audit-log.jsonl`
2. `chain-of-custody.json`
3. `report-citations.json`
4. `export-manifest.json`
5. `limitations-and-blockers.md`
6. report package with hashes
7. operator validation checklist.

Pass/fail release criteria for MVP:
- 100% of report items have source citation or an approved explicit exception.
- 100% of recovered files carry confidence and limitation fields.
- 100% of exported files have SHA-256 recorded in `export-manifest.json`.
- 100% of export package manifests are hash-verifiable.
- 100% of report limitations are preserved in the exported report package.
- `legal-operator-review-checklist.md` exists and all required reviews are complete before release.
- Any claim of legal suitability fails the release gate unless the legal review explicitly approves that exact wording.

Verification:
- Citation completeness test.
- Export package verification test.
- Audit log append-only test.
- Report limitation preservation test.

Exit:
- A report reviewer can trace each claim back to source evidence and understand the limits.

### 61. Large-Scale Survival Gate

Canonical sequence reference: Wave 5 - Validation.

Purpose: prove the tool does not die on million-file and 10TB-class workflows.

Measurement dimensions:
1. Scale:
   - 10k files
   - 100k files
   - 1M file metadata rows
   - 100GB local stress
   - 1TB external stress
   - 10TB stress backlog
2. Resource limits:
   - peak RSS memory
   - disk usage
   - temp directory growth
   - open file handles
   - SQLite DB size
3. Throughput:
   - files/sec
   - MB/sec
   - hashes/sec
   - indexed rows/sec
   - UI page load latency
4. Stability:
   - no unbounded memory growth
   - no UI freeze beyond threshold
   - recoverable crash behavior
   - resume checkpoint interval
   - failed item isolation.

Required outputs:
1. `large-case-benchmark.json`
2. `resource-usage.csv`
3. `checkpoint-audit.json`
4. `failed-items.json`
5. `resume-validation.json`
6. UI performance screenshot or browser timing report.

Pass/fail release criteria for MVP:
- Target corpus size: 100k real/synthetic files and 1M metadata rows.
- Required completion rate: 100% job completion for the 100k-file profile.
- Required item completion rate: >= 99.9% for the 1M-row metadata profile, with all failed items isolated in `failed-items.json`.
- Maximum RSS memory: <= 4 GiB for the 100k-file profile and 1M-row metadata profile.
- Maximum sustained system CPU utilization: <= 90% over a 5-minute window unless explicit high-performance mode is selected.
- Throughput: >= 20 MB/s sequential scan on local SSD for hashing/indexing profile, or >= 5,000 metadata rows/sec for metadata-only profile.
- Resume duplicates: 0 duplicate completed outputs after forced interruption and resume.
- Checkpoint interval: <= 60 seconds or <= 1 GiB scanned, whichever occurs first, for long-running scan stages.
- UI p95 latency: <= 2.0s for page/search/filter on 100k-row case.
- UI p99 latency: <= 5.0s for page/search/filter on 100k-row case.
- A single item parse failure must not abort the whole job.
- 10TB support is blocked until actual or representative stress evidence exists.

Verification:
- `rapidtriage benchmark --profile large-local`
- `rapidtriage recovery-benchmark --profile stress`
- Browser large-table smoke.
- Memory peak check.
- Resume after forced termination.

Exit:
- The product can state its tested scale honestly and show the evidence.

### 62. External Validation and Trusted-Tool Diff Gate

Canonical sequence reference: Wave 5 - Validation.

Purpose: compare RapidForensic against independent tools and stop relying only on self-tests.

Comparison tools/adapters:
1. Sleuth Kit/Autopsy exports.
2. libewf/ewfmount transcripts.
3. X-Ways exported CSV/report when supplied by operator.
4. EnCase exported CSV/report when supplied by operator.
5. SQLite trusted tools for DB recovery.
6. Volatility output for memory workflows where applicable.

Diff levels:
1. file-level:
   - path
   - size
   - hash
   - deleted/allocated state
   - source offset/record id
2. artifact-level:
   - row id
   - timestamp
   - event type
   - field-level values
3. recovery-level:
   - recovered file count
   - matching hashes
   - extra RapidForensic candidates
   - missed trusted-tool candidates
   - false-positive classification.

Required outputs:
1. `trusted-tool-diff.json`
2. `trusted-tool-diff.csv`
3. `tool-version-transcript.txt`
4. `disagreement-review.md`
5. accepted limitation/backlog entries.

Pass/fail release criteria for any strong claim:
- At least one independent trusted-tool comparison exists for each claimed source type.
- 100% of disagreements are listed in `disagreement-review.md`.
- 100% of unresolved disagreements have accepted limitation or backlog entries.
- 100% of strong claims name compared tool versions, corpus id, source type, and limitations.
- Any strong claim without trusted-tool evidence fails the release gate.

Verification:
- Trusted export parser tests.
- Row-level diff fixture.
- Disagreement report schema test.

Exit:
- The project can explain where it agrees/disagrees with external tools.

### 63. Operational Readiness and Support Gate

Canonical sequence reference: Wave 5 - Validation.

Purpose: prove the product can be used repeatedly by an analyst, not just by the developer.

Readiness dimensions:
1. Installation:
   - Windows clean install
   - macOS clean install
   - dependency failure guidance
   - offline/dependency bundle backlog
2. Operations:
   - crash logs
   - job history
   - support bundle
   - settings export/import
3. UX:
   - first-run flow
   - progress visibility
   - warning visibility
   - export discoverability
4. Documentation:
   - quickstart
   - known limitations
   - validation method
   - recovery benchmark interpretation
   - legal/authority warning.

Required outputs:
1. install smoke transcript
2. support bundle sample
3. crash recovery sample
4. known limitations update
5. release checklist.

Pass/fail release criteria:
- Fresh Windows startup smoke completes with exit code 0.
- Fresh macOS startup smoke completes with exit code 0.
- 100% of startup failures in smoke tests produce an actionable diagnostic message.
- Support bundle generation completes with exit code 0 and includes logs, config, environment, and run transcript.
- Known limitations document is updated in the same release commit or a cited prior commit.

Verification:
- Windows clean smoke.
- macOS clean smoke.
- Support bundle generation test.

Exit:
- The product can be handed to a user without a live developer sitting next to them.

### 64. Final Release Readiness Gate

Canonical sequence reference: Wave 6 - Release Readiness.

Purpose: prevent overclaiming and preserve forensic trust.

Required evidence:
1. macOS full local verification.
2. Windows full local verification.
3. Rust worker verification.
4. Known-answer E01 or blocked limitation clearly recorded.
5. Trusted-tool diff backlog updated.
6. Large-case benchmark evidence attached.
7. README known limitations updated.
8. Release checklist updated.
9. Recovery benchmark report attached.
10. Viewer/export smoke evidence attached.
11. Resume/crash-recovery evidence attached.
12. Accuracy measurement report attached.
13. Reproducibility diff attached.
14. Report-defensibility package attached.
15. Large-scale survival report attached.
16. External validation/trusted-tool diff attached for any strong source-type claim.
17. Operational readiness smoke attached.

Exit:
- Release passes only when every row in `Updated Release Scorecard` is pass.
- Release can be described as a local forensic triage and recovery preview only unless external validation proves more.
- Release must not claim legal suitability.

## Acceptance Criteria

1. This plan is committed before execution and execution records cite the committed revision.
2. All milestones execute through `Canonical Execution Sequence`.
3. Wave 0 completion criteria pass before Wave 1 starts.
4. Wave 1 completion criteria pass before Wave 2 starts.
5. Wave 2 completion criteria pass before Wave 3 starts.
6. Wave 3 completion criteria pass before Wave 4 starts.
7. Wave 4 completion criteria pass before Wave 5 starts.
8. Wave 5 completion criteria pass before Wave 6 starts.
9. `python3.12 -m unittest discover -s tests` passes on macOS.
10. `python3.12 -m compileall -q rapidtriage tests scripts` passes.
11. Web JS syntax checks pass.
12. Rust fmt/check/test pass.
13. README contract tests pass.
14. E01 dummy smoke remains blocked and honest.
15. Windows manifest sample is deterministic.
16. Launch scripts reject unsupported Python versions before venv creation.
17. Windows handoff checklist exists with exact commands and results.
18. Static analysis commands are repeatable from documented project tooling, not only temporary `/tmp` installs.
19. Dead-code cleanup removes or justifies Ruff/Vulture findings without weakening output contracts.
20. Duplicate definitions and import shadowing are fixed or explicitly documented with tests.
21. Security review has no unresolved blocker findings before refactor.
22. Case DB unused tables/columns are classified before any destructive migration.
23. Case DB migrations follow `Database Migration Contract`.
24. Case DB index changes are backed by `EXPLAIN QUERY PLAN` evidence.
25. Code review findings are severity-ranked, accepted or rejected with rationale, and linked to fix items.
26. No recovery feature work begins until PRD, test specification, and recovery architecture review are approved.
27. Recovery jobs have checkpoint/resume metadata before deleted-file or carving work ships.
28. Every recovered output has a file hash, source citation, confidence, limitation field, and validation status.
29. Existing-file export and recovered-file export share one manifest contract.
30. Korean filenames and CP949/UTF-16/UTF-8 text fixtures pass scan, search, viewer, and export tests.
31. Viewer can group existing, deleted, carved, artifact, document, browser/AI, media, and archive results.
32. Progress API reports stage, bytes/files processed, recovered candidate count, and checkpoint path.
33. Accuracy gates meet precision >= 0.995, recall >= 0.990, and false positive rate <= 0.005 on approved MVP corpus.
34. Complete allocated existing-file export reaches precision 1.000 and recall 1.000.
35. Reproducibility gates show 100% normalized material equivalence with 0 unapproved material diffs.
36. Performance gates meet maximum RSS <= 4 GiB, CPU <= 90% sustained unless high-performance mode is selected, and throughput targets from `Quantitative Validation Matrix`.
37. UI gates meet p95 <= 2.0s and p99 <= 5.0s for page/search/filter on 100k-row case.
38. Large dataset survival gates complete 100k-file and 1M-row profiles with required completion rates.
39. External tool adapters record version, command transcript, output parser status, and limitations.
40. Strong recovery/source-type claims require external trusted-tool diff evidence.
41. Report/export packages include source citations, chain-of-custody data, limitations, hashes, and review status.
42. Legal and operator review gate passes before release.
43. Release readiness does not allow legal suitability, universal recovery-rate, or unsupported source coverage claims.
44. Operational readiness is proven by clean Windows/macOS install smoke and actionable diagnostics.
45. Updated Release Scorecard has no failing blocker.

## Primary Risks and Mitigations

1. Risk: README is patched just to satisfy tests but becomes misleading.
   - Mitigation: keep limitation language and commercial blockers near the contract links.
2. Risk: E01 preflight becomes too strict and blocks valid tool-ready environments.
   - Mitigation: add mocked ready-path tests.
3. Risk: Golden sample update hides a real artifact schema regression.
   - Mitigation: inspect added fields and document them in output schema if public.
4. Risk: Launcher changes break older but valid Python installs.
   - Mitigation: support 3.10, 3.11, and 3.12 explicitly.
5. Risk: Large refactor introduces behavioral regressions.
   - Mitigation: do not refactor until current test suite is green.
6. Risk: Carving floods the analyst with false positives.
   - Mitigation: require per-profile validation, confidence scoring, and false-positive control fixtures.
7. Risk: Resume corrupts partial outputs.
   - Mitigation: use atomic temp files, output hash verification, and checkpoint replay tests.
8. Risk: External tools differ by platform and version.
   - Mitigation: capture tool versions/transcripts and treat missing tools as explicit blockers.
9. Risk: Unicode works on macOS but breaks on Windows.
   - Mitigation: add Windows CP949/long-path validation and macOS NFC/NFD fixtures.
10. Risk: Performance work makes results less accurate.
   - Mitigation: benchmark speed separately from recovery accuracy and fail on schema/provenance loss.
11. Risk: Dead-code cleanup removes unfinished but intended forensic profile fields.
   - Mitigation: classify unused locals before deletion and add payload/schema tests for anything kept.
12. Risk: Dropping unused DB columns breaks existing case databases.
   - Mitigation: deprecate first, migrate with backup, and test old fixture DBs.
13. Risk: New indexes improve reads but slow large ingest.
   - Mitigation: benchmark ingest and query paths before keeping index changes.
14. Risk: Static analysis creates noisy churn.
   - Mitigation: start with narrow rules, per-file ignores, and small focused cleanup commits.
15. Risk: Accuracy metrics are overstated by using only easy fixtures.
   - Mitigation: include negative controls, corrupt/partial cases, real E01 when available, and unsupported-scope reporting.
16. Risk: Reproducibility fails because dynamic fields pollute diffs.
   - Mitigation: define normalized-output hashing and separate raw hashes from normalized hashes.
17. Risk: Report output looks polished but is not defensible.
   - Mitigation: block report/export items missing citation, hash, limitation, or review status.
18. Risk: Large-case tests pass synthetically but fail on real storage.
   - Mitigation: distinguish CI/local/external stress profiles and forbid 10TB claims without evidence.
19. Risk: Trusted-tool disagreement is treated as tool failure instead of a finding.
   - Mitigation: require disagreement review files and backlog entries for unresolved differences.

## Verification Order

Canonical sequence reference: `Canonical Execution Sequence`.

Wave 0 - Baseline Validation:
1. Focused README docs tests.
2. Focused rule engine docs test.
3. Focused Windows manifest sample test.
4. Focused E01 smoke test.
5. Full unittest.
6. Compileall.
7. JS syntax.
8. Rust fmt/check/test.
9. Manual launcher smoke.
10. Windows handoff smoke.

Wave 1 - Static Cleanup:
11. Ruff selected-rule check.
12. Vulture advisory dead-code check.
13. Focused tests for touched modules.
14. Full unittest and compileall after cleanup.

Wave 2 - Security and Audit:
15. Security review checklist and blocker verification.
16. Case DB schema inventory.
17. Case DB migration fixture tests.
18. Query plan/index regression tests.
19. Post-security and post-DB code review.

Wave 3 - Refactor:
20. Characterization tests before each extraction.
21. Focused API/DB/UI tests after each extraction.
22. Browser smoke for moved UI code.
23. Full macOS verification after refactor batch.

Wave 4 - Recovery MVP:
24. Recovery PRD approval check.
25. Recovery test specification approval check.
26. Recovery architecture review check.
27. Recovery fixture smoke.
28. Resume interruption test.
29. Korean/Unicode round-trip test.
30. External adapter mocked-tool test.

Wave 5 - Validation:
31. Accuracy benchmark.
32. Reproducibility/determinism check.
33. Performance benchmark.
34. UI p95/p99 latency check.
35. Large-scale survival benchmark.
36. Citation and export report-defensibility tests.
37. Trusted-tool row-level diff.
38. Legal and operator review checklist.
39. Clean install operational smoke.

Wave 6 - Release Readiness:
40. Updated Release Scorecard.
41. Release claims map review.
42. Known limitations update check.
43. Final release checklist.

## ADR

Decision: use `Canonical Execution Sequence` and wave gates as the only execution authority.

Drivers:
- Current CI is red.
- E01 status semantics affect forensic trust.
- Windows/macOS setup must be deterministic.
- Recovery implementation requires PRD approval, test specification approval, and recovery architecture review.
- Release claims require quantitative validation and legal/operator review.

Alternatives considered:
- README-only fix: rejected because it leaves runtime/test drift.
- Refactor first: rejected because red tests make behavior movement unsafe.
- Stabilize first: chosen.
- Numeric-section execution order: rejected because it conflicted with static cleanup, security, DB audit, code review, and recovery governance.

Consequences:
- Feature work is gated behind baseline, cleanup, security, DB audit, code review, and refactor.
- Recovery implementation cannot start from backlog text alone.
- Release decisions become pass/fail against measurable evidence.

Follow-ups:
- Commit this plan before execution.
- Execute Wave 0 first.
- Create PRD, test specification, and architecture review before Wave 4 implementation.
