# RapidTriage Commercial Readiness Gate

- Generated at: `2026-05-19T00:21:38.334369+00:00`
- Backlog: `/Users/shinyoohag/rapidforensic/repo/docs/rapidtriage-commercial-parity-backlog.md`
- Status: `commercial-gaps-present`
- Commercial claim allowed: `False`
- Readiness score: `90/100`
- Non-commercial items: `120`/`120`
- Release claim: do not claim AXIOM/WISDOM-class commercial parity; disclose triage/validation limits

## Maturity Gate Summary

- `implemented`: `120` passed, `0` remaining
- `usable`: `120` passed, `0` remaining
- `validated`: `0` passed, `120` remaining
- `commercial_grade`: `0` passed, `120` remaining

## Commercial Blocker Matrix

- Matrix version: `commercial-blocker-matrix-v1`
- Blocked items: `120`
- Internally actionable next steps: `120`
- External/trusted evidence required: `120`
- Lane counts: `{'external-operator-evidence': 120, 'native-parser-depth': 73, 'known-answer-validation': 120, 'large-scale-performance': 24, 'platform-release-evidence': 32, 'security-legal-assurance': 42}`
- Rule: Rows classify why commercial_grade is blocked; internally_actionable=true does not mean commercial-ready, only that the next narrowing step can be produced inside the repo before external evidence is collected.

### Top Internal Blockers

- `#1` Native EVTX BinXML full parsing: lane `external-operator-evidence`, next `validated`
- `#2` EVTX event template/message rendering: lane `external-operator-evidence`, next `validated`
- `#3` EVTX deleted/corrupt record recovery validation: lane `external-operator-evidence`, next `validated`
- `#4` Registry hive full key tree reconstruction: lane `external-operator-evidence`, next `validated`
- `#5` Registry deleted key/value recovery: lane `external-operator-evidence`, next `validated`
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser: lane `external-operator-evidence`, next `validated`
- `#7` Amcache parser: lane `external-operator-evidence`, next `validated`
- `#8` ShimCache/AppCompatCache parser: lane `external-operator-evidence`, next `validated`
- `#9` BAM/DAM execution parser: lane `external-operator-evidence`, next `validated`
- `#10` SRUM full ESE table parser: lane `external-operator-evidence`, next `validated`

### Top External Evidence Blockers


## Internal vs External Blockers

- Profile: `blocker-separation-profile-v1`
- Immediate queue item: `#10`
- Internal-only blockers: `0`
- Internal then external blockers: `120`
- External-only blockers: `0`
- Internal work available: `120`
- External/trusted evidence required: `120`
- Rule: Do internal implementation/fixture/reporting work first, but keep commercial_grade=false until the paired trusted-tool, independent-review, signed-platform, large-hardware, or staffed-support evidence is attached.

### Next Internal Batch

- `#1` Native EVTX BinXML full parsing: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#2` EVTX event template/message rendering: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#3` EVTX deleted/corrupt record recovery validation: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#4` Registry hive full key tree reconstruction: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#5` Registry deleted key/value recovery: Record the blocker explicitly and collect the external run/signoff artifact when available.

### Next External Evidence Batch

- `#1` Native EVTX BinXML full parsing: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#2` EVTX event template/message rendering: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#3` EVTX deleted/corrupt record recovery validation: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#4` Registry hive full key tree reconstruction: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#5` Registry deleted key/value recovery: Record the blocker explicitly and collect the external run/signoff artifact when available.

## Platform Uplift Actionability

- Profile: `platform-uplift-actionability-v1`
- Can reach 100 on Mac alone: `False`
- Mac preparatory evidence available: `True`
- Remaining score points: `10`
- Mac-preparable blocked items: `120`
- Windows/Windows-evidence blocked items: `26`
- External/trusted-evidence blocked items: `120`
- Rule: Run Mac-local QC whenever possible, but do not mark commercial_grade true until the Windows/E01/trusted-tool/large-case/independent-review evidence is attached and passes.

### Mac-Executable Commands

- `macos-live-smoke`: `rapidtriage macos-live-smoke --output-dir ./qc/macos-live --overwrite --json`
- `validation-diff-runners`: `rapidtriage validation-diff-runners --output ./qc/runner-matrix.json --probe-versions --json`
- `sample-workflow`: `rapidtriage sample --output-dir ./qc/sample --run --overwrite --json`
- `submission-bundle`: `rapidtriage bundle ./case.json --allowed-root ./qc/sample --output-dir ./qc/submission-bundle --include-all --json`
- `final-qc-report`: `rapidtriage final-qc-report --validation-package ./validation.json --runner-matrix ./qc/runner-matrix.json --chain-of-custody ./custody.json --audit-bundle ./audit.json --exhibit-bundle ./exhibit.zip --performance-run ./benchmark.json --browser-trace ./trace.json --reviewer-signoff ./review.md --output ./qc/final-qc.json --json`
- `commercial-readiness`: `rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --output-dir ./qc/commercial-readiness --json`

### Windows Or External Evidence Samples

- `#1` Native EVTX BinXML full parsing
- `#2` EVTX event template/message rendering
- `#3` EVTX deleted/corrupt record recovery validation
- `#4` Registry hive full key tree reconstruction
- `#5` Registry deleted key/value recovery

## Functional Defensibility Progress

- Range: `#42`-`#70`
- Status: `usable-internal-validation-required`
- Item count: `29`
- Batch count: `6`
- Commercial claim allowed by this section: `False`
- Rule: This section tracks #42-#70 implementation/usability progress only; commercial-grade claims still require validated and commercial_grade gates for every item.
- `implemented` in range: `29`
- `usable` in range: `29`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Functional Batches

- Batch `1` (#42, #43, #44, #45, #46) status `usable-internal-validation-required`, next gates `{'validated': 5}`
- Batch `2` (#47, #48, #49, #50, #51) status `usable-internal-validation-required`, next gates `{'validated': 5}`
- Batch `3` (#52, #53, #54, #55, #56) status `usable-internal-validation-required`, next gates `{'validated': 5}`
- Batch `4` (#57, #58, #59, #60, #61) status `usable-internal-validation-required`, next gates `{'validated': 5}`
- Batch `5` (#62, #63, #64, #65, #66) status `usable-internal-validation-required`, next gates `{'validated': 5}`
- Batch `6` (#67, #68, #69, #70) status `usable-internal-validation-required`, next gates `{'validated': 4}`

## Review Scale Resilience Progress

- Range: `#76`-`#80`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Commercial claim allowed by this section: `False`
- Rule: #76-#80 controls reduce review overload, but they must not be advertised as commercial-scale complete until trusted manifests and large-case replay evidence are attached.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Review-Scale Items

- `#76` hash-cache: next `validated`, trusted manifest `hash-cache-manifest`, outputs `files.hash_cache_assessment, api metadata hash assessment`
- `#77` duplicate-detection: next `validated`, trusted manifest `duplicate-file-manifest`, outputs `files.duplicate_detection_assessment, duplicate_content_groups, duplicate_content_manifest`
- `#78` cursor-api: next `validated`, trusted manifest `pagination-cursor-manifest`, outputs `api pagination.cursor, next_cursor, previous_cursor, pagination-cursor-manifest-v1, page_window_id`
- `#79` ui-virtualization: next `validated`, trusted manifest `ui-virtualization-manifest`, outputs `api pagination.ui_virtualization, ui-virtualization-manifest-v1, ui-virtualization-report-grade-validation-plan-v1, web bounded row rendering notice, web virtual row-window controls`
- `#80` cancel-retry: next `validated`, trusted manifest `cancellation-retry-transition-manifest`, outputs `run job cancellation_retry_assessment, cancellation-retry-manifest-v1, cancellation-retry-report-grade-validation-plan-v1, retry_lineage_profile, partial_output_policy, job step operational_gap_ids`

## Validation Spine Progress

- Range: `#81`-`#85`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #81-#85 are validation infrastructure controls. They can promote internal validated gates, but commercial-grade claims still require matching external/trusted evidence and no remaining item blockers.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Validation Evidence Chain

- `#81` known-answer-validation: next `validated`, produces `known_answer_validation.datasets`, trusted diff `trusted-known-answer-manifest-diff`
- `#82` parser-fixture-corpus: next `validated`, produces `parser_fixture_corpus.areas`, trusted diff `trusted-fixture-corpus-manifest-diff`
- `#83` fp-fn-risk-register: next `validated`, produces `parser_false_positive_false_negative_notes`, trusted diff `trusted-fp-fn-risk-register-diff`
- `#84` independent-validation-report: next `validated`, produces `independent_validation_report.sha256`, trusted diff `trusted-independent-validation-signoff-diff`
- `#85` validation-package: next `validated`, produces `rapidtriage-validation-artifacts.json`, trusted diff `trusted-validation-package-manifest-diff`

## Forensic Integrity Progress

- Range: `#86`-`#90`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #86-#90 make single-case review exports more defensible, but commercial/court-grade claims still require trusted custody, acquisition hash, audit, replay, and provenance manifests.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Forensic Integrity Evidence Chain

- `#86` chain-of-custody: next `validated`, produces `case-db-report-export.custody_workflow`, trusted diff `trusted-custody-event-manifest-diff`
- `#87` acquisition-hash-workflow: next `validated`, produces `case-db-report-export.acquisition_hash_workflow`, trusted diff `trusted-acquisition-hash-manifest-diff`
- `#88` immutable-audit-log: next `validated`, produces `case-db-report-export.audit_integrity`, trusted diff `trusted-audit-hash-chain-manifest-diff`
- `#89` report-reproducibility: next `validated`, produces `case-db-report-export.reproducibility`, trusted diff `trusted-report-replay-manifest-diff`
- `#90` report-item-provenance: next `validated`, produces `case-db-report-export.items[].provenance`, trusted diff `trusted-report-provenance-manifest-diff`

## Report Quality Progress

- Range: `#91`-`#95`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #91-#95 make report exports safer to review, cite, and package, but commercial/court-grade claims still require trusted calibration, warning, legal, exhibit, and external-tool evidence.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Report Quality Evidence Chain

- `#91` parser-confidence-scoring: next `validated`, produces `case-db-report-export.items[].validation_assessment.parser_confidence`, trusted diff `trusted-parser-confidence-calibration-diff`
- `#92` validation-warning-ux: next `validated`, produces `case-db-report-export.items[].validation_assessment.warnings`, trusted diff `trusted-validation-warning-checklist-diff`
- `#93` legal-limitation-statements: next `validated`, produces `case-db-report-export.items[].legal_limitations_assessment`, trusted diff `trusted-legal-limitation-wording-diff`
- `#94` court-exhibit-package: next `validated`, produces `reviewer-bundle.exhibit_index`, trusted diff `trusted-court-exhibit-manifest-diff`
- `#95` external-tool-version-capture: next `validated`, produces `validation-package.external_tool_versions`, trusted diff `trusted-external-tool-transcript-diff`

## Acquisition Quality Progress

- Range: `#96`-`#100`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #96-#100 make evidence handling and export warnings visible, but commercial/court-grade claims still require signed acquisition, trusted time/skew/contamination manifests, and external notarization.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Acquisition Quality Evidence Chain

- `#96` write-blocker-acquisition-metadata: next `validated`, produces `case-db-report-export.acquisition_metadata`, trusted diff `trusted-acquisition-metadata-handoff-diff`
- `#97` timezone-normalization-validation: next `validated`, produces `case-db-report-export.timezone_validation`, trusted diff `trusted-timezone-normalization-matrix-diff`
- `#98` clock-skew-analysis: next `validated`, produces `case-db-report-export.clock_skew_analysis`, trusted diff `trusted-clock-skew-baseline-diff`
- `#99` evidence-contamination-warning: next `validated`, produces `case-db-report-export.contamination_warnings`, trusted diff `trusted-contamination-checklist-diff`
- `#100` tamper-evident-audit-bundle: next `validated`, produces `reviewer-bundle.rapidtriage-tamper-evident-audit-bundle.json`, trusted diff `trusted-tamper-signature-attestation-diff`

## Release Operations Progress

- Range: `#101`-`#105`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #101-#105 make local release artifacts and crash reports inspectable, but commercial deployment claims still require real platform signing, notarization, package smoke logs, hosted update evidence, and crash export review.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Release Operations Evidence Chain

- `#101` windows-signed-installer: next `validated`, produces `release-manifest.package_readiness.windows_signed_installer`, trusted diff `trusted-windows-signing-evidence-diff`
- `#102` macos-notarized-package: next `validated`, produces `release-manifest.package_readiness.macos_notarized_package`, trusted diff `trusted-macos-notarization-evidence-diff`
- `#103` linux-package: next `validated`, produces `release-manifest.package_readiness.linux_package`, trusted diff `trusted-linux-package-smoke-diff`
- `#104` auto-update-channel: next `validated`, produces `update-manifest.json`, trusted diff `trusted-auto-update-channel-diff`
- `#105` local-crash-reporting: next `validated`, produces `crash-report.json`, trusted diff `trusted-crash-redaction-export-diff`

## Enterprise Governance Progress

- Range: `#106`-`#110`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #106-#110 document local-first enterprise guardrails and review/audit scope, but commercial multi-user or RBAC claims still require a real shared server, enforcement tests, identity handling, and trusted audit review.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Enterprise Governance Evidence Chain

- `#106` telemetry-free-local-only-mode: next `validated`, produces `enterprise-policy.telemetry`, trusted diff `trusted-local-only-deployment-policy-diff`
- `#107` license-activation-policy: next `validated`, produces `enterprise-policy.license_activation`, trusted diff `trusted-license-authority-diff`
- `#108` role-based-access-control: next `validated`, produces `enterprise-policy.rbac`, trusted diff `trusted-rbac-enforcement-diff`
- `#109` multi-user-case-server: next `validated`, produces `enterprise-policy.multi_user_case_server`, trusted diff `trusted-multi-user-server-review-diff`
- `#110` collaboration-audit-trail: next `validated`, produces `enterprise-policy.collaboration_audit_trail`, trusted diff `trusted-collaboration-audit-diff`

## Operations Continuity Progress

- Range: `#111`-`#115`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #111-#115 provide local continuity commands and packaged operations documents, but commercial operations claims still require real restore drills, CI release-note gates, maintained LTS/hotfix process, staffed SLA, and training delivery evidence.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Operations Continuity Evidence Chain

- `#111` backup-restore-migration: next `validated`, produces `case-backup/case-restore payloads`, trusted diff `trusted-backup-restore-rehearsal-diff`
- `#112` release-notes-changelog-discipline: next `validated`, produces `release-manifest.package_readiness.operations_documents`, trusted diff `trusted-release-notes-ci-gate-diff`
- `#113` lts-hotfix-policy: next `validated`, produces `docs/rapidtriage-lts-hotfix-policy.md`, trusted diff `trusted-lts-hotfix-policy-diff`
- `#114` support-sla-documentation: next `validated`, produces `docs/rapidtriage-support-sla.md`, trusted diff `trusted-support-desk-sla-diff`
- `#115` training-curriculum: next `validated`, produces `docs/rapidtriage-training-curriculum.md`, trusted diff `trusted-training-delivery-diff`

## Final Delivery Progress

- Range: `#116`-`#120`
- Status: `usable-internal-validation-required`
- Item count: `5`
- Validation package attached: `False`
- Mapped items in range: `[]`
- Commercial claim allowed by this section: `False`
- Rule: #116-#120 package the final analyst/admin/security/dependency materials, but commercial release claims still require real lab runs, admin deployment proof, independent AppSec, OS/corpus sandbox evidence, and CI/SBOM monitoring.
- `implemented` in range: `5`
- `usable` in range: `5`
- `validated` in range: `0`
- `commercial_grade` in range: `0`

### Final Delivery Evidence Chain

- `#116` analyst-quickstart-lab: next `validated`, produces `docs/rapidtriage-training-curriculum.md quickstart lab section`, trusted diff `trusted-quickstart-lab-run-diff`
- `#117` admin-deployment-guide: next `validated`, produces `docs/rapidtriage-admin-deployment-guide.md`, trusted diff `trusted-admin-deployment-proof-diff`
- `#118` security-hardening-review: next `validated`, produces `enterprise-policy.security_hardening`, trusted diff `trusted-security-hardening-review-diff`
- `#119` malicious-evidence-sandboxing: next `validated`, produces `enterprise-policy.security_hardening.trusted_malicious_sandbox_diff`, trusted diff `trusted-malicious-evidence-sandbox-diff`
- `#120` dependency-vulnerability-monitoring: next `validated`, produces `dependency-monitoring.json`, trusted diff `trusted-dependency-advisory-sbom-diff`

## Priority Work Plan

- `#1` Native EVTX BinXML full parsing (core-forensics, critical, next `validated`): complete provider-specific BinXML grammar coverage and independent corpus validation.
- `#2` EVTX event template/message rendering (core-forensics, critical, next `validated`): Resolve validation blockers: external-validation-or-infrastructure-required, known-answer-or-independent-validation-required, native-parser-depth-required
- `#3` EVTX deleted/corrupt record recovery validation (core-forensics, critical, next `validated`): large validation corpus coverage for real-world deleted EVTX slack and corrupt chunk edge cases.
- `#4` Registry hive full key tree reconstruction (core-forensics, critical, next `validated`): actual transaction-log replay engine, trusted RECmd/Registry Explorer replay diffs, and broad corpus validation across malformed/large hives.
- `#5` Registry deleted key/value recovery (core-forensics, critical, next `validated`): deleted-key/value testimony validation against full hive allocator state, transaction logs, and a labeled deleted-cell corpus.
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser (core-forensics, critical, next `validated`): full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction-log validation.
- `#7` Amcache parser (core-forensics, critical, next `validated`): full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- `#8` ShimCache/AppCompatCache parser (core-forensics, critical, next `validated`): native binary AppCompatCache layout decoding across Windows versions, AppCompatCacheParser/RECmd row-level diffs, and broad OS-build known-answer validation.
- `#9` BAM/DAM execution parser (core-forensics, critical, next `validated`): native SYSTEM hive binary value interpretation and broad version validation.
- `#10` SRUM full ESE table parser (core-forensics, critical, next `validated`): full native ESE catalog/table/page decoding, page checksum verification beyond header/page-size checks, and row-level timestamp/counter extraction.
- `#11` Windows.edb full ESE parser (core-forensics, critical, next `validated`): full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- `#12` `$MFT` full attribute parser (core-forensics, critical, next `validated`): full-volume attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, trusted parser diff, broad malformed/corpus validation, and full-volume timeline...
- `#13` `$UsnJrnl` large-scale timeline parser (core-forensics, critical, next `validated`): full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- `#14` JumpList DestList deep parser (core-forensics, critical, next `validated`): OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require validation before commercial parity.
- `#15` ShellBags native hive parser (core-forensics, critical, next `validated`): full binary shell-item payload decoding, bag/node relationship validation against dedicated parsers, transaction-log replay, deleted/slack ShellBag testimony validation, and corpus validation against dedicated commerc...
- `#16` Prefetch full version parser (core-forensics, critical, next `validated`): full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference decoding.
- `#17` LNK full metadata parser (core-forensics, critical, next `validated`): full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser (core-forensics, critical, next `validated`): deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and report-grade cross-artifact validation.
- `#19` Browser cache/session/extension/sync artifacts (core-forensics, critical, next `validated`): full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, deleted-state validation, and known-answer corpus validation.
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline (core-forensics, critical, next `validated`): browser-version-specific visit-transition semantics, deleted-history recovery, Safari cache/session/deleted-state parity, and large multi-profile timeline validation.
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity (core-forensics, critical, next `validated`): service-side export validation, service schema version tracking, deleted-fragment recovery, and corpus-backed false-positive/false-negative testing.
- `#22` E01/Ex01 fully integrated workflow (core-forensics, critical, next `validated`): broad libewf/Sleuth Kit version matrix, encrypted/malformed/corrupt E01/Ex01 validation, and independent known-answer image corpus reports.
- `#23` RAW/split image robust partition/filesystem handling (core-forensics, critical, next `validated`): large damaged/gapped split-set validation, filesystem-specific known-answer recovery checks, path/timestamp validation, encrypted volume handling, and full partition edge-case coverage.
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish (core-forensics, critical, next `validated`): snapshot/differencing-chain support, encrypted/compressed/corrupt VM disk validation, qemu-img version matrix, hypervisor metadata preservation, and large known-answer corpora.
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support (core-forensics, critical, next `validated`): native AD1/L01/Lx01/AFF/AFF4/XVA parsing, metadata/deleted-entry validation, encrypted/compressed container handling, vendor export known-answer tests, and independent vendor/tool-version diff signoff.

## 70-Goal Commercial Uplift Plan

- Status: `active`
- Selected goals: `70`/`70`
- Batch size: `5`
- Batch count: `14`
- Current readiness score: `90/100`

### Large Data Strategy

- `rule`: Large evidence must be streamed, checkpointed, cursor-paged, and hash-referenced; UI and reports must never require loading all rows.
- `parser_runtime`: Keep Python as orchestration/API/UI glue; move hot EVTX/Registry/ESE/MFT/USN/hash/OCR workers toward Rust or isolated native subprocesses.
- `storage`: Use SQLite/PostgreSQL for case metadata, FTS/Tantivy-style indexes for search, and Parquet/DuckDB-style sidecars for large analytical outputs when needed.
- `api`: Every massive table/search/timeline endpoint should expose cursor tokens, limits, total estimates, and snapshot warnings.
- `ui`: Use virtualized result tables, lazy previews, dedupe collapse, and explicit loading/progress states.
- `proof`: Publish benchmark JSON with hardware profile, evidence size, record count, wall time, peak memory, p95 latency, failures, and resume behavior.

### Five-Item Batches

- Batch `1` (#1, #2, #3, #4, #5) categories `core-forensics`: 5 goals
- Batch `2` (#6, #7, #8, #9, #10) categories `core-forensics`: 5 goals
- Batch `3` (#11, #12, #13, #14, #15) categories `core-forensics`: 5 goals
- Batch `4` (#16, #17, #18, #19, #20) categories `core-forensics`: 5 goals
- Batch `5` (#21, #22, #23, #24, #25) categories `core-forensics`: 5 goals
- Batch `6` (#26, #27, #28, #29, #30) categories `mobile-cloud-apps`: 5 goals
- Batch `7` (#31, #32, #33, #34, #35) categories `mobile-cloud-apps`: 5 goals
- Batch `8` (#36, #37, #38, #39, #40) categories `mobile-cloud-apps`: 5 goals
- Batch `9` (#41, #42, #43, #44, #45) categories `mobile-cloud-apps`: 5 goals
- Batch `10` (#81, #82, #83, #84, #85) categories `validation-legal`: 5 goals
- Batch `11` (#86, #87, #88, #89, #90) categories `validation-legal`: 5 goals
- Batch `12` (#91, #92, #93, #94, #95) categories `validation-legal`: 5 goals
- Batch `13` (#96, #97, #98, #99, #100) categories `validation-legal`: 5 goals
- Batch `14` (#66, #67, #68, #69, #70) categories `performance-large-scale`: 5 goals

### First Goals

- Rank `1` batch `1` `#1` Native EVTX BinXML full parsing: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: complete provider-specific BinXML grammar coverage and independent corpus validation.
- Rank `2` batch `1` `#2` EVTX event template/message rendering: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: Resolve validation blockers: external-validation-or-infrastructure-required, known-answer-or-independent-validation-required, native-parser-depth-required
- Rank `3` batch `1` `#3` EVTX deleted/corrupt record recovery validation: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: large validation corpus coverage for real-world deleted EVTX slack and corrupt chunk edge cases.
- Rank `4` batch `1` `#4` Registry hive full key tree reconstruction: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: actual transaction-log replay engine, trusted RECmd/Registry Explorer replay diffs, and broad corpus validation across malformed/large hives.
- Rank `5` batch `1` `#5` Registry deleted key/value recovery: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: deleted-key/value testimony validation against full hive allocator state, transaction logs, and a labeled deleted-cell corpus.
- Rank `6` batch `2` `#6` SAM/SECURITY/SYSTEM account and permission deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction...
- Rank `7` batch `2` `#7` Amcache parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- Rank `8` batch `2` `#8` ShimCache/AppCompatCache parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: native binary AppCompatCache layout decoding across Windows versions, AppCompatCacheParser/RECmd row-level diffs, and broad OS-build known-answer validation.
- Rank `9` batch `2` `#9` BAM/DAM execution parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: native SYSTEM hive binary value interpretation and broad version validation.
- Rank `10` batch `2` `#10` SRUM full ESE table parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full native ESE catalog/table/page decoding, page checksum verification beyond header/page-size checks, and row-level timestamp/counter extraction.
- Rank `11` batch `3` `#11` Windows.edb full ESE parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- Rank `12` batch `3` `#12` `$MFT` full attribute parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full-volume attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, trusted parser diff,...
- Rank `13` batch `3` `#13` `$UsnJrnl` large-scale timeline parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- Rank `14` batch `3` `#14` JumpList DestList deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require v...
- Rank `15` batch `3` `#15` ShellBags native hive parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full binary shell-item payload decoding, bag/node relationship validation against dedicated parsers, transaction-log replay, deleted/slack ShellBag testimony...
- Rank `16` batch `4` `#16` Prefetch full version parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference de...
- Rank `17` batch `4` `#17` LNK full metadata parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- Rank `18` batch `4` `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and...
- Rank `19` batch `4` `#19` Browser cache/session/extension/sync artifacts: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, delete...
- Rank `20` batch `4` `#20` Chrome/Edge/Firefox/Safari unified browser timeline: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: browser-version-specific visit-transition semantics, deleted-history recovery, Safari cache/session/deleted-state parity, and large multi-profile timeline va...

## Required Release Evidence

- `core-parser-known-answer-corpus`: known-answer corpus, external parser comparison, source hashes, offset-level diffs, reviewer sign-off
- `mobile-cloud-schema-validation`: authorized export samples, app/provider schema versions, deleted/encrypted-store limitations, validation matrix
- `large-case-stress-results`: hardware profile, run logs, peak memory, p95 latency, failure thresholds, reproducibility notes
- `legal-validation-package`: NIST-style known-answer results, chain-of-custody records, audit hash chain, independent validation report
- `commercial-release-operations`: signed installers, notarization, CI scans, support SLA, staffed escalation, admin deployment proof

## Critical And High Non-Commercial Items

- `#1` Native EVTX BinXML full parsing (Partial++, critical): must label as validation-required before report testimony
- `#2` EVTX event template/message rendering (Partial++, critical): must label as validation-required before report testimony
- `#3` EVTX deleted/corrupt record recovery validation (Partial++, critical): must label as validation-required before report testimony
- `#4` Registry hive full key tree reconstruction (Partial++, critical): must label as validation-required before report testimony
- `#5` Registry deleted key/value recovery (Partial++, critical): must label as validation-required before report testimony
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser (Partial++ with explicit commercial gate, critical): must label as validation-required before report testimony
- `#7` Amcache parser (Partial++ with explicit commercial gate, critical): must label as validation-required before report testimony
- `#8` ShimCache/AppCompatCache parser (Partial++ with explicit commercial gate, critical): must label as validation-required before report testimony
- `#9` BAM/DAM execution parser (Partial++ with explicit commercial gate, critical): must label as validation-required before report testimony
- `#10` SRUM full ESE table parser (Partial++ with explicit commercial gate, critical): must label as validation-required before report testimony
- `#11` Windows.edb full ESE parser (Partial++, critical): must label as validation-required before report testimony
- `#12` `$MFT` full attribute parser (Partial++, critical): must label as validation-required before report testimony
- `#13` `$UsnJrnl` large-scale timeline parser (Partial++, critical): must label as validation-required before report testimony
- `#14` JumpList DestList deep parser (Partial++, critical): must label as validation-required before report testimony
- `#15` ShellBags native hive parser (Partial++, critical): must label as validation-required before report testimony
- `#16` Prefetch full version parser (Partial++, critical): must label as validation-required before report testimony
- `#17` LNK full metadata parser (Partial++, critical): must label as validation-required before report testimony
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser (Partial++, critical): must label as validation-required before report testimony
- `#19` Browser cache/session/extension/sync artifacts (Partial++, critical): must label as validation-required before report testimony
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline (Partial++, critical): must label as validation-required before report testimony
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity (Partial++, critical): must label as validation-required before report testimony
- `#22` E01/Ex01 fully integrated workflow (Partial++, critical): must label as validation-required before report testimony
- `#23` RAW/split image robust partition/filesystem handling (Partial++, critical): must label as validation-required before report testimony
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish (Partial++, critical): must label as validation-required before report testimony
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support (Partial++ with explicit export-first gate and internal validated fixture, critical): must label as validation-required before report testimony
- `#26` Cellebrite/XRY/GrayKey/AXIOM export deep import (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#27` iOS backup parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#28` iOS keychain/artifact parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#29` Android backup/artifact parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#30` Android app package/data parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#31` KakaoTalk parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#32` WhatsApp parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#33` Telegram parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#34` Signal parser (Partial++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#35` WeChat/LINE/Discord/Instagram and extended messenger parser (Partial+++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#36` Email PST/OST full mailbox parser (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#37` Gmail/Google Takeout deep parser (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#38` Apple iCloud export parser (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#39` Microsoft 365/OneDrive/Teams export parser (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#40` Cloud API acquisition workflow (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#41` Cloud token/credential secure handling (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#42` Browser password/cookie/session artifact handling with strict legal warning (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#43` Mobile app media/message timeline correlation (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#44` Contact/call/SMS unified mobile view (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#45` App-specific known schema version management (Partial++++ with report-grade validation plan, high): must label as validation-required before report testimony
- `#81` NIST CFReDS/CFTT based known-answer tests (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#82` Parser-specific fixture corpus (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#83` Parser-specific false positive/false negative documentation (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#84` Independent validation report (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#85` Tool validation package automation hardening (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#86` Chain-of-custody full workflow (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#87` Evidence acquisition hash workflow (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#88` Analyst action immutable audit log (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#89` Report reproducibility: same input, same output (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#90` Report item source provenance completeness (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#91` Parser confidence scoring (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#92` Validation-required warning UX (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#93` Legal limitation statement per artifact (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#94` Court exhibit export package (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#95` External tool version capture (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#96` Write-blocker/acquisition metadata recording (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#97` Timezone normalization validation (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#98` Clock skew analysis (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#99` Evidence contamination warning (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#100` Tamper-evident audit bundle (Partial+++ with report-grade validation plan and internal validated fixture, high): must attach legal/known-answer validation evidence

## All Non-Commercial Items

- `#1` Native EVTX BinXML full parsing (Partial++, core-forensics, highest `usable`, next `validated`): complete provider-specific BinXML grammar coverage and independent corpus validation.
- `#2` EVTX event template/message rendering (Partial++, core-forensics, highest `usable`, next `validated`): must label as validation-required before report testimony
- `#3` EVTX deleted/corrupt record recovery validation (Partial++, core-forensics, highest `usable`, next `validated`): large validation corpus coverage for real-world deleted EVTX slack and corrupt chunk edge cases.
- `#4` Registry hive full key tree reconstruction (Partial++, core-forensics, highest `usable`, next `validated`): actual transaction-log replay engine, trusted RECmd/Registry Explorer replay diffs, and broad corpus validation across malformed/large hives.
- `#5` Registry deleted key/value recovery (Partial++, core-forensics, highest `usable`, next `validated`): deleted-key/value testimony validation against full hive allocator state, transaction logs, and a labeled deleted-cell corpus.
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction-log validation.
- `#7` Amcache parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- `#8` ShimCache/AppCompatCache parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): native binary AppCompatCache layout decoding across Windows versions, AppCompatCacheParser/RECmd row-level diffs, and broad OS-build known-answer validation.
- `#9` BAM/DAM execution parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): native SYSTEM hive binary value interpretation and broad version validation.
- `#10` SRUM full ESE table parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full native ESE catalog/table/page decoding, page checksum verification beyond header/page-size checks, and row-level timestamp/counter extraction.
- `#11` Windows.edb full ESE parser (Partial++, core-forensics, highest `usable`, next `validated`): full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- `#12` `$MFT` full attribute parser (Partial++, core-forensics, highest `usable`, next `validated`): full-volume attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, trusted parser diff, broad malformed/corpus validation, and full-volume timeline...
- `#13` `$UsnJrnl` large-scale timeline parser (Partial++, core-forensics, highest `usable`, next `validated`): full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- `#14` JumpList DestList deep parser (Partial++, core-forensics, highest `usable`, next `validated`): OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require validation before commercial parity.
- `#15` ShellBags native hive parser (Partial++, core-forensics, highest `usable`, next `validated`): full binary shell-item payload decoding, bag/node relationship validation against dedicated parsers, transaction-log replay, deleted/slack ShellBag testimony validation, and corpus validation against dedicated commerc...
- `#16` Prefetch full version parser (Partial++, core-forensics, highest `usable`, next `validated`): full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference decoding.
- `#17` LNK full metadata parser (Partial++, core-forensics, highest `usable`, next `validated`): full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser (Partial++, core-forensics, highest `usable`, next `validated`): deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and report-grade cross-artifact validation.
- `#19` Browser cache/session/extension/sync artifacts (Partial++, core-forensics, highest `usable`, next `validated`): full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, deleted-state validation, and known-answer corpus validation.
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline (Partial++, core-forensics, highest `usable`, next `validated`): browser-version-specific visit-transition semantics, deleted-history recovery, Safari cache/session/deleted-state parity, and large multi-profile timeline validation.
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity (Partial++, core-forensics, highest `usable`, next `validated`): service-side export validation, service schema version tracking, deleted-fragment recovery, and corpus-backed false-positive/false-negative testing.
- `#22` E01/Ex01 fully integrated workflow (Partial++, core-forensics, highest `usable`, next `validated`): broad libewf/Sleuth Kit version matrix, encrypted/malformed/corrupt E01/Ex01 validation, and independent known-answer image corpus reports.
- `#23` RAW/split image robust partition/filesystem handling (Partial++, core-forensics, highest `usable`, next `validated`): large damaged/gapped split-set validation, filesystem-specific known-answer recovery checks, path/timestamp validation, encrypted volume handling, and full partition edge-case coverage.
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish (Partial++, core-forensics, highest `usable`, next `validated`): snapshot/differencing-chain support, encrypted/compressed/corrupt VM disk validation, qemu-img version matrix, hypervisor metadata preservation, and large known-answer corpora.
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support (Partial++ with explicit export-first gate and internal validated fixture, core-forensics, highest `usable`, next `validated`): native AD1/L01/Lx01/AFF/AFF4/XVA parsing, metadata/deleted-entry validation, encrypted/compressed container handling, vendor export known-answer tests, and independent vendor/tool-version diff signoff.
- `#26` Cellebrite/XRY/GrayKey/AXIOM export deep import (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): external Cellebrite/XRY/GrayKey/AXIOM version-specific schemas, deleted-record semantics, original acquisition hash review, trusted vendor diff, and independent known-answer validation.
- `#27` iOS backup parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): encrypted backup handling, app DB parsing, deleted records, trusted parser diff, and known-answer validation.
- `#28` iOS keychain/artifact parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): validated protected-data workflow outside core, trusted diff, and legal/authorization package.
- `#29` Android backup/artifact parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): app-specific DB schemas, native Android backup payload decoding, trusted diff, and deleted/encrypted stores.
- `#30` Android app package/data parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): binary manifest decoding, DEX control-flow analysis, signing trust, trusted APK diffs, and malware validation.
- `#31` KakaoTalk parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): post-2025-08 KakaoTalk known-answer corpus, schema-version-specific parser mapping, deleted/read-state validation, attachment byte validation, independent validation, and proprietary-key-free operational guidance.
- `#32` WhatsApp parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): encrypted `crypt*` backups, contacts/calls/media recovery, deleted records, media-byte validation, schema/ack semantics corpus validation, trusted diff, and independent signoff.
- `#33` Telegram parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): Telegram Desktop encrypted/local map decoding, cloud export schema coverage, account attribution validation, secret/edited/deleted semantics, cache/media byte validation, trusted diff, and independent signoff.
- `#34` Signal parser (Partial++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): encrypted backup and lawful SQLCipher authority workflow, recipient/thread schema validation, attachment-byte locality, deleted/disappearing/delivery/read-state corpus validation, trusted diff, and independent signoff.
- `#35` WeChat/LINE/Discord/Instagram and extended messenger parser (Partial+++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): app-specific encrypted stores, schema drift, media recovery, reactions/read receipts completeness, ephemeral/secret chat validation, trusted diff, service coverage matrix, and known-answer validation.
- `#36` Email PST/OST full mailbox parser (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): native PST/OST folder/message/deleted-item decoding, full MSG MAPI properties, DKIM/ARC/S/MIME/OpenPGP validation, threading validation, corrupt-store recovery, trusted external diff corpus, and mailbox corpus testing.
- `#37` Gmail/Google Takeout deep parser (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): full Takeout product matrix, provider-native Gmail conversation diff, duplicate/timezone/thread validation corpus, Photos sidecar/EXIF merge, archive split/expiration handling, deleted/retention semantics, and provide...
- `#38` Apple iCloud export parser (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): full Apple data export schemas, iCloud Photos albums/EXIF correlation, device inventory, shared album fidelity/comments/likes, third-party iCloud containers, Advanced Data Protection limits, provider-native diffs, and...
- `#39` Microsoft 365/OneDrive/Teams export parser (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): Graph/eDiscovery export variants, Teams Cosmos DB vs Exchange compliance record reconciliation, retention/deleted-item semantics, provider-native Teams attachment/reaction completeness, SharePoint permissions, provide...
- `#40` Cloud API acquisition workflow (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): OAuth device flows, token vaulting/rotation, provider-native pagination/delta known-answer validation, throttling/backoff validation, provider-specific collectors, and legal hold/export package validation.
- `#41` Cloud token/credential secure handling (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): actual token vaulting, controlled reveal workflow, rotation enforcement, RBAC enforcement, trusted authority/vault diff, and enterprise secret-store integration.
- `#42` Browser password/cookie/session artifact handling with strict legal warning (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): audited opt-in reveal workflow, DPAPI/keychain integration where lawful, browser-version validation corpus, RBAC-controlled reveal enforcement, and independent review evidence.
- `#43` Mobile app media/message timeline correlation (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): cross-source/device-wide timeline merge, timezone normalization, attachment byte recovery, trusted vendor/native timeline diff, and known-answer validation.
- `#44` Contact/call/SMS unified mobile view (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): UI-specific grouped mobile view, persistent dedupe/entity merge-split decisions, device-wide identity resolution, cross-app known-answer validation, trusted actor diff, and independent review.
- `#45` App-specific known schema version management (Partial++++ with report-grade validation plan, mobile-cloud-apps, highest `usable`, next `validated`): migration tests, schema diff fixtures, upgrade/deleted-state validation, trusted migration diffs, independent review, and operator-approved release-gated parser support policy.
- `#46` Large-result clustering (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): persistent cluster review state, near-duplicate text/media clustering, hand-labeled trusted diff, false-positive corpus, large-case performance validation, and independent review.
- `#47` Entity view: people, accounts, email, phone, IP, and domain (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): person/account resolution, false-positive tuning, first/last seen across full case index, persistent analyst merge/split decisions, merge/split workflow, trusted entity review diff, and independent review.
- `#48` Graph view: account-file-URL-time relationships (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): interactive graph canvas, time-edge semantics, persistent saved layouts, server-side graph paging API, trusted source-citation diff, large-case graph validation, and independent review.
- `#49` Unified timeline correlation (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): full Case DB timeline join, trusted timezone/skew validation, review annotation overlays, cursor-paged timeline API, trusted timeline diff, and large-case chronology validation.
- `#50` Incident hypothesis/workbook feature (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): editable Case DB workbook, source-row evidence attachment workflow, reviewer assignments, report export sections, version history, and trusted workbook rubric validation.
- `#51` Reviewer assignment/status workflow (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): role-based assignment queues, SLA dashboards, notifications, conflict-aware multi-user review, reviewer SOP signoff, and trusted analyst review log diff.
- `#52` A/B/C multi-evidence compare (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): web-side three-pane compare UI, binary/hex/image/SQLite/mailbox semantic diff, timeline-aware compare, persistent Case DB compare notes, reviewed citation signoff, and trusted expected-diff manifests.
- `#53` Raw/source hex viewer (Partial++++ with report-grade validation plan, search-analysis-ux, highest `usable`, next `validated`): interactive full-file jump-to-offset UI, copy-safe byte selection UI, trusted offset manifest diff, full-file hash display inline for very large files, sector/partition-aware navigation, and external byte-level citati...
- `#54` SQLite/table specialized viewer (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): browser E2E validation for pagination UI, arbitrary-query builder intentionally not allowed, virtual table/FTS ranking, deleted-row/WAL recovery, trusted sqlite3 diff, export-selected-rows workflow, and large SQLite c...
- `#55` Email conversation viewer (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): full PST/OST/MSG native conversations, deleted item recovery, native mailbox attachment extraction, message-ID graph validation, trusted mail-client thread/export diff, mailbox corpus validation, and report citation e...
- `#56` Image gallery review mode (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): dedicated virtualized multi-image grid, persistent gallery tags, ML visual similarity clustering UI, sensitive/deepfake classifier validation, trusted image manifest diff, and selected-image report export flow.
- `#57` Video/audio preview and transcript (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): video duration extraction, waveform/thumb previews, hardened playback sandboxing, trusted cue/alignment diff, manual playback/ASR validation, transcript alignment corpus, and report export integration for selected cue...
- `#58` OCR queue manager (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): actual OCR worker execution, engine-specific retry logs, engine version capture, confidence calibration corpus, browser-side queue state editing, trusted engine/sidecar diff, and per-case OCR job persistence in Case DB.
- `#59` Korean OCR/translation workflow hardening (Partial++++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): built-in Korean OCR engine execution, machine translation worker integration, OCR engine/version language-pack logs, confidence calibration by engine, trusted Korean OCR/translation review diff, and certified translat...
- `#60` Search hit deduplication (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): persistent Case DB duplicate suppression decisions, fuzzy near-duplicate text corpus, perceptual media duplicate corpus, OCR duplicate corpus, trusted duplicate manifest validation, and large-case dedup performance va...
- `#61` Fuzzy search/stemming/regex proximity search (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): source-row hash verification for report candidates, multilingual relevance corpus, tuned FP/FN metrics, independent trusted query-hit manifest diff corpus, large-case search performance validation, and full browser qu...
- `#62` Saved keyword pack library (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): full per-case pack editing UI/audit, signed/versioned pack distribution, release-review records, language/domain-specific pack validation, trusted expansion manifest corpus, and large-case keyword-pack performance val...
- `#63` IOC/TI enrichment plugin (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): signed feed packages, STIX/TAXII/provider validation, configurable confidence decay, feed trust workflow, trusted enrichment manifest corpus, false-positive/source-correlation corpus, and external TI governance.
- `#64` Report citation manager (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): exhibit numbering/editor workflow, jurisdiction templates, trusted citation manifest corpus, source-hash/parser-version completeness validation across every parser, and reviewer signoff corpus.
- `#65` Evidence selection/version history (Partial+++ with report-grade validation plan and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): signed multi-user history, trusted history manifest corpus/diff, conflict handling, independent append-only trigger review, reviewer identity/RBAC corpus, and history replay corpus.
- `#66` 100k/1M/10M record benchmark (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): published 100k/1M/10M representative hardware runs, trusted threshold manifests, release-approved threshold comparisons, and independent reproduction logs.
- `#67` 1TB-10TB evidence stress test (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): actual published 1TB/5TB/10TB hardware runs, trusted run-log manifests, bottleneck traces, and independent reproduction logs.
- `#68` Incremental indexing (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): full large-file content-hash delta reindex, row-level stage delta reuse, trusted reuse manifests, multi-million-file replay, Case DB dedup validation, cross-platform fingerprint semantics validation, and large-case va...
- `#69` Background job queue (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): distributed workers, externally trusted transition logs, parser-level progress percentages, resource telemetry under load, cooperative parser-level cancellation validation under load, and multi-worker retry idempotenc...
- `#70` Stage checkpoint/resume hardening (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): mid-parser checkpointing, failed-stage partial resume validation, trusted checkpoint manifests, long-running replay validation, partial-output cleanup validation, and Case DB resume dedup validation.
- `#71` Parser crash isolation (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): native process sandboxing for every parser, trusted parser crash-corpus manifests, corrupt-input fuzz/crash corpus validation, subprocess crash-boundary validation, long-running corrupt-evidence replay, and cross-plat...
- `#72` Memory cap enforcement (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): hard OS cgroup/job-object limits, per-parser live RSS telemetry, trusted RSS manifests, 1TB+ RSS graphs, platform-specific RSS validation, and allocation-level enforcement validation.
- `#73` Preview sandboxing (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): separate OS sandbox for risky codecs/macros/renderers, trusted active-content no-exec corpus validation, browser exploit corpus, and browser E2E no-exec/no-network validation.
- `#74` Large SQLite/FTS optimization (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): 10M-row query-plan regression, trusted query-plan manifests, deleted-row/WAL replay, browser pagination/query-plan E2E, index-maintenance/vacuum regression, UI virtualization proof, and huge-source-DB corpus validation.
- `#75` Parallel parser scheduler (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): distributed priority scheduler, live per-worker telemetry UI/stream, trusted scheduler manifests, cross-platform worker quota validation, priority-starvation regression, and TB-scale fairness/backpressure validation.
- `#76` File hash cache (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): automatic on-disk cache wiring, trusted hash-cache manifests, large-case hit-ratio validation, cross-platform cache-key semantics, content-addressed lookup mode, and multi-run stale-cache replay.
- `#77` Duplicate file/content detection (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): perceptual media duplicate grouping, trusted external duplicate manifests, analyst suppression workflow validation, large-case dedupe performance validation, near-duplicate text known-answer corpus, and cross-run supp...
- `#78` Artifact pagination/cursor API (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): snapshot-isolated database cursors, trusted external pagination manifests, endpoint-wide compatibility validation, cursor invalidation/replay validation, large-case page latency evidence, and cross-client cursor compa...
- `#79` UI virtualization for massive result tables (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): true recycling virtual scroller, persisted viewport restoration across reloads, trusted browser row-window manifests, browser 100k/1M row-window e2e performance, memory profile, and cross-client virtualization compati...
- `#80` Long-running job cancellation/retry (Partial+++ with report-grade validation plan and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): parser-level cooperative cancellation under long-running load, trusted cancellation/retry transition manifests, partial-output cleanup/resume replay validation, idempotent retry output validation, long-running parser...
- `#81` NIST CFReDS/CFTT based known-answer tests (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): publish real CFReDS/CFTT corpus run outputs, trusted known-answer manifests, parser-scope coverage maps, chain-of-custody rows, independent expected-answer review, and release signoff for each report-grade parser.
- `#82` Parser-specific fixture corpus (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): broader malformed/deleted/native/versioned fixture corpora, parser-version compatibility matrix, release-blocking fixture policy, coverage threshold signoff, broad platform fixture corpus, and trusted fixture corpus m...
- `#83` Parser-specific false positive/false negative documentation (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): quantified FP/FN rates by corpus and parser version, parser-version risk matrix, independent risk-register review, regression threshold policy, and report-wording signoff.
- `#84` Independent validation report (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): actual third-party signed validation report, trusted signoff manifest, and release-owner legal signoff for the shipped release.
- `#85` Tool validation package automation hardening (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): operator-attached test logs, release evidence, trusted validation package manifest, and independent review.
- `#86` Chain-of-custody full workflow (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): signed custody handoff forms, acquisition-device/write-blocker metadata, lab custody policy, full lifecycle stage coverage, and trusted custody event manifests.
- `#87` Evidence acquisition hash workflow (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): whole-device acquisition hash UI, source SHA-256 completeness across all rows, write-blocker/operator metadata capture, hash tool-version logs, and trusted acquisition hash manifests.
- `#88` Analyst action immutable audit log (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): database-level audit append-only enforcement, external notarization/signing, signed audit export bundle, multi-user identity binding, audit retention policy, and trusted audit chain manifests.
- `#89` Report reproducibility: same input, same output (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): end-to-end same-input artifact byte-for-byte report tests across platforms, repeat-run logs, report template/schema version lock, volatile-field normalization review, release-build replay evidence, and trusted report...
- `#90` Report item source provenance completeness (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): all-parser provenance corpus, trusted provenance manifests, final report template review, source-viewer round-trip evidence, offset locator trusted diffs, and parser-version release locks.
- `#91` Parser confidence scoring (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): calibrated parser-specific confidence tables, trusted calibration manifests, cross-tool confidence validation, low-confidence FP/FN corpus, reportability threshold review, and release parser-confidence policy locks.
- `#92` Validation-required warning UX (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): all-table warning badge coverage, trusted warning checklists, UX e2e checks across every table, final report-template warning review, action playbook review, and accessibility warning-badge review.
- `#93` Legal limitation statement per artifact (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): jurisdiction-specific approved wording, trusted wording manifests, formal legal review signoff, artifact-family limitation corpus, report-template limitation rendering review, and analyst acknowledgement workflow.
- `#94` Court exhibit export package (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): signed/notarized exhibit manifests, jurisdiction-specific forms, independent package review, controlled source-file copy bundles, and final archive signature attestation.
- `#95` External tool version capture (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): per-run external parser/import command transcripts, trusted transcript manifests, original tool logs, parser/import transcript corpus, acquisition-tool version linkage, and release environment inventory signoff.
- `#96` Write-blocker/acquisition metadata recording (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): polished web form, write-blocker device logs/integration, signed handoff forms, original acquisition notes, whole-source hash verification logs, acquisition tool-version linkage, and read-only handling policy signoff.
- `#97` Timezone normalization validation (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): source-timezone completeness, parser-specific timezone assumption matrix, multi-source timezone reconciliation, timezone known-answer/DST corpus, and source clock baseline linkage.
- `#98` Clock skew analysis (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): host/device clock baseline, acquisition-time baseline, trusted external timestamp comparison, timezone-normalization linkage, trusted baseline manifests, multi-device skew model, and known-answer clock-skew corpus.
- `#99` Evidence contamination warning (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): acquisition-time mtime baseline, write-blocker integration, source read-only proof, output-path policy enforcement, trusted contamination checklist, known-answer contamination corpus, and reviewer signoff.
- `#100` Tamper-evident audit bundle (Partial+++ with report-grade validation plan and internal validated fixture, validation-legal, highest `usable`, next `validated`): detached signature, notarization/release attestation, independent recompute log, final archive hash manifest, signing-key custody record, long-term verification policy, and trusted signature attestations.
- `#101` Windows signed installer (Partial++++ with repo evidence, report-grade validation plan, and deployment readiness matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#102` macOS notarized package (Partial++++ with repo evidence, report-grade validation plan, and deployment readiness matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#103` Linux package/deb/rpm/AppImage (Partial++++ with report-grade validation plan and deployment readiness matrix, deployment-operations, highest `usable`, next `validated`): actual deb/rpm/AppImage artifact builds, clean-container build logs, package signing policy, dependency resolution proof, and distro smoke logs.
- `#104` Auto-update channel (Partial++++ with report-grade validation plan and deployment readiness matrix, deployment-operations, highest `usable`, next `validated`): hosted signed update service, update client/channel resolver, signed update manifest, rollback test, release artifact signatures, and trusted signed-channel evidence.
- `#105` Crash reporting (Partial+++++++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): run both scripts on the actual signed/release build host, attach operator export/dashboard smoke evidence, and attach independent reviewer/lab signoff.
- `#106` Telemetry-free/local-only enterprise mode (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): trusted network-egress capture, remote-bind auth smoke, release-host local-only smoke, deployment-policy signoff, and independent egress review.
- `#107` License/activation system, if needed (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): release-host offline activation smoke, evidence-touch audit, key custody/signing review, independent license authority review, and paid activation workflow if the project needs commercialization.
- `#108` Role-based access control (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): per-action RBAC enforcement in a real multi-user server, export-control enforcement smoke, multi-user identity binding, release-host RBAC smoke, and independent RBAC review.
- `#109` Multi-user case server (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): implementation of that server, identity-provider smoke, case locking/conflict tests, concurrency/migration tests, release-host smoke, and independent security architecture review.
- `#110` Collaboration audit trail (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): database-enforced append-only audit, multi-user identities, conflict handling tests, release-host collaboration audit smoke, and independent collaboration audit review.
- `#111` Backup/restore/migration (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): multi-version migration test corpus, scheduled backup automation, release-host backup/restore smoke, and independent restore rehearsal review.
- `#112` Release notes/changelog discipline (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): enforced changelog gate in CI, release owner review, migration/validation state review, release-host smoke log, checksum publication review, and independent wording review.
- `#113` LTS branch/hotfix policy (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): maintained branch proof, hotfix backport validation transcript, emergency patch drill, release owner hotfix signoff, release-host smoke, and independent LTS policy review.
- `#114` Support SLA documentation (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): actual staffed support desk, contractual SLA execution, support ticket samples, release-host support-flow smoke, and independent SLA review remain operator-owned.
- `#115` Training curriculum (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): real training delivery logs, scoring rubric results, instructor signoff, trainee completion records, lab environment proof, and independent training review remain operator-owned.
- `#116` Analyst quickstart lab (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): real analyst lab run logs, expected-output manifests, reviewer bundle verification transcript, cross-platform run evidence, and independent quickstart review remain operator-owned.
- `#117` Admin deployment guide (Partial+++ with report-grade validation plan, deployment-operations, highest `usable`, next `validated`): fresh deployment proof, operator acceptance signoff, clean-machine install smoke, upgrade/rollback drill, auth/network proof, backup/restore drill, logging policy proof, and security deployment review remain operator-...
- `#118` Security hardening review (Partial++++ with report-grade validation plan, control matrix, release self-review, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): independent AppSec review, threat-model review, path/auth/export/crash/parser hardening evidence, and release-host hardening smoke.
- `#119` Malicious evidence sandboxing (Partial+++++ with report-grade validation plan, control matrix, parser isolation smoke, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): OS-level process sandbox for parsers, trusted malicious corpus/fuzz validation, active-content renderer escape tests, quarantine workflow proof, release-host malicious-sandbox smoke, and independent review.
- `#120` Dependency vulnerability monitoring (Partial+++++ with report-grade validation plan, dependency matrix, scheduled workflow contract, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): attach an actual CI run log/artifact URL, publish or archive the SBOM with release checksums, capture scanner/vulnerability DB versions, prove artifact checksum linkage, and complete trusted exception/independent revi...

## Operator Guidance

- Use RapidTriage as a triage/review accelerator, not as a sole AXIOM/WISDOM replacement.
- Any item marked non-commercial must keep validation_required/reportability warnings in artifacts and reports.
- For testimony-grade conclusions, attach trusted-tool comparison output and known-answer validation evidence.
- Do not advertise signed installer, notarized package, multi-user server, or support SLA until external evidence exists.
