# RapidTriage Commercial Readiness Gate

- Generated at: `2026-05-11T04:14:10.092167+00:00`
- Backlog: `/Users/shinyoohag/rapidforensic/repo/docs/rapidtriage-commercial-parity-backlog.md`
- Status: `commercial-gaps-present`
- Commercial claim allowed: `False`
- Readiness score: `88/100`
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
- Internally actionable next steps: `119`
- External/trusted evidence required: `112`
- Lane counts: `{'external-operator-evidence': 98, 'native-parser-depth': 65, 'known-answer-validation': 118, 'large-scale-performance': 20, 'platform-release-evidence': 16, 'security-legal-assurance': 41}`
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

- `#104` Auto-update channel: lane `platform-release-evidence`, next `validated`

## Internal vs External Blockers

- Profile: `blocker-separation-profile-v1`
- Immediate queue item: `#10`
- Internal-only blockers: `8`
- Internal then external blockers: `111`
- External-only blockers: `1`
- Internal work available: `119`
- External/trusted evidence required: `112`
- Rule: Do internal implementation/fixture/reporting work first, but keep commercial_grade=false until the paired trusted-tool, independent-review, signed-platform, large-hardware, or staffed-support evidence is attached.

### Next Internal Batch

- `#47` Entity view: people, accounts, email, phone, IP, and domain: Attach fixture/corpus manifests and pass/fail assertions that map directly to item numbers.
- `#50` Incident hypothesis/workbook feature: Attach fixture/corpus manifests and pass/fail assertions that map directly to item numbers.
- `#52` A/B/C multi-evidence compare: Attach fixture/corpus manifests and pass/fail assertions that map directly to item numbers.
- `#58` OCR queue manager: Implement or deepen parser logic, then lock row-level expected output with fixtures.
- `#107` License/activation system, if needed: Attach fixture/corpus manifests and pass/fail assertions that map directly to item numbers.

### Next External Evidence Batch

- `#104` Auto-update channel: Generate packaging manifests internally; final commercial gate needs signed platform smoke evidence.
- `#1` Native EVTX BinXML full parsing: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#2` EVTX event template/message rendering: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#3` EVTX deleted/corrupt record recovery validation: Record the blocker explicitly and collect the external run/signoff artifact when available.
- `#4` Registry hive full key tree reconstruction: Record the blocker explicitly and collect the external run/signoff artifact when available.

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
- `#79` ui-virtualization: next `validated`, trusted manifest `ui-virtualization-manifest`, outputs `api pagination.ui_virtualization, ui-virtualization-manifest-v1, web bounded row rendering notice, web virtual row-window controls`
- `#80` cancel-retry: next `validated`, trusted manifest `cancellation-retry-transition-manifest`, outputs `run job cancellation_retry_assessment, cancellation-retry-manifest-v1, retry_lineage_profile, partial_output_policy, job step operational_gap_ids`

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
- `#4` Registry hive full key tree reconstruction (core-forensics, critical, next `validated`): transaction-log replay and broad corpus validation across malformed/large hives.
- `#5` Registry deleted key/value recovery (core-forensics, critical, next `validated`): deleted-key/value testimony validation against full hive allocator state and transaction logs.
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser (core-forensics, critical, next `validated`): full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction-log validation.
- `#7` Amcache parser (core-forensics, critical, next `validated`): full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- `#8` ShimCache/AppCompatCache parser (core-forensics, critical, next `validated`): native binary AppCompatCache layout decoding across Windows versions.
- `#9` BAM/DAM execution parser (core-forensics, critical, next `validated`): native SYSTEM hive binary value interpretation and broad version validation.
- `#10` SRUM full ESE table parser (core-forensics, critical, next `validated`): full native ESE catalog/table/page decoding, page checksum validation, and row-level timestamp/counter extraction.
- `#11` Windows.edb full ESE parser (core-forensics, critical, next `validated`): full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- `#12` `$MFT` full attribute parser (core-forensics, critical, next `validated`): full attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, broad malformed/corpus validation, and full-volume timeline validation.
- `#13` `$UsnJrnl` large-scale timeline parser (core-forensics, critical, next `validated`): full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- `#14` JumpList DestList deep parser (core-forensics, critical, next `validated`): OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require validation before commercial parity.
- `#15` ShellBags native hive parser (core-forensics, critical, next `validated`): full binary shell-item payload decoding, bag/node relationship validation, transaction-log replay, deleted/slack ShellBag testimony validation, and corpus validation against dedicated commercial parsers.
- `#16` Prefetch full version parser (core-forensics, critical, next `validated`): full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference decoding.
- `#17` LNK full metadata parser (core-forensics, critical, next `validated`): full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser (core-forensics, critical, next `validated`): deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and report-grade cross-artifact validation.
- `#19` Browser cache/session/extension/sync artifacts (core-forensics, critical, next `validated`): full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, and known-answer corpus validation.
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline (core-forensics, critical, next `validated`): browser-version-specific visit-transition semantics, deleted-history recovery, Safari download/session/cache parity, and large multi-profile timeline validation.
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity (core-forensics, critical, next `validated`): service-side export validation, service schema version tracking, deleted-fragment recovery, and corpus-backed false-positive/false-negative testing.
- `#22` E01/Ex01 fully integrated workflow (core-forensics, critical, next `validated`): broad libewf/Sleuth Kit version matrix, encrypted/malformed/corrupt E01/Ex01 validation, and independent known-answer image corpus reports.
- `#23` RAW/split image robust partition/filesystem handling (core-forensics, critical, next `validated`): large damaged/gapped split-set validation, filesystem-specific known-answer recovery checks, path/timestamp validation, encrypted volume handling, and full partition edge-case coverage.
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish (core-forensics, critical, next `validated`): snapshot/differencing-chain support, encrypted/compressed/corrupt VM disk validation, qemu-img version matrix, hypervisor metadata preservation, and large known-answer corpora.
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support (core-forensics, critical, next `validated`): native AD1/L01/Lx01/AFF/AFF4/XVA parsing, metadata/deleted-entry validation, encrypted/compressed container handling, and vendor export known-answer tests.

## 70-Goal Commercial Uplift Plan

- Status: `active`
- Selected goals: `70`/`70`
- Batch size: `5`
- Batch count: `14`
- Current readiness score: `88/100`

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
- Rank `4` batch `1` `#4` Registry hive full key tree reconstruction: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: transaction-log replay and broad corpus validation across malformed/large hives.
- Rank `5` batch `1` `#5` Registry deleted key/value recovery: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: deleted-key/value testimony validation against full hive allocator state and transaction logs.
- Rank `6` batch `2` `#6` SAM/SECURITY/SYSTEM account and permission deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction...
- Rank `7` batch `2` `#7` Amcache parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- Rank `8` batch `2` `#8` ShimCache/AppCompatCache parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: native binary AppCompatCache layout decoding across Windows versions.
- Rank `9` batch `2` `#9` BAM/DAM execution parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: native SYSTEM hive binary value interpretation and broad version validation.
- Rank `10` batch `2` `#10` SRUM full ESE table parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full native ESE catalog/table/page decoding, page checksum validation, and row-level timestamp/counter extraction.
- Rank `11` batch `3` `#11` Windows.edb full ESE parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- Rank `12` batch `3` `#12` `$MFT` full attribute parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, broad malformed/corpus valid...
- Rank `13` batch `3` `#13` `$UsnJrnl` large-scale timeline parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- Rank `14` batch `3` `#14` JumpList DestList deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require v...
- Rank `15` batch `3` `#15` ShellBags native hive parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full binary shell-item payload decoding, bag/node relationship validation, transaction-log replay, deleted/slack ShellBag testimony validation, and corpus va...
- Rank `16` batch `4` `#16` Prefetch full version parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference de...
- Rank `17` batch `4` `#17` LNK full metadata parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- Rank `18` batch `4` `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and...
- Rank `19` batch `4` `#19` Browser cache/session/extension/sync artifacts: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, and kn...
- Rank `20` batch `4` `#20` Chrome/Edge/Firefox/Safari unified browser timeline: Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence. Remaining: browser-version-specific visit-transition semantics, deleted-history recovery, Safari download/session/cache parity, and large multi-profile timeline validat...

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
- `#26` Cellebrite/XRY/GrayKey/AXIOM export deep import (Partial++, high): must label as validation-required before report testimony
- `#27` iOS backup parser (Partial++, high): must label as validation-required before report testimony
- `#28` iOS keychain/artifact parser (Partial++, high): must label as validation-required before report testimony
- `#29` Android backup/artifact parser (Partial++, high): must label as validation-required before report testimony
- `#30` Android app package/data parser (Partial++, high): must label as validation-required before report testimony
- `#31` KakaoTalk parser (Partial++, high): must label as validation-required before report testimony
- `#32` WhatsApp parser (Partial++, high): must label as validation-required before report testimony
- `#33` Telegram parser (Partial++, high): must label as validation-required before report testimony
- `#34` Signal parser (Partial++, high): must label as validation-required before report testimony
- `#35` WeChat/LINE/Discord/Instagram and extended messenger parser (Partial+++, high): must label as validation-required before report testimony
- `#36` Email PST/OST full mailbox parser (Partial+++, high): must label as validation-required before report testimony
- `#37` Gmail/Google Takeout deep parser (Partial+++, high): must label as validation-required before report testimony
- `#38` Apple iCloud export parser (Partial+++, high): must label as validation-required before report testimony
- `#39` Microsoft 365/OneDrive/Teams export parser (Partial+++, high): must label as validation-required before report testimony
- `#40` Cloud API acquisition workflow (Partial+++, high): must label as validation-required before report testimony
- `#41` Cloud token/credential secure handling (Partial+++ with explicit commercial gate and internal validated fixture, high): must label as validation-required before report testimony
- `#42` Browser password/cookie/session artifact handling with strict legal warning (Partial+++ with explicit commercial gate and internal validated fixture, high): must label as validation-required before report testimony
- `#43` Mobile app media/message timeline correlation (Partial+++ with explicit commercial gate and internal validated fixture, high): must label as validation-required before report testimony
- `#44` Contact/call/SMS unified mobile view (Partial+++ with explicit commercial gate and internal validated fixture, high): must label as validation-required before report testimony
- `#45` App-specific known schema version management (Partial+++ with explicit commercial gate and internal validated fixture, high): must label as validation-required before report testimony
- `#81` NIST CFReDS/CFTT based known-answer tests (Partial++ with explicit validation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#82` Parser-specific fixture corpus (Partial++ with explicit validation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#83` Parser-specific false positive/false negative documentation (Partial++ with explicit validation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#84` Independent validation report (Partial++ with explicit validation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#85` Tool validation package automation hardening (Partial++ with explicit validation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#86` Chain-of-custody full workflow (Partial++ with explicit custody gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#87` Evidence acquisition hash workflow (Partial++ with explicit hash gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#88` Analyst action immutable audit log (Partial++ with explicit audit gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#89` Report reproducibility: same input, same output (Partial++ with explicit reproducibility gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#90` Report item source provenance completeness (Partial++ with explicit provenance gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#91` Parser confidence scoring (Partial++ with explicit confidence gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#92` Validation-required warning UX (Partial++ with explicit warning gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#93` Legal limitation statement per artifact (Partial++ with explicit limitation gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#94` Court exhibit export package (Partial++ with explicit exhibit gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#95` External tool version capture (Partial++ with explicit tool-version gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#96` Write-blocker/acquisition metadata recording (Partial++ with explicit acquisition gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#97` Timezone normalization validation (Partial++ with explicit timezone gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#98` Clock skew analysis (Partial++ with explicit skew gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#99` Evidence contamination warning (Partial++ with explicit contamination gate and internal validated fixture, high): must attach legal/known-answer validation evidence
- `#100` Tamper-evident audit bundle (Partial++ with explicit tamper-evidence gate and internal validated fixture, high): must attach legal/known-answer validation evidence

## All Non-Commercial Items

- `#1` Native EVTX BinXML full parsing (Partial++, core-forensics, highest `usable`, next `validated`): complete provider-specific BinXML grammar coverage and independent corpus validation.
- `#2` EVTX event template/message rendering (Partial++, core-forensics, highest `usable`, next `validated`): must label as validation-required before report testimony
- `#3` EVTX deleted/corrupt record recovery validation (Partial++, core-forensics, highest `usable`, next `validated`): large validation corpus coverage for real-world deleted EVTX slack and corrupt chunk edge cases.
- `#4` Registry hive full key tree reconstruction (Partial++, core-forensics, highest `usable`, next `validated`): transaction-log replay and broad corpus validation across malformed/large hives.
- `#5` Registry deleted key/value recovery (Partial++, core-forensics, highest `usable`, next `validated`): deleted-key/value testimony validation against full hive allocator state and transaction logs.
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full OS-version validated SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction from native binary attributes, and transaction-log validation.
- `#7` Amcache parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
- `#8` ShimCache/AppCompatCache parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): native binary AppCompatCache layout decoding across Windows versions.
- `#9` BAM/DAM execution parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): native SYSTEM hive binary value interpretation and broad version validation.
- `#10` SRUM full ESE table parser (Partial++ with explicit commercial gate, core-forensics, highest `usable`, next `validated`): full native ESE catalog/table/page decoding, page checksum validation, and row-level timestamp/counter extraction.
- `#11` Windows.edb full ESE parser (Partial++, core-forensics, highest `usable`, next `validated`): full native ESE catalog/table/row decoding, authoritative row-level timestamp/property extraction, and deleted/index-state validation.
- `#12` `$MFT` full attribute parser (Partial++, core-forensics, highest `usable`, next `validated`): full attribute-list extension resolution, report-grade nonresident data-run decoding, path reconstruction across parent records, broad malformed/corpus validation, and full-volume timeline validation.
- `#13` `$UsnJrnl` large-scale timeline parser (Partial++, core-forensics, highest `usable`, next `validated`): full journal replay/correlation, cross-record path reconstruction, and broad known-answer large-corpus pagination validation.
- `#14` JumpList DestList deep parser (Partial++, core-forensics, highest `usable`, next `validated`): OS-version-specific DestList field semantics, deleted-entry recovery, report-grade account attribution, and AppID hash-to-application mapping still require validation before commercial parity.
- `#15` ShellBags native hive parser (Partial++, core-forensics, highest `usable`, next `validated`): full binary shell-item payload decoding, bag/node relationship validation, transaction-log replay, deleted/slack ShellBag testimony validation, and corpus validation against dedicated commercial parsers.
- `#16` Prefetch full version parser (Partial++, core-forensics, highest `usable`, next `validated`): full file metrics, authoritative volume table, trace-chain/directory sections, compressed/malformed corpus validation, and report-grade MFT file-reference decoding.
- `#17` LNK full metadata parser (Partial++, core-forensics, highest `usable`, next `validated`): full shell-item property store semantics, drive/network provider validation, and broad Shell Link known-answer corpus coverage.
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser (Partial++, core-forensics, highest `usable`, next `validated`): deeper Defender/Firewall event semantics, native WMI repository object decoding, TaskCache/security descriptor/history correlation, WER dump/CAB linkage, and report-grade cross-artifact validation.
- `#19` Browser cache/session/extension/sync artifacts (Partial++, core-forensics, highest `usable`, next `validated`): full cache-entry decoding, cookie/session/password decryption with explicit opt-in authority, extension schema interpretation, sync-engine validation, and known-answer corpus validation.
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline (Partial++, core-forensics, highest `usable`, next `validated`): browser-version-specific visit-transition semantics, deleted-history recovery, Safari download/session/cache parity, and large multi-profile timeline validation.
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity (Partial++, core-forensics, highest `usable`, next `validated`): service-side export validation, service schema version tracking, deleted-fragment recovery, and corpus-backed false-positive/false-negative testing.
- `#22` E01/Ex01 fully integrated workflow (Partial++, core-forensics, highest `usable`, next `validated`): broad libewf/Sleuth Kit version matrix, encrypted/malformed/corrupt E01/Ex01 validation, and independent known-answer image corpus reports.
- `#23` RAW/split image robust partition/filesystem handling (Partial++, core-forensics, highest `usable`, next `validated`): large damaged/gapped split-set validation, filesystem-specific known-answer recovery checks, path/timestamp validation, encrypted volume handling, and full partition edge-case coverage.
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish (Partial++, core-forensics, highest `usable`, next `validated`): snapshot/differencing-chain support, encrypted/compressed/corrupt VM disk validation, qemu-img version matrix, hypervisor metadata preservation, and large known-answer corpora.
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support (Partial++ with explicit export-first gate and internal validated fixture, core-forensics, highest `usable`, next `validated`): native AD1/L01/Lx01/AFF/AFF4/XVA parsing, metadata/deleted-entry validation, encrypted/compressed container handling, and vendor export known-answer tests.
- `#26` Cellebrite/XRY/GrayKey/AXIOM export deep import (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): vendor-version-specific schemas, deleted-record semantics, original acquisition hash verification, and independent known-answer validation.
- `#27` iOS backup parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): encrypted backup handling, app DB parsing, deleted records, and known-answer validation.
- `#28` iOS keychain/artifact parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): validated protected-data workflow outside core and legal/authorization package.
- `#29` Android backup/artifact parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): app-specific DB schemas and deleted/encrypted stores.
- `#30` Android app package/data parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): binary manifest decoding, DEX control-flow analysis, signing trust, and malware validation.
- `#31` KakaoTalk parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): post-2025-08 KakaoTalk known-answer corpus, schema-version-specific parser mapping, deleted records, independent validation, and proprietary-key-free operational guidance.
- `#32` WhatsApp parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): encrypted `crypt*` backups, contacts/calls/media recovery, deleted records, and corpus validation.
- `#33` Telegram parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): Telegram Desktop encrypted/local map decoding, cloud export schema coverage, account attribution, and deleted/cache recovery validation.
- `#34` Signal parser (Partial++, mobile-cloud-apps, highest `usable`, next `validated`): encrypted backup support, SQLCipher/key handling outside core, attachment recovery, deleted records, and legal authorization package.
- `#35` WeChat/LINE/Discord/Instagram and extended messenger parser (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): app-specific encrypted stores, schema drift, media recovery, reactions/read receipts completeness, ephemeral/secret chat validation, and known-answer validation.
- `#36` Email PST/OST full mailbox parser (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): native PST/OST folder/message/deleted-item decoding, full MSG MAPI properties, DKIM/ARC/S/MIME/OpenPGP validation, threading validation, corrupt-store recovery, and mailbox corpus testing.
- `#37` Gmail/Google Takeout deep parser (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): full Takeout product matrix, MBOX threading, Photos sidecar/EXIF merge, archive split/expiration handling, deleted/retention semantics, and provider schema-version tracking.
- `#38` Apple iCloud export parser (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): full Apple data export schemas, iCloud Photos albums/EXIF correlation, device inventory, shared album fidelity/comments/likes, third-party iCloud containers, Advanced Data Protection limits, and known-answer validation.
- `#39` Microsoft 365/OneDrive/Teams export parser (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): Graph/eDiscovery export variants, Teams Cosmos DB vs Exchange compliance record reconciliation, retention/deleted-item semantics, Teams attachments/reactions, SharePoint permissions, and audit completeness validation.
- `#40` Cloud API acquisition workflow (Partial+++, mobile-cloud-apps, highest `usable`, next `validated`): OAuth device flows, token vaulting/rotation, pagination execution, throttling/backoff validation, provider-specific collectors, and legal hold/export package validation.
- `#41` Cloud token/credential secure handling (Partial+++ with explicit commercial gate and internal validated fixture, mobile-cloud-apps, highest `usable`, next `validated`): actual token vaulting, controlled reveal workflow, rotation enforcement, RBAC enforcement, and enterprise secret-store integration.
- `#42` Browser password/cookie/session artifact handling with strict legal warning (Partial+++ with explicit commercial gate and internal validated fixture, mobile-cloud-apps, highest `usable`, next `validated`): audited opt-in reveal workflow, DPAPI/keychain integration where lawful, and browser-version validation corpus.
- `#43` Mobile app media/message timeline correlation (Partial+++ with explicit commercial gate and internal validated fixture, mobile-cloud-apps, highest `usable`, next `validated`): cross-source/device-wide timeline merge, timezone normalization, attachment byte recovery, and known-answer validation.
- `#44` Contact/call/SMS unified mobile view (Partial+++ with explicit commercial gate and internal validated fixture, mobile-cloud-apps, highest `usable`, next `validated`): UI-specific grouped mobile view, persistent dedupe/entity merge-split decisions, and full app schema validation.
- `#45` App-specific known schema version management (Partial+++ with explicit commercial gate and internal validated fixture, mobile-cloud-apps, highest `usable`, next `validated`): per-app compatibility matrix, migration tests, schema diff fixtures, and operator-approved release-gated parser support policy.
- `#46` Large-result clustering (Partial+++ with UX gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): persistent cluster review state, near-duplicate text/media clustering, and large-case validation.
- `#47` Entity view: people, accounts, email, phone, IP, and domain (Partial+++ with validation gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): person/account resolution, false-positive tuning, first/last seen across full case index, persistent analyst merge/split decisions, and hand-labeled entity fixture expansion.
- `#48` Graph view: account-file-URL-time relationships (Partial+++ with explicit validation gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): interactive graph canvas, time-edge semantics, persistent saved layouts, server-side graph paging API, and large-case graph validation.
- `#49` Unified timeline correlation (Partial+++ with explicit validation gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): full Case DB timeline join, trusted timezone/skew validation, review annotation overlays, cursor-paged timeline API, and large-case chronology validation.
- `#50` Incident hypothesis/workbook feature (Partial+++ with explicit validation gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): editable Case DB workbook, source-row evidence attachment workflow, reviewer assignments, report export sections, and version history.
- `#51` Reviewer assignment/status workflow (Partial++ with explicit UX gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): role-based assignment queues, SLA dashboards, notifications, and conflict-aware multi-user review.
- `#52` A/B/C multi-evidence compare (Partial++ with explicit UX gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): web-side three-pane compare UI, binary/hex diff, timeline-aware compare, persistent Case DB compare notes, and trusted expected-diff manifests.
- `#53` Raw/source hex viewer (Partial++ with explicit viewer gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): interactive full-file jump-to-offset UI, copy-safe byte selection UI, trusted offset manifest diff, full-file hash display inline for very large files, and external byte-level citation package validation.
- `#54` SQLite/table specialized viewer (Partial++ with explicit viewer gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): browser E2E validation for pagination UI, arbitrary-query builder intentionally not allowed, virtual table/FTS ranking, deleted-row/WAL recovery, trusted sqlite3 diff, and export-selected-rows workflow.
- `#55` Email conversation viewer (Partial++ with explicit viewer gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): full PST/OST/MSG native conversations, deleted item recovery, native mailbox attachment extraction, message-ID graph validation, trusted mail-client thread/export diff, and report citation export.
- `#56` Image gallery review mode (Partial++ with explicit viewer gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): dedicated virtualized multi-image grid, persistent gallery tags, ML visual similarity clustering UI, sensitive/deepfake classifier validation, trusted image manifest diff, and selected-image report export flow.
- `#57` Video/audio preview and transcript (Partial++ with explicit viewer gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): video duration extraction, waveform/thumb previews, hardened playback sandboxing, trusted cue/alignment diff, manual playback/ASR validation, and report export integration for selected cue ranges.
- `#58` OCR queue manager (Partial++ with explicit workflow gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): actual OCR worker execution, engine-specific retry logs, browser-side queue state editing, and per-case OCR job persistence in Case DB.
- `#59` Korean OCR/translation workflow hardening (Partial++ with explicit workflow gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): built-in Korean OCR engine execution, machine translation worker integration, confidence calibration by engine, and certified translation/reviewer signoff workflow.
- `#60` Search hit deduplication (Partial++ with explicit analysis gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): persistent Case DB duplicate suppression decisions, fuzzy near-duplicate text grouping, media perceptual duplicate grouping, and trusted duplicate manifest validation.
- `#61` Fuzzy search/stemming/regex proximity search (Partial++ with explicit search gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): multilingual relevance corpus, tuned FP/FN metrics, independent trusted query-hit manifest diff corpus, and full browser query-builder UX validation.
- `#62` Saved keyword pack library (Partial++ with explicit search gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): full per-case pack editing UI, signed pack distribution, language/domain-specific pack validation, trusted expansion manifest corpus, and release-reviewed pack versions.
- `#63` IOC/TI enrichment plugin (Partial++ with explicit local-only gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): signed feed packages, STIX/TAXII import, configurable confidence decay, feed trust workflow, trusted enrichment manifest corpus, and external TI governance.
- `#64` Report citation manager (Partial++ with explicit report gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): exhibit numbering/editor workflow, jurisdiction templates, trusted citation manifest corpus, and full source-hash completeness validation.
- `#65` Evidence selection/version history (Partial++ with explicit report gate and internal validated fixture, search-analysis-ux, highest `usable`, next `validated`): signed multi-user history, trusted history manifest corpus/diff, and conflict handling.
- `#66` 100k/1M/10M record benchmark (Partial++ with explicit performance gate, batch uplift evidence, and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): published 100k/1M/10M hardware runs, trusted threshold manifests, and release-approved threshold comparisons.
- `#67` 1TB-10TB evidence stress test (Partial++ with explicit performance gate, batch uplift evidence, and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): actual published 1TB-10TB hardware runs, trusted run-log manifests, bottleneck traces, and independent reproduction logs.
- `#68` Incremental indexing (Partial++ with explicit resume gate, batch uplift evidence, and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): full large-file content-hash delta reindex, row-level stage delta reuse, trusted reuse manifests, and large-case validation.
- `#69` Background job queue (Partial++ with explicit operational gate, batch uplift evidence, and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): distributed workers, externally trusted transition logs, parser-level progress percentages, and cooperative parser-level cancellation validation under load.
- `#70` Stage checkpoint/resume hardening (Partial++ with explicit resume gate, batch uplift evidence, and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): mid-parser checkpointing, failed-stage resume, trusted checkpoint manifests, and long-running replay validation.
- `#71` Parser crash isolation (Partial++ with explicit operational gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): native process sandboxing for every parser and corrupt-input fuzz/crash corpus validation.
- `#72` Memory cap enforcement (Partial++ with explicit resource gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): hard OS cgroup/job-object limits, per-parser live RSS telemetry, 1TB+ RSS graphs, and platform-specific RSS validation.
- `#73` Preview sandboxing (Partial++ with explicit viewer safety gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): separate OS sandbox for risky codecs/macros/renderers and trusted active-content no-exec corpus validation.
- `#74` Large SQLite/FTS optimization (Partial++ with explicit performance gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): 10M-row query-plan regression, trusted query-plan manifests, deleted-row/WAL replay, and huge-source-DB corpus validation.
- `#75` Parallel parser scheduler (Partial++ with explicit scheduler gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): distributed priority scheduler, live per-worker telemetry UI/stream, trusted scheduler manifests, and TB-scale fairness/backpressure validation.
- `#76` File hash cache (Partial++ with explicit cache gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): automatic on-disk cache wiring, trusted hash-cache manifests, and large-case hit-ratio validation.
- `#77` Duplicate file/content detection (Partial+++ with explicit dedupe gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): perceptual media duplicate grouping, trusted external duplicate manifests, and analyst suppression workflow validation.
- `#78` Artifact pagination/cursor API (Partial++ with explicit API gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): snapshot-isolated database cursors and endpoint-wide compatibility validation.
- `#79` UI virtualization for massive result tables (Partial++ with explicit UX performance gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): true recycling virtual scroller, persisted viewport restoration across reloads, trusted browser row-window manifests, and browser e2e performance validation.
- `#80` Long-running job cancellation/retry (Partial++ with explicit job-control gate and internal validated fixture, performance-large-scale, highest `usable`, next `validated`): parser-level cooperative cancellation under load, trusted cancellation/retry transition manifests, and partial-output cleanup/resume validation.
- `#81` NIST CFReDS/CFTT based known-answer tests (Partial++ with explicit validation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): publish real public-corpus run outputs for each report-grade parser.
- `#82` Parser-specific fixture corpus (Partial++ with explicit validation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): broader malformed/deleted/native/versioned fixture corpora and release-blocking coverage policy.
- `#83` Parser-specific false positive/false negative documentation (Partial++ with explicit validation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): quantified FP/FN rates by corpus and parser version.
- `#84` Independent validation report (Partial++ with explicit validation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): must attach legal/known-answer validation evidence
- `#85` Tool validation package automation hardening (Partial++ with explicit validation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): operator-attached test logs, release evidence, and independent review.
- `#86` Chain-of-custody full workflow (Partial++ with explicit custody gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): signed custody handoff forms, acquisition-device metadata, and lab custody policy.
- `#87` Evidence acquisition hash workflow (Partial++ with explicit hash gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): whole-device acquisition hash UI and write-blocker/operator metadata capture.
- `#88` Analyst action immutable audit log (Partial++ with explicit audit gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): database-level append-only enforcement and external notarization/signing.
- `#89` Report reproducibility: same input, same output (Partial++ with explicit reproducibility gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): end-to-end same-input artifact byte-for-byte report tests across platforms.
- `#90` Report item source provenance completeness (Partial++ with explicit provenance gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): completeness validation across every parser and final report template.
- `#91` Parser confidence scoring (Partial++ with explicit confidence gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): calibrated parser-specific confidence tables and cross-tool confidence validation.
- `#92` Validation-required warning UX (Partial++ with explicit warning gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): stronger web visual badges across every table.
- `#93` Legal limitation statement per artifact (Partial++ with explicit limitation gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): jurisdiction-specific approved wording and legal review signoff.
- `#94` Court exhibit export package (Partial++ with explicit exhibit gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): jurisdiction-specific forms and signed/notarized exhibit manifests.
- `#95` External tool version capture (Partial++ with explicit tool-version gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): per-run capture for every external parser/import execution and original tool logs.
- `#96` Write-blocker/acquisition metadata recording (Partial++ with explicit acquisition gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): web form, write-blocker device integration, signed handoff forms, and acquisition-time hash verification against original imaging logs.
- `#97` Timezone normalization validation (Partial++ with explicit timezone gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): parser-specific timezone assumption matrix and multi-source timezone reconciliation.
- `#98` Clock skew analysis (Partial++ with explicit skew gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): host-specific baseline comparison and multi-device skew model.
- `#99` Evidence contamination warning (Partial++ with explicit contamination gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): persistent acquisition-time mtime comparison and write-blocker integration.
- `#100` Tamper-evident audit bundle (Partial++ with explicit tamper-evidence gate and internal validated fixture, validation-legal, highest `usable`, next `validated`): external signing/notarization.
- `#101` Windows signed installer (Partial++ with repo evidence, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#102` macOS notarized package (Partial++ with repo evidence, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#103` Linux package/deb/rpm/AppImage (Partial++, deployment-operations, highest `usable`, next `validated`): actual deb/rpm/AppImage artifact builds and distro smoke logs.
- `#104` Auto-update channel (Partial++, deployment-operations, highest `usable`, next `validated`): hosted signed update service and client updater.
- `#105` Crash reporting (Partial++++++ with local-only redaction matrix, API listing/detail endpoints, web crash dashboard, operator ZIP export bundle, release smoke script, redaction review script, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): run both scripts on the actual signed/release build host and attach independent reviewer/lab signoff.
- `#106` Telemetry-free/local-only enterprise mode (Partial++ with control matrix, deployment-operations, highest `usable`, next `validated`): trusted network-egress and deployment-policy proof.
- `#107` License/activation system, if needed (Partial++ with control matrix, deployment-operations, highest `usable`, next `validated`): paid activation workflow if the project needs commercialization.
- `#108` Role-based access control (Partial++ with control matrix, deployment-operations, highest `usable`, next `validated`): per-action RBAC enforcement in a real multi-user server.
- `#109` Multi-user case server (Partial++ with explicit guard and control matrix, deployment-operations, highest `usable`, next `validated`): implementation of that server.
- `#110` Collaboration audit trail (Partial++ with control matrix, deployment-operations, highest `usable`, next `validated`): multi-user identities, conflict handling, and database-enforced append-only audit.
- `#111` Backup/restore/migration (Partial++ with rehearsal matrix, deployment-operations, highest `usable`, next `validated`): multi-version migration test corpus and scheduled backup automation.
- `#112` Release notes/changelog discipline (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): enforced changelog gate in CI.
- `#113` LTS branch/hotfix policy (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#114` Support SLA documentation (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): actual staffed support desk and contractual SLA execution remain operator-owned.
- `#115` Training curriculum (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#116` Analyst quickstart lab (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#117` Admin deployment guide (Partial++ with document matrix, deployment-operations, highest `usable`, next `validated`): must attach platform/operations evidence before commercial distribution
- `#118` Security hardening review (Partial+++ with control matrix, release self-review, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): independent AppSec review.
- `#119` Malicious evidence sandboxing (Partial++++ with control matrix, parser isolation smoke, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): OS-level process sandbox for parsers and trusted malicious corpus/fuzz validation.
- `#120` Dependency vulnerability monitoring (Partial++++ with dependency matrix, scheduled workflow contract, and release-evidence verifier gates, deployment-operations, highest `usable`, next `validated`): attach an actual CI run log/artifact URL, publish or archive the SBOM with release checksums, and complete trusted exception review for unresolved high/critical findings.

## Operator Guidance

- Use RapidTriage as a triage/review accelerator, not as a sole AXIOM/WISDOM replacement.
- Any item marked non-commercial must keep validation_required/reportability warnings in artifacts and reports.
- For testimony-grade conclusions, attach trusted-tool comparison output and known-answer validation evidence.
- Do not advertise signed installer, notarized package, multi-user server, or support SLA until external evidence exists.
