# RapidTriage Release Validation Package

- Generated at: `2026-05-19T00:13:09.568512+00:00`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Internal roadmap score: `100/100`
- Commercial readiness score: `90/100`
- Status: `release-validation-package-ready`

## Required Checks

- `unit-tests` (quality, required): Full Python unittest output for the release commit.
- `build-artifacts` (packaging, required): Wheel/sdist build output and portable ZIP smoke result.
- `windows-code-signing` (packaging, operator-owned): Authenticode signature verification output for Windows executable/installers, including certificate subject, timestamp, and SHA256.
- `macos-notarization` (packaging, operator-owned): macOS codesign verification, notarization ticket/staple output, Gatekeeper assessment, and package SHA256.
- `release-checksums-sbom` (supply-chain, required): Release artifact SHA256SUMS, dependency lock/build metadata, and SBOM or dependency inventory.
- `fresh-machine-smoke` (usability, required): Windows and macOS checklist run from docs/rapidtriage-fresh-machine-smoke-test.md.
- `sample-case` (workflow, required): rapidtriage sample --run output with run summary, report, and searchable results.
- `benchmark` (performance, required): rapidtriage benchmark JSON/Markdown attached to release notes.
- `parser-coverage` (forensic-coverage, required): docs/rapidtriage-parser-coverage.md and deterministic parser fixture tests.
- `known-limitations` (trust, required): docs/rapidtriage-known-limitations.md reviewed for the release version.
- `chain-of-custody` (evidence, required): Submission bundle hash manifest, audit events, source paths, and review decisions.
- `security-posture` (security, required): Localhost default, remote auth-token requirement, path handling tests, and release notes warning.
- `support-readiness` (operations, operator-owned): Support contact, triage SLA, training material, escalation process, and emergency parser-fix policy for deployed users.

## Known-Answer Validation

- Status: `not-provided`
- Dataset count: `0`
- Release gate: known-answer manifest should be attached for any parser claimed report-grade

## #1-#120 Core Forensics Accuracy Profiles

- Version: `core-forensics-accuracy-v1`
- Profile count: `120`
- Release gate: Each #1-#120 parser/legal/operations claim must attach pass/fail evidence against its profile before report-grade wording.
- `#1` Native EVTX BinXML full parsing: 6 required checks; oracle `EvtxECmd/Hayabusa/Windows Event Viewer XML export record-level diff`
- `#2` EVTX event template/message rendering: 6 required checks; oracle `Windows Event Viewer rendered message and trusted EVTX export tools`
- `#3` EVTX deleted/corrupt record recovery validation: 6 required checks; oracle `hand-labeled offsets plus second-parser recovery output`
- `#4` Registry hive full key tree reconstruction: 6 required checks; oracle `regripper/RegRipper, python-registry, exported .reg, and hand-labeled offsets`
- `#5` Registry deleted key/value recovery: 6 required checks; oracle `hand-labeled deleted-cell corpus and second-parser comparison`
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser: 6 required checks; oracle `Windows API/Registry exports, RegRipper, and known account lifecycle assertions`
- `#7` Amcache parser: 6 required checks; oracle `AmcacheParser/RegRipper export and hand-labeled timestamp semantics`
- `#8` ShimCache/AppCompatCache parser: 6 required checks; oracle `AppCompatCacheParser/ShimCacheParser and OS-version known-answer data`
- `#9` BAM/DAM execution parser: 6 required checks; oracle `RegRipper/BAM parser output plus known execution timeline`
- `#10` SRUM full ESE table parser: 6 required checks; oracle `srum-dump/SrumECmd export and hand-labeled ESE page assertions`
- `#11` Windows.edb full ESE parser: 6 required checks; oracle `esentutl/export utilities, ESE parser exports, and known document/property assertions`
- `#12` $MFT full attribute parser: 6 required checks; oracle `MFTECmd/TSK output and byte-level FILE record assertions`
- `#13` $UsnJrnl large-scale timeline parser: 6 required checks; oracle `MFTECmd/USN parser output plus replayed filesystem known-answer timeline`
- `#14` JumpList DestList deep parser: 6 required checks; oracle `JLECmd/LNK parser output and known application mapping`
- `#15` ShellBags native hive parser: 6 required checks; oracle `ShellBagsExplorer/SBECmd output and hand-labeled shell item paths`
- `#16` Prefetch full version parser: 6 required checks; oracle `PECmd/WinPrefetchView output and known run-count fixtures`
- `#17` LNK full metadata parser: 6 required checks; oracle `LECmd/Windows shell properties and hand-labeled link fields`
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser: 6 required checks; oracle `Windows native exports, Chainsaw/Hayabusa/Velociraptor, and hand-labeled IR assertions`
- `#19` Browser cache/session/extension/sync artifacts: 6 required checks; oracle `browser DB queries, BrowserHistoryView/Hindsight exports, and known browsing sessions`
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline: 6 required checks; oracle `browser-native SQLite queries and trusted browser forensic exports`
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity: 6 required checks; oracle `service export JSON/HTML and hand-labeled Q/A pairs`
- `#22` E01/Ex01 fully integrated workflow: 6 required checks; oracle `ewfverify, mmls/fls/tsk_recover output, and known-answer image manifest`
- `#23` RAW/split image robust partition/filesystem handling: 6 required checks; oracle `TSK output plus known-answer recovered file/hash manifest`
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish: 6 required checks; oracle `qemu-img info/convert, TSK extraction, and hypervisor metadata manifest`
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support: 6 required checks; oracle `vendor export logs, afflib where available, and known-answer file/hash manifest`
- `#26` Cellebrite/XRY/GrayKey/AXIOM export deep import: 6 required checks; oracle `source vendor tool report, acquisition hash manifest, and hand-labeled row counts`
- `#27` iOS backup parser: 6 required checks; oracle `iTunes/idevicebackup metadata, iLEAPP exports, and known backup manifest assertions`
- `#28` iOS keychain/artifact parser: 6 required checks; oracle `iLEAPP/keychain-dumper style inventory and legal authority manifest`
- `#29` Android backup/artifact parser: 6 required checks; oracle `ALEAPP/vendor export plus known app/table assertions`
- `#30` Android app package/data parser: 6 required checks; oracle `apkanalyzer/aapt/jadx/MobSF exports and known malware triage labels`
- Known-answer template datasets: `120`; status `template-not-run`

## Parser Fixture Corpus

- Fixture root: `/Users/shinyoohag/rapidforensic/repo`
- Coverage: `9`/`9` parser areas; status `fixture-backed-baseline`
- `windows-eventlog`: fixtures `1`, tests `1`, backed `True`
- `windows-registry`: fixtures `2`, tests `2`, backed `True`
- `windows-execution`: fixtures `1`, tests `1`, backed `True`
- `browser`: fixtures `3`, tests `2`, backed `True`
- `mobile-export`: fixtures `0`, tests `1`, backed `True`
- `cloud-export`: fixtures `0`, tests `2`, backed `True`
- `email`: fixtures `0`, tests `1`, backed `True`
- `memory`: fixtures `0`, tests `1`, backed `True`
- `media-ocr`: fixtures `0`, tests `1`, backed `True`

## Parser FP/FN Notes

- `EVTX/EventLog`: Validate high-value events against a known-answer EVTX corpus or trusted parser export.
- `Registry/SAM/SECURITY/SYSTEM/NTUSER`: Attach hive hashes, source offsets, and external parser comparison for report-grade claims.
- `MFT/USN/Prefetch/Execution`: Use PEcmd/MFTECmd/USN known-answer outputs for critical execution timelines.
- `Browser/AI services`: Correlate browser DB rows, profile metadata, timestamps, and source hashes before reporting.
- `Mobile/Cloud/Email/Media`: Record export tool/version, schema version, authorization, and known-answer comparison where possible.

## Independent Validation Report

- Status: `not-attached`

## Legal Defensibility Matrix

- Items: `[81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98]`
- Implemented/usable/validated: `12`/`12`/`3`
- External evidence required rows: `12`
- Matrix hash: `aaca84d8f9b815ee043c56335fa93f06c49dd0d0a13355e520746465737a86b9`
- `#81` known-answer validation: status `not-provided`, validated `False`, scope `known-answer-manifest`
- `#82` parser fixture corpus: status `fixture-backed-baseline`, validated `True`, scope `fixture-corpus`
- `#83` parser FP/FN risk register: status `partial`, validated `True`, scope `fp-fn-risk-register`
- `#84` independent validation report: status `not-attached`, validated `False`, scope `independent-validation-report`
- `#85` validation package automation: status `json-markdown-hash-manifest-generated`, validated `True`, scope `validation-package-artifacts`
- `#86` chain-of-custody workflow: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#87` evidence acquisition hash workflow: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#88` immutable analyst audit log: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#89` report reproducibility: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#90` report source provenance completeness: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#97` timezone normalization validation: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`
- `#98` clock skew analysis: status `external-evidence-required`, validated `False`, scope `case-report-control-and-known-answer-coverage`

## External Tool Versions

- `python`: available; `Python 3.9.6`
- `ewfmount`: available; `ewfmount 20140816

Copyright (C) 2006-2021, Joachim Metz.`
- `mmls`: available; `The Sleuth Kit ver 4.14.0`
- `tsk_recover`: available; `The Sleuth Kit ver 4.14.0`
- `qemu-img`: missing; ``
- `tesseract`: available; `tesseract 5.5.2
 leptonica-1.87.0
  libgif 5.2.2 : libjpeg 8d (libjpeg-turbo 3.1.3) : libpng 1.6.55 : libtiff 4.7.1 : zlib 1.2.12 : libwebp 1.6.0 : libopenjp2 2.5.4`
- `node`: available; `v25.8.1`

## Recommended Commands

- `unit-tests`: `python -m unittest discover -s tests`
- `compile`: `python -m compileall -q rapidtriage`
- `web-js-syntax`: `node --check rapidtriage/web/static/app.js`
- `build`: `python -m build --wheel --sdist`
- `release-zip`: `python scripts/build-release.py --output-dir release`
- `windows-signature-verify`: `Get-AuthenticodeSignature .\release\*.exe | Format-List`
- `macos-notarization-verify`: `codesign --verify --deep --strict APP && spctl --assess --type execute APP`
- `doctor`: `rapidtriage doctor --json`
- `sample`: `rapidtriage sample --run --overwrite --read-only --json`
- `benchmark`: `rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite --json`
- `validation-package`: `rapidtriage validation --output-dir ./release-validation --overwrite --json`
- `windows-smoke-test`: `.\scripts\windows\smoke-test-rapidtriage.ps1`
- `macos-linux-smoke-test`: `sh scripts/smoke-test-rapidtriage.sh`
- `release-checksums`: `python scripts/build-release.py --output-dir release`
- `verify-release-checksums`: `python scripts/build-release.py --output-dir release --verify`
- `smoke-summary`: `python scripts/summarize-smoke.py ./rapidtriage-macos-linux-smoke`
- `release-evidence`: `python scripts/verify-release-evidence.py --release-dir release --validation-dir release-validation --benchmark-dir release-benchmark --smoke-dir rapidtriage-windows-smoke --smoke-dir rapidtriage-macos-linux-smoke --require-smoke-platform windows --require-smoke-platform macos-linux`

## Required Documents

- `README.md`: Install, run, evidence support, and command entry points.
- `docs/rapidtriage-user-guide.md`: Analyst workflow and limitations from a user view.
- `docs/rapidtriage-known-limitations.md`: Clear non-claims and parser/acquisition gaps.
- `docs/rapidtriage-parser-coverage.md`: Implemented artifact and extension coverage.
- `docs/rapidtriage-core-forensics-accuracy-profiles.md`: #1-#120 parser/legal/operations accuracy profile gates and pass/fail evidence requirements.
- `docs/rapidtriage-core-forensics-001-005-validation.md`: #1-#5 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-006-010-validation.md`: #6-#10 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-011-015-validation.md`: #11-#15 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-016-020-validation.md`: #16-#20 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-021-025-validation.md`: #21-#25 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-026-030-validation.md`: #26-#30 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-031-040-validation.md`: #31-#40 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-041-050-validation.md`: #41-#50 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-051-060-validation.md`: #51-#60 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-061-070-validation.md`: #61-#70 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-071-080-validation.md`: #71-#80 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-081-090-validation.md`: #81-#90 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-091-100-validation.md`: #91-#100 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-core-forensics-101-120-validation.md`: #101-#120 internal fixture validation manifest and commercial-readiness attachment workflow.
- `docs/rapidtriage-release-checklist.md`: Repeatable release verification checklist.
- `docs/rapidtriage-release-notes-template.md`: Release communication template.
- `docs/rapidtriage-support-sla.md`: Support severity, escalation, secure evidence intake, and patch target template.
- `docs/rapidtriage-lts-hotfix-policy.md`: LTS branch and emergency hotfix policy.
- `docs/rapidtriage-training-curriculum.md`: Analyst/admin training labs and validation exercises.
- `docs/rapidtriage-admin-deployment-guide.md`: Enterprise deployment, backup, update, and hardening guide.
- `docs/rapidtriage-output-schemas.md`: Machine-readable output contracts.
- `docs/rapidtriage-score-improvement-plan.md`: Score target rationale and remaining external work.

## Release Artifact Requirements

- `windows-installer` (windows): must-pass-before-public-release; evidence: installer_or_portable_zip_sha256, authenticode_signature_status, timestamp_authority, fresh_windows_smoke_test
- `macos-app-or-package` (macos): must-pass-before-public-release; evidence: artifact_sha256, codesign_verify_output, notarization_ticket_or_staple_output, gatekeeper_assessment, fresh_macos_smoke_test
- `source-wheel-sdist` (cross-platform): required-for-internal-release; evidence: wheel_sha256, sdist_sha256, python_version, dependency_inventory, unit_test_output

## Independent Validation Plan

- `parser-corpus` (independent-reviewer): Windows EVTX/Registry/MFT/USN, browser history, mobile export, cloud export, memory import, and media/OCR fixtures. Evidence: Expected-result corpus, tool output, diff against RapidTriage JSON, and reviewed false-positive/false-negative notes.
- `large-case-performance` (release-engineer): 10k, 100k, and representative real exported case folders where legally available. Evidence: Benchmark JSON/Markdown, peak memory notes, elapsed time, skipped files, and resume behavior.
- `legal-report-review` (forensic-lead): Report wording, limitations, source hashes, review decisions, and non-claims. Evidence: Signed review checklist attached to release notes.

## Support SLA Template

- `sev1`: data loss, evidence mutation risk, crash blocking urgent case; target response: 4 business hours
- `sev2`: parser regression or incorrect high-value artifact field; target response: 1 business day
- `sev3`: usability issue, missing parser coverage, documentation gap; target response: 3 business days
- `sev4`: feature request or training question; target response: 5 business days
- Emergency patch policy: Do not claim a parser fix as report-grade until a fixture and validation note are attached.

## Known Limits To Disclose

- RapidTriage is still a triage/review tool, not a full AXIOM/WISDOM replacement.
- Native acquisition, deep carving, signed installers, and legal validation require external release processes.
- Some direct image formats are detected but require mounting/exporting or external tools before scanning.
- OCR, perceptual hashing, APK risk flags, memory imports, and cloud imports are analyst triage aids.

## Commercial Readiness Gate

- Status: `commercial-gaps-present`
- Commercial claim allowed: `False`
- Readiness score: `90/100`
- Non-commercial items: `120`/`120`
- Release claim: do not claim AXIOM/WISDOM-class commercial parity; disclose triage/validation limits
- `#1` Native EVTX BinXML full parsing: Partial++; must label as validation-required before report testimony
- `#2` EVTX event template/message rendering: Partial++; must label as validation-required before report testimony
- `#3` EVTX deleted/corrupt record recovery validation: Partial++; must label as validation-required before report testimony
- `#4` Registry hive full key tree reconstruction: Partial++; must label as validation-required before report testimony
- `#5` Registry deleted key/value recovery: Partial++; must label as validation-required before report testimony
- `#6` SAM/SECURITY/SYSTEM account and permission deep parser: Partial++ with explicit commercial gate; must label as validation-required before report testimony
- `#7` Amcache parser: Partial++ with explicit commercial gate; must label as validation-required before report testimony
- `#8` ShimCache/AppCompatCache parser: Partial++ with explicit commercial gate; must label as validation-required before report testimony
- `#9` BAM/DAM execution parser: Partial++ with explicit commercial gate; must label as validation-required before report testimony
- `#10` SRUM full ESE table parser: Partial++ with explicit commercial gate; must label as validation-required before report testimony
- `#11` Windows.edb full ESE parser: Partial++; must label as validation-required before report testimony
- `#12` `$MFT` full attribute parser: Partial++; must label as validation-required before report testimony
- `#13` `$UsnJrnl` large-scale timeline parser: Partial++; must label as validation-required before report testimony
- `#14` JumpList DestList deep parser: Partial++; must label as validation-required before report testimony
- `#15` ShellBags native hive parser: Partial++; must label as validation-required before report testimony
- `#16` Prefetch full version parser: Partial++; must label as validation-required before report testimony
- `#17` LNK full metadata parser: Partial++; must label as validation-required before report testimony
- `#18` WER/Defender/Firewall/Task Scheduler/WMI deep parser: Partial++; must label as validation-required before report testimony
- `#19` Browser cache/session/extension/sync artifacts: Partial++; must label as validation-required before report testimony
- `#20` Chrome/Edge/Firefox/Safari unified browser timeline: Partial++; must label as validation-required before report testimony
- `#21` AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity: Partial++; must label as validation-required before report testimony
- `#22` E01/Ex01 fully integrated workflow: Partial++; must label as validation-required before report testimony
- `#23` RAW/split image robust partition/filesystem handling: Partial++; must label as validation-required before report testimony
- `#24` VHD/VHDX/VMDK/VDI/QCOW direct handling polish: Partial++; must label as validation-required before report testimony
- `#25` AD1/L01/Lx01/AFF/AFF4/XVA support: Partial++ with explicit export-first gate and internal validated fixture; must label as validation-required before report testimony

## Commercial Gap Assessment

### native-evidence-acquisition

- Severity: `high`
- Current status: E01/Ex01 direct extraction works only when external libewf/Sleuth Kit tools are present; other image families are detected with guidance.
- Needed for commercial parity: Read-only native or orchestrated handling for raw/split images, AD1/L01/Lx01, AFF/AFF4, VHD/VHDX, VMDK, VDI, XVA, QCOW/QCOW2, ISO, DMG, WIM/SWM, and reliable partition/filesystem selection.
- Operator workaround: Mount or export with validated forensic tooling and scan the resulting folder.

### binary-windows-artifact-depth

- Severity: `high`
- Current status: EVTX native scanning is partial but now preserves common BinXML scalar values, SIDs, TemplateInstance IDs, message-rendering provenance, native chunk structure rows, and cautious slack/deleted/corrupt record candidate metadata; MFT/USN support includes imports plus bounded native inventory/USN record recovery; registry/OS-account support includes exports, inventory-level native hive parsing, hbin-aware bounded key-tree rows, key/value recovery candidates, SAM account/RID candidates, service/mounted-device/LSA/privilege export rows, and first-pass NTUSER/UsrClass user-activity pivots; execution support includes Amcache/ShimCache/BAM/UserAssist exports, native Amcache path/hash candidates, SRUM imports, and SRUDB table/string pivots; Windows.edb includes direct ESE header and bounded string-pivot inventory but not full table decoding.
- Needed for commercial parity: Full EVTX BinXML/provider message resource rendering, native Registry hive transaction-log replay, deep NTUSER.DAT/UsrClass.dat binary value decoding and deleted-value testimony validation, full SAM F/V and SECURITY secret decoding, native Amcache/ShimCache/BAM binary decoding, SRUDB ESE table/page row decoding, Windows.edb ESE, $MFT, $UsnJrnl, JumpList, ShellBags, and Prefetch parsers with validation corpora.
- Operator workaround: Import exports from trusted tools such as EvtxECmd, Hayabusa, Chainsaw, Velociraptor, PECmd, MFTECmd, and SRUM/EDB export utilities.

### mobile-cloud-memory-depth

- Severity: `high`
- Current status: APK triage includes permissions, dex/native inventory, and bounded string/URL/IP pivots; cloud export imports, Volatility-style output imports, and bounded direct memory dump indicator scans exist; direct acquisition and deep native analysis are not implemented.
- Needed for commercial parity: Vendor package importers, app database parsers, direct cloud/API acquisition workflows, full raw memory process reconstruction, validated BitLocker key workflows, and malware process scoring.
- Operator workaround: Use Cellebrite/XRY/GrayKey/AXIOM/cloud provider exports and Volatility outputs, then import the resulting folder/files; validate direct memory string/key candidates before reporting.

### cross-platform-release

- Severity: `medium`
- Current status: Source/wheel build and launchers exist, but signed Windows/macOS installers and notarization are outside the repo.
- Needed for commercial parity: Signed installers, notarized macOS packages, update channel, repeatable release artifacts, and fresh-machine test evidence.
- Operator workaround: Run fresh-machine smoke tests and distribute through an internally controlled packaging process.

### legal-validation-support

- Severity: `medium`
- Current status: Validation package and deterministic fixtures exist, but independent legal validation, training, and SLA are operator-owned.
- Needed for commercial parity: Third-party validation datasets, documented support process, training material, release notes, and escalation SLA.
- Operator workaround: Attach validation output, benchmark output, known limitations, and analyst verification notes to every internal release.


## Release Decision

The internal 100-point target means the repository can generate a repeatable validation package.
The commercial readiness score is intentionally lower and reflects gaps versus full forensic suites such as AXIOM/WISDOM.
It does not replace independent legal validation, signed installer infrastructure, or a maintained support program.
