# RapidTriage Release Evidence Report

- Result: PASS
- Generated: `2026-05-19T00:39:04.980222+00:00`
- Release dir: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release`
- Validation dir: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/validation`
- Benchmark dir: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/benchmark`
- Columnar benchmark dir: ``
- Smoke dirs: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke`
- Crash smoke JSON: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json`
- Crash redaction review JSON: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json`
- Parser sandbox smoke JSON: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json`
- Dependency monitoring JSON: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json`
- Security hardening review JSON: `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json`
- External release evidence JSON: ``
- Hostile evidence containment JSON: ``
- Independent operations evidence JSON: ``
- Required smoke platforms: `macos-linux`
- Release gate: `pass`

| Check | Status | Detail | Path |
| --- | --- | --- | --- |
| release-dir | pass | directory present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release` |
| release-portable-zip | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/rapidtriage-portable.zip` |
| release-sha256s | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/SHA256SUMS` |
| release-manifest | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/release-manifest.json` |
| release-dependency-inventory | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/dependency-inventory.txt` |
| release-commercial-readiness-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/rapidtriage-commercial-readiness.json` |
| release-commercial-readiness-markdown | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/rapidtriage-commercial-readiness.md` |
| release-sha256-verification | pass | checked=13 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/SHA256SUMS` |
| release-manifest-artifacts | pass | artifacts=12, missing=[] | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/release-manifest.json` |
| release-commercial-readiness-disclosure | pass | claim_allowed=False, non_commercial_count=120, status=commercial-gaps-present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/release/rapidtriage-commercial-readiness.json` |
| validation-dir | pass | directory present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/validation` |
| validation-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/validation/rapidtriage-validation-package.json` |
| validation-markdown | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/validation/rapidtriage-validation-report.md` |
| validation-status | pass | status=release-validation-package-ready | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/validation/rapidtriage-validation-package.json` |
| benchmark-dir | pass | directory present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/benchmark` |
| benchmark-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/benchmark/rapidtriage-benchmark.json` |
| benchmark-markdown | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/benchmark/rapidtriage-benchmark.md` |
| benchmark-metrics | pass | ingest_seconds=1.240179, search_p50_seconds=0.046653 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/benchmark/rapidtriage-benchmark.json` |
| columnar-benchmark-not-provided | skip | optional columnar benchmark evidence not requested; pass --columnar-benchmark-dir to verify it | `` |
| smoke-smoke-dir | pass | directory present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke` |
| smoke-smoke-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/smoke-summary.json` |
| smoke-smoke-markdown | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/smoke-summary.md` |
| smoke-smoke-status | pass | passed=True, platform=macos-linux | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/smoke/smoke-summary.json` |
| smoke-minimum-count | pass | passing=1, required=1 | `` |
| smoke-platform-macos-linux | pass | passing_platforms=['macos-linux'], required=macos-linux | `` |
| crash-export-smoke-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json` |
| crash-export-smoke-payload | pass | command=crash-export-smoke, profile=crash-export-release-smoke-v1 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json` |
| crash-export-smoke-checks | pass | failed_check_ids=[], commercial_claim_allowed=False | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json` |
| crash-export-smoke-bundle-hash | pass | bundle_exists=True, bundle_sha256=9989f0c3ae25cff60dd4dbc577247c96e9b5cac32a1f42fb125b853dffbb55db | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/exports/crash-20260519T002038Z-ba888bd0-export.zip` |
| crash-export-smoke-manifest-hash | pass | manifest_hash=f3004ff36a7ab31be97eedbb69fca0abb02883b4c62f7b0af8fec194234708c5, smoke_hash=ff8e164243b5d15958256d6ca93dee0183aa02542350b5c9b4735db7f945ac68 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json` |
| crash-export-smoke-report-grade-plan | pass | plan_hash=2ac5975914d8fab155d8eb6295ab58e7db6472e41e06c23032f098c22f56c375, ready=8, blocking=8 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/crash-export-smoke.json` |
| crash-redaction-review-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json` |
| crash-redaction-review-payload | pass | command=crash-redaction-review, profile=crash-redaction-export-review-v1 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json` |
| crash-redaction-review-checks | pass | failed_check_ids=[], trusted_diff_status=pass, commercial_claim_allowed=False | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json` |
| crash-redaction-review-bundle-hash | pass | bundle_exists=True, bundle_sha256=9989f0c3ae25cff60dd4dbc577247c96e9b5cac32a1f42fb125b853dffbb55db | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-export-smoke/exports/crash-20260519T002038Z-ba888bd0-export.zip` |
| crash-redaction-review-hash | pass | review_hash=1516baa7ca99e1eb55e48031961138a5267037130b78fc74ac84f58e3b0dc477 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json` |
| crash-redaction-review-report-grade-plan | pass | plan_hash=2ac5975914d8fab155d8eb6295ab58e7db6472e41e06c23032f098c22f56c375, ready=8, blocking=8 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/crash-redaction-review.json` |
| parser-sandbox-smoke-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json` |
| parser-sandbox-smoke-payload | pass | command=parser-sandbox-smoke, profile=parser-subprocess-isolation-smoke-v1 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json` |
| parser-sandbox-smoke-checks | pass | failed_check_ids=[], boundary={'current_level': 'subprocess-isolation-smoke', 'os_level_sandbox_enabled': False, 'active_content_execution_allowed': False, 'network_probe_performed': False} | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json` |
| parser-sandbox-smoke-limitation-preserved | pass | os_level_sandbox_enabled=False | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json` |
| parser-sandbox-smoke-hash | pass | smoke_hash=b523cb50f6de0651891715869151b3ba5e6609663f14b56fde1469d3c41a40a0 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/parser-sandbox-smoke.json` |
| dependency-monitoring-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| dependency-monitoring-payload | pass | command=dependency-monitoring, commercial_gap_ids=['#120'] | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| dependency-monitoring-ci-workflow | pass | configured=True, passed_checks=['workflow_file_exists', 'scheduled_trigger', 'manual_trigger', 'pull_request_dependency_paths', 'check_dependencies_invoked', 'artifact_upload_configured', 'sbom_archived_in_dependency_artifact', 'read_only_permissions'] | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| dependency-monitoring-sbom-hash | pass | sbom_hash=1ef9b3b01b896e17c6f4640812c590f0d92dea2b0efefb2c2864b576e7848cde, manifest_hash=4489aac97fa1166c163ad4d815676d5fc46286cb832a6fe0173a7eb837235e11 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| dependency-monitoring-release-policy | pass | release_policy=Block release on known exploitable high/critical dependency issues unless a documented exception is approved. | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| dependency-monitoring-limitation-preserved | pass | trusted_diff_status=missing, blockers=['artifact-checksum-linkage-required', 'ci-advisory-run-log-required', 'dependency-exception-review-required', 'high-critical-triage-required', 'independent-dependency-review-required', 'release-host-dependency-smoke-required', 'sbom-publication-required', 'scanner-version-lock-required', 'trusted-dependency-advisory-sbom-diff-missing'] | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json` |
| security-hardening-review-json | pass | file present | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json` |
| security-hardening-review-payload | pass | command=security-hardening-review, profile=security-hardening-release-review-v1, gaps=['#118', '#119'] | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json` |
| security-hardening-review-checks | pass | failed_check_ids=[], commercial_claim_allowed=False | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json` |
| security-hardening-review-hashes | pass | review_hash=855f434290b1222eaba7d8eba8feeb3f22c9e25d46164b48620e9decd1c62d36, baseline_hash=dde7d49cf954a03e02027b0a3892240a1d3dc30ca6ce6a09939c4d9e6e56788a, control_matrix_hash=95699da8fe1012e31f95d69110a8f52b565ee626b7ec509ba331187987831c22 | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json` |
| security-hardening-review-boundaries | pass | checks={'security_section_present': True, 'telemetry_uploads_disabled': True, 'remote_bind_requires_auth': True, 'crash_uploads_disabled': True, 'baseline_manifest_hash_present': True, 'hardening_manifest_hash_present': True, 'malicious_sandbox_manifest_hash_present': True, 'control_matrix_hash_present': True, 'docs_present_and_hashed': True, 'appsec_blocker_preserved': True, 'malicious_corpus_blocker_preserved': True, 'os_sandbox_limitation_preserved': True} | `/Users/shinyoohag/rapidforensic/repo/qc-runs/2026-05-19-macos-full/ops-security/security-hardening-review.json` |
| external-release-evidence-not-provided | skip | optional 1-8 external commercial evidence not requested; pass --external-release-evidence-json to verify it | `` |
| hostile-evidence-containment-not-provided | skip | optional 9-13 hostile evidence containment package not requested; pass --hostile-evidence-containment-json to verify it | `` |
| independent-operations-evidence-not-provided | skip | optional 14-18 independent validation and operations package not requested; pass --independent-operations-evidence-json to verify it | `` |
