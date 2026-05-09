# RapidTriage External Commercial Evidence Plan

This plan tracks the evidence that cannot be honestly produced by repository code alone. These items must be attached from real release hosts, independent reviewers, lab environments, or operator-owned support processes before RapidTriage can claim commercial-grade readiness.

## Phase 1 - Release Artifact Evidence

1. CI advisory scan artifact
   - Goal: prove dependency monitoring runs in CI, not only locally.
   - Required evidence: GitHub Actions run URL, `dependency-monitoring-ci.json`, pip-audit output or explicit unavailable-tool note, workflow commit SHA.
   - Release verifier target: `--dependency-monitoring-json` plus future CI artifact URL field.
   - Done when: the release evidence report records a real CI run artifact and no unresolved high/critical issue is hidden.

2. SBOM publication evidence
   - Goal: prove the dependency/SBOM inventory is archived with the release.
   - Required evidence: SBOM file, SHA256, artifact upload record, release attachment path.
   - Release verifier target: dependency monitoring SBOM hash and publication slot.
   - Done when: the release package and release evidence report point to the same SBOM hash.

3. Windows signed build pipeline
   - Goal: produce a Windows installer or executable with Authenticode signature.
   - Required evidence: signing command log, certificate subject, timestamp authority, `Get-AuthenticodeSignature` output, artifact SHA256.
   - Release verifier target: Windows signing evidence manifest.
   - Done when: unsigned Windows release artifacts are blocked from commercial release.

4. Windows 11 fresh-machine smoke
   - Goal: prove a clean Windows 11 workstation can install and run the signed build.
   - Required evidence: smoke-summary JSON/Markdown, screenshots or console logs, host OS version, installer hash.
   - Release verifier target: Windows smoke platform gate.
   - Done when: E01 select, dependency check, sample case, search, review, report, and export smoke pass on Windows 11.

5. macOS signed and notarized build pipeline
   - Goal: produce a macOS package that passes codesign, notarization, and Gatekeeper checks.
   - Required evidence: `codesign --verify`, notarization submission/result, staple output, `spctl` assessment, package SHA256.
   - Release verifier target: macOS notarization evidence manifest.
   - Done when: non-notarized macOS artifacts are blocked from commercial release.

6. macOS Gatekeeper smoke
   - Goal: prove the notarized package opens and runs on a clean macOS host.
   - Required evidence: smoke-summary JSON/Markdown, Gatekeeper result, host OS version, package hash.
   - Release verifier target: macOS/Linux smoke platform gate.
   - Done when: install, launch, sample workflow, web UI, search, report, and export smoke pass.

7. Linux package smoke
   - Goal: prove Linux deb/rpm/AppImage or portable ZIP installs and uninstalls cleanly.
   - Required evidence: package build logs, install logs, uninstall logs, smoke summary, distro/container version.
   - Release verifier target: Linux package evidence manifest.
   - Done when: at least one clean Linux environment passes install, run, smoke, and uninstall.

8. Release evidence verifier schema expansion
   - Goal: prevent external artifacts from becoming loose attachments that nobody validates.
   - Required evidence: verifier checks for signing, notarization, CI artifact URL, SBOM publication, and platform smoke evidence.
   - Release verifier target: `release-evidence-report.json` PASS only when required external evidence is attached through `--external-release-evidence-json`.
   - Done when: missing evidence fails with actionable remediation and attached evidence hashes are checked.

## Phase 1 Evidence JSON Contract

The release verifier accepts the phase 1 package with:

```bash
python scripts/external-release-evidence-template.py \
  --output logs/external-commercial-evidence.json

python scripts/verify-release-evidence.py \
  --external-release-evidence-json logs/external-commercial-evidence.json \
  ...
```

The template intentionally fails until a release operator replaces placeholder rows with real evidence. The final JSON must use `profile_version: external-commercial-evidence-v1`, `scope: release-artifact-evidence-1-8`, and eight `items`. Every item must include `status: pass`, one or more `required_files` rows with `path` and `sha256`, and the item-specific checks below.

Required item checks:

- `1`: `ci_run_url` and `checks.ci_artifact_attached=true`.
- `2`: `sbom_path` or `sbom_url`, plus `checks.sbom_hash_matches_release=true`.
- `3`: `certificate_subject` plus `checks.authenticode_valid=true`.
- `4`: `platform` containing `Windows` plus `checks.windows_11_smoke_passed=true`.
- `5`: `checks.codesign_verified=true`, `checks.notarization_accepted=true`, and `checks.gatekeeper_accepted=true`.
- `6`: `platform` containing `mac` plus `checks.gatekeeper_smoke_passed=true`.
- `7`: `checks.install_smoke_passed=true` and `checks.uninstall_smoke_passed=true`.
- `8`: `checks.verifier_schema_updated=true`, `checks.missing_evidence_fails=true`, and `checks.attached_hashes_checked=true`.

## Phase 2 - Hostile Evidence Containment

9. Parser sandbox design
   - Goal: define OS-level isolation for parser workers before implementation.
   - Required evidence: sandbox threat model, allowed filesystem paths, network policy, process limits, supported OS matrix.
   - Release verifier target: security hardening self-review and sandbox evidence manifest.
   - Done when: parser boundary, preview boundary, temp directory policy, and kill/retry behavior are explicit.

10. OS-level parser sandbox implementation
   - Goal: move beyond subprocess-only crash isolation.
   - Required evidence: Windows Job Object/AppContainer or equivalent, macOS sandbox profile, Linux namespace/seccomp or container policy.
   - Release verifier target: parser sandbox smoke with `os_level_sandbox_enabled=true` only after real proof.
   - Done when: parser subprocesses cannot write outside allowed output paths, cannot open network sockets, and can be killed safely.

11. Sandbox escape, timeout, memory, and network tests
   - Goal: prove sandbox controls fail closed.
   - Required evidence: attempted path escape, network probe, fork/timeout probe, memory pressure probe, active content probe.
   - Release verifier target: parser sandbox smoke and hardening review.
   - Done when: each hostile behavior is blocked or quarantined with a deterministic audit record.

12. Malicious/corrupt corpus assembly
   - Goal: build a repeatable corpus for hostile files.
   - Required evidence: corpus manifest, source/license notes, hashes, expected behavior, quarantine expectations.
   - Release verifier target: malicious corpus evidence slot.
   - Done when: EVTX, Registry, SQLite, ZIP/archive, HTML, document, media, and image edge cases are represented.

13. Fuzz and crash-quarantine run
   - Goal: prove fuzzing does not silently corrupt case output.
   - Required evidence: fuzz command, seed corpus hash, crash count, timeout count, quarantine outputs, fixed/known-open issue list.
   - Release verifier target: malicious sandbox trusted corpus diff.
   - Done when: parser crashes become isolated crash artifacts and no active evidence content executes.

## Phase 2 Evidence JSON Contract

The release verifier accepts the phase 2 hostile-evidence package with:

```bash
python scripts/hostile-evidence-containment-template.py \
  --output logs/hostile-evidence-containment.json

python scripts/verify-release-evidence.py \
  --hostile-evidence-containment-json logs/hostile-evidence-containment.json \
  ...
```

The template intentionally fails until the operator attaches real sandbox, corpus, and fuzz evidence. The final JSON must use `profile_version: hostile-evidence-containment-v1`, `scope: hostile-evidence-containment-9-13`, and five `items`. Every item must include `status: pass`, one or more `required_files` rows with `path` and `sha256`, and the item-specific checks below.

Required item checks:

- `9`: `checks.threat_model_attached=true`, `checks.allowed_paths_defined=true`, `checks.network_policy_defined=true`, `checks.resource_limits_defined=true`, and `checks.os_matrix_defined=true`.
- `10`: `checks.os_level_sandbox_enabled=true`, `checks.write_escape_blocked=true`, `checks.network_blocked=true`, and `checks.kill_timeout_supported=true`.
- `11`: `checks.path_escape_test_passed=true`, `checks.network_probe_blocked=true`, `checks.timeout_test_passed=true`, `checks.memory_pressure_test_passed=true`, and `checks.active_content_test_passed=true`.
- `12`: `checks.corpus_manifest_attached=true`, `checks.license_notes_attached=true`, `checks.expected_behavior_recorded=true`, `checks.quarantine_expectations_recorded=true`, and `checks.artifact_families_covered=true`.
- `13`: `checks.fuzz_command_recorded=true`, `checks.seed_corpus_hash_recorded=true`, `checks.crash_quarantine_recorded=true`, `checks.timeout_count_recorded=true`, and `checks.no_silent_corruption=true`.

## Phase 3 - Independent Validation And Operations

14. Independent AppSec review package
   - Goal: prepare what an external reviewer needs.
   - Required evidence: architecture overview, threat model, auth/network boundaries, export rendering policy, sandbox design, dependency report.
   - Release verifier target: security hardening review evidence slot.
   - Done when: an external reviewer can reproduce the security posture without private tribal knowledge.

15. Independent AppSec or lab signoff
   - Goal: replace internal self-review with third-party evidence.
   - Required evidence: signed report, reviewer identity, scope, findings, exceptions, fixed issue references, residual risk.
   - Release verifier target: trusted independent AppSec diff.
   - Done when: #118 commercial-grade blocker can be removed for the reviewed scope only.

16. Support SLA ownership
   - Goal: prove support exists outside the codebase.
   - Required evidence: support contact, severity matrix, staffed schedule, escalation owner, secure intake procedure.
   - Release verifier target: support SLA evidence manifest.
   - Done when: users know who responds to Sev1-Sev4 issues and how evidence-sensitive reports are handled.

17. Emergency hotfix drill
   - Goal: prove urgent parser/security fixes can be shipped safely.
   - Required evidence: simulated critical issue, branch, patch, validation run, release notes, signed build, rollback note.
   - Release verifier target: LTS/hotfix evidence slot.
   - Done when: emergency release can be reproduced without bypassing validation gates.

18. Final commercial release evidence gate
   - Goal: run one consolidated release verification over all required evidence.
   - Required evidence: release package, platform smoke outputs, signing/notarization logs, dependency/SBOM artifacts, sandbox/corpus results, AppSec signoff, support evidence.
   - Release verifier target: `release-evidence-report.json` and `commercial-readiness` report.
   - Done when: any remaining blocker is explicit, owner-assigned, and not described as commercial-grade.

## Phase 3 Evidence JSON Contract

The release verifier accepts the phase 3 independent operations package with:

```bash
python scripts/independent-operations-evidence-template.py \
  --output logs/independent-operations-evidence.json

python scripts/verify-release-evidence.py \
  --independent-operations-evidence-json logs/independent-operations-evidence.json \
  ...
```

The template intentionally fails until the operator attaches real independent review, support, hotfix, and final release evidence. The final JSON must use `profile_version: independent-operations-evidence-v1`, `scope: independent-validation-operations-14-18`, and five `items`. Every item must include `status: pass`, one or more `required_files` rows with `path` and `sha256`, and the item-specific checks below.

Required item checks:

- `14`: `checks.architecture_overview_attached=true`, `checks.threat_model_attached=true`, `checks.auth_network_boundary_attached=true`, `checks.export_rendering_policy_attached=true`, `checks.sandbox_design_attached=true`, and `checks.dependency_report_attached=true`.
- `15`: `reviewer_identity`, `checks.signed_report_attached=true`, `checks.scope_recorded=true`, `checks.findings_recorded=true`, `checks.exceptions_recorded=true`, and `checks.residual_risk_recorded=true`.
- `16`: `support_contact`, `checks.support_contact_defined=true`, `checks.severity_matrix_defined=true`, `checks.staffed_schedule_defined=true`, `checks.escalation_owner_defined=true`, and `checks.secure_intake_defined=true`.
- `17`: `checks.simulated_issue_recorded=true`, `checks.patch_branch_recorded=true`, `checks.validation_run_attached=true`, `checks.signed_build_attached=true`, and `checks.rollback_note_attached=true`.
- `18`: `checks.release_package_attached=true`, `checks.platform_smoke_outputs_attached=true`, `checks.signing_notarization_logs_attached=true`, `checks.dependency_sbom_attached=true`, `checks.sandbox_corpus_results_attached=true`, `checks.appsec_signoff_attached=true`, `checks.support_evidence_attached=true`, and `checks.remaining_blockers_owner_assigned=true`.

## Recommended Execution Order

1. Complete items 1-8 first because independent review needs a real build and release evidence package.
2. Complete items 9-13 next because hostile-evidence containment changes implementation and test design.
3. Complete items 14-18 last because external reviewers and support owners need the prior artifacts.

## Current Boundary

RapidTriage can internally generate scripts, manifests, smoke outputs, and release evidence reports. It cannot honestly generate signing certificates, notarization tickets, clean-host smoke proof, independent lab signoff, real CI run URLs, malicious-corpus licenses, staffed support evidence, or legal admissibility by itself.
