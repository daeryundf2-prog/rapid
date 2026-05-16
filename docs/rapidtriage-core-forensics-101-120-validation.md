# RapidTriage #101-#120 Internal Validation

This package records internal fixture evidence for deployment, operations, and commercialization items #101 through #120.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-101-120 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-101-120-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-101-120/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-101-120 \
  --json
```

## Internal Fixture Scope

| Items | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #101-#104 Packaging/update | Release scripts generate portable ZIP, release manifest, packaging plan, update manifest, checksums, platform evidence gates, #101 Windows signing evidence manifest hashes/slots plus `windows-signing-report-grade-validation-plan-v1` ready/blocking slot counts, #102 macOS notarization evidence manifest hashes/slots plus `macos-notarization-report-grade-validation-plan-v1` ready/blocking slot counts, #103 Linux package evidence manifest hashes/slots plus `linux-package-report-grade-validation-plan-v1` ready/blocking slot counts, #104 auto-update evidence manifest hashes/slots plus `auto-update-report-grade-validation-plan-v1` ready/blocking slot counts, trusted signing/notarization/package/update diff placeholders, and explicit blockers. | Real signed Windows installer, notarized macOS package, deb/rpm/AppImage builds, hosted signed update channel, fresh host smoke logs, and trusted release attestation manifests. |
| #105-#110 Enterprise operations | Enterprise policy and crash reports document local-only operation, redaction, crash-export evidence manifest hashes/slots, local crash dashboard/list/detail/export API, packaged release crash-export smoke script, packaged redaction review script, offline license posture, RBAC policy, multi-user guardrails, audit trail limits, trusted crash redaction/export diff placeholders, and trusted enterprise policy/RBAC/server/audit diff placeholders. | Release-build host smoke/review JSON, independent reviewer signoff, paid license service if needed, per-action RBAC, real multi-user server, trusted enterprise deployment evidence, and independent security review. |
| #111 Backup/restore | Case backup and restore commands preserve DB/WAL/SHM hashes, schema inventory, migration readiness, restore verification, `backup-restore-rehearsal-manifest-v1` hashes/slots, and trusted restore-rehearsal diff placeholders. | Scheduled backups, multi-version migration corpus, trusted rehearsal logs, and restore drills on production-scale cases. |
| #112-#117 Release/support/training | Release notes, LTS/hotfix policy, support SLA template, training curriculum, quickstart lab, and admin deployment guide are packaged; #112-#117 emit document evidence manifest hashes/slots plus trusted CI/LTS/SLA/training/lab/deployment evidence blockers. | CI changelog enforcement, staffed support desk, real training delivery, trusted operational attestations, and deployment proof from customer environments. |
| #118-#120 Security/dependencies | Enterprise policy, admin guide, security policy, malicious-evidence guidance, parser subprocess isolation smoke, dependency monitoring script, and scheduled dependency workflow provide baseline gates plus document evidence manifest hashes/slots and trusted AppSec/sandbox/advisory/SBOM blockers. | Independent AppSec review, OS-level parser sandboxing, trusted malicious corpus/fuzz validation, actual CI advisory logs, SBOM publication, and release-blocking CI enforcement. |

## Interpretation

Passing this manifest promotes #101 through #120 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until external signing, notarization, hosted update infrastructure, staffed operations, independent security review, and CI/security evidence are attached.
