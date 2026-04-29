# RapidTriage Support SLA Template

This document is a template for an operator or vendor that distributes RapidTriage to analysts. It does not create a staffed support obligation by itself.

## Severity Levels

| Severity | Example | Target response | Target update cadence | Patch target |
| --- | --- | --- | --- | --- |
| Sev1 | Evidence mutation risk, data loss, crash blocking an urgent active case | 4 business hours | Daily until workaround or fix | Emergency hotfix or documented workaround as soon as safely validated |
| Sev2 | Parser regression, incorrect high-value artifact field, report export blocker | 1 business day | Every 2 business days | Next hotfix after fixture and validation note |
| Sev3 | Usability issue, missing parser coverage, documentation gap | 3 business days | Weekly until scheduled | Next regular release |
| Sev4 | Feature request, training question, non-blocking improvement | 5 business days | Release planning update | Roadmap review |

## Required Intake

- Product version, git commit, release manifest, and SHA256SUMS.
- Operating system, Python version, install method, and `rapidtriage doctor --json`.
- Evidence type and acquisition metadata, but not raw evidence unless a secure legal sharing process is approved.
- Minimal reproduction, logs, crash report, command line, and output folder manifest.
- Whether the issue changes report conclusions, parser confidence, or chain-of-custody documentation.

## Escalation

- Sev1 and Sev2 issues must be reviewed by a forensic lead before public parser claims are updated.
- Parser fixes must include a fixture or known-answer note before being described as report-grade.
- Emergency builds must clearly state validation gaps, affected parsers, rollback guidance, and previous release hashes.
- Security issues follow `docs/rapidtriage-security-policy.md` and should not be filed with sensitive evidence attached.

## Secure Evidence Handling

- Prefer synthetic reproductions, redacted exports, hashes, screenshots, and parser logs.
- Do not send proprietary, personal, privileged, or court-sensitive evidence through ordinary support channels.
- If evidence sharing is unavoidable, require written authorization, encryption, access expiry, and chain-of-custody notes.

## Release Attachment Checklist

- Current support contact and staffed hours.
- Severity owner and escalation owner.
- Known limitations and parser coverage documents for the shipped version.
- Validation package, benchmark output, release evidence report, and smoke test folders.
