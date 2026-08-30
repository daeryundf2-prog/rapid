# Legal and Operator Review Checklist

Status: prepared, awaiting reviewer signoff (no review has been completed or signed)
Created: 2026-08-30
Authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md`
Required before: any release suitability claim. All four tracks must be complete and signed.

This checklist is the master record for the four external reviews required before a
release suitability claim. It is an input form for reviewers, not review evidence.
A completed checkbox without a signed, hash-identified reviewer record behind it is a
false entry and violates the claim discipline.

## Review Tracks

### 1. Technical Review

| Item | Requirement | Evidence to attach | Reviewer / Date |
| --- | --- | --- | --- |
| T-1 | Engineering baseline green on all supported platforms | CI run URL(s) + local transcripts (Windows baseline: 790 tests OK) | `<pending>` |
| T-2 | Security hardening findings closed or formally accepted | `security-hardening-review.json`, AppSec report | `<pending>` |
| T-3 | Parser FP/FN register complete for report-grade families | FP/FN register + trusted-diff JSONs (external corpus) | `<pending>` |
| T-4 | Release evidence verifier passes with all required attachments | `release-evidence-report.md` PASS | `<pending>` |
| T-5 | Performance claims carry measured thresholds and hardware context | benchmark manifests (100k/1M) + threshold status | `<pending>` |

### 2. Forensic Methodology Review

| Item | Requirement | Evidence to attach | Reviewer / Date |
| --- | --- | --- | --- |
| M-1 | Every report-grade parser has a documented accuracy profile and trusted-diff plan | `core_forensics_accuracy_profiles` output | `<pending>` |
| M-2 | Recovery/elimination claims match corpus evidence; no overstatement | corpus manifests + `recovery-accuracy.json` | `<pending>` |
| M-3 | Artifact caveats (ShimCache not-execution-proof, BAM correlation-before-testimony, deleted-cell caution labels) preserved in report wording | report templates + warning display profiles | `<pending>` |
| M-4 | Timezone, clock skew, contamination, and tamper-evidence disclosures adequate | time-semantics and audit-replay manifests | `<pending>` |
| M-5 | Known limitations document matches actual parser behavior | `docs/rapidtriage-known-limitations.md` diff review | `<pending>` |

### 3. Operator Review

| Item | Requirement | Evidence to attach | Reviewer / Date |
| --- | --- | --- | --- |
| O-1 | Fresh-machine install and smoke pass on target platform | `rapidtriage-windows-smoke/` summary + fresh Windows 11 transcript | `<pending>` |
| O-2 | Case workflow (ingest → search → review → report → bundle) completes on a real case | analyst run transcript + outputs | `<pending>` |
| O-3 | Training lab walkthroughs usable by a working analyst | training lab manifest + run logs | `<pending>` |
| O-4 | Admin deployment guide actions verified (install, auth, backup, restore, logging) | admin deployment smoke JSON | `<pending>` |
| O-5 | Crash export and redaction behavior acceptable in a lab setting | crash-export smoke + redaction review | `<pending>` |

### 4. Legal Review

| Item | Requirement | Evidence to attach | Reviewer / Date |
| --- | --- | --- | --- |
| L-1 | UI, report, and doc wording makes no legal-sufficiency, admissibility, or universal-acceptance claim | claims map with wording inventory | `<pending>` |
| L-2 | Secret/credential handling (browser, cloud token, messenger key, memory) gated behind lawful authority, opt-in, and redaction | secret-handling assessment outputs | `<pending>` |
| L-3 | Court exhibit package limitations and external-signature slots clearly disclosed | court exhibit package sample | `<pending>` |
| L-4 | Support and SLA documents avoid contractual commitments the operator does not control | SLA document review | `<pending>` |
| L-5 | Licensing of bundled/external dependencies compatible with distribution | SBOM + dependency license review | `<pending>` |

## Signoff Record

| Track | Reviewer name / ID | Organization | Signature or signed hash | Date | Result (pass / fail / conditional) |
| --- | --- | --- | --- | --- | --- |
| Technical | `<pending>` | `<pending>` | `<pending>` | `<pending>` | `<pending>` |
| Forensic methodology | `<pending>` | `<pending>` | `<pending>` | `<pending>` | `<pending>` |
| Operator | `<pending>` | `<pending>` | `<pending>` | `<pending>` | `<pending>` |
| Legal | `<pending>` | `<pending>` | `<pending>` | `<pending>` | `<pending>` |

Conditional approvals must list every condition and its evidence slot. A conditional
pass blocks release until the conditions are closed and re-signed.

## Claim Discipline (binding)

- Allowed: "report-defensible technical package" when this gate passes.
- Allowed: corpus-scoped accuracy statements with measured thresholds and limitations.
- Forbidden: any claim that a result is legally sufficient, admissible, or universally
  accepted, unless the legal review explicitly approves that exact wording in writing.
- No review in this file may be marked complete by the tool, its automation, or its
  maintainers acting alone.

## Not Evidence

This checklist is not review evidence. Until all four signoff rows are complete with
signed records, every release claim remains blocked and `commercial_claim_allowed`
stays false.
