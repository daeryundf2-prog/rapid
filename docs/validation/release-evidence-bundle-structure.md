# Release Evidence Bundle Structure

Status: designed
Date: 2026-06-17
Scope: RapidForensic release evidence packaging contract

This document defines the directory structure for a future release evidence bundle. It is not a completed release bundle and does not approve production distribution.

## Directory Layout

```text
release-evidence-bundle/
  README.md
  manifests/
  schemas/
  validation-results/
  rapid-results/
  trusted-results/
  diffs/
  summaries/
  logs/
  hashes/
  tool-versions/
  dependency/
  sbom/
  windows-smoke/
  scale/
  reviews/
  exceptions/
```

## State Model

| State | Meaning |
| --- | --- |
| designed | The required artifact shape is documented. |
| implemented | Tooling can produce or validate the artifact shape. |
| executed | The artifact was generated from an approved run. |
| reviewed | A qualified reviewer checked the artifact and recorded findings. |
| approved | Required review gates accepted the artifact for release decision use. |
| blocked | The artifact is missing, invalid, externally unavailable, or policy-blocked. |

## Required Artifact Classes

| Directory | Contents | Required Before Release Claim |
| --- | --- | --- |
| `manifests/` | Truth manifests and case manifests. | Yes |
| `schemas/` | Frozen schema copies used for validation. | Yes |
| `validation-results/` | `known-answer-qc` JSON and logs. | Yes |
| `rapid-results/` | Normalized RapidForensic observed results. | Yes |
| `trusted-results/` | Normalized independent reference results. | Yes |
| `diffs/` | `trusted-diff` machine-readable outputs. | Yes |
| `summaries/` | Human-readable summaries. | Yes |
| `logs/` | Execution logs with timestamps and host details. | Yes |
| `hashes/` | SHA-256 checksum manifests for all bundle artifacts. | Yes |
| `tool-versions/` | RapidForensic, Python, OS, dependency, and trusted tool versions. | Yes |
| `dependency/` | Dependency inventory and advisory outputs. | Yes |
| `sbom/` | SBOM or package inventory artifacts. | Yes |
| `windows-smoke/` | Windows host smoke evidence. | Yes |
| `scale/` | Large dataset and long-run survival evidence. | Yes |
| `reviews/` | Technical, methodology, operator, and legal reviews. | Yes |
| `exceptions/` | Approved exceptions with owner, expiry, and impact. | Conditional |

## Prohibited Bundle Content

Do not place these in Git or a public release evidence bundle:

- Raw customer data.
- PII.
- Malware.
- Raw evidence binaries.
- License-restricted vendor output in a public repository.
- Secrets.
- Tokens.
- Actual case data.

## Current In-Repo Boundary

The repository may contain tiny synthetic JSON, Markdown, and text fixtures used to validate the bundle plumbing. The repository must not contain real E01, Ex01, raw, dd, img, VHD/VHDX, AFF, split-image, or recovered evidence binaries.

Use `scripts/build-evidence-bundle.py` to produce an engineering manifest for small synthetic artifacts. A passing engineering manifest is not release approval.
