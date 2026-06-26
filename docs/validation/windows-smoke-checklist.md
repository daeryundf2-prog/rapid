# Windows Smoke Checklist

Status: designed only
Date: 2026-06-17
Scope: Future Windows execution evidence

This checklist is not execution evidence. It defines the records required before Windows behavior can be used for release evidence.

## Purpose

Verify RapidForensic engineering validation tooling and future E01/Ex01 workflows on a Windows host without using customer data or committing evidence binaries to Git.

## Pre-Flight

- Confirm the test host is approved for synthetic forensic validation.
- Confirm no PII, no customer data, no malware, and no actual case data.
- Confirm external evidence storage path.
- Confirm Git working tree does not contain E01, Ex01, raw, dd, img, VHD/VHDX, AFF, split-image, recovered output, secrets, or tokens.

## Windows Host Info

Record:

- Windows edition and build.
- Filesystem type.
- Timezone.
- Long-path policy.
- Python version.
- RapidForensic commit hash.
- Trusted/reference tool names and versions.
- Operator name or controlled operator ID.

## Tool Version Checks

```powershell
python --version
python -m pip show dashcam-tools
python -m pip show jsonschema
python -m pip show ruff
python -m pip show vulture
python -m pip show pip-audit
```

## Engineering Checks

```powershell
python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json
python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --check-files --fixture-root tests/fixtures/known_answer/tier0-basic/files --json
python scripts/trusted-diff.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json --json
python scripts/normalize-trusted-export.py --tool synthetic-tsv --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv --json
python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json
```

## Future T1 E01/Ex01 Run

- Generate the synthetic source tree on Windows NTFS.
- Include Korean path checks.
- Include spaces in filenames.
- Include long path checks within policy limits.
- Include duplicate basenames in different directories.
- Include zero-byte file checks.
- Include deleted-file semantics only when the source procedure records the delete operation.
- Acquire E01 and Ex01 outside Git.
- Record chain-of-custody, hashes, tool versions, and commands.
- Normalize trusted/reference exports.
- Run RapidForensic and collect normalized results.
- Run `trusted-diff`.
- Build the release evidence bundle manifest.

## NTFS-Specific Checks

| Check | Required Evidence |
| --- | --- |
| Unicode Korean path | Source hash, observed path, normalized path, reviewer note. |
| Spaces in path | Source hash, observed path, normalized path. |
| Long path | Windows policy record and observed path. |
| Deleted recoverable file | Operation log, trusted/reference result, RapidForensic result. |
| Deleted unrecoverable file | Operation log, expected failure reason, diff result. |
| E01 mount/read | Tool version, command, exit code, logs. |

## Artifacts To Collect

- `known-answer-qc` JSON.
- RapidForensic observed results JSON.
- Trusted/reference observed results JSON.
- `trusted-diff` JSON and summary.
- Bundle manifest JSON and summary.
- SHA-256 checksum manifest.
- Windows host info.
- Tool version records.
- Execution logs.
- Operator notes.
- Technical review.
- Methodology review.
- Operator review.
- Legal review.

## Pass/Fail Status

| Gate | PASS | FAIL |
| --- | --- | --- |
| Tier 0 plumbing | All engineering commands exit 0 and schemas validate. | Any engineering command fails. |
| T1 manifest | Schema-valid and chain-of-custody populated. | Missing required metadata or dummy values remain. |
| Trusted diff | No critical unapproved mismatch. | Critical mismatch without approved exception. |
| Reviews | All required review records complete. | Any required review missing. |

## Review Gate

Release blockers remain until all are complete:

- Technical review.
- Forensic methodology review.
- Operator review.
- Legal review.

Checklist completion alone is not approval and must not be described as release readiness.
