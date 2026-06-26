# Windows T1 PowerShell Command Template

Status: template only, not executed
Date: 2026-06-18

This is a Markdown command template, not a PowerShell script. Commands that create, format, acquire, mount, or delete evidence require explicit operator approval before execution.

## Variables

```powershell
$ExternalCorpusRoot = "<external_corpus_root>"
$CaseId = "<case_id>"
$RepoRoot = "<rapid_repo_root>"
$Python = "python"
$ManifestPath = Join-Path $ExternalCorpusRoot "manifests\\t1-minimal-e01.manifest.json"
$RapidResultsPath = Join-Path $ExternalCorpusRoot "rapid-results\\rapid-observed-results.json"
$TrustedResultsPath = Join-Path $ExternalCorpusRoot "trusted-exports\\trusted-observed-results.json"
$DiffPath = Join-Path $ExternalCorpusRoot "diffs\\trusted-diff.json"
$DiffSummaryPath = Join-Path $ExternalCorpusRoot "diffs\\trusted-diff-summary.md"
```

## Preflight

```powershell
Set-Location $RepoRoot
git rev-parse HEAD
git status --short
$Python --version
$Python -m pip show dashcam-tools
$Python -m pip show jsonschema
```

## Engineering Sanity Check

```powershell
$Python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --check-files --fixture-root tests/fixtures/known_answer/tier0-basic/files --json
$Python scripts/trusted-diff.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json --json
$Python scripts/normalize-trusted-export.py --tool synthetic-tsv --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv --json
$Python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json
```

## Source Tree Creation

Create the synthetic source tree under `$ExternalCorpusRoot`. Do not use customer data.

```powershell
# Operator approval required before writing to external evidence storage.
# New-Item -ItemType Directory -Force ...
# Set-Content -Encoding UTF8 ...
# New-Item -ItemType File ...
```

## NTFS VHD/VHDX Creation

```powershell
# Operator approval required.
# These are placeholders only. Do not run without confirming target paths.
# New-VHD ...
# Mount-VHD ...
# Initialize-Disk ...
# New-Partition ...
# Format-Volume -FileSystem NTFS ...
```

## E01/Ex01 Acquisition

```powershell
# Operator approval required.
# Replace with approved acquisition tool commands.
# <acquisition_tool> <source_volume_or_disk> <output_e01_path>
# <ex01_capable_tool> <source_volume_or_disk> <output_ex01_path>
```

## Hash Recording

```powershell
Get-FileHash -Algorithm SHA256 <path> | Tee-Object -Append (Join-Path $ExternalCorpusRoot "hashes\\SHA256SUMS.txt")
```

## Trusted/Reference Export

```powershell
# Operator approval required.
# Replace with approved trusted/reference export command.
# Do not store license-restricted raw vendor output in public Git.
```

## Normalize Trusted Output

```powershell
$Python scripts/normalize-trusted-export.py --tool <approved_tool_normalizer> --input <trusted_export_path> --out $TrustedResultsPath
```

## RapidForensic Actual Run

```powershell
# Operator approval required.
# Replace with the approved RapidForensic command that emits normalized observed results.
```

## Known-Answer QC

```powershell
$Python scripts/known-answer-qc.py --manifest $ManifestPath
```

## Trusted Diff

```powershell
$Python scripts/trusted-diff.py --manifest $ManifestPath --rapid-results $RapidResultsPath --trusted-results $TrustedResultsPath --out $DiffPath --summary $DiffSummaryPath
```

## Evidence Bundle

```powershell
$Python scripts/build-evidence-bundle.py --root (Join-Path $ExternalCorpusRoot "bundle") --out (Join-Path $ExternalCorpusRoot "bundle\\bundle-manifest.json") --summary (Join-Path $ExternalCorpusRoot "bundle\\bundle-summary.md")
```

## Not Completed By This Template

- Actual E01/Ex01 generation.
- Actual trusted export.
- Actual RapidForensic recovery run.
- Technical/methodology/operator/legal review.

Do not add binary evidence to Git.
