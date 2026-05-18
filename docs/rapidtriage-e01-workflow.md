# RapidTriage E01/Ex01 Workflow

RapidTriage can identify E01/Ex01 files and can run direct extraction only when external forensic tools are available.

## What Happens Today

When you select an E01/Ex01 directly:

1. RapidTriage checks for `ewfmount`, `mmls`, and `tsk_recover`.
   The preflight output records each tool's role, resolved path, version command attempts, version result, package/install hint, Windows/WSL2 guidance, and a structured remediation summary.
2. If the tools exist, RapidTriage mounts/exposes the image through `ewfmount`.
3. It uses `mmls` to enumerate partitions and chooses the largest supported filesystem partition by default.
   Analysts can override this with an explicit start sector when a case requires a different partition.
4. It uses `tsk_recover` to recover files into the run output staging directory.
5. It runs the normal folder triage workflow on the recovered filesystem.
   The Windows-focused run now includes browser history/downloads/AI-use hints, recent files and JumpLists,
   EVTX/event-log exports, Windows Search/`Windows.edb` pivots, remote-access traces, execution artifacts,
   Registry/NTUSER/UsrClass activity, ShellBags review rows, Prefetch, NTFS MFT/USN pivots, SRUM, tasks,
   Defender/firewall/WMI/WER-style system artifacts, document text search, file categorization, timeline,
   indicator summary, extraction manifests, and the run report.

For split EWF sets, the output records `segment_set_profile`: selected segment, discovered segment count,
segment numbers, contiguous/missing-segment warnings, selected-is-first status, total segment bytes, and a
commercial note that this is filename/sequence provenance rather than native EWF segment-table decoding.

If any required tool is missing, direct E01 processing is blocked and the UI/API tells you to mount or export first.

The GUI `Check evidence support` action now shows a compact E01 readiness card:

- available vs missing tool count
- exact missing tool names
- operator-facing remediation steps
- per-tool details such as purpose, path/version, and install hint
- fallback strategy: direct extraction when ready, mount/export-first when blocked
- operator runbook commands for preflight, smoke/plan, run, and review

## Recommended Windows Workflow

Direct E01 handling is usually more reliable through WSL2 or a separate forensic mounting/export workflow.

Recommended steps:

1. Mount or export the E01/Ex01 using your trusted forensic toolchain.
2. Verify the mounted/exported folder is read-only or copied to a safe analysis location.
3. Start RapidTriage.
4. Use `Check evidence support` on the folder or source image.
5. Run `Fast first pass` against the mounted/exported folder.

You can also save the same preflight/runbook JSON before running the case:

```powershell
rapidtriage evidence .\case.E01 --output .\case-run\rapidtriage-evidence-preflight.json
```

The saved JSON includes `ingest_workflow.operator_runbook` with:

- exact command templates for `evidence`, `e01-smoke`, `run`, and web review
- GUI-oriented steps from E01 selection through report export
- expected output files such as `rapidtriage-e01.json` and `rapidtriage-run-summary.json`
- large-case controls for `--resume`, extraction caps, cursor tables, and virtualized review
- explicit limitations so direct E01 orchestration is not overstated as native commercial EWF parsing

The same evidence JSON also includes two report-limiting readiness objects:

- `e01_validation_plan` records the #22 E01/Ex01 report-grade evidence slots, including segment inventory, dependency preflight, partition selection, corrupt/encrypted corpus requirements, recovered-root hashes, trusted workflow diff requirements, and large-case controls.
- `image_stress_workflow_profile` records the normalized corrupt/encrypted/large known-answer workflow for image-like inputs. For E01/Ex01 it calls out clean, split, missing-segment, corrupt, encrypted/locked-volume, and large-image cases; for RAW, VM disks, and proprietary forensic containers the same field is reused with their own stress matrix.

These fields are deliberately conservative. They make the UI and reports show what can be triaged now, what requires a lawful unlock or externally decrypted export, and which corpus/trusted-tool evidence is still missing before commercial-grade or court-report claims.

## Recommended macOS/Linux Workflow

If `libewf` and Sleuth Kit tools are installed:

```bash
rapidtriage evidence ./case.E01 --json
rapidtriage run ./case.E01 --mode fraud --output-dir ./case-run
```

To preserve the readiness/runbook artifact:

```bash
rapidtriage evidence ./case.E01 --output ./case-run/rapidtriage-evidence-preflight.json
```

If the automatic partition choice is wrong, pass the start sector shown by `mmls` or a trusted tool:

```bash
rapidtriage run ./case.E01 --mode fraud --output-dir ./case-run --e01-partition-start-sector 2048
```

The API/job payload accepts `e01_partition_start_sector`, and the GUI Run form has an optional `E01 partition start sector` field. The output records `partition_selection.selected_start_sector`, `recommended_start_sector`, `requested_start_sector`, and a warning if the analyst override differs from the automatic recommendation.

Direct extraction also writes a durable stage checkpoint at:

```text
<output-dir>/_e01/rapidtriage-e01-stage-status.json
```

The checkpoint records dependency preflight, mount, partition enumeration, filesystem recovery, command history, source signature, selected partition, recovered-root hash manifest, and resume readiness. If filesystem recovery already completed and the source signature plus requested partition still match, a later run can reuse the recovered filesystem instead of running the external tools again.

The recovered-root manifest is intentionally bounded for large cases. It records relative path, size, mtime, SHA-256 for files under the configured hash limit, skipped-large-file counters, truncation state, and per-file errors. Use it as triage provenance, then preserve full acquisition hashes and trusted-tool logs for report-grade evidence.

Both the extraction metadata (`rapidtriage-e01.json`) and direct E01 run summary now include `e01_ex01_workflow_manifest`.
This is the stable #22 single-case contract that the GUI, API, and reports can read:

- `select-e01`: source path, hash status, segment count, selected-first-segment status.
- `dependency-preflight`: available/missing `ewfmount`, `mmls`, and `tsk_recover` details.
- `partition-selection`: selected, requested, and recommended start sector plus partition counts.
- `filesystem-extraction`: command-history count, recovered-file count, checkpoint/resume state.
- `artifact-analysis`: run output keys and artifact output count once the full run completes.
- `unified-search-indexing`: docs, docs-index, and files search outputs.
- `review-workflow`: source-viewer and Case DB review requirements.
- `report-export`: summary/report output keys, source-hash requirement, and trusted-tool diff requirement.

The manifest carries `profile_version=e01-ex01-integrated-workflow-manifest-v1`, `gap_id=#22`, `item_number=22`, large-data controls, a reportability decision, explicit commercial blockers, and a stable `manifest_sha256`. It should be treated as workflow evidence and UI state, not proof that RapidTriage has a complete native EWF parser.

`image_stress_workflow_profile` carries `profile_version=image-stress-known-answer-workflow-v1` and a stable `manifest_sha256`. Treat it as the compact analyst-facing gate for E01/RAW/VM/container image readiness: it is useful for routing work, warning about large/deferred hashes, and blocking overclaiming, but it does not replace source acquisition hashes, trusted-tool diffs, or external corrupt/encrypted corpus validation.

Failure guidance is normalized so the operator sees the likely class of problem instead of a raw command failure only:

- `missing-tool`: libewf/Sleuth Kit dependency is unavailable.
- `unsupported-image`: path or suffix is not a readable E01/Ex01 input.
- `encrypted-volume`: BitLocker/locked/decryption indicators appear.
- `partition-ambiguity`: no supported partition or the requested start sector is invalid.
- `permission`: mount/output access is denied.
- `external-tool-failure`: ewfmount, mmls, or tsk_recover failed for another reason.

If tools are missing:

```bash
rapidtriage evidence ./case.E01 --json
```

Then mount/export externally and scan the resulting folder:

```bash
rapidtriage run ./mounted-case-folder --mode fraud --output-dir ./case-run --read-only
```

## Current Limitations

- Direct E01 extraction can auto-select or use one explicit partition start sector; complex multi-partition analysis should still be mounted/exported externally until the full partition browser and multi-partition processing workflow are complete.
- Checkpoint/resume currently reuses completed filesystem recovery; interrupted mid-stage resume and live progress visualization are roadmap work.
- Deep deleted-file carving is not implemented.
- Volume Shadow Copy comparison and preservation packaging are available through `rapidtriage vsc-compare` and `rapidtriage vsc-extract` after VSC/current folders are mounted or exported; direct VSC mounting from an E01 is still external-tool/operator work.
- Tool versions and extraction actions are recorded in run outputs/audit records, but full commercial chain-of-custody automation is still roadmap work.

## Analyst Rule

For report-worthy evidence, verify source paths and hashes from the mounted/exported evidence or the original forensic workflow. RapidTriage is currently a triage/review assistant, not the sole authoritative acquisition tool.
