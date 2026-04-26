# RapidTriage E01/Ex01 Workflow

RapidTriage can identify E01/Ex01 files and can run direct extraction only when external forensic tools are available.

## What Happens Today

When you select an E01/Ex01 directly:

1. RapidTriage checks for `ewfmount`, `mmls`, and `tsk_recover`.
2. If the tools exist, RapidTriage mounts/exposes the image through `ewfmount`.
3. It uses `mmls` to find the first likely FAT/exFAT/NTFS/basic-data filesystem partition.
4. It uses `tsk_recover` to recover files into the run output staging directory.
5. It runs the normal folder triage workflow on the recovered filesystem.

If any required tool is missing, direct E01 processing is blocked and the UI/API tells you to mount or export first.

## Recommended Windows Workflow

Direct E01 handling is usually more reliable through WSL2 or a separate forensic mounting/export workflow.

Recommended steps:

1. Mount or export the E01/Ex01 using your trusted forensic toolchain.
2. Verify the mounted/exported folder is read-only or copied to a safe analysis location.
3. Start RapidTriage.
4. Use `Check evidence support` on the folder or source image.
5. Run `Fast first pass` against the mounted/exported folder.

## Recommended macOS/Linux Workflow

If `libewf` and Sleuth Kit tools are installed:

```bash
rapidtriage evidence ./case.E01 --json
rapidtriage run ./case.E01 --mode fraud --output-dir ./case-run
```

If tools are missing:

```bash
rapidtriage evidence ./case.E01 --json
```

Then mount/export externally and scan the resulting folder:

```bash
rapidtriage run ./mounted-case-folder --mode fraud --output-dir ./case-run --read-only
```

## Current Limitations

- Direct E01 extraction selects the first likely filesystem partition; complex multi-partition analysis should be mounted/exported externally.
- Deep deleted-file carving is not implemented.
- Volume Shadow Copy comparison is not implemented.
- Tool versions and extraction actions are recorded in run outputs/audit records, but full commercial chain-of-custody automation is still roadmap work.

## Analyst Rule

For report-worthy evidence, verify source paths and hashes from the mounted/exported evidence or the original forensic workflow. RapidTriage is currently a triage/review assistant, not the sole authoritative acquisition tool.
