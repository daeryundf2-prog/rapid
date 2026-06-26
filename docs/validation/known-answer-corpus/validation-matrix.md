# E01/Ex01 Validation Matrix

Status: designed only
Date: 2026-06-17

This matrix turns the corpus design into independently executable pass/fail rows. Each row requires a populated truth manifest, RapidForensic outputs, trusted reference outputs, and reviewer status before it can be marked pass.

## Matrix

| ID | Tier | Image format | Filesystem | Scenario | Expected item count | Expected outcome | Required trusted comparison | Required host OS | Automatable in CI | Release gate | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E01-T1-ALLOCATED-BASIC | T1 | E01 | NTFS | Allocated files in normal user paths. | >= 10 | PASS requires exact path, size, SHA256, citation, and no source mutation. | ewfverify, mmls, fls, tsk_recover | macOS or Windows for preflight; Windows before release | No, external image required | Required | First E01 smoke gate. |
| E01-T1-DELETED-BASIC | T1 | E01 | NTFS | Deleted recoverable resident and simple nonresident files. | >= 5 | PASS requires recall >= 0.990, precision >= 0.995, and no overstated unrecoverable item. | fls, istat, icat, tsk_recover, reviewer manifest | Windows before release | No | Required | Must separate recoverable and unrecoverable deleted files. |
| E01-T1-UNICODE-KO | T1 | E01 | NTFS | Korean filename plus Unicode normalization paths. | >= 6 | PASS requires original and normalized path match through index, viewer, export, and report. | fls, reviewer export | Windows before release | No | Required | Covers Korean, NFC, NFD, spaces, and emoji-name policy. |
| E01-T1-LONG-PATH | T1 | E01 | NTFS | Very long path and nested directories. | >= 3 | PASS requires safe export without traversal, silent truncation, or ambiguous dedupe. | fls, reviewer manifest | Windows before release | No | Required | Includes duplicate filename in different directories. |
| E01-T1-CARVE-JPEG | T1 | E01 | NTFS/unallocated | Carved JPEG. | >= 2 | PASS requires correct offset, type, length, and SHA256 when complete. | byte-offset reviewer manifest, icat when applicable | macOS or Windows | No | Required | Include non-carvable negative control in same case. |
| E01-T1-CARVE-PDF | T1 | E01 | NTFS/unallocated | Carved PDF. | >= 2 | PASS requires correct offset, type, length, and SHA256 when complete. | byte-offset reviewer manifest, icat when applicable | macOS or Windows | No | Required | Pair with random data false-positive control. |
| E01-T2-WINDOWS-NTFS-USERPROFILE | T2 | E01 | NTFS | Realistic Windows user profile and app paths. | >= 100 | PASS requires user-profile recall >= 0.990, app-location filters, and report citations. | fls, vendor export, reviewer manifest | Windows 10/11 | No | Required | Covers Desktop, Documents, Downloads, browser, messenger, temp. |
| E01-T2-RECYCLE-BIN | T2 | E01 | NTFS | Recycle Bin `$I` and `$R` artifacts. | >= 5 | PASS requires original path, deletion time, SID, paired file, and hash where recoverable. | fls, Windows artifact reviewer manifest | Windows 10/11 | No | Required | Timestamp tolerance must be explicit. |
| E01-T2-ADS | T2 | E01 | NTFS | Alternate data streams. | >= 3 | PASS requires stream name, stream size/hash, and limitation/report handling. | fls, istat, vendor export | Windows 10/11 | No | Required | Must include unsupported/export limitation when applicable. |
| E01-T2-FRAGMENTED | T2 | E01 | NTFS | Fragmented and partially overwritten files. | >= 5 | PASS requires complete hash match for complete files and limitation for partial files. | istat, icat, tsk_recover, reviewer manifest | Windows 10/11 | No | Required | Includes sparse and zero-filled ranges. |
| E01-T3-CORRUPT-SEGMENT | T3 | E01 | NTFS | Corrupted E01 segment. | >= 1 image | PASS requires FAIL/WARN/INCONCLUSIVE with explicit corruption evidence and no silent pass. | ewfverify, ewfinfo | macOS or Windows | No | Required | No recovery completeness claim. |
| E01-T3-MISSING-SEGMENT | T3 | E01 | NTFS | Missing segment in split E01 set. | >= 1 image | PASS requires blocked or inconclusive status with missing segment evidence. | ewfverify, ewfinfo | macOS or Windows | No | Required | Multi-segment ordering must be recorded. |
| E01-T3-UNSUPPORTED-ENCRYPTED | T3 | E01 | NTFS/encrypted | Unsupported encrypted or locked evidence. | >= 1 image | PASS requires EXPECTED_UNSUPPORTED and no recovery claim. | mmls, vendor export or reviewer manifest | Windows 10/11 | No | Required | BitLocker or encrypted container indicator. |
| E01-T3-SSD-TRIM-NONRECOVERY | T3 | E01 | NTFS | SSD/TRIM expected-non-recovery case. | >= 5 deleted items | PASS requires EXPECTED_UNRECOVERABLE for trimmed data, acquisition note, and no false recovered content. | acquisition note, trusted tool export, reviewer manifest | Windows 10/11 | No | Required for deleted SSD claims | Must record TRIM and acquisition method. |
| EX01-T1-ALLOCATED-BASIC | T1 | Ex01 | NTFS | Ex01 allocated files. | >= 10 | PASS requires exact path, size, SHA256, citation, and no source mutation. | ewfverify, ewfinfo, mmls, fls, tsk_recover | Windows before release | No | Required | Mirrors E01 allocated baseline. |
| EX01-T1-DELETED-BASIC | T1 | Ex01 | NTFS | Ex01 deleted recoverable files. | >= 5 | PASS requires recall >= 0.990, precision >= 0.995, and no overstated unrecoverable item. | fls, istat, icat, reviewer manifest | Windows before release | No | Required | Mirrors E01 deleted baseline. |
| EX01-T2-WINDOWS-NTFS | T2 | Ex01 | NTFS | Realistic Windows NTFS Ex01 case. | >= 100 | PASS requires trusted diff, Unicode paths, timestamps, deleted files, and report citations. | ewfverify, ewfinfo, fls, vendor export, reviewer manifest | Windows 10/11 | No | Required | Required before broad Ex01 claim. |
| SCALE-T4-100K-FILES | T4 | E01 or Ex01 | NTFS | 100k file metadata and export-filter case. | >= 100000 | PASS requires completion 1.000, RSS <= 4 GiB, p95 <= 2000 ms. | generated manifest, run telemetry, reviewer approval | macOS and Windows before release | Partial, if generated externally | Required | No 100k claim without telemetry. |
| SCALE-T4-1M-FILES | T4 | E01 or Ex01 | NTFS | 1M files or metadata rows. | >= 1000000 | PASS requires completion 1.000, rows/sec >= 5000, p99 <= 5000 ms. | generated manifest, run telemetry, reviewer approval | Windows before release | No | Required | May use approved metadata proxy if documented. |
| SCALE-T4-10TB-PROXY | T4 | E01 or Ex01 | NTFS | Approved sparse or real 10TB-class profile. | Case-defined | PASS requires completed run, resource telemetry, throughput, resume evidence, and reviewer approval. | run telemetry, generated manifest, reviewer approval | Windows before release | No | Required for 10TB-class claim | Proxy must be approved before execution. |

## Required Status Columns for Future Execution

When this matrix is converted into an executable tracking file, every row must include:

- `truth_manifest_status`
- `rapid_run_status`
- `trusted_tool_status`
- `diff_status`
- `metrics_status`
- `review_status`
- `release_gate_status`
- `blockers`

## Blocking Rule

Any row with missing source hashes, missing trusted reference output, failed metric threshold, unreviewed mismatch, or missing required review is `blocked` or `fail`. It cannot be counted as release evidence.
