# Windows T1 Operator Inputs

Status: input form, not executed
Date: 2026-06-18

Fill this file before a real Windows T1 E01/Ex01 execution. Do not enter secrets, tokens, customer data, or actual case data.

| Field | Value | Required | Notes |
| --- | --- | --- | --- |
| `external_corpus_root` | `<required>` | yes | Must be outside Git. |
| `case_id` | `<required>` | yes | Synthetic T1 case identifier. |
| `operator_name` | `<required>` | yes | Operator or controlled operator ID. |
| `reviewer_name` | `<required>` | yes | Technical reviewer or controlled reviewer ID. |
| `windows_version` | `<required>` | yes | Include edition/build. |
| `timezone` | `<required>` | yes | Record Windows timezone. |
| `python_version` | `<required>` | yes | `python --version`. |
| `rapid_commit` | `<required>` | yes | Git commit under test. |
| `acquisition_tool` | `<required>` | yes | Tool name and version. |
| `ex01_capable_tool` | `<optional>` | conditional | Required for Ex01 run. |
| `trusted_tool_paths` | `<required>` | yes | Approved trusted/reference tools only. |
| `retention_policy` | `<required>` | yes | Storage duration and disposal rule. |
| `license_restrictions` | `<required>` | yes | Vendor output handling policy. |
| `evidence_storage_access_control` | `<required>` | yes | Who can read/write external evidence. |
| `review_ticket` | `<required>` | yes | Ticket or document ID for review trail. |
| `long_path_policy` | `<required>` | yes | Windows policy state. |
| `ntfs_volume_id` | `<required after creation>` | yes | Generated during execution. |
| `e01_image_path` | `<required after acquisition>` | yes | External path only. |
| `ex01_image_path` | `<required if Ex01 acquired>` | conditional | External path only. |
| `trusted_export_path` | `<required after export>` | yes | External path or restricted storage record. |
| `rapid_results_path` | `<required after run>` | yes | Normalized observed results. |
| `diff_result_path` | `<required after diff>` | yes | Trusted diff JSON. |

## Approval Checkboxes

- [ ] External evidence storage approved.
- [ ] Synthetic-only source tree approved.
- [ ] Disk creation/formatting command approved.
- [ ] E01 acquisition command approved.
- [ ] Ex01 acquisition command approved or explicitly skipped.
- [ ] Trusted/reference export command approved.
- [ ] RapidForensic actual run approved.
- [ ] No Git storage for binary evidence confirmed.
- [ ] Technical review owner assigned.
- [ ] Methodology review owner assigned.
- [ ] Operator review owner assigned.
- [ ] Legal review owner assigned.

## Not Evidence

This document is an input form. It is not proof that E01/Ex01, trusted export, RapidForensic execution, or review has been completed.
