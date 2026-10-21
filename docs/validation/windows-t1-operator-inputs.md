# Windows T1 Operator Inputs

Status: partially filled (environment re-checked 2026-10-21; staging stage recorded 2026-08-30); approvals and acquisition still pending
Date: 2026-08-30 (environment fields re-checked 2026-10-21, R6 S4)
Filled by: ZCode automated Phase 1 staging (not a human signoff); R6 S4 automated re-check (not a human signoff)

## 현재 상태 (R6 S4, 2026-10-21)

Windows T1 릴리스 증거는 아래 운영자 입력이 채워지고 승인될 때까지 **차단 유지**다. 자동으로 확인할 수 있는 값(커밋·Python·Windows·시간대·긴 경로 정책·PATH 위 도구)은 2026-10-21에 취득을 실행하지 않고 읽기 전용 명령으로 다시 확인해 아래 필드 표에 반영했다(근거: `docs/plans/r6-followups-2026-10-19.md` §4.3 갈래 C).

운영자 입력(정확한 목록):

| 입력 | 종류 | 상태 |
|---|---|---|
| `operator_name`, `reviewer_name` | 사람 지정 | 미정 |
| `review_ticket` | 추적 ID | 미정 |
| `acquisition_tool`(+ 버전, 승인) | 도구 설치·승인(ewfacquire/FTK Imager/다른 E01 생성 도구) | 호스트에 없음(2026-10-21 PATH 재확인: `ewfacquire`·`ftkimager`·`ewfinfo`·`ewfverify` 없음) |
| `ex01_capable_tool` 또는 "Ex01 생략" 명시 | 결정 | 미정 |
| 디스크 생성·포맷 명령 승인 | 승인 체크 | 미승인 |
| E01 취득 명령 승인 / Ex01 취득 승인 또는 생략 | 승인 체크 | 미승인 |
| 신뢰/참조 도구 내보내기 명령 승인(EvtxECmd·LECmd·JLECmd·RECmd·PECmd·MFTECmd·SrumECmd; 관리자 권한 필요 항목 포함) | 승인 체크 + 관리자 권한 세션 | 부분(비관리자 3종만 실행됨, 2026-08-30). 2026-10-21 이 호스트에서는 7종 모두 PATH에 없고 2026-08-30 기록의 도구 폴더도 없음 → 재설치·경로 기록 필요 |
| `license_restrictions` 재확인(Zimmerman 도구 라이선스 → 출력 보관 가능 여부) | 법무 확인 | 미정 |
| `evidence_storage_access_control`(공유 저장소면 ACL 기록) | 기록 | 단일 운영자 가정 |
| `ntfs_volume_id`(취득 시 VSN) | 취득 후 기록 | 미기록 |
| `e01_image_path`·`ex01_image_path`·`trusted_export_path`·`rapid_results_path`·`diff_result_path` | 실행 후 경로 | 미실행 |
| 기술·방법론·운영자·법무 검토 담당 지정 | 사람 지정 | 미정 |
| EVTX 레코드 식별자(BinXML EventRecordID) 불일치 해소 여부 확인(2026-08-30 발견) | 코드 상태 확인 → 현재 코드로 재실행 | **코드·합성 확인 완료(2026-10-21)**: native 파서(`rapidtriage/artifacts/windows/eventlog.py`)의 `record_id`는 BinXML System `EventRecordID`이고, BinXML을 풀지 못한 레코드만 레코드 헤더 id로 대체한다. 레코드 헤더 id(42)와 BinXML 값(653881)이 다른 합성 EVTX에서 `record_id=653881`(`tests/test_parser_quality_eventlog.py` `test_record_id_is_the_binxml_event_record_id_not_the_record_header_id`). 남은 일: 운영자 호스트에서 EvtxECmd 출력과 레코드 단위 diff 재실행(실행 승인 필요) |

자동 확인 값(2026-10-21, 취득 미실행): `rapid_commit` = `fd7b1ca`(브랜치 `feat/r6-s4-validation` 작성 시점 HEAD), `python_version` = 3.12.5, `windows_version` = Windows 11 Pro 25H2(10.0.26200.9711, `platform` + 레지스트리 `UBR` 읽기), `timezone` = Korea Standard Time(UTC+09:00, `tzutil /g`), `long_path_policy` = `LongPathsEnabled=1`(`reg query`, 읽기 전용). Sleuth Kit(`mmls`·`fls`·`icat`)도 PATH에 없다.

Engineering Baseline과 Release Evidence는 따로 보고한다. 위 자동 값과 합성 시험 통과는 Engineering Baseline이고, Release Evidence는 실제 외부 E01/Ex01·Windows·신뢰/참조 도구·규모·검토 기록이 생길 때까지 차단이다.

## Field Record

Fill this file before a real Windows T1 E01/Ex01 execution. Do not enter secrets, tokens, customer data, or actual case data.

| Field | Value | Required | Notes |
| --- | --- | --- | --- |
| `external_corpus_root` | `C:\Users\Daeryun\rapid-forensic-corpus` | yes | Outside Git; runbook layout created (source-tree, images, manifests, trusted-exports, rapid-results, diffs, logs, hashes, reviews, bundle). |
| `case_id` | `case-t1-windows-synthetic` | yes | Synthetic T1 case identifier. |
| `operator_name` | `<pending>` | yes | Requires human assignment before acquisition. |
| `reviewer_name` | `<pending>` | yes | Requires human assignment before review. |
| `windows_version` | `Windows 11 Pro 25H2 (build 10.0.26200.9711)` | yes | Re-checked 2026-10-21 (`platform`, registry `UBR`/`DisplayVersion` read). 2026-08-30: build 10.0.26200.9168. |
| `timezone` | `Korea Standard Time (UTC+09:00)` | yes | `tzutil /g` = `Korea Standard Time` (re-checked 2026-10-21). |
| `python_version` | `3.12.5` | yes | `python --version` on 2026-10-21 (2026-08-30 staging host: 3.12.8). Re-record on the acquisition host. |
| `rapid_commit` | `fd7b1ca37cdcbaebb2b6f91156545a8506110e9f` (branch `feat/r6-s4-validation` HEAD when filled) | yes | Re-record the exact commit used for the T1 run; 2026-08-30 staging baseline was `c1c5be0ea7f68f4b1d04894ed8191ad2a2f71d85` (tag v0.2.0). |
| `acquisition_tool` | `<pending>` | yes | `ewfacquire`/`ftkimager` absent on host (staging time and 2026-10-21 PATH check); E01 acquisition blocked until an approved tool is installed. |
| `ex01_capable_tool` | `<pending>` | conditional | Same blocker as acquisition tool. |
| `trusted_tool_paths` | `C:\Users\Daeryun\rapid-forensic-corpus\tools\` (EvtxECmd v2026.5 (build 0), LECmd v2026.5 (build 0), JLECmd v2026.5 (build 0), RECmd v2026.5 (build 0), PECmd v2026.5 (build 0), MFTECmd v2026.5 (build 0), SrumECmd v2026.5 (build 0)) | yes | Downloaded from download.ericzimmermanstools.com/net9; RECmd/PECmd/MFTECmd/SrumECmd awaiting admin-gated artifacts (hives, Prefetch, MFT, SRUDB). 2026-10-21: none of the seven is on PATH on this host and the recorded tools folder does not exist here; versions to be re-recorded when reinstalled. |
| `retention_policy` | Synthetic fixtures retained while T1 evidence is approved; dispose per operator policy | yes | Mirrored in `manifests/t1-source-tree-manifest.json`. |
| `license_restrictions` | Synthetic-only corpus; no vendor outputs collected yet; vendor-license review pending before trusted tool exports | yes | To be re-filled when trusted tools are installed. |
| `evidence_storage_access_control` | Single-operator local host; external corpus directory is user-profile scoped; formal ACL record pending | yes | Must be re-recorded for shared storage. |
| `review_ticket` | `<pending>` | yes | Assign before review stage. |
| `long_path_policy` | `LongPathsEnabled=1` | yes | Registry `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` (re-checked 2026-10-21 with `reg query`, read-only). |
| `ntfs_volume_id` | `C:` NTFS fixed volume (serial not recorded; record at acquisition) | required after creation | Source tree staged on the system drive NTFS volume. |
| `e01_image_path` | `<pending acquisition>` | required after acquisition | Will live under `<external_corpus_root>/images/e01/`. |
| `ex01_image_path` | `<pending acquisition>` | conditional | Under `<external_corpus_root>/images/ex01/`. |
| `trusted_export_path` | `<pending export>` | required after export | Under `<external_corpus_root>/trusted-exports/`. |
| `rapid_results_path` | `<pending run>` | required after run | Under `<external_corpus_root>/rapid-results/`. |
| `diff_result_path` | `<pending diff>` | required after diff | Under `<external_corpus_root>/diffs/`. |

## Completed Staging Record (2026-08-30)

- T1 synthetic source tree staged at `<external_corpus_root>/source-tree/files/`
  (byte-identical copy of the Tier 0 fixture tree; 9 files, including the
  Korean filename and space-containing filename).
- Per-file SHA-256 and size recorded under `hashes/`.
- Truth manifest written to `manifests/t1-source-tree-manifest.json`
  (`rapidforensic-e01-ex01-truth-manifest-v1`, folder-baseline stage).
- `scripts/known-answer-qc.py --check-files` result: PASS, 9/9 files checked,
  0 errors (see `logs/known-answer-qc-t1-source-tree.json`).
- Windows smoke run output: `logs/windows-smoke/` — smoke summary PASS
  (doctor/sample/search/benchmark/validation/evidence-guidance/web/
  workbench-smoke-contract all pass on Windows 11 Pro 26200).
- E01/Ex01 acquisition: NOT executed (no approved acquisition tool on host).

## Phase 2 Trusted Diff Record (2026-08-30)

- Trusted tools staged under `<external_corpus_root>/tools/` (Zimmerman net9
  builds): EvtxECmd, LECmd, JLECmd, RECmd, PECmd, MFTECmd, SrumECmd — all
  v2026.5 (build 0). Only EvtxECmd/LECmd/JLECmd were executable against non-admin
  artifacts so far.
- Host artifacts staged under `source-artifacts/` (wevtutil epl exports of
  System/Application full + 24h channels, 197 LNK, 339 JumpList containers),
  SHA-256 recorded in `source-artifacts/source-artifacts-hashes.json`.
- Rapid outputs in `rapid-results/`, reference exports in `trusted-exports/`,
  diff reports and `recovery-accuracy.json` in `diffs/`.
- Findings: LNK field-level trusted diff PASS (234/234); JumpList entry-level
  rows not emitted by RapidForensic (gap documented); EVTX record identity
  mismatch (physical header id vs BinXML EventRecordID) blocks record-level
  diff — BinXML EventRecordID surfacing is the next required parser fix.
  R6 S4 re-check (2026-10-21): the current native parser emits the BinXML
  `EventRecordID` as `record_id` (header id only when BinXML is not decoded);
  a synthetic EVTX test pins it. The record-level diff still has to be re-run
  with the current code on the operator host.
- Registry/MFT/USN/SRUM/Prefetch/Amcache diffs pending an elevated host.

## Approval Checkboxes

- [x] External evidence storage approved. (operator-provided local path outside Git)
- [x] Synthetic-only source tree approved. (byte-identical Tier 0 fixture copy)
- [ ] Disk creation/formatting command approved.
- [ ] E01 acquisition command approved.
- [ ] Ex01 acquisition command approved or explicitly skipped.
- [ ] Trusted/reference export command approved.
- [x] RapidForensic actual run approved. (smoke run + folder-baseline QC only)
- [x] No Git storage for binary evidence confirmed.
- [ ] Technical review owner assigned.
- [ ] Methodology review owner assigned.
- [ ] Operator review owner assigned.
- [ ] Legal review owner assigned.

## Not Evidence

This document is an input form. It is not proof that E01/Ex01, trusted export, RapidForensic execution against a real E01/Ex01, or review has been completed. The folder-baseline known-answer QC and the smoke run do not substitute for trusted-tool diffs or independent validation.
