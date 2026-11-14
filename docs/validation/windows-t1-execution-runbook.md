# Windows T1 E01/Ex01 Execution Runbook

Status: prepared, not executed
Date: 2026-06-18
Scope: External Windows T1 minimal E01/Ex01 evidence execution

This runbook prepares the operator workflow for a future external Windows run. It does not create E01/Ex01 images, run trusted forensic tools, or complete review signoff.

## 현재 상태 (R6 S4, 2026-10-21)

- 이 런북은 여전히 **준비만 됨, 실행 안 됨**이다. E01/Ex01 취득, 신뢰/참조 도구 내보내기, 실제 E01/Ex01에 대한 RapidForensic 실행, 검토 서명은 하지 않았다.
- 필요한 운영자 입력의 정확한 목록과 상태는 `docs/validation/windows-t1-operator-inputs.md` 맨 위 "현재 상태" 표에 있다(사람 지정 `operator_name`·`reviewer_name`·`review_ticket`·검토 담당, 취득 도구와 Ex01 결정, 디스크 생성·E01/Ex01 취득·신뢰 도구 내보내기 승인, 라이선스·저장소 ACL, 취득 후 `ntfs_volume_id`와 결과 경로).
- 2026-10-21 자동 재확인(취득 미실행): 이 호스트의 PATH에 `ewfacquire`·`ftkimager`·Sleuth Kit·Zimmerman 도구가 없다. Windows 11 Pro 25H2(10.0.26200.9711), Python 3.12.5, Korea Standard Time, `LongPathsEnabled=1`.
- 2026-08-30 EVTX 레코드 식별자 불일치: 현재 native 파서는 BinXML `EventRecordID`를 `record_id`로 낸다(합성 EVTX 시험으로 고정). 운영자 호스트에서 EvtxECmd와 레코드 단위 diff를 현재 코드로 다시 돌려야 닫힌다.
- Engineering Baseline과 Release Evidence는 따로 보고한다. Release Evidence는 실제 외부 E01/Ex01·Windows·신뢰/참조 도구·규모·검토 기록이 생길 때까지 차단이다.

## Purpose

Produce a minimal, synthetic, Windows-generated NTFS T1 corpus outside Git and collect enough artifacts to evaluate RapidForensic against independent trusted/reference results.

## Preconditions

- Engineering Baseline is Green in a clean `/tmp` venv.
- External evidence storage path is approved.
- Windows host is approved for synthetic forensic validation.
- No customer data, PII, malware, contraband, secrets, or actual case data is used.
- Operator and reviewer identities are recorded.
- Dangerous acquisition or disk-formatting operations have explicit operator approval.

## External Evidence Storage Placeholder

Use an operator-provided path:

```text
<external_corpus_root>/
  source-tree/
  images/
    e01/
    ex01/
  manifests/
  trusted-exports/
  rapid-results/
  diffs/
  logs/
  hashes/
  reviews/
  bundle/
```

Do not place this directory inside the Git repository.

## Windows Host Requirements

- Windows 10/11 or Windows Server host/VM.
- NTFS volume available for the synthetic source tree.
- Python 3.11 or newer.
- RapidForensic checkout at the intended commit.
- Long path policy recorded.
- Timezone recorded.
- External trusted/reference tools installed only if approved.

## Required Tool Records

Record version and command output for:

- Python.
- RapidForensic / `rapidtriage` package.
- Acquisition tool.
- Ex01-capable tool, if used.
- Trusted/reference tools.
- PowerShell version.
- Windows build.

## T1 Source Tree Creation

Create only synthetic text fixtures:

```text
source-tree/
  hello.txt
  same-content-a.txt
  same-content-b.txt
  unicode/
    한글파일.txt
  spaces/
    file with spaces.txt
  nested/
    level1/
      level2/
        nested-example.txt
  duplicates/
    a/
      duplicate.txt
    b/
      duplicate.txt
  zero-byte/
    empty.txt
```

Record SHA-256 and size for every file before acquisition.

## NTFS VHD/VHDX Procedure

Creating, formatting, mounting, or detaching disks requires operator approval. Store all disk artifacts outside Git. Record command history, volume ID, filesystem type, and timestamps.

## E01 Acquisition Procedure

1. Confirm the source NTFS volume is no longer being modified.
2. Acquire E01 using the approved acquisition workflow.
3. Store segments under `<external_corpus_root>/images/e01/`.
4. Record acquisition command, version, operator, host, timestamp, and SHA-256.
5. Populate a truth manifest under `<external_corpus_root>/manifests/`.
6. Run `scripts/known-answer-qc.py` against the manifest.

## Ex01 Acquisition Procedure

1. Confirm an approved Ex01-capable workflow exists.
2. Record encryption/compression/container settings.
3. Store Ex01 artifacts under `<external_corpus_root>/images/ex01/`.
4. Record acquisition command, version, operator, host, timestamp, and SHA-256.
5. Populate a truth manifest under `<external_corpus_root>/manifests/`.
6. Run `scripts/known-answer-qc.py` against the manifest.

## Hash Recording

Record:

- Source file SHA-256 and size.
- Image segment SHA-256 and size.
- Trusted/reference export SHA-256.
- Rapid observed result SHA-256.
- Diff result SHA-256.
- Bundle manifest SHA-256.

## Trusted Tool Export

Trusted/reference tools must not be treated as absolute truth. Export results outside Git, normalize allowed outputs, and document license restrictions.

## Normalized Observed Results

Use:

```powershell
python scripts/normalize-trusted-export.py --tool <tool> --input <trusted_export> --out <trusted_results_json>
```

Placeholder normalizers are not sufficient for release evidence until the real parser is implemented and reviewed.

## RapidForensic Run

Run RapidForensic against the external E01/Ex01 images only after operator approval. Export normalized observed results and logs to `<external_corpus_root>/rapid-results/` and `<external_corpus_root>/logs/`.

## Known-Answer QC

```powershell
python scripts/known-answer-qc.py --manifest <manifest_json>
```

Use `--check-files` only with approved extracted synthetic source files, never by pointing at raw E01/Ex01 binaries.

## Trusted Diff

```powershell
python scripts/trusted-diff.py --manifest <manifest_json> --rapid-results <rapid_results_json> --trusted-results <trusted_results_json> --out <diff_json> --summary <diff_summary_md>
```

Critical differences require review before any release decision.

## Evidence Bundle

```powershell
python scripts/build-evidence-bundle.py --root <bundle_root> --out <bundle_manifest_json> --summary <bundle_summary_md>
```

The bundle root must not contain raw image binaries, recovered outputs, customer data, secrets, or license-restricted vendor output.

## Review and Signoff

Release Evidence remains blocked until these reviews are complete:

- Technical review.
- Forensic methodology review.
- Operator review.
- Legal review.

## Files Never Allowed In Git

- `.E01`, `.Ex01`, `.dd`, `.raw`, `.img`, `.vhd`, `.vhdx`, `.aff`, `.001`.
- Recovered evidence output.
- Customer data.
- PII.
- Malware or suspicious payloads.
- Secrets and tokens.
- License-restricted vendor output.

## Stop Conditions

Stop before execution and report if:

- External storage path is missing.
- Windows host is unavailable.
- Acquisition tool is not approved.
- Trusted/reference tool output is license-restricted without storage policy.
- A command would format, mount, acquire, or delete data without explicit operator approval.
- Review completion is required for a release claim.
