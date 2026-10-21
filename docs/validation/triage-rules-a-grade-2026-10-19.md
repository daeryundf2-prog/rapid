# A등급 특이사항 규칙 검증 (R6 S4, 2026-10-19 계획 · 2026-10-21 하네스)

근거: `docs/plans/r6-followups-2026-10-19.md` §4(단계 4 — 검증 갭). 하네스 `scripts/rule-validation.py`, 시험 `tests/test_rule_validation_script.py`, 카탈로그 `validation` 메타(`rapidtriage/core/triage_rules/catalog.py`, 7개 규칙 블록).

상태(2026-10-21): **실데이터 음성 대조·`$MFT` 측정 완료, 양성 실데이터 없음**. 서브셋 음성 대조(run-subset10)와 BSH 전체 이미지 `$MFT`(`ntfs-meta source=mft`) 측정 결과를 §1·§3에 채웠다. `ntfs.si_before_fn`은 실데이터에서 오탐 폭주(174,852건)라 버전 2로 재설계했다(§5). 공개 데이터셋·VM 열은 사용자 승인 대기. 이 문서는 Engineering Baseline 기록이며 Release Evidence가 아니다(AGENTS.md).

## 1. 규칙 × 근거 소스

| 규칙 | 등급·상태 | 합성(tests/triage_cases) | 서브셋 음성(run-subset10) | bsh-mft(`ntfs-meta source=mft`) | 공개 데이터셋 | VM 생성 |
|---|---|---|---|---|---|---|
| `antiforensics.wiper_run_after_incident` | A · provisional | 양성 5행 중 4행 적중(사건 기간 sdelete Prefetch, 사건 뒤 BleachBit PCA, `last_run_at`만 있는 Prefetch, 따옴표 경로 4688 `cipher /w`; 설치 행은 실행 시각 없음 → 미적중) · 음성 3행 0적중(사건 몇 주 전 실행, 사건 중 VeraCrypt) | **미평가**: 입력 가능 행 284,292행, 사건 기간을 주지 않아 규칙이 동작하지 않음(0적중은 음성 근거 아님) | 해당 없음(MFT 행을 읽지 않음) | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — SDelete 실행 → Prefetch·Amcache |
| `cloud.bulk_upload` | A · provisional | 양성 50행 50적중(한 계정 25분에 50개) · 음성 171행 0적중(하루에 걸친 50개, 경로 없는 키워드 60건, 같은 항목 60회, 600 MB 단일 항목) | **해당 없음**: 입력 가능 행 0(동기화 업로드 행 없음) | 해당 없음 | 승인 대기(공개 데이터셋·VM) — 공개 데이터셋에 동기화 로그 드묾 | 승인 대기(공개 데이터셋·VM) — 테스트 계정 필요, 없으면 "합성 유지" |
| `eventlog.rdp_external_ip` | A · verified | 양성 1행 1적중(4624 유형 10, 8.8.8.8) · 음성 1행 0적중(VPN 풀 10.8.0.15) | **0적중 / 292,370행, 기대 최대 0 통과**(오탐 0) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — VM NAT는 사설 주소라 양성 생성이 어려움 |
| `eventlog.log_cleared` | A · verified | 양성 1행 1적중(Security 1102) · 음성 1행 0적중(Kernel-Cache 104) | **0적중 / 292,370행, 기대 최대 0 통과**(오탐 0) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — `wevtutil cl Security` → 1102 |
| `ntfs.si_before_fn` | A · verified · **버전 2** | 양성 4행 4적중(A: $SI 초 미만 0 / A: $SI 수정·MFT 수정도 과거 / C: 단순 복사 / B: Downloads 실행 파일) · 음성 5행 0적중(같은 시간 대량 복사 3, WinSxS 1, $SI·$FN 생성 같음 1) | 해당 없음(서브셋에 `$MFT` 없음) | **버전 1: 174,852건 전부 A — 오탐 폭주**(표본 10건 모두 정상). **버전 2: 후보 174,854(분석 수와 일치) → 표시 8,970(A 2 · B 202 · C 8,766), 미표시 165,884**(§5) | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |
| `ntfs.ads_executable` | A · verified | 양성 2행 2적중(MZ 서명 ADS, 서명 종류만 있는 icat 스트림) · 음성 2행 0적중(보안 제품 태그 스트림, Zone.Identifier) | **해당 없음**: 입력 가능 행 0(`ads-stream-candidate` 행 없음) | **해당 없음**: `ntfs-meta` 분석 행에는 ADS 정보가 없다(하네스는 `not_applicable`로 보고). 이미지 런의 `windows-filesystem` 행으로 검증 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |
| `rdp.external_ip` | A · verified | 양성 2행 2적중(1149 8.8.8.8, RdpCoreTS 131 1.1.1.1:52344) · 음성 2행 0적중(VPN 풀 172.16.5.20) | **0적중 / 292,370행, 기대 최대 0 통과**(오탐 0) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |

"합성" 열은 `tests/test_rapidtriage_triage_rules.py`(`RuleFixtureTests`)가 엔진 전체를 돌려 확인한다. 하네스 시험(`tests/test_rule_validation_script.py`)도 같은 픽스처의 양성·음성 행을 합성 런·`ntfs-meta` 분석에 심어 적중·기대 대조·읽기 전용을 확인한다(Q-S4-1).

## 2. 하네스 사용(워커용)

모든 출력은 Git 밖(`D:\rapid-qa\derived\r6-s4-*`)에 둔다. 증거 폴더는 읽기 전용이며 하네스는 런·분석 폴더에 아무것도 쓰지 않는다(엔진 재계산은 시스템 임시 폴더에서 하고 지운다).

```powershell
# 서브셋 음성 대조(Q-S4-3): 저장된 특이사항 조인을 그대로 읽는다
'{"eventlog.log_cleared": {"max": 0}, "eventlog.rdp_external_ip": {"max": 0}, "rdp.external_ip": {"max": 0}}' |
  Set-Content -Encoding utf8 D:\rapid-qa\derived\r6-s4-subset\expected-negative.json
python scripts/rule-validation.py --run <run-subset10 출력 폴더> --rules A `
  --expect D:\rapid-qa\derived\r6-s4-subset\expected-negative.json `
  --output D:\rapid-qa\derived\r6-s4-subset\rule-validation.json
# 저장된 조인이 지금 카탈로그보다 오래됐으면(경고 "flag set computed with rule version …") --recompute

# bsh-mft(Q-S4-2): ntfs-meta(source=mft, parse) 분석 폴더 하나를 넘긴다
python scripts/rule-validation.py --ntfs-analysis <런>\analyses\<ntfs-meta 분석 id> `
  --expect D:\rapid-qa\derived\r6-s4-ntfs\expected-positive.json `
  --output D:\rapid-qa\derived\r6-s4-ntfs\rule-validation.json   # 기본 규칙: ntfs.si_before_fn, ntfs.ads_executable

# 사건 기준 시각이 필요한 규칙(wiper_run_after_incident)
python scripts/rule-validation.py --run <런> --rules antiforensics.wiper_run_after_incident --recompute `
  --incident-start 2024-05-01T00:00:00Z --incident-end 2024-05-03T00:00:00Z
```

- `--expect`: `{규칙 id: {"min": n} | {"max": n}}`(양성 n건 이상 / 음성 n건 이하). 기대에만 있는 규칙도 평가한다. 종료 코드 0 통과 · 1 불일치 · 2 입력 오류.
- 규칙마다: 적중 수, 등급별 수, 행 종류별 수, **입력 가능 행 수**(`eligible_rows`, 규칙 선택자가 읽는 행: 아티팩트 유형 수·파일 목록·분석 행), 표본 최대 10건(`--samples`; 아티팩트 유형, 경로 끝 이름만, 시각, 근거 필드 — 경로 값은 끝 이름, URL은 `scheme://host/…`로 줄임).
- 입력 가능 행이 0인 규칙은 `not_applicable`이고, 여기에 음성 기대(`max`)를 걸면 **불일치**(음성 대조 불성립)다. 0적중이 곧 오탐 0의 근거가 되지 않게 한다.
- `--run`은 지표(`rapidtriage-indicators.json`)의 IP 지표를 규칙의 `is_public_ip`로 공인/비공인으로 나눠 보고한다(`non_public_samples` 최대 10개 — 출력은 Git 밖에만).
- `--ntfs-analysis`는 분석 요약에 `timestamp_mismatch_reason_counts_all`이 있으면 `ntfs.si_before_fn` 적중 수와 분석 자체의 `si_created_before_fn` 수를 나란히 보고한다(`analysis_cross_check.agree`). 차이가 나면 수동 확인 3건(Q-S4-2)과 `scripts/mft-reference-diff.py` 교차를 권한다.

## 3. 결과 기록(워커가 채움)

| 소스 | 실행 커밋 | 규칙 | 적중 | 입력 가능 행 | 오탐 검토 | 판정 |
|---|---|---|---|---|---|---|
| run-subset10(음성) | 94be1df | `eventlog.log_cleared` · `eventlog.rdp_external_ip` · `rdp.external_ip` | 0 · 0 · 0 | 292,370 · 292,370 · 292,370 | 해당 없음(적중 없음) | 통과(기대 최대 0). r6-s1-run·qa-case1·r4-v1도 0적중이나 같은 증거 재처리라 독립 근거 아님 |
| run-subset10 | 94be1df | `antiforensics.wiper_run_after_incident` | 0 | 284,292 | — | 미평가(사건 기간 없음) |
| run-subset10 | 94be1df | `cloud.bulk_upload` · `ntfs.ads_executable` | 0 · 0 | 0 · 0 | — | 해당 없음(입력 없음) |
| BSH 전체 이미지 `$MFT` | 94be1df(버전 1) | `ntfs.si_before_fn` | 174,852(전부 A) | 1,421,896 | 무작위 10건 모두 정상(시각 보존 복사·압축 해제·서비싱), 수동 확인 3건($SI<$FN 자체는 사실) | **오탐 폭주 → 재설계** |
| BSH 전체 이미지 `$MFT` | fix/r6-s4-si-before-fn(버전 2) | `ntfs.si_before_fn` | 8,970(A 2 · B 202 · C 8,766) | 1,421,896 | A 2건 전수 검토(§5.3), B 상위 폴더 검토 | A는 이상 모양이 맞으나 조작 여부 미확정 |
| 공개 데이터셋 | — | — | — | — | — | 승인 대기(공개 데이터셋·VM) |
| VM 생성 | — | — | — | — | — | 승인 대기(공개 데이터셋·VM) |

위 결과는 7개 규칙의 카탈로그 `validation.real`에 `{source, hits, false_positives, checked_at: '2026-10-21', note_ko}`로 기록했다(메타데이터만으로는 `version`을 올리지 않는다; `ntfs.si_before_fn`은 판정 로직이 바뀌어 버전 2). 콘솔 팝오버 한 줄은 "검증: 실데이터 n건(…) · 합성 픽스처"다. 음성·미평가·해당 없음은 출처 이름에 그대로 적었다(예: "run-subset10(사건 기간 없음 — 미평가)").

## 4. 등급 권고(현재)

- `eventlog.log_cleared`·`eventlog.rdp_external_ip`·`rdp.external_ip`: 음성 대조에서 오탐 0. 등급 유지. 참양성은 실데이터로 아직 증명되지 않았다.
- `antiforensics.wiper_run_after_incident`·`cloud.bulk_upload`·`ntfs.ads_executable`: 실데이터에서 평가하지 못했다(사건 기간 없음 / 입력 없음). 등급 유지, 합성 근거만.
- `ntfs.si_before_fn`: 버전 1의 "단순 $SI<$FN = A"는 실데이터에서 A 오탐 폭주였다. 버전 2(§5)는 A를 타임스톰핑 보강 근거가 있는 경우로 좁혔다. 카탈로그 등급은 A로 두고 결과별 상한(B/C)과 미표시로 낮춘다.
- 어느 규칙도 실데이터 양성이 없다. 공개 데이터셋·일회용 VM 생성은 사용자 승인 대기다.

## 5. `ntfs.si_before_fn` 재설계(버전 2, 2026-10-21)

### 5.1 버전 1 실데이터 결과(BSH 전체 `$MFT`, 1,421,896 레코드)

적중 174,852건(파일 156,999 · 디렉터리 17,855; 사용 중 93,010 · 삭제 81,844). $FN−$SI 차이: 1일 이하 396, 30일 이하 4,839, 1년 이하 138,308, 1년 초과 31,311. 적중의 87%가 $FN 생성 8일에 몰렸고 2025-02-21에 62,967건, 2025-02-23에 59,957건(Windows 기능 업데이트 10.0.26100)이다. WinSxS 49,482건, Program Files 25,116건. 무작위 10건 모두 시각 보존 복사·압축 해제·서비싱이었다.

**2건 차이(엔진 174,852 vs 분석 `si_created_before_fn` 174,854)**: 규칙의 시각 해석(`parse_time`)은 1971년 이전을 "시각 없음"으로 버린다. BSH의 Microsoft 병음 IME 파일 2개(`ChsPinyinUDL_RoamUp.dat`, `ChsPinyinEUDP_RoamUp.lex`, 엔트리 448437·448438)는 $SI 생성·수정이 1970-01-02T00:00:00이라 규칙에서만 빠졌다. 버전 2는 $SI/$FN에 FILETIME 0(1601년)만 "시각 없음"으로 보는 해석을 써서 분석과 같은 174,854 후보를 센다(하네스 `analysis_cross_check.agree: true`). 두 파일은 $SI MFT 수정이 생성 시각과 같아 버전 2에서 C다.

### 5.2 버전 2 판정

후보: $SI 생성 < $FN 생성 − `min_delta_seconds`(60초, 버전 1과 같음). 결과:

| 결과 | 조건 | BSH `$MFT` |
|---|---|---|
| A | 보강 근거 ① $SI 생성·수정·MFT 수정 모두 초 미만 0 + $FN 생성은 초 미만 있음, 또는 ② $SI 수정·MFT 수정도 $FN 생성보다 임계값 이상 앞섬. 대량·서비싱이어도 표시 | 2 |
| B | 보강 근거 없음 + 사용자 쓰기 가능 경로(`\AppData\`, `\Temp\`, `\Downloads\`, `\Users\Public\`, `\ProgramData\` 등)의 실행·스크립트 확장자(`executable_extensions`) | 202 |
| C | 보강 근거 없음, 그 밖 | 8,766 |
| 미표시 | 보강 근거 없음 + 서비싱 경로(`suppress_path_markers`: WinSxS·servicing·SoftwareDistribution) 또는 $FN 생성 같은 구간(`bulk_bucket_seconds` 3600초)의 후보가 `bulk_min_records`(500)건 이상 | 165,884 |

설계 근거(실측): $SI 생성·수정만 초 미만 0인 후보는 30,489건(압축 해제·MSI의 2초 단위 시각)이라 보강 근거가 못 된다 — NTFS가 직접 쓰는 $SI MFT 수정까지 0인 경우는 1건뿐이다. $SI 수정만 $FN보다 앞선 후보는 비대량에서도 8,029건(복사가 수정 시각을 보존)이라 MFT 수정까지 요구한다. "사용자 쓰기 가능 경로의 실행 파일"을 A 근거로 쓰면 202건이 모두 설치기·Teams 추가 기능 압축 해제라 B로 낮췄다. 500건/시간 기준은 후보의 165,587건(21개 시간 구간)을 덮고 서비싱 경로가 297건을 더한다. 보강 근거가 있는 후보는 대량·서비싱 구간에 0건이었다.

`$MFT` 단독 분석의 판단은 엔진의 `finalize`에서 한다(시간 구간 수를 다 센 뒤). 후보 메모리는 BSH 기준 약 17.5만 건이다.

### 5.3 남은 A 2건 검토(전수 — 10건 미만)

| 엔트리 | 경로 끝 | $SI 생성 / 수정 / MFT 수정 | $FN 생성 | 근거 | 검토 |
|---|---|---|---|---|---|
| 321434(사용 중) | `AhnLab\Safe Transaction\TrueEyesU_1.3.4.3.dll` | 2023-03-16 00:52:44.741139 / 2022-02-16 02:29:35 / 2023-03-16 00:52:44.741139 | 2025-05-29 23:25:46.800693 | ② | $FN이 $SI 네 시각보다 2년 늦다. 이름이 새로 쓰였는데 $SI MFT 수정이 갱신되지 않은 모양 — 보안 제품 자기 보호 드라이버의 커널 수준 이름 변경일 가능성이 크지만 USN·$LogFile 없이 확정 불가. 검토 대상으로 타당 |
| 540183(삭제) | `\fb6dd03b-99d7-4cc8-a878-91c8e655c2d3`(볼륨 루트) | 2024-11-07 20:24:12 ×4(모두 초 미만 0) | 2025-04-02 23:45:24.124423 | ①② | $SI 네 시각이 같은 초·초 미만 0, $FN은 5개월 뒤 — 고전적 타임스톰핑 모양. 삭제된 GUID 이름 임시 파일(설치기·업데이트 추정)이라 내용 확인 불가. 검토 대상으로 타당 |

B 202건 상위 폴더: Teams 회의 추가 기능(`TeamsMeetingAdd-in\1.25.08601\x64`·`x86` 38), AnySupport 원격 지원(`Users\Public\Documents\Koino\AnySupport` 19+), 설치기 임시 폴더(`AppData\Local\Temp\ICD*.tmp`), kdefense — 모두 압축 해제·설치로 보인다. C 8,766건은 Program Files 3,541 · Users 3,813 · 기타.

### 5.4 재측정 방법

```powershell
python scripts/rule-validation.py --ntfs-analysis <런>\analyses\<ntfs-meta 분석 id> --rules ntfs.si_before_fn --json --output <Git 밖>\after.json
```

`analysis_cross_check`는 `{analysis_count, engine_candidates, engine_hits, not_flagged, agree}`다. `engine_candidates`는 하네스가 행을 한 번 더 읽어 규칙의 `apply`만 돌린 후보 수(등급·미표시 전)이고 `agree`는 이것과 분석 수의 일치다. BSH 측정: 버전 1 71.7초, 버전 2 52.1초(엔진) + 후보 재계산.

## Not Evidence

이 문서와 하네스 결과는 엔지니어링 측정이다. 합성 픽스처 적중, 서브셋 음성 대조, `$MFT` 단독 분석은 독립 도구 대조·검토 서명을 대신하지 않으며 릴리스 증거가 아니다.
