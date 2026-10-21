# A등급 특이사항 규칙 검증 (R6 S4, 2026-10-19 계획 · 2026-10-21 하네스)

근거: `docs/plans/r6-followups-2026-10-19.md` §4(단계 4 — 검증 갭). 하네스 `scripts/rule-validation.py`, 시험 `tests/test_rule_validation_script.py`, 카탈로그 `validation` 메타(`rapidtriage/core/triage_rules/catalog.py`, 7개 규칙 블록).

상태: **합성 근거만**. 실데이터·공개 데이터셋·VM 열은 워커 실행(Sonnet, 사용자 승인 후) 결과로 채운다. 이 문서는 Engineering Baseline 기록이며 Release Evidence가 아니다(AGENTS.md).

## 1. 규칙 × 근거 소스

| 규칙 | 등급·상태 | 합성(tests/triage_cases) | 서브셋 음성(run-subset10) | bsh-mft(`ntfs-meta source=mft`) | 공개 데이터셋 | VM 생성 |
|---|---|---|---|---|---|---|
| `antiforensics.wiper_run_after_incident` | A · provisional | 양성 5행 중 4행 적중(사건 기간 sdelete Prefetch, 사건 뒤 BleachBit PCA, `last_run_at`만 있는 Prefetch, 따옴표 경로 4688 `cipher /w`; 설치 행은 실행 시각 없음 → 미적중) · 음성 3행 0적중(사건 몇 주 전 실행, 사건 중 VeraCrypt) | 대기(워커 실행 예정) — 사건 기준 시각 필요(`--recompute --incident-start/--incident-end`) | 해당 없음(MFT 행을 읽지 않음) | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — SDelete 실행 → Prefetch·Amcache |
| `cloud.bulk_upload` | A · provisional | 양성 50행 50적중(한 계정 25분에 50개) · 음성 171행 0적중(하루에 걸친 50개, 경로 없는 키워드 60건, 같은 항목 60회, 600 MB 단일 항목) | 대기(워커 실행 예정) | 해당 없음 | 승인 대기(공개 데이터셋·VM) — 공개 데이터셋에 동기화 로그 드묾 | 승인 대기(공개 데이터셋·VM) — 테스트 계정 필요, 없으면 "합성 유지" |
| `eventlog.rdp_external_ip` | A · verified | 양성 1행 1적중(4624 유형 10, 8.8.8.8) · 음성 1행 0적중(VPN 풀 10.8.0.15) | 대기(워커 실행 예정) — 기대 0적중(서브셋에 외부 IP 로그온 없음) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — VM NAT는 사설 주소라 양성 생성이 어려움 |
| `eventlog.log_cleared` | A · verified | 양성 1행 1적중(Security 1102) · 음성 1행 0적중(Kernel-Cache 104) | 대기(워커 실행 예정) — 기대 0적중(서브셋 Security/System에 1102·104 없음) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) — `wevtutil cl Security` → 1102 |
| `ntfs.si_before_fn` | A · verified | 양성 1행 1적중($SI 생성 2019 < $FN 생성 2024) · 음성 1행 0적중(복사본: $SI 수정만 과거) | 해당 없음(서브셋에 `$MFT` 없음) | 대기(워커 실행 예정) — `--ntfs-analysis`, 분석 자체의 `si_created_before_fn` 수와 교차 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |
| `ntfs.ads_executable` | A · verified | 양성 2행 2적중(MZ 서명 ADS, 서명 종류만 있는 icat 스트림) · 음성 2행 0적중(보안 제품 태그 스트림, Zone.Identifier) | 대기(워커 실행 예정) — `windows-filesystem` ADS 행이 있을 때만 의미 | **해당 없음**: `ntfs-meta` 분석 행에는 ADS 정보가 없다(하네스는 `not_applicable`로 보고). 이미지 런의 `windows-filesystem` 행으로 검증 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |
| `rdp.external_ip` | A · verified | 양성 2행 2적중(1149 8.8.8.8, RdpCoreTS 131 1.1.1.1:52344) · 음성 2행 0적중(VPN 풀 172.16.5.20) | 대기(워커 실행 예정) — 기대 0적중, 지표의 사설 IP가 외부로 오분류되지 않는지(`indicators.ip.non_public`) | 해당 없음 | 승인 대기(공개 데이터셋·VM) | 승인 대기(공개 데이터셋·VM) |

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
| run-subset10(음성) | 대기 | `eventlog.log_cleared` · `eventlog.rdp_external_ip` · `rdp.external_ip` | 대기 | 대기 | 대기 | 대기(워커 실행 예정) |
| bsh-mft | 대기 | `ntfs.si_before_fn` | 대기 | 대기 | 표본 10건 대기 | 대기(워커 실행 예정) |
| 공개 데이터셋 | — | — | — | — | — | 승인 대기(공개 데이터셋·VM) |
| VM 생성 | — | — | — | — | — | 승인 대기(공개 데이터셋·VM) |

결과가 나오면 해당 규칙의 카탈로그 `validation.real` / `validation.public`에 `{source, hits, false_positives, checked_at: '날짜', note_ko}`를 추가한다(규칙 `version`은 올리지 않는다 — 판정 로직 불변). 콘솔 팝오버 한 줄이 "검증: 합성 픽스처만"에서 "검증: 실데이터 n건(…) · 합성 픽스처"로 바뀐다.

## 4. 등급 권고(현재)

실데이터 양성이 아직 없으므로 7개 규칙 모두 등급을 유지하되 "합성 근거만"으로 표시한다(카탈로그 `validation.synthetic: true`, `real`·`public` 비어 있음). 실데이터에서 오탐이 확인되면 그때 등급·조건을 다시 검토한다.

## Not Evidence

이 문서와 하네스 결과는 엔지니어링 측정이다. 합성 픽스처 적중, 서브셋 음성 대조, `$MFT` 단독 분석은 독립 도구 대조·검토 서명을 대신하지 않으며 릴리스 증거가 아니다.
