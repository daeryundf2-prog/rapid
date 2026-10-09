# BSH 126 GB 실측 이미지 검증 보고서 — 2026-10-09

대상: `D:\devin\bsh-e01\BSH.E01` (EWF 17-segment set, 135.6 GB compressed)
런: `8c821ed6a78d` (외부 Sleuth Kit 엔진, 출력 `D:\devin\bsh-e01\rt-run-tsk`)
상태: **검증 단계 종결 — triage는 manifest 쓰기에서 실패, 추출·측정 산출물은 보존**

---

## 1. 원래 목표

1. E01 이미지를 읽고 파티션/파일시스템을 발견해 할당·삭제 파일을 복구한다.
2. 복구 결과를 신뢰도구(Sleuth Kit) 기준값과 대조해 커버리지를 측정한다.
3. MFT 파서 정확도(삭제 판정 포함)를 계량한다.
4. 수집된 행을 유형별로 탐색·검토할 수 있는 분석가 워크플로를 검증한다.
5. 모든 결과를 프로비넌스·해시와 함께 기록하고, 공학적 측정과 Release Evidence를 구분한다.

## 2. 단계별 수행 내역과 소요 시간

| # | 단계 | 소요 | 결과 |
|---|------|------|------|
| 1 | `mmls` 파티션 열거 | 수 초 | GPT 설명이 `?????`로 출력(Windows TSK 빌드의 mojibake) → 최대 데이터 파티션 폴백 로직 추가 (`0a3f955`, `374f424`) |
| 2 | 파티션 선택 | 즉시 | 섹터 **567296** = 233.9 GB NTFS, `fsstat`으로 검증 |
| 3 | `tsk_recover -e` 추출 | **~7시간** | **646,661개 파일** 추출, checkpoint 완료 |
| 4 | fingerprint 기록 | 즉시 | `rapidtriage-run-fingerprint.json` |
| 5 | 파일 스캔·해싱·시그니처 | **~33시간** (단일 스레드) | 완료됐으나 산출물이 메모리에만 존재 — `files.json` 미기록 |
| 6 | 아티팩트 수집·docs 인덱스 | 수 시간 | `rapidtriage-docs-index.json` **5.2 GB** — 유효 JSON으로 완결 |
| 7 | `rapidtriage-manifest.json` 쓰기 | — | **7.2 GB 기록 중 실패** — `Object of type bytes is not JSON serializable`로 절단 |
| 8 | persist / finalize | — | 미도달 (런 상태 `failed`) |

**총 경과: 41.7시간** (2026-10-07 12:59 → 2026-10-09 06:38 KST)

### 실패한 두 런의 기록

| 런 | 사망 지점 | 원인 | 조치 |
|----|-----------|------|------|
| `0f1f32c78b0a` | tsk_recover 1시간째 (188,554개 추출 상태) | 자식 프로세스 고정 타임아웃 3600 s | 크기 비례 타임아웃으로 수정 (`835a42c`, 234 GB → ~12.4 h 상한) |
| `8c821ed6a78d` | manifest 쓰기 중 (41.7 h) | 실행 중 서버가 `default=json_default` 없는 `write_result` 버전을 로드 — bytes 값이 `json.dump` 스트림을 중단 | 현재 HEAD에 이미 수정됨 (bytes→hex 보존 변환) |

## 3. 계량 결과

### 3.1 MFT 파서 정확도 (vs Sleuth Kit `ils -e`)

- 기준값: `ils -e` 1,379,052건 / `icat` $MFT 1.46 GB
- MFT inode 커버리지: **99.9999%** (1,379,048 / 1,379,049)
- 삭제 파일 판정: **precision 1.0 / recall 1.0** — 731,301개 삭제 엔트리 전수 일치, 오탐·누락 0
- 크기 일치율: **99.9958%**

### 3.2 추출 파일 트리 커버리지 (vs `fls -rp`)

- 기준값: `bsh-fls.txt` 780,645 경로 (할당 파일 623,770 / 디렉터리 93,219 / 삭제 63,656)
- 추출 고유 경로: 646,661 → fls 할당 경로 커버: **589,929 / 623,770 = 94.57%**
- 추출됐으나 할당 목록에 없음: 56,732 — 대부분 `$Extend/$Deleted` 삭제 복구물 + 8.3 별칭

미추출 33,841건의 분류 (전수 분석):

| 분류 | 건수 | 성격 |
|------|------|------|
| NTFS 메타파일 (`$MFT`, `$LogFile`, `$Secure`…) | 27 | tsk_recover는 메타파일을 일반 파일로 쓰지 않음 — `$MFT`는 `icat`으로 별도 수집됨 |
| ADS 스트림 (`:Zone.Identifier`, `:encryptable`…) | 1,825 | ADS를 독립 파일로 쓰지 않는 도구 설계 |
| 0바이트 파일 | ~29,500 (샘플 3,000 중 92%) | 데이터 런이 없는 레코드 — tsk_recover 설계상 스킵 |
| 소형 실파일 (45–~200 B) | ~2,500 | 잔여 갭 — stderr에 기록된 추출 에러 포함, 추가 조사 필요 |

**판정**: 갭의 대부분은 구조적(메타파일/ADS/0바이트)이며 사용자 콘텐츠 손실이 아님. 그러나 ~2,500개 비영바이트 잔여는 미해결이므로 완전 패리티로 주장하지 않음.

### 3.3 처리 속도

- tsk_recover 추출: 646,661개 / 7.1 h ≈ **시간당 ~9만 파일**
- 파일 스캔·시그니처: 646,661개 / ~33 h ≈ 시간당 ~2만 파일 (단일 스레드 per-file I/O — 이번 런의 최대 병목)

## 4. 발견·수정된 결함

| 결함 | 증상 | 수정 |
|------|------|------|
| mmls mojibake | GPT 설명 `?????` → 네이티브 파이썬 경로로 고착, 수 일 소요 | 최대 데이터 파티션 폴백 + 정직한 `selection_source` 라벨 |
| 고정 타임아웃 | 3600 s → tsk_recover rc=124 사망 | 파티션 크기 비례 상한 + env 오버라이드 |
| bytes 직렬화 | manifest 7.2 GB 쓰기 중 TypeError | `default=json_default` (이미 HEAD에 존재 — 서버 재기동으로 적용) |
| 필터 0건 무표시 | 가상 테이블이 빈 채로 "10건 로드" 공지 | 필터 결과 배너 + 빈 테이블 숨김 (`9fb3079`) |
| 중간 산출물 부재 | 41.7 h 작업이 한 번의 쓰기 실패로 소실 | 미수정 — 증분 저장 패치 필요 (아래 §6) |

## 5. 보존된 산출물 인벤토리

| 산출물 | 경로 | 상태 |
|--------|------|------|
| 추출 파일 트리 | `D:\devin\bsh-e01\rt-run-tsk\_e01\filesystem\` | ✅ 완결 646,661개 |
| E01 단계 상태 | `rt-run-tsk\_e01\rapidtriage-e01-stage-status.json` | ✅ `completed` |
| fingerprint | `rt-run-tsk\rapidtriage-run-fingerprint.json` | ✅ |
| E01 메타데이터 | `rt-run-tsk\rapidtriage-e01.json` | ✅ |
| docs 인덱스 | `rt-run-tsk\rapidtriage-docs-index.json` | ✅ 5.2 GB 유효 |
| manifest | `rt-run-tsk\rapidtriage-manifest.json` | ⚠️ 7.2 GB 절단 — 폐기 대상 |
| fls 기준값 | `D:\devin\bsh-e01\bsh-fls.txt` | ✅ SHA-256 `410d87c5…aa7a3d` |
| $MFT 참조 | `D:\devin\bsh-e01\bsh-mft.bin` (1.46 GB) | ✅ |
| 추출 매니페스트 | `bsh-extracted-files-tsk.json` | ✅ SHA-256 `6df0433e…cf5c3c85` |
| 커버리지 리포트 | `bsh-fls-diff-tsk.json` | ✅ `engineering_check_only` |
| 단계별 타이밍 | `bsh-run-timing.json` | ✅ |
| 런 감시 로그 | `bsh-e01\monitor.log` | ✅ |

## 6. 구조적 교훈 (다음 작업의 근거)

1. **증분 저장 부재** — 스캔 결과가 33시간 내낄 메모리에만 있고 마지막에 한 번에 씀. 한 번의 쓰기 실패로 전부 소실. → 스캔/아티팩트 중간 산출물을 주기적으로 디스크에 기록하는 패치 필요.
2. **단일 스레드 per-file I/O** — 646k 파일 시그니처·해싱이 33시간. → 배치/멀티워커 구조 필요.
3. **진행률 산출 부재** — triage 내부에서 % 진행을 외부로 노출하지 않아 잔여 시간을 알 수 없음.
4. **타임아웃/직렬화 방어** — 대형 케이스는 고정 상수(3600 s, JSON default 부재)가 치명적. 둘 다 수정됨.

## 7. 결론

- **달성**: E01 파티션 선택(mojibake 환경 포함), 646k 파일 신뢰도구 추출, MFT 파서 99.9999%·삭제 판정 완전 일치, 추출 커버리지 94.57%(갭 구조적 해명), 단계별 시간·해시·산출물 기록 완비.
- **미달성**: `files.json`/`docs.json` 기반의 유형별 행 수 vs AXIOM 대조 — manifest 쓰기 실패로 산출되지 못함. 이 항목은 재실행이 필요.
- **에비던스 등급**: 전 항목 `engineering_check_only`. Release Evidence는 리뷰어 승인 + 유형별 행 대조 완료 후에만 승격 가능.
- **재실행 경로**: 서버 재기동(수정된 `json_default` 로드) → `resume` 시 추출·fingerprint는 재사용, 스캔 ~33 h는 재실행. 증분 저장 패치를 먼저 넣으면 재실패 시에도 이어서 진행 가능.
