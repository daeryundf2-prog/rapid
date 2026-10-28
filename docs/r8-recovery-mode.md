# R8 복구 모드 (`--mode recovery`)

근거: `feat/r8-overhaul` 브랜치 커밋(`081c97a..HEAD`), `rapidtriage/core/e01_native.py`, `rapidtriage/core/run/procpool.py`, `rapidtriage/core/carving.py`, `frontend/src/features/stages/CoveragePanel.tsx`.
측정 절차와 판정 기준은 `docs/validation/r8-benchmark-and-recovery.md`에 있다.

복구 모드는 "가능한 한 전부 꺼낸다"를 목표로 한다. 다른 모드는 속도를 위해 상한을 유지하되, 상한에 걸린 곳은 run summary의 `coverage` 목록에 남기고 콘솔의 **복구 범위** 패널에 보여 준다. 조용히 잘리는 곳은 없어야 한다.

---

## 1. 복구 모드에서 달라지는 점

| 영역 | 복구 모드 | 다른 모드 |
|---|---|---|
| 파티션 | 모든 파티션을 추출한다. NTFS는 dissect.ntfs, 그 밖의 파일시스템은 pytsk3로 처리한다 | 같음. 지원하지 않는 파티션과 파일시스템은 coverage에 기록 |
| 이미지당 파일 수 | 상한 없음. `RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES`를 지정했을 때만 그 값으로 자른다 | 기본 200,000개. 넘으면 `file-count-cap` 기록 |
| 삭제 MFT 탐색 | 상한 없이 끝까지 훑는다. 중간에 멈춘 결과는 partial로 표시된다 | 상한에서 멈추고 `deleted-sweep-cap` 기록 |
| EVTX | 레코드당 문자열, BinXML 토큰, 중첩 BinXML 크기, 레코드 크기 상한을 모두 푼다 | 상한 유지. 걸릴 때마다 해당 코드 기록 |
| 레지스트리 하이브 | 하이브 문자열 스캔 상한을 푼다 | 상한 유지. `string-count-cap` 기록 |
| 미할당 영역 카빙 | `$Bitmap` 기준 미할당 클러스터를 전부 카빙해 `carve-unallocated`에 쓴다 | 기본은 하지 않음. `--carve`를 주면 상한 안에서 수행 |

### 공통 변경 (모든 모드)

- **MFT 로컬 사본**: `$MFT`를 파티션의 `_system/MFT*.bin`으로 한 번 순차 복사하고, 계획 단계와 워커가 그 사본에서 MFT 레코드를 읽는다. 파일 내용은 여전히 이미지에서 읽는다. 복사에 실패하면 예전 경로(이미지에서 무작위 읽기)로 처리하고 `mft-local-copy-failed`를 기록한다.
- **프로세스 풀**: EVTX, 레지스트리, ESE 수집기는 프로세스 풀에서 돈다. 단, 아티팩트 단계에 run plan이 **없을 때만** 쓴다. run plan이 있으면 협조적 취소, 부분 결과, 실시간 행 카운터를 지키기 위해 스레드로 처리한다.
- **체크포인트**: E01 체크포인트 지문에 실행 모드가 들어가므로, 상한이 걸린 이전 단계 결과를 복구 모드 실행이 이어받지 않는다.

---

## 2. coverage 코드와 패널 문구

패널은 항목마다 "영역: 사유 (확인 N / 상한 M)" 한 문장을 보여 준다. 사유 코드는 대소문자와 `_`/`-`를 구분하지 않는다.

### 사유 (`reason_code`)

| reason_code | 패널 문구 |
|---|---|
| `file-count-cap` | 파일 수 상한에 걸려 일부만 추출됨 |
| `deleted-sweep-cap` | 삭제 항목 탐색 상한에 걸려 일부만 처리됨 |
| `unsupported-filesystem` | 지원하지 않는 파일시스템이라 처리하지 않음 |
| `partition-not-supported` | 지원하지 않는 파티션이라 처리하지 않음 |
| `mft-local-copy-failed` | MFT 사본을 만들지 못해 느린 경로로 처리함 |
| `evtx-string-cap` | 레코드당 문자열 상한에 걸려 일부만 처리됨 |
| `evtx-binxml-token-cap` | 레코드당 BinXML 토큰 상한에 걸려 일부만 처리됨 |
| `evtx-nested-binxml-size-cap` | 중첩 BinXML 크기 상한에 걸려 일부만 처리됨 |
| `evtx-record-size-cap` | 레코드 크기 상한에 걸려 일부만 처리됨 |
| `etl-scan-prefix-cap` | 앞부분 스캔 상한에 걸려 일부만 처리됨 |
| `string-count-cap` | 문자열 수 상한에 걸려 일부만 처리됨 |
| `scan_bytes_cap` | 스캔 용량 상한에 걸려 일부만 처리됨 |
| `candidate_cap` | 후보 수 상한에 걸려 일부만 처리됨 |
| `unallocated_run_cap` | 미할당 구간 수 상한에 걸려 일부만 처리됨 |
| 그 밖의 코드 | 기타 제한이 적용됨 (원래 코드는 툴팁) |

### 영역 (`area`)

| area | 패널 문구 |
|---|---|
| `e01_native.files` | 파일 추출 |
| `e01_native.deleted_mft` | 삭제 항목 (NTFS) |
| `e01_native.deleted_tsk`, `deleted` | 삭제 항목 |
| `e01_native.partition`, `partition` | 파티션 |
| `e01_native.filesystem` | 파일시스템 |
| `eventlog` | 이벤트 로그 |
| `registry` | 레지스트리 |
| `registry-hive-strings` | 레지스트리 하이브 문자열 |
| `carving.unallocated` | 미할당 영역 카빙 |
| `carving`, `carve` | 카빙 |
| `docs` | 문서 |
| `files` | 파일 |
| `timeline` | 타임라인 |
| 그 밖의 영역 | 기타 영역 (원래 이름은 툴팁) |

### 패널 상태 문구

| 상황 | 문구 |
|---|---|
| coverage가 빈 목록 | 제한 없이 처리됨 |
| coverage 기록이 없는 예전 런 | 이 런은 복구 범위 기록 이전에 만들어졌습니다 |

수치 단위는 후보, 레코드, MFT 레코드, 문자열, 섹터, 파티션, 파일시스템, 구간, 파일, 항목으로 표시하고, 바이트는 용량(예: 12 MB)으로 바꾼다. 모르는 단위는 "항목"으로 나온다.

---

## 3. 환경 변수

| 변수 | 기본값 | 의미 |
|---|---|---|
| `RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES` | 복구 모드: 상한 없음 / 다른 모드: 200,000 | 이미지당 추출 파일 수 상한. 양의 정수만 받는다. 복구 모드에서도 지정하면 그 값으로 자른다 |
| `RAPIDTRIAGE_E01_WORKERS` | `min(8, CPU 수)` | E01 네이티브 추출 워커 수. 양의 정수만 받는다 |
| `RAPIDTRIAGE_PARSE_PROCS` | `max(2, CPU 수 // 2)` | EVTX, 레지스트리, ESE 파서와 미할당 카빙의 프로세스 수. 0 이하면 프로세스 풀을 끄고 스레드로 처리한다 |

---

## 4. 콘솔 변경 (R8)

- 증거 트리는 가상화되어 항목이 많아도 보이는 부분만 그린다.
- 검토 큐: `N`은 다음, `Shift+N`은 이전 미검토 행으로 이동해 뷰어로 연다. 사용자 태그가 없는 행이 미검토이며, 시스템 우선순위 태그(1~5)와 북마크는 검토로 치지 않는다. "미검토 k/n" 또는 "미검토 없음"으로 알려 준다.
- 화면 용어를 "분석관" 기준으로 맞추고 디자인 토큰을 정리했다.
- 좁은 화면에서 연 뷰어 서랍은 단계를 바꾸면 닫힌다. 같은 단계 안에서 행을 바꿀 때는 열린 채로 둔다.

---

## 5. 운영 메모

- 증거와 출력이 같은 회전식 디스크에 있으면 읽기와 쓰기가 서로 막아 처리량이 크게 떨어진다. 가능하면 출력은 다른 디스크(SSD)에 둔다.
- 복구 모드는 파일 수 상한이 없으므로 출력 용량이 이미지 사용량에 가깝게 커질 수 있다. 출력 디스크 여유 공간을 먼저 확인한다.
- 복구 모드 실행 뒤에도 복구 범위 패널에 항목이 남아 있으면, 그 영역은 전부 처리된 것이 아니다. 보고서에 그대로 적는다.
