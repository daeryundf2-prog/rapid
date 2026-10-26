# R7 단계 1 적대적 재리뷰 (feat/r6-ux @0112678, 2026-10-27)

기준 문서: `console-adversarial-review-2026-10-26.md`(A표 S1 6·S2 35 고유 행, 구조 D). 리뷰 모델 Fable. 자체 API(`RAPIDTRIAGE_INDEX_PERSIST=0`, 런 등록부·케이스 DB 복사본, 토큰 고정), Playwright Chromium ko-KR, 비-GET `/api` 403(허용: `saved-searches/list`·`case-db/ensure`), 쓰기 확인 대화상자 전부 취소. 뷰포트 1280×720·1920×1000 양 테마·880×700. 증거는 로컬 임시 폴더(Git 미기록).

## 1. S1·S2 판정

| id | 판정 | 근거 | 남은 일 |
|---|---|---|---|
| C-G1 | 해결 | "대기" 0·✕ 0·모두 취소 0, "계획 기록 없음(이전 형식)" 배너, 결과 우선 순서 | 단계표 소요 열 전부 "—"; 단계명 원시 id(R-5) |
| C-G2 | 해결 | 가져온 런 소요 42:06 = 진행 기록, 툴팁 "가져옴 … (처리 시각 아님)" | — |
| C-G3 | 해결 | 랜딩·처리·접수·선택기·케이스 열기 동일 문자열 | — |
| C-D1 | 해결 | `/files?sort=` 4,814행 전수 정렬 위반 0, `q=계약` 45건, "불러온 500 / 전체 4,814" | NFD 0건(R-3); 전부 빈 열 정렬 무표시(R-9) |
| C-D2 | 해결 | 정렬 클릭 후 `row=`·뷰어·선택 불변 | — |
| C-W1 | 해결 | History → `detected_by=magic-bytes`, SQLite 탭, `urls` rowid 강조; evtx 비활성 | 비-history SQLite 행은 첫 테이블 열림 |
| C-G4 | 부분 | 접수 toLocaleString 제거, 레지스트리 "마지막 기록" 한 포맷, UTC 병기에 날짜 | 소요 "34분 9초" vs "34:08"; 레지스트리 키 경로 줄 ISO 원문 잔존 |
| C-G5 | 해결 | "런 2건 · 케이스 1건", "런 선택…" | — |
| C-G6 | 해결 | 샘플 → 확인 대화상자(무엇·어디), 취소 기본 포커스, 차단 POST 0 | — |
| C-G7 | 해결 | 검증 패키지 → 대화상자 2파일 절대경로, 열기 시 쓰기 0 | 880 드로어 안에만(R-11) |
| C-G8 | 해결 | 보고 버튼 4개 중복 없음 | — |
| C-G9 | 해결 | 케이스 열린 상태 "새 런…" → 런 추가 | 상단/팔레트 명칭 2종 |
| C-G10 | 해결 | "왼쪽 패널 접기/열기" | — |
| C-G11 | 해결 | 케이스 없을 때 "이동:" 0 | 비활성 60개 여전히 나열 |
| C-L1 | 해결 | "케이스 열기", 칩, ⋯ 메뉴 삭제 | — |
| C-L2 | 부분 | 사건 유형 select | "검사관" 용어(단계 6), 상시 안내 문구(C-L4) |
| C-I1 | 부분 | 콜드 3.4 s에 카드 채움, 코드상 skeleton·"카드 N/M" 존재 | 12 s 환경 재검증 |
| C-I2 | 부분 | 대부분 한글, 원시 키 툴팁 | 1줄 원문 잔존(R-7) |
| C-T1 | 해결 | 파일 목록 1·폴더 탐색기 1, NTFS·파일시스템 아티팩트 | 검색 결과 노드 건수(C-T3) |
| C-T2 | 해결 | 레지스트리 탐색기 1곳 | — |
| C-D3 | 해결 | 조건 68×28 1줄 | — |
| C-D4 | 해결 | portal z 750, 뷰포트 안 | 프리셋 세그먼트 넘침(R-6) |
| C-D5 | 부분 | 증거 기준 프리셋·툴팁, 타임라인 7일 97,463건 | 파일 목록 시간 조건 0건(R-2) |
| C-D6 | 해결 | 수정 180px, 칩 헤더 | — |
| C-D7 | 해결 | 1920 전 그리드 overflow 0 | 브라우저 빈 특이사항 열 유지 |
| C-D8 | 해결 | 꼬리 우선, 파일명 포함 | — |
| C-D9 | 해결 | 지표·브라우저·유형 한글 | R-5·C-W2·R-10 |
| C-D10 | 해결 | "검토"/"범위" | — |
| C-D15 | 해결 | 시각·시각 종류·대상·요약 | — |
| C-V1 | 해결 | 31 라벨 중복 0 | — |
| C-V2 | 해결 | KST 헤더, 폭 맞춤, 범위 클라이언트 클립 | 서버 히스토그램 from/to 무시 |
| C-W2 | 부분 | 한글 라벨, 기타 필드 접힘 | 핵심·출처 섹션 원시 id 잔존(R-10) |
| C-W3 | 해결 | QA 메타 없음 | — |
| C-W4 | 해결 | 한글 aria | — |
| C-X1 | 해결 | overflow-x, 하단 분할, 200행 더 불러오기 중복 0 | — |
| C-X2 | 해결 | 다시 만들기 확인 | — |
| C-R2 | 해결 | 검토 단계 안 목록 | 1280 Enter 팝오버+뷰어(R-12) |
| C-R3 | 해결 | "검토" 열, 빈 상태 안내 | — |
| C-P1 | 해결 | "모바일 — rapidtriage-artifacts-android-apk.json" | — |
| C-E1 | 해결 | 루트 폴더 행 3, 더블클릭·Enter·브레드크럼 | 직속 파일 0 안내 부재 |

구조: D1·D2·D3 반영, D4·D5·D8 부분.

## 2. 새 결함(회귀·미발견)

| # | 심각도 | 위치 | 재현 | 제안 |
|---|---|---|---|---|
| R-1 | S2 | `viewer/ViewerToolbar.tsx:203-222` | 상태 칩 메뉴 → 관련 있음, 서버 403 → 토스트 "표시 실패"인데 칩은 "관련 있음" 유지(리로드하면 미검토). 그리드 R 경로는 롤백됨 | onRun Promise 성공 시만 setApplied, 실패 시 revert |
| R-2 | S2 | `api/app/files_index.py:460-476`, `row_conditions.py:292-303` | `/files?from=…&to=…`·`weekday=` → matched 0(전 행 `modified_at_origin=acquisition-copy`, NTFS 조인 없음); "증거 기준 최근 7일" 0건, 안내 없음; `sort=mtime`은 폴백 정렬 → 정렬/조건 불일치 | 조건도 표시 mtime 폴백 + 배너 고지, 또는 빈 상태 안내 |
| R-3 | S3 | `files_index.py:668` | `q=` NFD 한글 0건, NFC 45건 | `nfc_fold` |
| R-4 | S2 | `case/exports.ts:88-123`, `ReportDialog.tsx`; `core/case_report.py:412-422`, `routes_reports.py:74-98` | 보고서 대화상자는 "원본(Markdown)·감사 기록 + 선택 형식"만 명시, 실제 md·html·docx·pdf·manifest·audit 6파일; 제출 매니페스트는 GET 2회마다 재작성+감사 2건 | 실제 파일 목록 전부 표기; 매니페스트 1회 작성 후 `/saved` |
| R-5 | S2 | `stages/ProcessStage.tsx:454` | 단계명 "아티팩트 수집: browser/recent-files/…" 원시 id(접수는 `stepLabelKo`) | `stepLabelKo`; 소요 전부 "—"면 열 숨김 |
| R-6 | S3 | `filters/filters.css:343`, `conditionValues.ts:108` | 프리셋 세그먼트 팝오버 폭 초과(338/475) | wrap 또는 접두 1회 |
| R-7 | S3 | `dashboard/disclosures.ts` | "…결과가 전수가 아님: summary.size_caps.truncated" 가시 | 키→사유 |
| R-8 | S3 | `routes_runs.py:1552` | `order=DESC` 422, `sort=flags&order=desc` order 무시 | 대소문자 무시 |
| R-9 | S3 | `files_index.py:640-650`, `DataGrid.tsx` | 전부 빈 열 정렬 무의미·무표시; `?sort=bogus` 조용히 무시 | descriptor `empty`, 상태줄 안내 |
| R-10 | S3 | `RegistryExplorer.tsx`, `SqliteView.tsx`, `GridFooter`, `MetaView` | ISO 원문, "셀 오프셋 0x1020", "발견: rollback_journal", "총 알 수 없음", 메타 핵심 원시 식별자 | 라벨 보강 |
| R-11 | S3 | `Layout.tsx` 880 | 보고 내보내기 버튼이 드로어 안에만; 브라우저 빈 특이사항 열 | 본문 버튼, 빈 열 숨김 |
| R-12 | S3 | 검토 특이사항 Enter | 1280에서 팝오버+뷰어 동시 | Enter=뷰어 |
| R-13 | S3 | `files_index.py` mtime 정렬 | asc 첫 행 1980-01-01 센티널 | 값 없음 취급 |

검증한 엣지(정상): 빈 폴더/루트/`..`/미존재/limit 0/after 오류, offset 초과, `q=` 정규식 문자 리터럴, `locate_rowid` 경계, 0-행 그리드, 2,000행 페이징 중복 0, `?row=` 제거·복원, Esc 토스트, 샘플 대화상자 키 누설 0, `case_db_ready`로 ensure 0.

## 3. 폴더 변경·차단 집계

- 런 폴더: SQLite `-shm`/`-wal` 사이드카와 디렉터리 mtime 외 신규·변경·삭제 0.
- 차단된 비-GET 7건 전부 `review-batch`(R 키·상태 칩 — 의도한 쓰기); UI 부작용성 차단 쓰기 0. 차단 GET 0, 페이지 오류 0.

## 4. 요약

S1 6/6 해결. S2 28 해결 · 7 부분 · 0 미해결. 수정 우선순위: R-1 → R-2 → R-4 → R-5 → R-6/R-7/R-3 → 나머지 S3.

## 5. 수정 라운드 결과
(채움)
