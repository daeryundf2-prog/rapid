# R7 단계 2 적대적 리뷰 — 검색 지연 · v2/v3 색인 (feat/r6-ux @274b0fe, 2026-10-27)

리뷰 모델 Fable, 읽기 전용. 자체 API(`RAPIDTRIAGE_INDEX_PERSIST=0`, `RAPIDTRIAGE_SEARCH_AUTO_INDEX=0`), 스크래치 런 등록부(af54 런 폴더 v2 색인 읽기만, b5fa 색인 없음, b5fa 섀도 런에 스크래치 v3 색인 사본). Playwright: GET 이외는 `search/query`·`saved-searches/list`만 통과. 런 폴더 신규·삭제 0(SQLite 사이드카 mtime만).

## 1. 결함표

| # | 심각도 | 위치 | 내용 | 제안 |
|---|---|---|---|---|
| 1 | S2 | `core/search_index/hits.py:83-100,131`, `core/search_hits.py:211-218` | **v2 적중 시각 손실**: 파일·문서 적중 `timestamp=null`(v1 문서 96/96·파일 30/30 → v2 0/126·0/45), 아티팩트 시각 종류 상이(공통 255행 중 220 불일치) | 파일·문서 `ts` 색인 또는 compact 메타에 `modified_at` |
| 2 | S2 | `search_index/hits.py:38-40` vs `engine.py:302-312`(`lower` ASCII만), `textutil.py:38-44` | **비ASCII 대소문자 불일치**: `école`/`ÉCOLE`, 전각 `Ａ１`, 그리스·키릴 대문자, `straße` — v2가 대문자/전각 행 놓침(합성 52건 중 10) | 접은 본문 색인 또는 등록 함수 비교 |
| 3 | S2 | `search_index/build.py:88-90`(문서 64 KB·아티팩트 8 KB 상한), `frontend/src/api/search.ts:94-99`(`warnings` 미사용) | **긴 문서 뒷부분 v2 누락**(`등록절차` v1 2/v2 1, `위탁의료기관용` 4/2), 경고가 오지만 콘솔은 버림 | 바닥줄 경고 표시; 상한 상향 또는 문서 출처 v1 보강 |
| 4 | S2 | `routes_search_index.py:134-136`(keywords ≤32), `query.py` 4,000자, `api/collections.ts:1066-1072`(404/409/503만 폴백), `TopBar.tsx:73` | **33개 이상 키워드·4,000자 초과 → 영문 pydantic 오류**, v1 폴백 없음 | 클라이언트 32개 절단 또는 400/422 폴백; 한국어 메시지 |
| 5 | S2 | `core/search_budget.py:83-92`, `core/search.py:327-328,416-426` | **예산 중단 v1 결과가 앞부분이 아니고 쪽 불연속**(출처별 균등 분할; 0.2 s에서 2쪽 사이 누락), `elapsed_ms`가 예산 초과 | 출처 순서 중단 지점에서 멈추고 `has_more` 끄기; 문서 수정 |
| 6 | S2 | `search_index/build.py:654-660`, `hits.py:112-115`, `columns/search.ts:124-127`, `DataGrid.tsx:706` | **압축 항목 행이 부모 로케이터 공유** → rowKey 중복 12(선택·포커스·리뷰 표시 겹침) | 항목 전용 로케이터/rowKey에 경로 추가 |
| 7 | S2 | `routes_search.py:193-197`, `core/search_fts.py:139-157`, `core/search.py:1699-1703,1761-1765` | **v1 정규식 재앙적 역추적**(`Live(a+)+$` + a×30 → 45 s 넘게 실행, 예산 무효, 워커 점유); v2는 400 거절 | v1에도 `regex_guard`(중첩 반복 거절 + 행별 시간 한도) |
| 8 | S2(기존) | `grid/gridCommands.ts:55-69`, `columns/search.ts:102-105`, `viewer/citation.ts:160-166` | 뷰어에서 문서 적중 리뷰·북마크 불가, 인용 `[search:/search/0]` — 뷰어 대상에 API 로케이터 누락(v1·v2 공통) | 뷰어 대상에 `reviewCollection/Kind/Pointer` |
| 9 | S3 | `api/search.ts:65-74` | 1자·ASCII 2자 키워드는 v2가 느린데 항상 v2(`계` 0.85 vs 0.48 s, `ab` 1.33 vs 0.72 s) | 그 경우 v1 또는 경고 |
| 10 | S3 | `hits.py:158` | 같은 행 제목 불일치 33/255(브라우저 "History" vs 사이트명) | 빈약 제목은 v1식 요약 |
| 11 | S3 | `routes_search_index.py:119,338` | `search_result_id`가 클라이언트 offset 신뢰 | 서버 번호/상한 |
| 12 | S3 | `artifact_path_index.py:47-54,71-90` | 메모리 상한이 종류 수뿐(최대 ≈1.8 GB 추정) | 바이트 예산 LRU |
| 13 | S3 | `SearchOptionsPopover.tsx:100` | 저장 검색이 `case_db_ready`여도 ensure POST | 핸들 재사용 |
| 14 | S3 | `core/search.py:63-80`, `columns/search.ts:97,116` | v1 compact `hashes` 맵 vs 그리드 `sha256` → v1 파일 적중 해시 열 빔 | 평탄화 |
| 15 | S3(기존) | v1 스캔 haystack(JSON 직렬화) | `"`·`_` 전 행 일치, `quote"inside` 등 v1 0/v2 1 | 값 텍스트 haystack |
| 16 | S3(정책) | 검색 응답 경로 전체 | `redact_secret_text` 미적용: `token=` 스니펫 v1 22건·v2 290건 원문 노출 | 스니펫 생성 시 redaction |
| 17 | S3(문서) | known-limitations R7 P2·검색 지연 | 시각·앞부분·3건·같은 정규화 주장 수정, v2 경고 미표시 기재 | |

S1 없음. 정상 확인: XSS 0, URL 토큰 0, v2 정규식 거절, 예산 `truncated` 결정적, 커서 오류 400 한국어, 경로 색인 16 needle 스캔 동일·동시 빌드 1회, stale/none 힌트·링크·대화상자 0, Esc 취소, 저장 검색 한 질의, v1 기본값 변경에 깨진 호출자 없음.

## 2. 등가성(b5fa, 로케이터 키)

| 키워드 | v1 | v2 | 공통 | v1만(전부 타임라인) | v2만 | 같은 행 차이 |
|---|---|---|---|---|---|---|
| 계약 | 441 | 429 | 255 | 186 | 162 | 시각 220·제목 33·경로 3 |
| 근로 | 556 | 255 | 241 | 315 | 13 | 시각 236·제목 22 |
| LiveUpdate | 20 | 30 | 18 | 2 | 12 | 시각 16·제목 14 |
| 계약 근로 | 867 | 523 | 422 | 445 | 88 | 시각 383·제목 47 |
| 계약서 | 320 | 325 | 174 | 146 | 139 | 시각 141·제목 23 |

로케이터 해석 v1 441/441·v2 429/429, 페이지 이어붙임 중복·누락 0.

## 3. 성능(HTTP, 따뜻한 중앙값, 250건)

| 질의 | v1 | v2(v3 색인) |
|---|---|---|
| 계약 | 0.475 s | 0.065 s |
| 근로 | 0.410 | 0.047 |
| 계약서 | 0.242 | 0.214 |
| LiveUpdate | 0.097 | 0.016 |
| LiveUpdate+계약 | 0.518 | 0.155 |
| 계(1자) | 0.477 | 0.851 |
| ab(ASCII 2자) | 0.723 | 1.334 |

## 4. 수정 라운드 결과 (39368a1, Fable 확인 2026-10-27)

수정: 프런트 `fix/r7-s2-review-frontend`(1d85d50), 백엔드 `fix/r7-s2-review-backend`(39368a1, 색인 v4).

| # | 판정 | 근거 |
|---|---|---|
| 1 | 해결 | 같은 행 시각 불일치 계약 0(220)·근로 0(236)·계약서 0(141)·LiveUpdate 0(16) |
| 2 | 해결 | 합성 52건 대소문자·전각·그리스·키릴·ß 전부 일치(남은 3건은 설계) |
| 3 | 해결 | `등록절차` 2/2, `위탁의료기관용` 6/6; 바닥줄 경고 + 출처별 툴팁 |
| 4 | 해결(콘솔) | 33개 → 32개 전송 + 안내; API 직접 호출은 영문 422 잔존 → 확인 라운드 |
| 5 | 해결 | 0.05 s 예산: 1쪽 = 전체 접두, `budget_stopped`, 2쪽 한국어 거절 |
| 6 | 해결 | `#entry:` 행 고유 키, 표시 본문이 부모 로케이터로 해석 |
| 7 | 해결 | `Live(a+)+$` 422 0.00 s |
| 8 | 해결 | 인용 `[artifacts:…:/artifacts/18#entry:15]`, 표시·북마크 본문 동일 |
| 9 | 해결 | `계` → v1 |
| 10 | 부분 | 제목 차이 30/20/20/14 그대로(compact 메타로 폴백 불가) → 확인 라운드(서버 요약 제목) |
| 11 | 해결 | 서버 번호, offset 1,000,001 → 한국어 422 |
| 12 | 해결(단위) | 바이트 LRU |
| 13 | 해결 | ready 런 ensure 0 |
| 14 | 해결 | 평탄 해시 30/30 |
| 15 | 해결 | 값 텍스트 일치 |
| 16 | 해결 / **회귀** | 원문 0(v1 44·v2 1,587 가림) — 단 가림 정규식이 v1 지연 10배(아래) |
| 17 | 해결 | |

확인 패스가 찾은 회귀: (1) **S2** `core/search_hits.py:180-183,226` 가림 정규식이 2차 시간이고 모든 leaf에 적용 → v1 `근로` 0.41 → 11.1 s, `계약` 0.48 → 5.9 s; (2) S3 `shell/TopBar.tsx:31-40` `useSearchBusy` setState-during-render(P2 기원); (3) S3 API 직접 33개 키워드 영문 422; (4) #10 제목. → `fix/r7-s2-confirm`.
