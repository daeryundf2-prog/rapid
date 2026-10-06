# RapidForensic 사용성 오버홀 — 사용자·이상상태·갭·계획·QA

작성: 2026-10-04 | 근거: 정적 코드 분석 + 4개 탐색 에이전트 조사 보고

## 1. 최종 사용자 정의

**한국어 사용 디지털 포렌식 분석관(수사기관/민간 감정인).** 프로그래머가 아니다.
E01 이미지·폴더·아카이브를 넣고, 키워드를 치고, 브라우저/카톡/문서/미디어
아티팩트를 눈으로 보면서, 유의미 항목을 골라 보고서를 뽑는 사람.
판단 기준은 Magnet AXIOM/EnCase: **케이스 열기 → 증거 넣기 → 처리 →
아티팩트 검토 → 보고서** 5단계가 화면 흐름 그대로여야 한다.
토큰·JSON·CLI·validation 패키지는 이 사람의 세계에 없다.

## 2. 이상적 상태 (타협 없는 정의)

| # | 상태 | 이유 |
|---|---|---|
| I1 | 서버 실행 → 브라우저 열림 → **토큰 입력 없이 바로 콘솔** | loopback 인증 장벽은 순수 마찰. v2는 이미 `#token=` 지원 |
| I2 | 첫 화면 = 카드 3개 (이미지/폴더/최근케이스) + 경로 입력 + 실행 버튼. **파일 브라우저로 경로 선택 가능** | 현재 ~20 컨트롤 + 손으로 경로 타이핑. AXIOM은 탐색기 제공 |
| I3 | 처리 진행이 단계별로 보이고, 완료 시 결과 화면으로 자동 진입 | run.steps 이미 존재 — 보여주기만 하면 됨 |
| I4 | 결과 화면 = 5개 탭만 (요약/아티팩트/문서/검색/타임라인) + 보고서. **QC·validation·commercial-readiness 패널은 dev 플래그 뒤에** | 분석가에게 `commercial_grade_ready=false`는 노이즈 |
| I5 | **보고서 탭이 렌더링된 보고서를 보여줌** (raw markdown 아님). 북마크 0개여도 "보고서 생성/다운로드" 가능 | 현재 `<pre>` 덤프 + 마킹 선행 요구 = 죽은 끝 |
| I6 | 검색 결과 키워드 `<mark>` 하이라이트, 이미지는 썸네일 그리드 | 현재 평문 스니펫 + 갤러리는 JSON 링크 |
| I7 | API 응답 = 페이지 요청이 파일 전체 파싱 없이 반환. 57MB manifest 클릭이 즉시 | 현재 매 요청 `json.loads(57MB)` |
| I8 | 스캔 = 기본 프로필에서 이중 수집·이중 해시·무제한 추출 없음 | 프로바이더 24개×2회, 지문 해시, copy+SHA256 추출 |
| I9 | 검색 = 이미 만든 docs-index 사용. 매 쿼리 문서 재추출/OCR 없음 | 현재 쿼리마다 extract_text 재실행 |
| I10 | 하나의 UI. v1이 기능 보유 → v1을 얇게. v2는 `/v2` 유지(선택) | 두 UI 공존은 최악 |

## 3. 현재와의 갭 (근거 포함)

| 갭 | 현재 | 증거 |
|---|---|---|
| G1 토큰 장벽 | 랜덤 토큰 콘솔 출력 → 수동 붙여넣기 | `cli/web.py:86-92`, `index.html:41-47` |
| G2 파일 피커 없음 | 경로 수동 타이핑 | `app_intake.js`; 브라우즈 엔드포인트 없음 |
| G3 15개 중복 내비 | 같은 9탭에 15개 분류체계; `redundant-tab-row` 클래스 자체 인정 | `app_workbench_config.js`, `app_detail_panel.js:119` |
| G4 QC 표면 노출 | 상용준비 게이트·smoke체크포인트·lazyweb 커맨드센터가 분석 콘솔에 | `app.js:1990-2050` |
| G5 보고서 = `<pre>` | raw markdown; 북마크 없으면 생성 버튼 비활성 | `app.js:6677-6694,6991-6995` |
| G6 검색 하이라이트 없음 | 평문 스니펫 | `app.js:4864` |
| G7 갤러리 = JSON 링크 | 썸네일 그리드 없음, 동영상 재생 없음 | `app.js:5825-5831` |
| G8 매 요청 전체 파싱 | `read_output` = `json.loads(read_text())` 후 슬라이스 | `jobs.py:296-298`, `routes_runs.py:327-346` |
| G9 프로바이더 이중 실행 | manifest 수집(직렬) + artifacts 수집(병렬) 같은 24개 프로바이더 | `docs.py:113-132`, `run/__init__.py:652-680` |
| G10 manifest 이중 직렬화 | manifest 내용이 docs.json에도 통째로 | `docs.py:185` |
| G11 기본 추출 | 모든 모드가 파일 추출+SHA256 복사 (무제한) | `profiles.py:37-129`, `extract.py:140-146` |
| G12 지문 해시 매 실행 | ≤16MiB×5000파일 매 실행 전처리 | `incremental_indexing.py:112-171` |
| G13 검색 재추출 | 쿼리마다 모든 문서 extract_text + 이미지 OCR | `search.py:940-997,1231-1320` |
| G14 중복 해시 그룹 | 무조건 실행, O(n²) fuzzy 텍스트 비교 | `files.py:416-417,1556-1649` |
| G15 v2 미완성 | 실행 불가, Ctrl+K 사장 | `CaseQueuePane.tsx:47`, `App.tsx:81` |

## 4. 실행 계획 (우선순위)

### Wave A — 즉시 체감 (병렬 가능)

- **A1 첫 진입**: `run_web_server`가 루프백 기본 토큰을 URL fragment로 안내
  (`http://host:port/#token=…` 출력) + index.html의 토큰바가 fragment를 읽어
  자동 저장. → I1/G1
- **A2 파일 피커**: `GET /api/browse?path=` (디렉터리 목록, 로컬 전용,
  루트 화이트리스트 + 경로 정규화) + 인테이크 폼에 "찾아보기" 버튼 → I2/G2
- **A3 출력 캐시**: `RunJobStore.read_output`에 (path,mtime,size) 키 LRU 캐시.
  `/files`,`/docs`,`/artifacts`,`/outputs/*` 전부 혜택 → I7/G8
- **A4 dev 패널 격리**: QC/validation/lazyweb/commercial-readiness 블록을
  `localStorage rapidtriage.devMode` 또는 `?dev=1` 없으면 렌더 안 함 → I4/G4

### Wave B — 파이프라인 중복 제거 (병렬 가능, 단 A와 파일 겹침 주의)

- **B1 프로바이더 단일 수집**: manifest 단계가 artifacts 수집 결과를 재사용
  (또는 반대). docs.json의 `manifest` 임베드 → 참조로 → I8/G9,G10
- **B2 추출 기본값**: 기본 프로필을 `extract=off` + `carve=off`로, 추출은
  명시 옵션. 이미 있는 해시 재사용 → I8/G11
- **B3 지문 해시**: `--resume` 지정 시에만 콘텐츠 해시; 아니면
  경로+size+mtime만 → I8/G12
- **B4 검색 경량화**: docs 검색을 docs-index로 라우팅(있으면), OCR 기본 off,
  `to_dict()` 매니페스트 필드 캐시 → I9/G13 + 폴링 비용

### Wave C — 결과물 조회 (A2 이후 또는 병렬, 파일: app.js 영역 분리)

- **C1 보고서 렌더**: 경량 md→HTML 렌더러(서버 사이드 또는 40줄 JS)로
  보고서 탭 렌더링. 북마크 0개도 "실행 보고서 생성" 활성화 → I5/G5
- **C2 검색 하이라이트**: 스니펫 내 키워드 `<mark>` → I6/G6
- **C3 이미지 그리드**: `source-image-gallery` 결과를 `<img>` 썸네일 그리드로 → I6/G7

## 5. QA 시나리오 (이상상태와 1:1 대조)

| QA | 절차 | 합격 기준 |
|---|---|---|
| Q1 | `rapidtriage web` → 출력된 URL 그대로 브라우저 오픈 | 토큰 입력 없이 콘솔 표시 (I1) |
| Q2 | 첫 화면에서 "찾아보기"로 폴더 선택 → 분석 실행 | 실행 제출 성공, 진행 단계 표시 (I2,I3) |
| Q3 | 완료 후 탭 구성 확인 | 분석 탭만 보임; `?dev=1`일 때만 QC 패널 (I4) |
| Q4 | 보고서 탭 | 렌더링된 보고서 + 다운로드, 북마크 0개 가능 (I5) |
| Q5 | 키워드 검색 | 스니펫에 `<mark>` 하이라이트 (I6) |
| Q6 | 이미지 포함 케이스 갤러리 | 썸네일 그리드 렌더 (I6) |
| Q7 | `/api/runs/{id}/outputs/manifest` 연속 2회 | 2번째가 캐시 히트(로그/계측), p95 대폭 감소 (I7) |
| Q8 | 기본 프로필 run | 출력물에 `docs-extract/`/`files-extract/` 없음(명시 옵션 시에만), manifest 단계 아티팩트 재수집 없음 (I8) |
| Q9 | 검색 2회 연속 | 문서 재추출 없이 docs-index 경로 사용 (I9) |
| Q10 | 회귀 | `python -m unittest discover -s tests` + ruff + compileall 그린 |

## 6. 리스크/통제

- B1(단일 수집)은 출력 스키마 영향 → manifest 내용은 동일 키 유지, 소스만 재사용
- B2 추출 기본값 변경은 "기본으로 추출하던" 기존 행동 변경 → CLI 플래그로 복원 가능
  (`--extract` 명시), 문서/도움말 갱신
- A3 캐시는 run 완료 후 파일이 안 바뀌는 게 전제 → mtime+size 키로 무효화
- dev 패널 격리는 DOM에서만 숨김 (엔드포인트는 그대로) → 기능 손실 없음

## 7. 구현 결과 (2026-10-05)

| 항목 | 구현 | 파일 |
|---|---|---|
| P1 토큰 장벽 | CLI가 `/#token=…` URL 출력 + v1이 프래그먼트 토큰을 localStorage로 채택 후 주소창에서 제거 | `cli/web.py`, `app.js` |
| P1 파일 피커 | `GET /api/browse`(루트/디렉터리 목록, 200개 한도, 숨김 제외, 토큰 인증) + 모달 피커 UI | `api/app/routes_browse.py`, `app_browse.js`, `index.html` |
| P2 출력 캐시 | 파싱된 run 출력 JSON의 LRU (path+mtime+size 키, 4엔트리/200MB 상한, 런 완료·삭제 시 무효화) | `core/jobs.py`, `api/app/tree.py` |
| P3 수집 중복 | `collect_cached()` — (kind, root) 키로 manifest/artifacts 단계가 수집 공유, 런 시작 시 클리어 | `artifacts/__init__.py`, `core/docs.py`, `core/artifacts.py`, `core/run/__init__.py` |
| P3 추출 기본 off | `rapidtriage run --extract` 옵트인, 비활성 시 플레이스홀더 페이로드(스키마 동일) + 웹 폼 체크박스 | `cli/parser.py`, `core/extract.py`, `core/jobs.py`, `api/app/models.py`, `api/app/routes_runs.py`, `index.html` |
| P3 지문 해시 | `--resume` 시에만 콘텐츠 해시; 비레줌은 경로+size+mtime. 정책 혼합 비교는 메타 다이제스트로 | `core/run/incremental_indexing.py` |
| P4 보고서 | 경량 md→HTML 렌더러 + 북마크 0건 실행 요약 보고서 생성 허용 | `app_markdown.js`, `api/app/runops.py` |
| P5 하이라이트 | `highlightSnippet` 재작성(원문 매칭→세그먼트 이스케이프) + 검색/문서/케이스DB 프리뷰 적용 | `app_utils.js`, `app.js` |
| P5 갤러리 | 이미지 뷰어에 썸네일 그리드 + 페이지네이션 | `app.js`, `styles.css` |
| P5 v2 검색 | 헤더 검색창 → 중앙 표 클라이언트 필터 + Ctrl+K 포커스 | `frontend/src/app/App.tsx`, `state/ui.ts`, `item-table/*.tsx` |
| P6 QC 격리 | 개발자 도구 토글(`?dev` 또는 로컬스토리지) — 인텔 드로어/검증 패널/크래시 대시보드 게이팅 | `app_detail_panel.js`, `app.js`, `app_utils.js` |
| 첫 화면 | `입력 유형`을 고급 옵션으로 이동(자동 판단이 기본), 경로 옆 찾아보기 버튼 | `index.html` |

수정 중 발견된 회귀: `collect()`가 generator를 반환해 캐시된 이터레이터 재소비 시 0건 → `list()` 구체화로 수정(테스트 재현·통과).
`RunRequest.extract` 직렬화/실행 경로 누락 → to_dict/from_dict/`run_triage_mode` 전달 + API 모델·웹 폼까지 전 구간 연결.

## 8. 실제 브라우저 E2E 검증 (2026-10-05, 2차)

Playwright로 토큰 인증→파일 브라우저→런 제출→완료→상세→보고서→검색 하이라이트→QC 격리 전 구간을 실제 클릭 경로로 검증. **11/11 통과.**

실테스트에서 발견·수정한 사전 버그 4건:

| 증상 | 원인 | 수정 |
|---|---|---|
| 브라우즈 다이얼로그 무반응 | `app_state.js`가 `storageAvailable` 임포트 누락 → 모듈 초기화 중단으로 이후 이벤트 바인딩 전부 사망 | 임포트 추가 |
| 런 폼 바인딩 사망 | `collectPlanButton` 등 요소 래퍼를 함수인 채로 요소처럼 사용(`.addEventListener`/`.textContent`가 사일런트 no-op) | `app_intake.js` 전수 교정 |
| 런이 10분+ 멈춤 (재실행할수록 악화) | 스캔이 이전 런의 `rapidtriage-run-*` 산출물을 증거로 재수집 → 대형 JSON을 fuzzy 중복검사가 `SequenceMatcher.ratio()` O(n²)로 비교 | `iter_evidence_paths()` 공통 헬퍼로 73곳 수집 경로에서 런 산출물 디렉터리 제외 + `quick_ratio()` 선필터 |
| 상세 화면이 렌더되지 않음 | `app_detail_panel.js`가 미주입 변수 `activeViewGroup` 참조 → `ReferenceError`로 렌더 체인 사망 | workbench 스토어에서 상태 읽기 |
| 검색 결과가 빈 테이블 | 검색 제출 후 재렌더에서 `mountVirtualTables()` 미호출 → 가상 테이블 tbody 비움 | 제출 경로에 마운트 추가 |

성능 검증: 수정 전 런 10분+ 미완료 → 수정 후 동일 증거로 **약 30초 완료**.
수집 경로 스캔 대상 49파일 → 3파일(런 산출물 제외 확인).

회귀: 전체 스위트 재실행 1143 tests — 4 실패 전부 동일 원인(`assert_run_mode_outputs` 헬퍼에 `--extract` 미전달) → 플래그 추가 후 재실행 통과. ruff/compileall/diff-check 그린.

부수 수정: 배치 패치 스크립트가 artifacts 파일을 CRLF로 재작성한 것을 LF로 복원 (git diff --check 그린).
