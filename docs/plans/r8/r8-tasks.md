# R8 부록 F — 작업 분해 (T-001 ~ T-128, 유효 127개)

마스터 10절. 소유자 방식: 큰 레인 대신 **작은 quick 과제**(한 영역, 형제와 파일이 겹치지 않음, 4시간 이하, 독립 검증 가능)로 쪼개 병렬로 돌리고, 검증을 더 엄격하게 한다.

## F.1 공통 규칙

- **역할**: 구현 Opus(과제당 워크트리 1개) → 검증 Sonnet(구현자와 다른 세션이 수용 검사·검증 명령을 처음부터 다시 실행, 실데이터 QA 수행) → 적대적 리뷰 Fable(묶음마다 diff 전체 + 추적표 대조). 표에서 담당이 다르면 따로 적는다(`QA` = Sonnet 단독, `RV` = Fable 단독).
- **묶음**: 물결 W0~W11, 물결 안의 묶음(a·b·c…)마다 과제 6개 이하. 같은 묶음의 과제는 파일이 겹치지 않는다(표의 "파일"이 배타 소유 범위). 묶음은 앞 묶음이 통합 브랜치에 들어간 뒤 시작한다.
- **브랜치**: 통합 `feat/r8`(`feat/r6-ux` ffab479에서 분기, D13), 과제 `r8/T-xxx-짧은이름`. 머지는 소유자 지시 때만.
- **공유 파일 금지 구역**(한 묶음에서 한 과제만): `frontend/src/features/grid/DataGrid.tsx`, `frontend/src/app/shell.css`, `frontend/src/shell/Layout.tsx`, `frontend/src/router.ts`, `frontend/src/tokens/tokens.css`, `rapidtriage/api/app/routes_runs.py`, `rapidtriage/api/app/factory.py`, 카탈로그 YAML, `docs/console-glossary.md`, `docs/rapidtriage-known-limitations.md`, OpenAPI 스냅샷(코디네이터가 묶음 끝에 재생성).
- **[승인]**: AGENTS.md 계약(복구 엔진·파서·핵심 포렌식 로직·API 동작·DB 스키마). 승인 전 착수 금지. 표시·API 응답 추가·보고서 생성기·검색 색인 질의·케이스 워크플로는 승인 불필요로 분류했고, 경계가 애매한 것은 `[확인]`으로 표시했다(결정 D6 범위 확인).
- **과제 공통 검증 명령**(수용 검사와 별개로 항상):
  ```bash
  python -m ruff check rapidtriage tests scripts && python -m vulture rapidtriage tests scripts --min-confidence 80
  python -m compileall -q rapidtriage tests scripts
  python scripts/run-tests-parallel.py --changed   # T-011 이전에는 관련 모듈만 python -m unittest tests.<module>
  (cd frontend && npm run typecheck && npm run lint && npx vitest run <관련 폴더> && npm run build)
  (cd frontend && npx playwright test <과제에 적힌 스펙>)
  git diff --check && git status --short
  ```
  묶음 끝(코디네이터): AGENTS.md 검증 명령 전부 + vitest 전체 + e2e 전체 + 계약 테스트 + 번들 예산 + 부록 E의 회귀 묶음(E.6).
- **닫는 조건**: 수용 검사 통과 + Sonnet 재실행 통과 + (화면 과제) 실데이터 스크린샷 1장 이상 + 추적표 갱신. vitest·TestClient만으로 닫지 않는다(IS-125).

## F.2 물결 요약

| 물결 | 주제 | 과제 수 | 묶음 | 승인 |
|---|---|---|---|---|
| W0 | 계약·측정·기반 | 12 | a(6)·b(6) | 불필요 |
| W1 | 깨진 것·거짓 표시·방어 가능성 긴급 수정 | 24 | a·b·c·d(각 6) | 불필요(T-036 `[확인]`) |
| W2 | 실데이터 기준선 구축·재확인 | 8 | a(6)·b(2: T-043·T-044) | D24·D32 |
| W3 | 백엔드 지원(`/brief`·색인·백그라운드·분류) | 15 | a(6)·b(5)·c(4) | 불필요 |
| W4 | 디자인 시스템 컴포넌트 | 10 | a(6)·b(4) | 불필요 |
| W5 | 셸·브리핑·내비·접수 흐름 | 12 | a(6)·b(6) | 불필요 |
| W6 | 목록·뷰어 | 10 | a(6)·b(4) | 불필요 |
| W7 | 검색·검토·시간순·AI·사람·장치 | 12 | a(6)·b(6) | 불필요 |
| W8 | 보고서 | 6 | a(6) | 불필요 |
| W9 | AX·정리·잔여 | 9 | a(6)·b(3) | 불필요 |
| W10 | 엔진·수집기(승인 묶음) | 7 | a(6)·b(1) | **필요(D6·D6a·D7·D8·D10·D34)** |
| W11 | 1:1 최종 검증·사람 테스트 | 2 | a(2) | — |
| 합계 | | 127 | 23묶음 | |

순서의 근거: (1) 계약이 없으면 재설계가 테스트를 한꺼번에 깬다 → W0. (2) 지금 화면이 **틀린 사실**을 말하는 곳(GAP S1)을 구조 변경보다 먼저 → W1. (3) 소유자의 의심(실데이터 미검증)을 설계 전에 수치로 닫는다 → W2가 W1 직후. (4) W3·W4는 서로 파일이 겹치지 않아(백엔드 vs 컴포넌트) **동시에** 진행 가능. (5) W10은 승인 시점에 맞춰 W3 이후 어디든 끼울 수 있다(파일이 겹치지 않음).

## F.3 과제표

열: ID · 제목 · 배타 파일 · 의존 · 크기(h) · 수용 검사 · 닫는 GAP/IS · QA.

### W0-a 계약·측정 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-001 | UI 계약 추출기와 계약 테스트 | `scripts/extract-ui-contract.mjs`, `frontend/src/contracts/uiContract.ts`, `frontend/src/contracts/*.contract.test.ts` | — | 4 | testid 전수 목록·접근성 이름·주소 왕복 30종·인용 스냅샷 12종 테스트가 현 코드에서 통과, 부록 D와 표 일치 | GAP-149·172 / IS-116 | QA-041·104 |
| T-002 | 토큰 lint·대비 검사 확장 | `frontend/scripts/check-tokens.mjs`, `frontend/scripts/check-contrast.mjs`, `frontend/package.json`(scripts 블록) | — | 3 | 현 위반 수를 기준선 JSON으로 기록(색 0·radius 42·px 124·font-size 9), 새 위반은 실패 | GAP-140 / IS-110 | QA-096 |
| T-003 | 증거 스냅샷·로그 스캔·보고서 감사 스크립트 | `scripts/r8-evidence-snapshot.py`, `scripts/r8-log-scan.py`, `scripts/r8-report-audit.py`, `scripts/r8-trace-audit.py`(부록 A·B·E·F에서 추적표 생성·구멍 검사), `tests/test_r8_qa_scripts.py` | — | 4 | 합성 폴더에서 변경 1바이트·신규 파일 검출, 가짜 비밀·경로 검출, 보고서 필드 누락 검출 단위 테스트 | IS-067·074·059 | QA-001·013·009·078 |
| T-004 | 합성 풍부 픽스처 생성기(가짜 값) | `scripts/make-r8-fixture.py`, `tests/fixtures/r8_rich/`(생성 스크립트·매니페스트만), `frontend/e2e/r8_fixture.py` | — | 4 | Tier 1 9카드 전부 행 > 0, 가짜 비밀·가짜 개체 포함, 실데이터·PII 0(스캔), 생성 60 s 이하 | GAP-057 / IS-121(CI용) | QA-045 |
| T-005 | 용어 lint와 용어집 R8 개정 | `scripts/check-glossary-terms.py`, `docs/console-glossary.md`, `tests/test_glossary_lint.py` | — | 4 | 부록 C.7 표가 용어집에 반영(보고서 포함 키 표기 오류 수정 포함), lint가 금지 표기를 경고 모드로 집계(기준선 기록) | GAP-130·182 / IS-096 | QA-035 |
| T-006 | 병렬 테스트 실행기와 CI 전환 | `scripts/run-tests-parallel.py`, `.github/workflows/rapidtriage-ci.yml` | — | 4 | 빠른 묶음 8분 이하(느린 4모듈 분리), 전체 결과가 단일 discover와 같은 테스트 수 | GAP-152 / IS-119 | QA-104 |

### W0-b 기반 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-007 | 서버 오류 봉투와 500 경로 제거 | `rapidtriage/api/app/errors.py`(신규), `rapidtriage/api/app/factory.py`, `docs/api-error-codes.md`, `tests/test_error_envelope.py` | — | 4 | 모든 `HTTPException`·검증 오류·401/403/500이 `{code,message,hint}`(+`detail_text` 호환), 500 본문에 절대경로 0, API 스냅샷 차이는 오류 스키마뿐 | GAP-126·018·156 / IS-091·074 | QA-083 |
| T-008 | 프런트 오류 정규화 | `frontend/src/api/client.ts`, `frontend/src/api/errors.ts`(신규), 해당 테스트 | — | 3 | 네트워크 실패·중단·시간 초과·영문 detail이 한국어 봉투로, "Failed to fetch"·"Request failed" 문자열 0(grep) | GAP-126·051 / IS-091 | QA-083 |
| T-009 | Python 잠금 파일과 프로젝트 기준 감사 | `pyproject.toml`, `requirements.lock`, `.github/workflows/dependency-monitoring.yml`, `scripts/check-dependencies.py` | — | 4 | 잠금 기준 pip_audit 실행, `requires-python>=3.12` 정렬, 권고 목록과 D25 판단 근거 문서 | GAP-151 / IS-118 | QA-104 |
| T-010 | 비결정·기준 실패 테스트 4건 수정 | `rapidtriage/core/derived/stage.py`(analysis_id 충돌만), `tests/`의 해당 3파일, `frontend/src/**/qaRealData.test.tsx` | — | 4 | 4건 각각 20회 반복 통과, `test_rapidtriage_email_external…` 원인 기록 | GAP-152 / IS-119 | — |
| T-011 | 과제 측정 하네스(T1~T5 골격·지표 수집) | `frontend/e2e/tasks/`(신규 폴더), `scripts/r8-measure.py` | T-001 | 4 | 현 화면에서 UX 감사 수치(트리 366±10%, 잘림 29~37%, Tab 32)를 재현하는 기준선 JSON | IS-121 | QA-033·044·091 |
| T-012 | e2e CSS 클래스 선택자 제거 | `frontend/e2e/*.spec.ts`(기존 13개), 선택자 대체에 필요한 testid 추가는 `features/views/ChatView.tsx`·`features/case/EntityPanel.tsx`·`features/viewer/views/ImageView.tsx`만 | T-001 | 4 | e2e에서 `locator('.…')` 0(lint), 13스펙 통과 수 변화 없음 | GAP-150 / IS-117 | QA-104 |

### W1-a 깨진 컴포넌트 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-013 | 검색 옵션 체크박스가 빈 막대로 그려지는 결함 | `frontend/src/app/shell.css`(`.global-search input` 범위를 검색 입력 하나로), `frontend/src/tokens/controls.css` | — | 2 | 체크박스 폭 ≤24px·라벨 우측(boundingBox), 라이트·다크 스크린샷 | GAP-105 / IS-034 | QA-060 |
| T-014 | 메뉴 포털·충돌 보정(뷰어 … 메뉴 잘림) | `frontend/src/components/MenuButton.tsx`, `frontend/src/components/popover.css`, `frontend/src/components/Popover.tsx` | — | 4 | 뷰어 최소 폭·880에서 메뉴 사각형이 뷰포트 안, Esc·포커스 복귀 유지 | GAP-095 / IS-102 | QA-049 |
| T-015 | 트리 건수 잘림·가로 스크롤·이탤릭·검색 공백 | `frontend/src/features/tree/tree.css`, `frontend/src/features/tree/EvidenceTree.tsx`, `frontend/src/features/case/case.css`(`.case-tree` 블록만) | — | 4 | 스크롤바가 있어도 건수 `scrollWidth==clientWidth`, 가로 스크롤 0, 이탤릭 0("자료 없음" 글자), 검색 결과 사이 공백 ≤행 높이 | GAP-082 / IS-012·106 | QA-094 |
| T-016 | 추가 분석 카드 글자 겹침·격자 구멍 | `frontend/src/features/stages/stages.css`(`.process-card`·`.analysis-cards` 블록) | — | 2 | 2줄 제목에서 겹침 0(요소 사각형 교차 검사), 880~1920 | GAP-078 | QA-094 |
| T-017 | 미디어 길이 문구·썸네일 대체 글리프 | `frontend/src/features/viewer/views/MediaView.tsx`, `frontend/src/features/views/ThumbnailView.tsx`, `frontend/src/features/views/thumb.css` | — | 3 | "알 수 없음초" 0, 미리보기 실패 칸에 형식 글리프 + "미리보기 없음", 콘솔 오류 0 | GAP-093·097·098 / IS-027 | QA-046·050 |
| T-018 | 썸네일 415를 정상 응답(대체 가능 신호)으로 | `rapidtriage/api/app/routes_media.py`(thumbnail 핸들러), `rapidtriage/api/app/thumbnail.py`, 테스트 | — | 3 | 깨진 이미지에 204 또는 `{placeholder:true}` + 서버 로그 1줄(경로 없음), 영문 오류 0 | GAP-097 / IS-027·091 | QA-050 |

### W1-b 거짓 표시(범위·건수) (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-019 | 목록 응답 부분 결과 계약(서버) | `rapidtriage/api/app/artifact_filter.py`, `rapidtriage/api/app/pagination.py`, 테스트 | T-007 | 4 | 예산 중단·lookahead 시 `total_lower_bound`·`budget_stopped`·`notice` 반환, 기존 필드 불변 | GAP-031·033 / IS-029·088 | QA-021·022 |
| T-020 | 부분 결과 띠와 정직한 빈 상태(프런트) | `frontend/src/api/collections.ts`, `frontend/src/features/grid/GridToolbar.tsx`, `frontend/src/features/grid/DataGrid.tsx`(빈 상태 분기만), `frontend/src/features/grid/useCollectionQuery.ts` | T-019 | 4 | 예산 중단 시 "행이 없습니다" 0·호박 띠 표시, "세는 중" 고착 0("n건 이상"), 페이지 윈도 상한으로 메모리 고정 | GAP-031·033·067 / IS-029·083·088 | QA-021·022·056 |
| T-021 | 단계 상태 집계 단일 함수(서버) | `rapidtriage/api/app/run_steps_summary.py`(신규), `rapidtriage/api/app/dashboard.py` | — | 3 | `failed_isolated`·부분·건너뜀을 구분한 `{total,completed,partial,failed,skipped}`를 `/dashboard`에 추가, IMG-B 요약으로 42/부분 1/실패 1 재현 테스트 | GAP-029 / IS-086 | QA-019 |
| T-022 | 접수·처리 화면이 같은 집계를 쓰게 | `frontend/src/features/dashboard/model.ts`, `frontend/src/features/dashboard/cards.tsx`, `frontend/src/features/stages/ProcessStage.tsx`(집계 부분만) | T-021 | 3 | 접수·처리·문제 목록 수치 동일, "12/12 완료·오류 0" 재현 불가 | GAP-029 / IS-086 | QA-019 |
| T-023 | 처리 범위 % 고지(서버 표시 계층) | `rapidtriage/api/app/run_scope.py`(신규: 추출 통계 → 범위), `rapidtriage/api/app/run_problems.py` | — | 3 | `scope:{percent,files_skipped,file_limit}` 산출, 문구의 상한은 실제 설정값, 영문 경고를 한국어 제한 사항으로 대체 | GAP-027 / IS-004·085 | QA-017·018 |
| T-024 | 접수 화면 범위 띠(임시, 브리핑 전까지) | `frontend/src/features/dashboard/CaseDashboard.tsx`(머리 블록만), `frontend/src/features/dashboard/dashboard.css` | T-023 | 2 | IMG-B(31%)에서 첫 화면 최상단에 "볼륨의 31%만 처리" | GAP-027·073 / IS-004 | QA-017 |

### W1-c 보고서·검토 수치의 정확성 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-025 | 보고서 포함 수 단일 출처 | `rapidtriage/api/app/review_payload.py`, `rapidtriage/api/app/routes_case_db.py`(review-counts만), 테스트 | — | 3 | 표시 5건(포함 3) 픽스처에서 보고서·`/review-counts`·카드 = 3, DB 조회 실패는 오류로 표면화(조용한 `[]` 0) | GAP-012·167 / IS-057 | QA-075 |
| T-026 | 감정서 증거 표·버전·검토 수 정정 | `rapidtriage/core/korean_report.py`, `tests/`의 감정서 테스트, 출력 샘플 스냅샷 | — | 3 | 해시·경로 실제 값, 도구 버전 기재, "검토 완료 항목 수" = 검토 판단이 있는 항목 수, "미기재"·"-" 0(값이 있는 경우) | GAP-009·010 / IS-060 | QA-009 |
| T-027 | 사건 보고서 영문 제거·방어 필드 추가 | `rapidtriage/core/case_report.py`, 출력 샘플 스냅샷 | — | 4 | 영문 제목·필드 0(허용 목록 외), 도구·카탈로그 버전·증거 해시·처리 범위·실패/부분 단계·시간대·조건 절이 4형식·모든 템플릿에, 표는 실제 표 | GAP-011·122·021 / IS-058·059 | QA-009·078 |
| T-028 | 번들·검증 패키지가 케이스 DB 검토 반영 | `rapidtriage/api/app/viewer_core.py`, `rapidtriage/core/bundle.py`, `rapidtriage/cli/runops.py`(검증 상태 부분) | — | 3 | DB에만 표시가 있는 처리에서 "검토 없음" 0, 번들 보고서에 처리 정보 포함, 영문 limitation 0 | GAP-013 / IS-064 | QA-081 |
| T-029 | 내보내기 감사 누적·시간대·도구 버전 | `rapidtriage/core/audit.py`, `rapidtriage/core/case_db/database.py`(`tool_version` 채우기만, 스키마 불변), 테스트 | — | 3 | 두 창 교차 표시 유실 0(busy_timeout·재시도·충돌 알림), 내보내기 4회 → 기록 4건(JSONL 누적, 확장자 `.audit.jsonl` + 기존 파일 읽기 호환), 시각 `+09:00`, `tool_version` 비어 있지 않음 | GAP-014·015·017·177 / IS-063·071·076 | QA-010·012 |
| T-030 | GET이 쓰지 않게(보고서 3경로) | `rapidtriage/api/app/routes_reports.py`, `frontend/src/features/case/exports.ts`, `frontend/src/api/reports.ts` | — | 4 | 세 GET은 저장된 파일만 반환(없으면 404 + 안내), 생성은 POST. 읽기 전용 순회에서 결과 폴더 mtime 불변 | GAP-016 / IS-066 | QA-011 |

### W1-d 증거 보호 잔여·안전한 조작 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-031 | 가져오기·샘플·찾아보기 경로 범위 | `rapidtriage/api/app/routes_runs.py`(import만), `rapidtriage/api/app/routes_case_db.py`(sample만), `rapidtriage/api/app/routes_meta.py`(browse), `rapidtriage/core/browse.py` | T-025 | 4 | 증거 안 결과 폴더 가져오기는 "읽기 전용" 플래그로만, 샘플·찾아보기는 허용 루트 밖 403 | GAP-003·004·005 / IS-068·073 | QA-005·006 |
| T-032 | 읽기 전용 결과 모드(지연 쓰기 차단) | `rapidtriage/api/app/readonly_run.py`(신규), `rapidtriage/api/app/thumbnail.py`·`dashboard.py`의 쓰기 지점에 관문 호출 | T-031 | 4 | 플래그가 선 결과에서 썸네일·색인·메모·보고서 쓰기 0(메모리 계산), 응답에 `readonly_reason` | GAP-003·175 / IS-068 | QA-005 |
| T-033 | CLI 단일 파일 출력 기본 위치 가드 | `rapidtriage/cli/helpers.py`, `rapidtriage/cli/parser.py`, `rapidtriage/cli/vendor.py`, `tests/test_cli_output_guard.py` | — | 4 | 증거 폴더가 cwd일 때 12개 대표 명령이 증거 안에 쓰지 않음, `vendor.py:345` 제안 문구 수정 | GAP-002·006 / IS-068 | QA-004 |
| T-034 | 파괴적 동작 표현·기본 포커스 | `frontend/src/features/case/Modal.tsx`, `frontend/src/features/case/CasePicker.tsx`, `frontend/src/features/case/commands.ts` | — | 3 | 삭제 버튼 위험 스타일, 기본 포커스 "취소", 명령명 = 대화상자 제목, 포커스 트랩이 비활성·숨김 제외 | GAP-129 / IS-094 | QA-086 |
| T-035 | 한글 모드 단축키·팔레트 순위·4xx 재시도·폴링 | `frontend/src/shortcuts.ts`, `frontend/src/shell/CommandPalette.tsx`, `frontend/src/commands/fuzzy.ts`, `frontend/src/main.tsx`, `frontend/src/api/runsProgress.ts`, `frontend/src/features/analysis/store.ts` | — | 4 | `code:"Slash"`+Shift로 도움말 열림, "CSV" 입력 시 "선택 행 CSV 내보내기" 1위, 4xx 재시도 0, 유휴 폴링 30 s·숨은 탭 0 | GAP-131·066 / IS-099·082 | QA-092·101 |
| T-036 | 표시 해제 = 직전 상태, 실행 취소, 메모 보호 | `frontend/src/features/grid/reviewActions.ts`, `frontend/src/shell/ToastRegion.tsx`, `frontend/src/features/dashboard/caseCards.tsx`(메모 블록), `frontend/src/features/review/TagManagerDialog.tsx` | — | 4 | 해제가 이력의 직전 상태로, 토스트 "실행 취소", 메모 삭제 확인·오류 표시·이동 경고, 작성자 = 담당자(`web-ui` 0) `[확인: review-batch 요청 형태만 사용, 스키마 불변]` | GAP-024·025·113 / IS-042·043 | QA-065·067 |

### W2 실데이터 기준선(QA 담당 Sonnet, 코드 변경 없음)

| ID | 제목 | 산출물(Git 밖 `D:\rapid-qa\derived\r8\w2\`) | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-037 | C1 재처리와 수정분 브라우저 재확인(AD1·2·4·5, 출력 가드, 가져오기) | 스크린샷·events.jsonl·요약 md | W1 | 4 | QA-002·003·037·086 통과 기록, 증거 전/후 동일 | GAP-001·052·179 / IS-125 | QA-001~003·037·086·087 |
| T-038 | C2 100% 재처리 **[D24]** | 처리 로그·추출 통계·시간·출력 크기 | W1, 디스크 확인 | 4(+무인 6~8) | 추출 범위 ≥99%, 원본 불변, 단계별 시간·메모리 표 | GAP-046·026(측정) / IS-122 | QA-001·017 |
| T-039 | C2 전수 순회 재실행(건수 계약·타이밍·원시값) | `tree-sweep.json`·`timing.json`·`cells.json` | T-038(없으면 C2-31) | 4 | 부록 E의 QA-020·021·044·045·100을 현 화면 기준선으로 기록(실패 목록이 W3~W7의 입력) | GAP-032·059·089·090·053·054·055·180·181 | QA-020·021·044·045·100 |
| T-040 | C4 AI 스캔 런과 콘솔 확인(앱 종료 뒤 전/후 해시) | 건수표·스크린샷 | — | 4 | 13노드 순회, CLI 건수 = 콘솔 건수, 원본 불변 확정 | GAP-048·022 / IS-055 | QA-015·072 |
| T-041 | C3 구축 **[D32]**: 기준선 일반 모드 재처리 + VM 시나리오 스크립트 | 구축 절차 md(식별자 없음), 건수표 | D24·D32 | 4(+무인) | 메신저·이메일·USB·브라우저·클라우드·LNK 행 > 0 표 | GAP-049·056·050 / IS-122 | QA-047·043 |
| T-042 | 미실행 분석 실행: OCR·VSS·NTFS 메타(TSK 설치)·교차 사건·메모리 | 분석별 결과·오류 | T-038·T-041 | 4 | 각 분석 "성공/부분/실패+사유" 기록, 실패는 GAP 추가 | GAP-047 / IS-123 | QA-024·088 |
| T-043 | C5 A등급 양성 데이터 **[D32]** | 규칙별 양성 표 | D32 | 4 | 7규칙 중 양성 확보 수, 미확보는 "검증 전" 대상 | GAP-044 / IS-124 | QA-032 |
| T-044 | 기준선 종합과 재계획 입력(Fable) `RV` | `docs/research/r8-w2-baseline.md`(건수만) | T-037~043 | 3 | coverage-matrix 갱신, 새 결함을 GAP-191 이후로 등록, W3~W8 과제 조정안 | GAP-058·162·173 / IS-121·123 | — |

### W3-a 백엔드: 브리핑·분류 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-045 | 카탈로그 분류 키와 검증기 | `rapidtriage/core/triage_rules/catalog/*.yaml`(키 추가만), `catalog/type_defaults.yaml`(신규), `rapidtriage/core/triage_rules/catalog.py`, 검증 테스트 | — | 4 | 131계열 + IMG-B·기준선 유형 전부 `tier`·`card`·`section` 해석, 누락은 오류, 기존 화면 동작 변화 0 | GAP-087 / IS-019 | QA-020 |
| T-046 | `/brief` 엔드포인트(골격·건수) | `rapidtriage/api/app/brief.py`(신규), `rapidtriage/api/app/routes_brief.py`(신규), 라우터 등록 1줄, `tests/test_brief_count_contract.py` | T-021·T-023·T-025·T-045 | 4 | 부록 D.6 스키마, 30 KB·200 ms(IMG-B), 카드·검토·특이사항 수 = 목록 total(계약 테스트) | GAP-071·144·034 / IS-001·005·111 | QA-033·103 |
| T-047 | 0건 사유 판정기 | `rapidtriage/api/app/zero_reason.py`(신규), 테스트 | T-045 | 4 | 8코드 판정 규칙(수집기 상태·모드·범위·대상 존재) 단위 테스트 24종, `none_found`는 완료+대상 읽음일 때만 | GAP-038·169·037·158 / IS-006·089 | QA-023 |
| T-048 | 사용 기간·주요 프로그램·다음 할 일 산정 | `rapidtriage/api/app/brief_insights.py`(신규), 테스트 | T-045 | 4 | Tier 1 사용자 행위만으로 기간 산정, 폴더 증거는 `unavailable`, 프로그램 상위 3은 OS 구성 요소 제외, `next_action` 규칙 5종 | GAP-171 / IS-001 | QA-033 |
| T-049 | `/summary`·`/runs/{id}` 다이어트, 압축·ETag | `rapidtriage/api/app/routes_runs.py`(summary·run 상세만), `rapidtriage/api/app/factory.py`(gzip) | T-007 | 4 | `?fields=`·ETag·304, 1 KB 초과 응답 gzip, 런 상세 ≤100 KB, 스냅샷 호환 | GAP-062·063 / IS-079 | QA-101 |
| T-050 | `CLI brief --json` | `rapidtriage/cli/brief.py`(신규), `rapidtriage/cli/parser.py`(등록 블록만) | T-046 | 2 | 봉투·종료 코드, `/brief`와 같은 값 | GAP-144 / IS-111 | QA-103 |

### W3-b 백엔드: 성능·필터 (병렬 5)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-051 | 유형 색인(artifact_type → 오프셋)과 캐시 | `rapidtriage/api/app/artifact_type_index.py`(신규), `rapidtriage/api/app/artifact_filter.py`(색인 사용 분기) | T-019 | 4 | 레지스트리 유형 필터 ≤1 s(IMG-B), total 확정, 색인은 결과 폴더(읽기 전용이면 메모리), 결과 행 동일(전/후 비교) | GAP-059·061 / IS-078 | QA-100 |
| T-052 | 검색 `lang:`·`list:`·부정 조건 구동·예산 고지 | `rapidtriage/core/search_index/engine.py`, `rapidtriage/api/app/routes_search_index.py`, 테스트 | — | 4 | `-lang:ko 계약`·`list:execution` ≤3 s(IMG-B), 후처리도 예산 안, 초과 시 `notice` | GAP-060·108·163 / IS-032 | QA-058 |
| T-053 | 파일 목록 서버 필터(확장자 등)·정렬 키 검증 | `rapidtriage/api/app/files_index.py`, `frontend/src/features/filters/filterModel.ts` | — | 4 | `ext=` 서버 처리, 건수 = 전수 집계, 무효 `sort` 422(봉투), "불러온 행에서만" 경로 제거 | GAP-043 / IS-028 | QA-027 |
| T-054 | 백그라운드 작업 틀(202·진행·취소) | `rapidtriage/api/app/bg_jobs.py`(신규), `rapidtriage/api/app/routes_bg_jobs.py`(신규), 테스트 | — | 4 | 등록·진행률·취소·직전 결과 반환 계약, 프로세스 재시작 시 "중단됨" | GAP-065·070 / IS-081 | QA-102 |
| T-055 | 계열·중복·예외·케이스 DB 준비·추출 zip을 작업으로 | `rapidtriage/api/app/routes_families.py`, `rapidtriage/api/app/routes_case_db.py`(ensure만), `rapidtriage/api/app/routes_runs.py`(extract만) | T-054 | 4 | 요청 응답 ≤1 s, 직전 결과 + "다시 계산 중" | GAP-065 / IS-081 | QA-102 |
| T-056 | 개체 요약 상한·진행·오류 | `rapidtriage/api/app/routes_search_index.py`(entities는 T-052와 충돌 → **W3-c로 이동**) | — | — | (아래 T-060으로 대체) | — | — |

> T-056은 파일 충돌로 폐기 번호다(번호 재사용 금지). 묶음 W3-b는 5개로 진행한다.

### W3-c 백엔드: 읽는 단위·정직성 (병렬 4)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-057 | 문서 단위 검색 응답 | `rapidtriage/api/app/search_documents.py`(신규), `rapidtriage/api/app/routes_search_index.py`(등록·호출) | T-052 | 4 | 한 파일 = 한 그룹(적중 수·위치·관련 행), 스니펫 ≥40자·가림, 숨긴 Tier 3 적중 수 | GAP-103·106 / IS-031·033·035 | QA-057·031 |
| T-058 | 사람·장치 롤업 파생 표 | `rapidtriage/core/derived/tables_people_devices.py`(신규), `rapidtriage/core/derived/engine.py`(등록만) `[확인: 파생 표는 수집기 불변]` | T-045 | 4 | 계정 묶음(시스템 숨김 규칙)·장치 병합(시리얼 키) 표, 기준선에서 장치 5대 = 5줄 | GAP-088·161 / IS-030 | QA-043 |
| T-059 | 확장자 위장 잡음 분리(표시 계층)·복구본 내용 상태(미리보기) | `rapidtriage/api/app/tree.py`(예외·불일치 집계), `rapidtriage/api/app/previews.py`, `rapidtriage/api/app/irregular_view.py`(신규) | T-045 | 4 | `_deleted_mft` 유래·0 채움·고엔트로피를 "내용 복구 불가"로 분리 집계, 미리보기 응답에 `content_state`, 수집기 출력 불변(D33 기본값) | GAP-040·041·176 / IS-022·023 | QA-025·026 |
| T-060 | 개체 요약 작업화·검색 색인 분석 건수 | `rapidtriage/api/app/entity_summary.py`(신규), `rapidtriage/api/app/analysis_kinds.py`(search-index 건수 기록만) | T-054·T-057 | 3 | 개체 요약 202+진행, IMG-B에서 성공, 색인 분석이 문서 수를 건수로 표시 | GAP-051·035 / IS-037·089 | QA-061 |

### W4-a 디자인 시스템 1 (병렬 6, W3와 동시 가능)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-061 | 토큰 v3(글자 7단·간격·색 역할 4계열·테마 system) | `frontend/src/tokens/tokens.css`, `frontend/src/state/slices/prefs.ts`, `frontend/src/app/themeBoot.ts` | T-002 | 4 | 새 토큰은 추가(옛 토큰은 별칭), OS 테마 추종 + 리스너, 대비 검사 통과, `tnum` 실측 결과 기록 | GAP-135·136·138 / IS-105·106·108 | QA-093·097 |
| T-062 | `Chip`·`CountBadge` | `frontend/src/components/ui/Chip.tsx`·`CountBadge.tsx`·css·테스트(신규 폴더) | T-061 | 4 | 6종 kind, 색+모양+글자, 줄임 규칙·접근성 이름 | GAP-137 / IS-107 | QA-095·098 |
| T-063 | `EmptyState`·`InlineAlert`·`Skeleton`·`PartialBanner`·`HiddenBanner` | `frontend/src/components/ui/feedback/*`(신규) | T-061 | 4 | 빈 상태 5유형·알림 4종, 오류 틀(무슨 일/영향/할 일/기술 정보), 카드·패널 단위 오류 경계 `SectionBoundary` | GAP-127·128 / IS-092 | QA-084 |
| T-064 | `Dialog`(포커스 규칙·위험·폭 3종) | `frontend/src/components/ui/Dialog.tsx`(신규)·테스트 | T-061 | 4 | 트랩·기본 포커스·복귀, 단계 전환에도 위치 고정 | GAP-137·129 / IS-094·107 | QA-086 |
| T-065 | `Button`·`Checkbox`·`Radio`·`Switch`·`Tabs` | `frontend/src/components/ui/controls/*`(신규) | T-061 | 4 | 4변형, 점선 0, 타깃 ≥28, 부모 선택자에 덮이지 않음 | GAP-137·133·139 / IS-107·109 | QA-093·095 |
| T-066 | `TimeText`·`HashValue`·`PathText`·`CopyButton` | `frontend/src/components/ui/values/*`(신규), `frontend/src/utils/time.ts`(단일 포맷터 정리) | T-061 | 4 | 표시 시간대 한 형식 + UTC title + 사본 시각 표식, 중복 `formatDuration` 제거 | GAP-116 / IS-049 | QA-071 |

### W4-b 디자인 시스템 2 (병렬 4)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-067 | `Menu` 단일화(행·뷰어·카드) | `frontend/src/components/ui/Menu.tsx`(신규), `frontend/src/components/MenuButton.tsx`(위임) | T-014 | 4 | 세 메뉴가 한 구현, 타입어헤드, 항목 ≥24px | GAP-137 / IS-107 | QA-049 |
| T-068 | `PageHeader`·`StatRow`·`ZeroReason`·`Disclosure`·`EvidenceStrip` | `frontend/src/components/ui/page/*`(신규) | T-062·T-063 | 4 | 숫자=링크+`data-count`, 무결성 4상태 표현 | IS-003·005·017 | QA-033 |
| T-069 | 전역 링크·입력·포커스 스타일 | `frontend/src/tokens/controls.css`, `frontend/src/tokens/base.css` | T-061 | 3 | 방문 색 없음, 라이트 입력 회색 채움 0, 포커스 링 통일 | GAP-133·134·099 / IS-101 | QA-093 |
| T-070 | 인쇄 스타일·화면 복사용 보기 | `frontend/src/tokens/print.css`(신규) | T-061 | 2 | 인쇄 시 패널·도구 막대 숨김, 본문 전폭 | GAP-124·189 / IS-108 | QA-082 |

### W5-a 셸·브리핑 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-071 | 주소 추가·구 주소 변환(`home`·`tools/*`·`review/set|one`·`report/preview`) | `frontend/src/router.ts`, `frontend/src/stages.ts`, 계약 테스트 갱신 | T-001 | 4 | 부록 D.1 표 전부 왕복, 쿼리 키 불변 | GAP-172 / IS-015 | QA-041 |
| T-072 | 전역 내비 4·⚙ 메뉴·상태바·역할 모드 | `frontend/src/shell/StageRail.tsx`, `frontend/src/shell/TopBar.tsx`, `frontend/src/shell/StatusBar.tsx`, `frontend/src/state/slices/role.ts`(신규) | T-061·T-067 | 4 | 4항목 + ⚙, 모드 기억, 상태바에 처리 ID 없음, 기존 e2e는 분석 담당 모드로 통과 | GAP-080·086·072·170 / IS-011·018·097 | QA-040·035 |
| T-073 | 사건 브리핑 화면 | `frontend/src/features/brief/*`(신규), `frontend/src/api/brief.ts`(신규) | T-046·T-068 | 4 | 부록 C (2) 와이어, 1440×900 스크롤 0, 6문항 DOM, 상태 5종 | GAP-071·074 / IS-001~006 | QA-033·017·023 |
| T-074 | 랜딩·토큰 화면 | `frontend/src/features/case/Landing.tsx`, `frontend/src/app/TokenGate.tsx` | T-065 | 3 | 주 동작 2 + 최근 사건 + 준비물, 토큰 안내 문장 | GAP-075·186 / IS-007 | QA-037 |
| T-075 | 처리 진행 띠·처리 중 409 제거 | `frontend/src/shell/ProgressStrip.tsx`(신규), `frontend/src/api/runPlan.ts`, `frontend/src/shell/Layout.tsx`(띠 삽입만) | T-022 | 4 | 한국어 단계·n/m·경과, 409 0, 중지는 실행 중만 | GAP-077·066·184 / IS-009 | QA-039 |
| T-076 | 다중 증거·케이스 미연결 홈 | `frontend/src/features/brief/EvidenceSwitcher.tsx`·`AllEvidenceTable.tsx`(신규, T-073 폴더와 파일 분리) | T-073(인터페이스 합의) | 3 | 증거 전환·비교 표·"사건에 연결" 머리줄 | GAP-079 / IS-010 | QA-036 |

### W5-b 내비·접수 흐름 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-077 | 살펴보기 범주 내비(검토자 모드) | `frontend/src/features/nav/CategoryNav.tsx`(신규), `frontend/src/features/tree/useTreeModel.ts`(카탈로그 분류 사용) | T-045·T-062·T-072 | 4 | 기본 ≤12, 0건=사유, 숨김 건수, 분석 담당 모드는 기존 트리 | GAP-080·081·083·084 / IS-012·013 | QA-040·020 |
| T-078 | 분류 사본 제거(`categories.ts` 폐기, `domains.ts` 생성화) | `frontend/src/features/tree/domains.ts`, `frontend/src/features/dashboard/categories.ts`, `scripts/gen-domains.py`, `rapidtriage/core/artifact_domains.py`(생성물) | T-045 | 4 | 생성 스크립트 + 동기화 테스트, 노드 id 불변(계약) | GAP-087 / IS-019 | QA-041 |
| T-079 | 새 사건 2단계·경로 사전 검사·폴더 선택기·여유 공간 | `frontend/src/features/case/CaseWizard.tsx`, `frontend/src/features/case/PathPicker.tsx`(신규), `rapidtriage/api/app/routes_cases.py`(output-check에 여유·예상 크기) | T-064·T-065 | 4 | 입력 ≤5, 고아 0, 필드 옆 오류, 모달 위치 고정 | GAP-076·183·141 / IS-008·095 | QA-037·038 |
| T-080 | 새 처리 대화상자(입력 5 + 세부 설정) | `frontend/src/features/case/RunDialog.tsx`, `frontend/src/features/case/RunPlanGroupsField.tsx` | T-064 | 4 | 처리 깊이 3·프리셋·세부 설정 접힘, `ai_read_mb`·`org_email_domain` 입력, 프로필 한국어명 | GAP-076·190 / IS-008 | QA-037 |
| T-081 | ⚙ 처리 이력·더 분석하기·작업 센터 | `frontend/src/features/stages/ProcessStage.tsx`, `frontend/src/features/stages/RunPlanTable.tsx`, `frontend/src/features/jobs/JobCenter.tsx`(신규) | T-054·T-062 | 4 | 상태 6종 글자+모양, X 제거(글자 "중지"), 분석 목록형(미실행/부분/실패 사유), 작업 진행·취소 | GAP-077·078·036·020 / IS-070·081·089 | QA-016·024·102 |
| T-082 | 설정 화면 | `frontend/src/features/settings/*`(신규) | T-061·T-065 | 3 | 표시·검토·처리 기본값·보안·고급 5절 | GAP-155 / IS-108 | QA-097 |

### W6-a 목록·뷰어 1 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-083 | DataGrid 분해(동작 불변) | `frontend/src/features/grid/DataGrid.tsx` → `GridBody`·`GridHeader`·`GridFooter`·`useGridKeyboard` | T-020 | 4 | 기존 grid vitest 341건·e2e 통과, 파일 ≤600줄 | GAP-150·143·132 / IS-117 | QA-104 |
| T-084 | 카드별 열 정의(6열)·값 라벨 단일 출처 | 카탈로그 `card_columns`·`value_labels`(YAML 블록), `frontend/src/features/grid/columns/*`(생성물 사용), `scripts/gen-labels.py` | T-045 | 4 | 하위 탭마다 ≤6열, 프런트 라벨 맵 5곳이 생성물, 원시 슬러그 요약 0 | GAP-089·090·154·091 / IS-020·021 | QA-044·045 |
| T-085 | 뷰어 머리·판단 버튼 줄·메모 영역 | `frontend/src/features/viewer/ViewerToolbar.tsx`, `frontend/src/features/viewer/viewer.css` | T-065·T-067 | 4 | 판단 버튼 3 + 보고서 포함 토글(P), 메모가 머리를 밀지 않음, 반영 ≤200 ms(낙관적) | GAP-096·069 / IS-039·046 | QA-064 |
| T-086 | 뷰어 탭(가능한 것만)·보류 사유·이진 안내 | `frontend/src/features/viewer/modes.ts`, `frontend/src/features/viewer/ModeTabs.tsx`, `frontend/src/api/viewer.ts`, `frontend/src/features/viewer/views/SourceView.tsx` | T-059·T-063 | 4 | 평균 탭 ≤4, `withheld`·`content_state` 문장, 원본 가림 + 해제 감사 | GAP-092·093·019 / IS-024·053 | QA-046·014 |
| T-087 | 메타 12필드·출처 구역 | `frontend/src/features/viewer/views/MetaView.tsx` → `MetaSummary`·`MetaTech`·`ProvenancePanel` | T-066·T-084 | 4 | 첫 화면 ≤12, 출처 고정, 영문 키 0 | GAP-094 / IS-025 | QA-048 |
| T-088 | 트리 단일 구현 | `frontend/src/components/ui/Tree.tsx`(신규), `frontend/src/features/explorers/ExplorerTree.tsx`(위임) | T-015 | 4 | 탐색기 트리가 공용 구현 사용, 동작 불변 | GAP-137 / IS-107 | QA-052 |

### W6-b 목록·뷰어 2 (병렬 4)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-089 | 목록 머리(제목·설명·건수 1회)·숨김 띠·보기 메뉴 | `frontend/src/features/grid/GridToolbar.tsx`, `frontend/src/app/ViewSwitch.tsx` | T-063·T-083 | 4 | h1 + 건수 한 번, "n건 숨김", `보기: 표 ▾` | GAP-085·045·097 / IS-017·027·072 | QA-031·051 |
| T-090 | 행·뷰어 메뉴 8 + 더 보기, 일괄 막대 | `frontend/src/features/grid/RowMenu.tsx`, `frontend/src/features/grid/BatchBar.tsx`, `frontend/src/features/grid/gridCommands.ts` | T-067 | 4 | 두 메뉴 동일 목록, 비활성 미노출, 막대가 행을 가리지 않음, 라벨 정본 import | GAP-095·101·109 / IS-026·044·039 | QA-049·064 |
| T-091 | 조건 띠(칩 5)·날짜 입력 | `frontend/src/features/filters/FilterBar.tsx` → `ChipFilterBar`·`ConditionDrawer` | T-065 | 4 | 그리드를 덮지 않음, 칩 5 + 더 보기, 파일 ≤600줄 | GAP-100 / IS-034 | QA-044 |
| T-092 | 복구본 표식·기본 정렬·폴더 트리 가상 위치 | `frontend/src/features/grid/columns/files.ts`, `frontend/src/features/explorers/FsExplorer.tsx` | T-059 | 3 | 복구본 칩, 기본 정렬 첫 화면 복구본 0, "복구된 항목(가상)" | GAP-042 / IS-023 | QA-026 |

### W7-a 검색·검토 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-093 | 문서 단위 검색 화면 | `frontend/src/features/search/*`(신규), `frontend/src/api/search.ts` | T-057·T-063 | 4 | 한 파일 한 행·펼침, 전부 색인 경로, "전문가 항목에 n건" | GAP-103·104 / IS-031·032·035 | QA-057·058 |
| T-094 | 검색 옵션·도움말 예시 | `frontend/src/features/case/SearchOptionsPopover.tsx`, `frontend/src/shell/SearchHelp.tsx`(신규) | T-065 | 3 | 범위 칩 3 + 접힘, 예시 5 | GAP-105·106 / IS-034·036 | QA-060·063 |
| T-095 | 개체 패널 | `frontend/src/features/case/EntityPanel.tsx`, `frontend/src/api/searchEntities.ts` | T-060·T-063 | 3 | 진행률·성공, 오류 봉투 | GAP-051 / IS-037 | QA-061 |
| T-096 | 검토 묶음 v1(저장 검색 기반) | `frontend/src/features/review/sets/*`(신규), `frontend/src/api/caseDb.ts` | T-093 | 4 | 묶음 생성·진행률·다음 미검토, 스키마 불변 | GAP-111 / IS-040 | QA-066 |
| T-097 | 한 건 보기 | `frontend/src/features/review/one/*`(신규) | T-085·T-096 | 4 | 50건 키보드만·건당 ≤2조작, 모순 경고 | GAP-111·112 / IS-041·045 | QA-066·068 |
| T-098 | 검토 색·라벨 정본·토스트 | `frontend/src/features/viewer/citation.ts`(정본 export), `frontend/src/features/grid/reviewActions.ts`(import로 교체 — T-036 뒤), `frontend/src/features/stages/ReviewReportStage.tsx` | T-062·T-036 | 3 | 라벨 정의 1곳, 색 역할표 적용(D35), 토스트 ≤2·성공 초록 | GAP-109·110 / IS-039·105 | QA-064·095 |

### W7-b 시간순·AI·사람·장치·키워드 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-099 | 하루 보기 | `frontend/src/features/timeline/DayView.tsx`(신규), `frontend/src/features/views/HistogramView.tsx` | T-066 | 4 | 막대+목록 한 화면, 합계 = 목록, 축·값 | GAP-114·039 / IS-047·051 | QA-069·028 |
| T-100 | 타임라인 기본 "사용자 행위만"·사본 시각 표식 | `rapidtriage/api/app/timeline_view.py`(신규: Tier 필터, 수집 불변), `frontend/src/features/grid/columns/timeline.ts` | T-045 | 4 | 기본 필터 Tier 1, 유형 한국어, 사본 시각 아이콘·필터 사유 | GAP-115·117 / IS-048·050 | QA-070 |
| T-101 | 대화 보기 시각·서브에이전트 관계 | `frontend/src/features/views/ChatView.tsx`, `frontend/src/features/views/chat.ts` | T-066 | 3 | ISO Z 0, 표시 시간대 일치 | GAP-116·118 / IS-049 | QA-071 |
| T-102 | AI 사용 개요 | `frontend/src/features/ai/AiOverview.tsx`(신규), `frontend/src/api/aiUsage.ts`, 픽스처 `aiSampleRows.ts`를 `frontend/tests/fixtures/`로 이동 | T-077 | 4 | T4 ≤2조작, 0건 문구, 유형 집합 보완 | GAP-118·119·150 / IS-052·054 | QA-072·073 |
| T-103 | 사람·장치 화면 | `frontend/src/features/people/*`(신규) | T-058·T-077 | 4 | 계정 묶음·장치 표·숨김 수·필터 카드 | GAP-088 / IS-030 | QA-043 |
| T-104 | 한국어 기본 키워드·사건 키워드·팩 적중 | `rapidtriage/core/run/profiles.py`(키워드 추가만), `rapidtriage/api/app/brief.py`(keywords — T-046 뒤 단독), 키워드 팩 YAML | T-046 | 4 | 프리셋 6종 한국어 키워드(초안 표시, D4), 브리핑 적중 = 검색 결과 | GAP-107·159 / IS-038 | QA-062 |

### W8 보고서 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-105 | 보고서 미리보기 API(절 구조 JSON) | `rapidtriage/api/app/report_preview.py`(신규), `rapidtriage/api/app/routes_reports.py`(등록만) | T-027·T-030 | 4 | 미리보기 구조 = 내보낸 파일 제목 구조(테스트), 절 선택·순서·의견·범위 | GAP-120·124 / IS-056 | QA-076 |
| T-106 | 보고서 화면(구성·종이·점검) | `frontend/src/features/report/*`(신규), `frontend/src/api/reports.ts` | T-105·T-068 | 4 | 부록 C (8), 0건 빈 상태, 주 버튼 1 | GAP-120·121·123 / IS-056·057·062 | QA-075·077·080 |
| T-107 | 제출 전 점검 계산 | `rapidtriage/api/app/report_checks.py`(신규) | T-025·T-023 | 3 | 7항목(무결성·사건 번호·담당자·메모 없음·모순·제한·가림 수) | GAP-123·112·174 / IS-062·045 | QA-080·068 |
| T-108 | PDF 한글 글꼴 포함·줄바꿈 | `rapidtriage/core/report_pdf.py`(case_report에서 PDF 부분 분리 — T-027 뒤), 글꼴 자산 | T-027 | 4 | `pdffonts`에 포함 글꼴, 해시·경로 복사 = 원값 | GAP-023 / IS-061 | QA-079 |
| T-109 | 보고서 프로파일·머리글/바닥글·AI 절 전 템플릿 | `rapidtriage/core/report_profiles.py`(신규), 템플릿 데이터 | T-027 | 3 | 3프로파일, 기밀 문구 반복, `korean-expert`·`hash-only`에 AI 절 | GAP-124 / IS-056·058 | QA-074·078 |
| T-110 | 내보내기 이력·파일 해시·알림 한 줄 | `frontend/src/features/case/ReportDialog.tsx`, `frontend/src/features/case/WriteConfirm.tsx` | T-029 | 3 | 이력에 해시 앞 8자·복사, 알림 한 줄 + 폴더 열기, "확인 중" 고착 0 | GAP-123·125·188 / IS-063·065 | QA-082·077 |

### W9-a AX·정리 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-111 | CLI `--json` 100%·봉투·종료 코드·`--dry-run`·`--lang ko` | `rapidtriage/cli/*`(parser·각 명령의 출력부) | T-033·T-050 | 4 | 89명령 스냅샷 테스트, `search --json`, 예시 100%, 이름 불변(D16 수정안), `dev`·`qa` 도움말 그룹 | GAP-145 / IS-112·098 | QA-103 |
| T-112 | `web --read-only`·`--no-browser` 기본·로컬 토큰 | `rapidtriage/cli/web.py`, `rapidtriage/api/app/readonly_mode.py`(신규) | T-007 | 3 | 허용 목록 밖 비-GET 403, 비터미널·CI에서 브라우저 미실행(D27), 토큰은 터미널일 때만 출력 | GAP-148·178·153 / IS-115 | QA-011 |
| T-113 | OpenAPI 태그·설명·스키마 100% | `rapidtriage/api/app/routes_*.py`의 데코레이터 인자만(코디네이터가 묶음 끝 단독 수행) | W3·W8 | 4 | 165+신규 연산 전부, 스냅샷 게이트 | GAP-146 / IS-113 | QA-103 |
| T-114 | 미호출 라우트 정리 | `docs/api-surface.md`(신규: 자동화용 문서화), 죽은 8개 제거는 **T-113 뒤 단독** | T-113 | 3 | 45개 각각 "자동화용/삭제/콘솔 연결" 판정, 삭제분 스냅샷 반영 | GAP-147 / IS-114 | QA-103 |
| T-115 | 저장 키 v3 이관·누적 정리 | `frontend/src/state/storageMigration.ts`(신규), `frontend/src/features/review/BaselineHistogram.tsx` | T-061 | 3 | 1회 이관·옛 키 삭제·LRU 20, `authToken` localStorage 미사용 | GAP-153 / IS-120 | QA-104 |
| T-116 | 코드 분할(전문가 화면 지연 로드) | `frontend/vite.config.ts`, `frontend/src/app/ViewSwitch.tsx`의 import 지점, `frontend/src/app/lazyViews.ts`(신규) | T-089 | 4 | 첫 화면 JS ≤1.0 MB, 번들 예산 게이트 | GAP-064 / IS-080 | QA-101 |

### W9-b 잔여 (3: T-117 단독 선행 → T-118·T-119 병렬)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-117 | 옛 컴포넌트·옛 토큰·임시 파일 삭제, 용어 lint 오류 승격 | 옛 `StatusChip`·`ToneChip`·`Badge`·`GridEmpty`·`ViewState`·`CardEmpty`·`Modal` 등, `frontend/rt-shot*.mjs`, CI 설정 | W4~W8 전부 | 4 | 옛 import 0, lint 위반 0, 600줄 초과 0 | GAP-137·150·130 / IS-107·117·096 | QA-098·104 |
| T-118 | 콘솔 S3 45건·P 계열 전수 재확인과 잔여 수정 | (Sonnet이 재확인 표 작성 → 잔여만 Opus가 파일별 소과제로) | W7 | 4 | C-xx·P1~P8 각각 "해소/잔여" 표, 잔여 0 | GAP-142·102 / IS-096·100 | QA-091·094 |
| T-119 | 에이전트 안내 문서·known-limitations 정합 | `docs/agent-guide.md`(신규), `docs/rapidtriage-known-limitations.md` | T-111 | 3 | 권장 순서·봉투·오류 코드·용어 대응표, AI 절 drift 3건 수정, 미검증 기능 목록 | GAP-148·119·165·185·187 / IS-115 | — |

> W9-b는 3개다(표 머리의 "병렬 2"는 T-117이 전역 삭제라 단독으로 먼저, 그 뒤 T-118·T-119 병렬이라는 뜻).

### W10 엔진·수집기 **[승인 필요]** (승인 시점에 삽입)

| ID | 제목 | 파일 | 결정 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-120 | E01 추출 스파이크(처리량·1패스 바이트 측정) | 측정 스크립트만 | D24 | 4 | 바이트·파일 수 기준 처리량 표, 목표(15분/90분) 확정 또는 수정 | GAP-068 / IS-084 | — |
| T-121 | 2패스 우선순위 추출·목록화 100%·삭제 sweep 상한 분리 | `rapidtriage/core/e01_native.py`, `rapidtriage/core/e01.py` | D6·D7 | 4×3(하위 과제 3개로 분할: 목록화 / 우선순위 / 삭제 상한) | `fls` 대비 누락 ≤0.5%, 사용자 프로필 100%, 원본 불변, 잘림 시 단계 "부분" | GAP-026·028·160 / IS-084·085 | QA-017·001 |
| T-122 | 시그니처 판정 재사용 + 복구본 제외 | `rapidtriage/artifacts/windows/filesystem.py`, `rapidtriage/core/files.py`(`content_state` 기록) | D6·D33 | 4 | 3,508 s → ≤120 s, 전/후 행 비교(복구본 제외분만 차이), `content_state` 목록 노출 | GAP-040·041·068 / IS-022·023 | QA-025·026 |
| T-123 | 레지스트리 키 트리 분리 저장 | `rapidtriage/artifacts/windows/registry.py` 출력부 | D10 | 4 | 1,391 s → ≤400 s, 탐색기 동일(e2e) | GAP-068 / IS-084 | QA-052·100 |
| T-124 | 침묵 실패 점검 전체 대상 | `rapidtriage/core/silent_failure.py` | D6a | 3 | 대상 100%, IMG-B 이벤트 로그 오판 0, 설명 한국어 | GAP-030 / IS-087 | QA-030 |
| T-125 | 매체 해시 계산·E01 내장 해시 대조 | `rapidtriage/core/e01_hash.py`, `rapidtriage/api/app/case_workspace.py`, `rapidtriage/core/case_db/intake.py`(상태값 추가) | D34 | 4 | 컨테이너/매체 구분, 내장 해시 대조, 거짓 불일치 0 | GAP-007·008·168 / IS-069·003 | QA-007·008 |
| T-126 | PST/OST 선택 구성 요소·단계 상태 매핑(`failed_isolated`→부분)·타임라인 매핑 | `rapidtriage/artifacts/email/*`, `rapidtriage/core/run/progress.py`, `rapidtriage/core/timeline.py` | D8·D6 | 4×3 | 메일 표본 메시지 > 0, 진행 기록에 부분 상태, 미매핑 3,200행 해소 | GAP-157·029·115 / IS-006·086·048 | QA-047·019·070 |

한국 환경 수집기(GAP-159)·카카오톡 메타 조사(GAP-158)는 v1 R8-6의 6-A를 그대로 승계하되 이 계획의 물결 밖(다음 계획)으로 둔다. 이번에는 0건 사유 화면(T-047)과 국내 호스트 분류(T-104의 YAML)만 한다.

### W11 1:1 최종 검증

| ID | 제목 | 담당 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-127 | 전 QA(QA-001~104) 실데이터 일괄 실행과 추적표 채우기 | Sonnet ×6(코퍼스·영역별 분담) | W1~W9 | 4×6 | 부록 E 전부 결과 기록, coverage-matrix 미확인 칸 수 0(잔여는 사유) | GAP-046 / IS-121·123 | QA-001~105 |
| T-128 | 적대적 최종 리뷰와 불일치 재계획 | Fable | T-127 | 4 | IS 125개 각각 "일치/불일치", 불일치는 새 T-xxx로 등록(마스터 9절 루프), 사람 테스트(QA-034) 결과 반영, R7 이월(단계 4·5) 범위 결정 반영 | GAP-164·166 / IS-121 | QA-034 |

## F.4 과제 수 검산

W0 12 · W1 24 · W2 8 · W3 15(T-056 폐기 번호 제외) · W4 10 · W5 12 · W6 10 · W7 12 · W8 6 · W9 9 · W10 7 · W11 2 = **127개 유효 과제**(번호는 T-001~T-128, T-056 결번). T-121·T-126은 착수 때 각 3개 하위 과제로 나눈다(4시간 상한 준수).

## F.5 물결별 검증 강도

| 물결 | Sonnet 검증 | Fable 리뷰 초점 | 실데이터 |
|---|---|---|---|
| W0 | 계약 테스트가 현 코드를 정확히 고정하는지(일부러 깨서 실패 확인) | 계약표 누락 | — |
| W1 | 수정 전/후 스크린샷 쌍, 증거 스냅샷 | S1 GAP 각각 닫혔는지, 새 거짓 표시 없는지 | C1·C2-31·S |
| W2 | (자체가 검증) | 기준선 해석·재계획 | C1~C5 |
| W3 | 전/후 행 동일성(색인·필터), 계약 테스트, 지연 측정 | 건수 계약·0건 사유 오판 | C2·C3 |
| W4 | 대비·타깃·시각 회귀 스크린샷(라이트·다크·6폭) | 컴포넌트 중복 재발 | — |
| W5~W8 | 과제 e2e(T1~T5) + 분석 담당 모드 회귀 + QA 해당 번호 | 페르소나 시나리오 걷기(마스터 2절) | C1~C4 |
| W9 | 스냅샷·삭제 영향 | 죽은 코드·계약 | C2 |
| W10 | `fls-coverage-diff`·`mft-reference-diff`·전/후 행 비교·원본 불변 | 복구 정확도 영향 | C1·C2 + TSK |
| W11 | 전수 | 1:1 | 전부 |
