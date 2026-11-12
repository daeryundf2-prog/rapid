# R8 부록 F — 작업 분해 (T-001 ~ T-144, 유효 143개)

마스터 10절. 소유자 방식: 큰 레인 대신 **작은 quick 과제**(한 영역, 형제와 파일이 겹치지 않음, 4시간 이하, 독립 검증 가능)로 쪼개 병렬로 돌리고, 검증을 더 엄격하게 한다.

**읽는 순서**: 이 표는 한 줄 요약이다. 구현자가 질문 없이 시작하는 데 필요한 것(대상 함수·동작 명세·수치 수용 검사·검증 명령·깨질 수 있는 기존 테스트·하지 말 것)은 **[부록 H — 과제 상세 카드](r8-task-cards.md)** 에 과제마다 있다. 표와 카드가 다르면 카드가 우선한다. 2차 적대적 리뷰(2026-11-11)가 고친 행에는 `〔2차〕`를 붙였다.

## F.1 공통 규칙

- **역할**: 구현 Opus(과제당 워크트리 1개) → 검증 Sonnet(구현자와 다른 세션이 수용 검사·검증 명령을 처음부터 다시 실행, 실데이터 QA 수행) → 적대적 리뷰 Fable(묶음마다 diff 전체 + 추적표 대조). 표에서 담당이 다르면 따로 적는다(`QA` = Sonnet 단독, `RV` = Fable 단독).
- **묶음**: 물결 W0~W11, 물결 안의 묶음(a·b·c…)마다 과제 6개 이하. 같은 묶음의 과제는 파일이 겹치지 않는다(표의 "파일"이 배타 소유 범위). 묶음은 앞 묶음이 통합 브랜치에 들어간 뒤 시작한다.
- **묶음 안 단계**〔2차〕: 같은 묶음 안에 선후 의존이 있으면 병렬이 아니다. F.6의 단계표(1단계 → 2단계 …)를 따른다. 뒤 단계 과제는 앞 단계 과제가 **통합 브랜치에 들어간 뒤** 시작한다. 예외는 카드에 "인터페이스 선합의"라고 적힌 과제뿐이다(카드에 적힌 응답 모양·함수 시그니처를 고정하고 병렬 구현, 통합 검증은 뒤 단계에서).
- **화면 장착**〔2차〕: 새 화면·패널은 `export`까지만 만든다. 슬롯·경로에 장착하는 파일(`frontend/src/app/registerSlots.tsx`, `frontend/src/app/ViewSwitch.tsx`, `frontend/src/app/IntakePane.tsx`)과 백엔드 라우터 등록(`rapidtriage/api/app/factory.py`의 `include_router`)은 금지 구역이다. 표에 그 파일이 적힌 과제만 직접 고치고, 나머지는 코디네이터가 묶음 끝에 한 번에 장착한다(장착 diff는 과제당 10줄 이하).
- **기존 테스트**〔2차〕: 과제가 기존 테스트의 단언을 바꿔야 하면 (a) 계약표(부록 D)에 있는 이름·주소·인용·키면 **바꾸지 않는다**(과제가 틀린 것), (b) 계약표에 없는 문구·클래스·치수면 같은 PR에서 testid·역할 선택자로 옮기고 PR 본문에 "바꾼 단언 n개" 목록을 적는다. 삭제·`skip`은 금지.
- **브랜치**: 통합 `feat/r8`(`feat/r6-ux` ffab479에서 분기, D13), 과제 `r8/T-xxx-짧은이름`. 머지는 소유자 지시 때만.
- **공유 파일 금지 구역**(한 묶음에서 한 과제만): `frontend/src/features/grid/DataGrid.tsx`, `frontend/src/app/shell.css`, `frontend/src/shell/Layout.tsx`, `frontend/src/router.ts`, `frontend/src/tokens/tokens.css`, `frontend/src/app/registerSlots.tsx`, `frontend/src/app/ViewSwitch.tsx`, `frontend/src/app/IntakePane.tsx`, `frontend/index.html`, `rapidtriage/api/app/routes_runs.py`, `rapidtriage/api/app/routes_case_db.py`, `rapidtriage/api/app/routes_reports.py`, `rapidtriage/api/app/routes_search_index.py`, `rapidtriage/api/app/factory.py`, `rapidtriage/core/case_report.py`, `rapidtriage/cli/parser.py`, 카탈로그 YAML, `docs/console-glossary.md`, `docs/rapidtriage-known-limitations.md`, OpenAPI 스냅샷(코디네이터가 묶음 끝에 재생성).
- **[승인]**: AGENTS.md 계약(복구 엔진·파서·핵심 포렌식 로직·API 동작·DB 스키마). 승인 전 착수 금지. 표시·API 응답 추가·보고서 생성기·검색 색인 질의·케이스 워크플로는 승인 불필요로 분류했고, 경계가 애매한 것은 `[확인]`으로 표시했다(결정 D6 범위 확인).
- **과제 공통 검증 명령**(수용 검사와 별개로 항상):
  ```bash
  python -m ruff check rapidtriage tests scripts && python -m vulture rapidtriage tests scripts --min-confidence 80
  python -m compileall -q rapidtriage tests scripts
  python scripts/run-tests-parallel.py --changed   # T-011 이전에는 관련 모듈만 python -m unittest tests.<module>
  (cd frontend && npm run typecheck && npm run lint && npx vitest run <관련 폴더> && npm run build)
  (cd frontend && npm run e2e -- <과제에 적힌 스펙>)   # = playwright test --config e2e/playwright.config.ts. 설정 없이 npx playwright test 는 스펙을 못 찾는다〔2차〕
  git diff --check && git status --short
  ```
  묶음 끝(코디네이터): AGENTS.md 검증 명령 전부 + vitest 전체 + e2e 전체 + 계약 테스트 + 번들 예산 + 부록 E의 회귀 묶음(E.6).
- **닫는 조건**: 수용 검사 통과 + Sonnet 재실행 통과 + (화면 과제) 실데이터 스크린샷 1장 이상 + 추적표 갱신. vitest·TestClient만으로 닫지 않는다(IS-125).

## F.2 물결 요약

| 물결 | 주제 | 과제 수 | 묶음 | 승인 |
|---|---|---|---|---|
| W0 | 계약·측정·기반 | 12 | a(6)·b(6) | 불필요 |
| W1 | 깨진 것·거짓 표시·방어 가능성 긴급 수정 | 31 | a·b·c·d·e(각 6)·f(1) | 불필요(T-036·T-129·T-131·T-132 `[확인]`) |
| W2 | 실데이터 기준선 구축·재확인 | 9 | a(6)·b(3: T-043·T-044·T-138) | D24·D32(미승인 시 부록 E.7 대체 경로) |
| W3 | 백엔드 지원(`/brief`·색인·백그라운드·분류) | 15 | a(6)·b(5)·c(4) | 불필요 |
| W4 | 디자인 시스템 컴포넌트 | 10 | a(6)·b(4) | 불필요 |
| W5 | 셸·브리핑·내비·접수 흐름 | 12 | a(6)·b(6) | 불필요 |
| W6 | 목록·뷰어 | 12 | a(6)·b(6) | 불필요 |
| W7 | 검색·검토·시간순·AI·사람·장치 | 15 | a(6)·b(6)·c(3) | 불필요 |
| W8 | 보고서 | 6 | a(6) | 불필요 |
| W9 | AX·정리·잔여 | 12 | a(6)·b(6) | 불필요 |
| W10 | 엔진·수집기(승인 묶음) | 7 | a(6)·b(1) | **필요(D6·D6a·D7·D8·D10·D34)** |
| W11 | 1:1 최종 검증·사람 테스트 | 2 | a(2) | — |
| 합계 | | 143 | 28묶음(1차 표의 "23"은 오산 — 1차 기준 25) | |

순서의 근거: (1) 계약이 없으면 재설계가 테스트를 한꺼번에 깬다 → W0. (2) 지금 화면이 **틀린 사실**을 말하는 곳(GAP S1)을 구조 변경보다 먼저 → W1. (3) 소유자의 의심(실데이터 미검증)을 설계 전에 수치로 닫는다 → W2가 W1 직후. (4) W3·W4는 서로 파일이 겹치지 않아(백엔드 vs 컴포넌트) **동시에** 진행 가능. (5) W10은 승인 시점에 맞춰 W3 이후 어디든 끼울 수 있다(파일이 겹치지 않음).

## F.3 과제표

열: ID · 제목 · 배타 파일 · 의존 · 크기(h) · 수용 검사 · 닫는 GAP/IS · QA. 묶음 제목의 "(병렬 n)"은 묶음 크기다 — 실제 동시 수와 순서는 F.6 단계표를 따른다. 과제별 상세는 [부록 H](r8-task-cards.md).

### W0-a 계약·측정 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-001 | UI 계약 추출기와 계약 테스트 〔2차: 범위 확대〕 | `scripts/extract-ui-contract.mjs`, `frontend/src/contracts/uiContract.ts`, `frontend/src/contracts/*.contract.test.ts` | — | 4 | testid 전수 목록 + **e2e·vitest의 `getByRole` 이름 전수(e2e 173회·vitest 536회의 고유 이름 표)** + 주소 왕복 30종 + 인용 스냅샷 12종 + sessionStorage 4키·팝아웃 메시지 종류(부록 D.11) 테스트가 현 코드에서 통과, 부록 D와 표 일치. 일부러 이름 1개를 바꾸면 계약 테스트가 실패 | GAP-149·172·194·208 / IS-116 | QA-041·104·111 |
| T-002 | 토큰 lint·대비 검사 확장 | `frontend/scripts/check-tokens.mjs`(신규), `frontend/scripts/check-contrast.mjs`(기존 확장), `frontend/package.json`(scripts 블록) | — | 3 | 현 위반 수를 기준선 JSON으로 기록(색 0·radius 42·px 124·font-size 9), 새 위반은 실패 | GAP-140 / IS-110 | QA-096 |
| T-003 | 증거 스냅샷·로그 스캔·보고서 감사 스크립트 | `scripts/r8-evidence-snapshot.py`, `scripts/r8-log-scan.py`, `scripts/r8-report-audit.py`, `scripts/r8-trace-audit.py`(부록 A·B·E·F에서 추적표 생성·구멍 검사), `tests/test_r8_qa_scripts.py` | — | 4 | 합성 폴더에서 변경 1바이트·신규 파일 검출, 가짜 비밀·경로 검출, 보고서 필드 누락 검출 단위 테스트. `r8-trace-audit.py`는 (a) GAP 없는 IS·과제 없는 GAP·QA 없는 IS, (b) 같은 묶음 안 파일 중복, (c) F.6 단계표와 의존 열의 모순을 실패로 보고 | GAP-204 / IS-067·074·059 | QA-001·013·009·078 |
| T-004 | 합성 풍부 픽스처 생성기(가짜 값) | `scripts/make-r8-fixture.py`, `tests/fixtures/r8_rich/`(생성 스크립트·매니페스트만), `frontend/e2e/r8_fixture.py` | — | 4 | Tier 1 9카드 전부 행 > 0, 가짜 비밀·가짜 개체 포함, 실데이터·PII 0(스캔), 생성 60 s 이하 | GAP-057 / IS-121(CI용) | QA-045 |
| T-005 | 용어 lint와 용어집 R8 개정 | `scripts/check-glossary-terms.py`, `docs/console-glossary.md`, `tests/test_glossary_lint.py` | — | 4 | 부록 C.7 표가 용어집에 반영(보고서 포함 키 표기 오류 수정 포함), lint가 금지 표기를 경고 모드로 집계(기준선 기록) | GAP-130·182 / IS-096 | QA-035 |
| T-006 | 병렬 테스트 실행기와 CI 전환 | `scripts/run-tests-parallel.py`, `.github/workflows/rapidtriage-ci.yml` | — | 4 | 빠른 묶음 8분 이하(느린 4모듈 분리), 전체 결과가 단일 discover와 같은 테스트 수 | GAP-152 / IS-119 | QA-104 |

### W0-b 기반 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-007 | 서버 오류 봉투와 500 경로 제거 〔2차: 추가 방식〕 | `rapidtriage/api/app/errors.py`(신규: 예외 처리기 + 영문 리터럴 → 한국어 대응표), `rapidtriage/api/app/factory.py`(처리기 등록·500 본문), `docs/api-error-codes.md`, `tests/test_error_envelope.py` | — | 4 | 모든 4xx·5xx 본문에 최상위 `code`·`message`·`hint`가 **추가**된다. **기존 `detail`은 형·값 그대로**(문자열·배열·`{code,message}` 객체 모두 불변) → `tests/`의 `["detail"]` 단언 190곳 무수정 통과. 영문 `detail` 리터럴 36종은 `message`만 한국어(대응표). 500 본문에 `crash_report` 절대경로 0(`crash_id`만). API 스냅샷 차이는 오류 스키마 추가뿐 | GAP-126·018·156·193 / IS-091·074 | QA-083·111 |
| T-008 | 프런트 오류 정규화 | `frontend/src/api/client.ts`, `frontend/src/api/errors.ts`(신규), 해당 테스트 | —(T-007과 인터페이스 선합의: 부록 D.7) | 3 | `ApiError`가 `code`·`message`·`hint`·`status`를 가진다. 서버가 최상위 `message`를 주면 그것을, 없으면 `detail`에서 만든 문장을 쓴다(옛 서버 호환). 네트워크 실패(`TypeError`)→`NETWORK_UNREACHABLE`, 중단→`REQUEST_ABORTED`(화면에 표시 안 함), 시간 초과→`REQUEST_TIMEOUT`. "Failed to fetch"·"Request failed" 문자열 0(grep `frontend/src`, 테스트 제외) | GAP-126·051·193 / IS-091 | QA-083 |
| T-009 | Python 잠금 파일과 프로젝트 기준 감사 | `pyproject.toml`, `requirements.lock`, `.github/workflows/dependency-monitoring.yml`, `scripts/check-dependencies.py` | — | 4 | 잠금 기준 pip_audit 실행, `requires-python>=3.12` 정렬, 권고 목록과 D25 판단 근거 문서 | GAP-151 / IS-118 | QA-104 |
| T-010 | 비결정·기준 실패 테스트 4건 수정 `[확인: 파생 표 단계의 폴더 이름 충돌만, 수집·복구 불변]` | `rapidtriage/core/derived/stage.py`(`:77-79` `new_run_stage_analysis_id` 충돌만), `tests/`의 해당 3파일, `frontend/src/features/grid/qaRealData.test.tsx`·`frontend/src/features/analysis/qaRealData.test.tsx`·`qaRealData2.test.tsx` | — | 4 | 4건 각각 20회 반복 통과, `test_rapidtriage_email_external…` 원인 기록 | GAP-152 / IS-119 | — |
| T-011 | 과제 측정 하네스(T1~T5 골격·지표 수집) | `frontend/e2e/tasks/`(신규 폴더), `scripts/r8-measure.py` | T-001 | 4 | 현 화면에서 UX 감사 수치(트리 366±10%, 잘림 29~37%, Tab 32)를 재현하는 기준선 JSON | IS-121 | QA-033·044·091 |
| T-012 | e2e CSS 클래스 선택자 제거 | `frontend/e2e/*.spec.ts`(기존 13개), 선택자 대체에 필요한 testid 추가는 `frontend/src/features/views/ChatView.tsx`·`frontend/src/features/case/EntityPanel.tsx`·`frontend/src/features/viewer/views/ImageView.tsx`만(그 밖의 클래스 — `.grid-row-stripe`·`.grid-scroll`·`.dash-*`·`.hist-cat-label`·`.flag-popover`·`.thumb-view` — 는 기존 testid·역할로 대체, 컴포넌트 수정 없이) | T-001 | 4 | e2e에서 `locator('.…')` 0(lint), 13스펙 통과 수 변화 없음 | GAP-150 / IS-117 | QA-104 |

### W1-a 깨진 컴포넌트 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-013 | 검색 옵션 체크박스가 빈 막대로 그려지는 결함 | `frontend/src/app/shell.css`(`.global-search input` 범위를 검색 입력 하나로), `frontend/src/tokens/controls.css` | — | 2 | 체크박스 폭 ≤24px·라벨 우측(boundingBox), 라이트·다크 스크린샷 | GAP-105 / IS-034 | QA-060 |
| T-014 | 메뉴 포털·충돌 보정(뷰어 … 메뉴 잘림) | `frontend/src/components/MenuButton.tsx`, `frontend/src/components/popover.css`, `frontend/src/components/Popover.tsx` | — | 4 | 뷰어 최소 폭·880에서 메뉴 사각형이 뷰포트 안, Esc·포커스 복귀 유지 | GAP-095 / IS-102 | QA-049 |
| T-015 | 트리 건수 잘림·가로 스크롤·이탤릭·검색 공백 | `frontend/src/features/tree/tree.css`, `frontend/src/features/tree/EvidenceTree.tsx`, `frontend/src/features/case/case.css`(`.case-tree` 블록만) | — | 4 | 스크롤바가 있어도 건수 `scrollWidth==clientWidth`, 가로 스크롤 0, 이탤릭 0("자료 없음" 글자), 검색 결과 사이 공백 ≤행 높이 | GAP-082 / IS-012·106 | QA-094 |
| T-016 | 추가 분석 카드 글자 겹침·격자 구멍 | `frontend/src/features/stages/stages.css`(`.process-card`·`.analysis-cards` 블록) | — | 2 | 2줄 제목에서 겹침 0(요소 사각형 교차 검사), 880~1920 | GAP-078 | QA-094 |
| T-017 | 미디어 길이 문구·썸네일 대체 글리프 | `frontend/src/features/viewer/views/MediaView.tsx`(`:97`), `frontend/src/features/views/ThumbnailView.tsx`, 〔2차: `thumb.css`는 없다〕 `frontend/src/features/views/views.css`(`.thumb*` 블록만) | —(T-018과 인터페이스 선합의: 204 = 미리보기 불가) | 3 | "알 수 없음초" 0, 미리보기 실패 칸에 형식 글리프 + "미리보기 없음", 콘솔 오류 0 | GAP-093·097·098 / IS-027 | QA-046·050 |
| T-018 | 썸네일 415를 정상 응답(대체 가능 신호)으로 | `rapidtriage/api/app/routes_media.py`(thumbnail 핸들러), `rapidtriage/api/app/thumbnail.py`, 테스트 | — | 3 | 깨진 이미지에 204 또는 `{placeholder:true}` + 서버 로그 1줄(경로 없음), 영문 오류 0 | GAP-097 / IS-027·091 | QA-050 |

### W1-b 거짓 표시(범위·건수) (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-019 | 목록 응답 부분 결과 계약(서버) | `rapidtriage/api/app/artifact_filter.py`(`filter_artifact_page` `:132-216`, `filter_across_kinds` `:350` 부근), `rapidtriage/api/app/pagination.py`(`paginate_payload`), 테스트 | T-007 | 4 | `budget_stopped`·`truncated`·`scanned`는 **이미 있다**(`:214-215`) → 추가만: `total_lower_bound`(= `offset + returned + (1 if has_more else 0)`, 중단 시 지금까지 일치한 수), `budget_stopped`를 항상 불리언으로, `notice:{code,message}`(`SCAN_BUDGET_STOPPED`·`TOTAL_NOT_COUNTED`). 기존 필드 이름·값 불변(스냅샷) | GAP-031·033 / IS-029·088 | QA-021·022 |
| T-020 | 부분 결과 띠와 정직한 빈 상태(프런트) 〔2차: 메모리 윈도는 T-143으로 분리〕 | `frontend/src/api/collections.ts`(pagination 형), `frontend/src/features/grid/GridToolbar.tsx`(`:420-425`), `frontend/src/features/grid/DataGrid.tsx`(빈 상태 분기 `:1467-1518`, 바닥 문구 `:1441-1453`만) | T-019 | 4 | `budget_stopped`면 빈 상태 대신 호박 띠 "시간 제한으로 일부만 확인했습니다(n행 확인) — 다시 시도 · 조건 좁히기", "이 노드에는 표시할 행이 없습니다"는 `total===0 && !budget_stopped && !truncated`일 때만. "총 세는 중…"은 실제 요청 중에만, 끝나면 `total` 또는 "n건 이상"(`total_lower_bound`). "전체 건수 미확정"·"전체 미확인" 문자열 0 | GAP-031·033 / IS-029·088 | QA-021·022 |
| T-021 | 단계 상태 집계 단일 함수(서버) | `rapidtriage/api/app/run_steps_summary.py`(신규: `summarize_steps(summary) -> {total,completed,partial,failed,skipped,failed_names[]}`), `rapidtriage/api/app/dashboard.py`(`build_run_dashboard` `:327`에 `steps` 키 추가) | — | 3 | 입력은 처리 요약의 `steps[].status`. 대응: `completed`→완료, `failed_isolated`(`core/run/steps.py:142`)→**부분**, `error`·`failed`→실패, `skipped`→건너뜀, `cancelled-partial`→부분. IMG-B 요약(Git 밖)을 줄인 픽스처로 42 / 부분 1 / 실패 1 재현. 수집기 progress(12단계)와 별개 수임을 응답 필드 이름으로 구분(`steps` vs `providers`) | GAP-029 / IS-086 | QA-019 |
| T-022 | 접수·처리 화면이 같은 집계를 쓰게 | `frontend/src/features/dashboard/model.ts`, `frontend/src/features/dashboard/cards.tsx`, `frontend/src/features/stages/ProcessStage.tsx`(집계 부분만) | T-021 | 3 | 접수·처리·문제 목록 수치 동일, "12/12 완료·오류 0" 재현 불가 | GAP-029 / IS-086 | QA-019 |
| T-023 | 처리 범위 % 고지(서버 표시 계층) | `rapidtriage/api/app/run_scope.py`(신규: 추출 통계 → 범위), `rapidtriage/api/app/run_problems.py` | — | 3 | `scope:{percent,files_skipped,file_limit}` 산출, 문구의 상한은 실제 설정값, 영문 경고를 한국어 제한 사항으로 대체 | GAP-027 / IS-004·085 | QA-017·018 |
| T-024 | 접수 화면 범위 띠(임시, 브리핑 전까지) | `frontend/src/features/dashboard/CaseDashboard.tsx`(머리 블록만), `frontend/src/features/dashboard/dashboard.css` | T-023 | 2 | IMG-B(31%)에서 첫 화면 최상단에 "볼륨의 31%만 처리" | GAP-027·073 / IS-004 | QA-017 |

### W1-c 보고서·검토 수치의 정확성 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-025 | 보고서 포함 수 단일 출처 | `rapidtriage/api/app/review_payload.py`(신규 함수 `report_candidate_count(summary, run_id, case_json) -> {count, db, case_json, error}`), `rapidtriage/api/app/routes_case_db.py`(review-counts `:99-163`만), 테스트 | — | 3 | 표시 5건(포함 3: DB 2 + 케이스 JSON 1) 픽스처에서 보고서 본문 항목 수 = `/review-counts.report_candidates` = 3. JSON 측은 `bookmark.review.include_in_report`를 읽는다(`:147-148` 수정). DB·JSON 양쪽에 같은 대상이 있으면 1로 센다(중복 제거 키 = 인용 id). `sqlite3.Error`는 `[]`·0이 아니라 응답의 `error:{code:"CASE_DB_UNREADABLE",message}` + `report_candidates:null`(`review_payload.py:76-77`, `routes_case_db.py:134-137`) | GAP-012·167 / IS-057 | QA-075 |
| T-026 | 감정서 증거 표·버전·검토 수 정정 | `rapidtriage/core/korean_report.py`, `tests/`의 감정서 테스트, 출력 샘플 스냅샷 | — | 3 | 해시·경로 실제 값, 도구 버전 기재, "검토 완료 항목 수" = 검토 판단이 있는 항목 수, "미기재"·"-" 0(값이 있는 경우) | GAP-009·010 / IS-060 | QA-009·115 |
| T-027 | 사건 보고서 영문 제거·방어 필드 추가 〔2차: "표는 실제 표"는 T-108(PDF)·T-109(DOCX)로 이동 — 4 h 초과〕 | `rapidtriage/core/case_report.py`(Markdown 생성부 `:40-290`, 제목 `:484,562,797`), 출력 샘플 스냅샷 | — | 4 | 영문 제목·필드 0(허용 목록 외; 대상 줄 `:53-54,76-78,130-152,173-207,247-264,279-283,484,562,797`). 신규 절 "처리 정보와 한계"가 5템플릿 전부·4형식 전부에: 도구 버전(`rapidtriage.__version__`), 카탈로그 버전(`core/triage_rules/catalog.py`의 `version`), 증거 해시(매니페스트 `item.evidence.hashes`), 처리 범위 %(T-023 값, 없으면 "산정 정보 없음"), 실패·부분 단계 이름, 표시 시간대, 적용 조건·숨긴 건수(요청에 실려 온 값) | GAP-011·122·021 / IS-058·059 | QA-009·078 |
| T-028 | 번들·검증 패키지가 케이스 DB 검토 반영 + 감사 입력에 케이스 DB | `rapidtriage/api/app/viewer_core.py`(`build_run_validation_review_status` `:850-880`), `rapidtriage/core/bundle.py`(`:97-102` `run_summary={}`), 〔2차: 경로 정정〕 `rapidtriage/api/app/runops.py`(`:695` 호출부, `:895-949` 감사 3함수의 `input_files`에 케이스 DB 추가) | —(기존 `case_db_mark_bookmarks` `review_payload.py:57` 사용 — T-025와 파일 무충돌) | 3 | DB에만 표시가 있는 처리에서 `bookmark_count`·`report_item_count` = DB 표시 수, "검토 없음"·`case review file has not been created` 0, 번들 보고서에 처리 정보(`run_summary` 전달), limitation 문장 한국어, 감사 기록 `input_files`에 `case-db`(경로·SHA-256) | GAP-013·014 / IS-064·063 | QA-081·010·115 |
| T-029 | 내보내기 감사 누적·시간대·도구 버전 〔2차: 동시 쓰기는 T-131, 나머지 시각 34곳은 T-132로 분리. 사이드카 이름 유지〕 | `rapidtriage/core/audit.py`(`audit_path_for` `:24-27`, `write_audit_record` `:112-154`), `rapidtriage/core/case_db/database.py`(`:1145-1146` `tool_version` 값만, 스키마 불변 `[확인]`), 테스트 | — | 3 | 기존 사이드카(`<이름>.audit.<확장자>`)는 **이름·내용 형식 그대로**(최신 1건, 응답의 `audit` 경로·기존 테스트 불변) + 같은 폴더의 누적 파일 `rapidtriage-export-audit.jsonl`에 호출마다 1줄 추가(덮어쓰기 없음). 각 줄: `command`·`generated_at`(오프셋 포함)·`tool_version`·`user`·`input_files[]`·`generated_outputs[]`(SHA-256). 내보내기 4회 → 4줄. 리뷰 `audit_event.tool_version` = `rapidtriage.__version__` | GAP-014·015·177·208 / IS-063·071 | QA-010 |
| T-030 | GET이 쓰지 않게 〔2차: 3경로가 아니라 6경로〕 | `rapidtriage/api/app/routes_reports.py`(`:83-98`, `:139-145`, `:148-154`, `:192-198`, `:221-229`, `:232-249`), `frontend/src/features/case/exports.ts`, `frontend/src/api/reports.ts` | — | 4 | 여섯 GET은 **쓰지 않는다**: `/submission-manifest`·`/validation-package`(JSON 조회)는 메모리에서 만들어 반환만, `…/file`·`/case-report/file[/{format}]`은 저장된 파일만 반환(없으면 404 `EXPORT_NOT_WRITTEN` + "먼저 내보내기를 실행하세요"). 생성은 POST(매니페스트는 신규 `POST /submission-manifest`, 검증 패키지·보고서는 기존 POST). 프런트 내보내기는 POST → 저장본 GET 순서. OpenAPI의 모든 GET을 한 번씩 부른 뒤 결과 폴더 스냅샷 동일 | GAP-016 / IS-066 | QA-011·108 |

### W1-d 증거 보호 잔여·안전한 조작 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-031 | 가져오기·샘플·찾아보기 경로 범위 〔2차: 모드별 규칙 명세〕 | `rapidtriage/api/app/routes_runs.py`(import `:525-531`만), `rapidtriage/api/app/routes_case_db.py`(sample `:78-95`만), `rapidtriage/api/app/routes_meta.py`(browse `:132-152`), `rapidtriage/core/browse.py`, `rapidtriage/core/sample_case.py`(`:25-28` 삭제 조건) | T-025 | 4 | (1) **샘플**: `output_dir`는 `~/.rapidtriage/` 아래만 허용(밖이면 403 `PATH_OUTSIDE_ALLOWED_ROOT`), 요청 기본 `overwrite=False`, 삭제는 폴더에 샘플 표식 파일 `rapidtriage-sample-expected.json`이 있을 때만(없는 비어 있지 않은 폴더는 409, **삭제 0**). (2) **가져오기**: 결과 폴더가 그 처리의 증거 경로 안/같음이면 가져오되 `readonly_reason:"OUTPUT_INSIDE_EVIDENCE"`를 처리에 기록(T-032가 소비). (3) **찾아보기**: 루프백(로컬) 서버는 현행대로 전체 — 분석 담당이 증거를 골라야 한다. `--remote` 서버는 `--browse-root`(반복 가능, 기본 = 사건 폴더들 + 홈)로 준 루트 안만, 밖은 403. 기존 `scope=analysis-*` 동작 불변 | GAP-003·004·005·207 / IS-068·073 | QA-005·006·107 |
| T-032 | 읽기 전용 결과 모드 — 관문 〔2차: 재정의. 지점별 차단은 T-133·T-134〕 | `rapidtriage/api/app/readonly_run.py`(신규: `run_readonly_reason(job) -> str\|None`, `may_persist(output_dir) -> bool`, 미들웨어 `reject_writes_for_readonly_run`), `rapidtriage/api/app/index_cache.py`(`index_persist_enabled` `:21-23`가 처리별 판단을 받도록 인자 추가, 환경 변수 동작 불변), `rapidtriage/api/app/thumbnail.py`(`cached_thumbnail` `:87`), `rapidtriage/api/app/dashboard.py`(`write_case_notes` `:71`) | T-031 | 4 | 읽기 전용 처리에 대한 **비-GET 요청은 전부 409 `RUN_READ_ONLY`**(허용 목록: 없음. 삭제 = 목록에서 빼기만 허용)를 미들웨어 한 곳에서 거부. `GET /api/runs/{id}`·`/dashboard`에 `readonly_reason`. 썸네일은 디스크 캐시 없이 메모리 응답, 메모 쓰기는 409. 가드 이전 결과가 아닌 처리의 동작·성능 불변(전/후 타이밍 ±5%) | GAP-003·175·192 / IS-068 | QA-005 |
| T-034 | 파괴적 동작 표현·기본 포커스 | `frontend/src/features/case/Modal.tsx`, `frontend/src/features/case/CasePicker.tsx`, `frontend/src/features/case/commands.ts` | — | 3 | 삭제 버튼 위험 스타일, 기본 포커스 "취소", 명령명 = 대화상자 제목, 포커스 트랩이 비활성·숨김 제외 | GAP-129 / IS-094 | QA-086 |
| T-035 | 한글 모드 단축키·팔레트 순위 〔2차: 재시도·폴링은 T-130으로 분리〕 | `frontend/src/shortcuts.ts`(`:61-66` 물리 키 폴백, `:84-85`), `frontend/src/shell/CommandPalette.tsx`(`:11-20` 그룹 순서, `:97-103` 정렬), `frontend/src/commands/fuzzy.ts` | — | 3 | 물리 키 폴백을 `Key[A-Z]` → `Key*`·`Digit*`·`Slash`·`Backquote`로 확대: `{key:"Process",code:"Slash",shiftKey:true}` → 도움말 열림, `isComposing` 중 발화 0. 질의가 있으면 그룹을 넘어 점수순(라벨 일치 > id 일치 > 부분 일치), "CSV" → "선택 행 CSV 내보내기" 1위. 질의가 없으면 현행 그룹 순서. 비활성 명령은 질의 결과 하단(사유 유지) | GAP-131 / IS-099 | QA-092 |
| T-036 | 표시 해제 = 직전 상태, 실행 취소, 작성자 〔2차: 메모 보호는 T-144로 분리, 경로 정정〕 | `frontend/src/features/grid/reviewActions.ts`(`unmarkActionOf` `:30-34`, 표시 실행부 `:433` 부근), 〔정정〕 `frontend/src/components/ToastRegion.tsx`·`frontend/src/components/toastStore.ts`(동작 버튼 있는 토스트), `frontend/src/features/review/author.ts`(`DEFAULT_REVIEWER` `:10`) | — | 4 | 직전 상태의 출처는 **표시 직전 클라이언트가 가진 상태**(`grid/reviewMap.ts`)를 실행 취소 스택(최근 20, 세션 한정)에 넣은 것 — 서버 이력 조회·스키마 변경 없음. 해제 = 스택의 직전 상태로 `review-batch` 재요청(없으면 미검토). 토스트 "n건 표시했습니다 · 실행 취소"(5 s) + `Ctrl+Z`. 작성자 미설정이면 첫 표시 전에 담당자 이름을 한 번 묻고(사건 담당자 값이 있으면 기본값) `web-ui`를 서버로 보내지 않는다 `[확인: review-batch 요청 형태만 사용, 스키마 불변]` | GAP-024·025 / IS-042·043 | QA-065·067 |
| T-144 | 〔2차 신규: T-036에서 분리〕 메모 보호·태그 관리 작성자 칸 | `frontend/src/features/dashboard/caseCards.tsx`(메모 블록 `:880-990`만), `frontend/src/features/review/TagManagerDialog.tsx`(`:180-187` 자리 표시자) | — | 3 | 메모 삭제는 확인 대화상자(기본 포커스 "취소") 뒤에만, 삭제·저장 실패는 메모 영역 안 오류 문장(영문 원문 0), 편집 중(`dirty` `:888`) 다른 화면으로 가면 "저장하지 않은 내용이 있습니다" 확인, 자리 표시자 `web-ui` → "담당자 이름", 이력 문구 "태그 없음→없음" 0 | GAP-025·113 / IS-043 | QA-067·086 |

> W1-d는 6개다: T-031·T-032·T-034·T-035·T-036·T-144. T-033은 W1-e로 옮겼다(파일이 겹치지 않아 순서 무관, 묶음 6개 상한 때문).

### W1-e 방어 가능성 보강 〔2차 신규 묶음〕 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-033 | CLI 단일 파일 출력 기본 위치 가드 〔2차: W1-d에서 이동, 경로 정정〕 | `rapidtriage/cli/helpers.py`(공용 `resolve_output_path(args, evidence_root)`), `rapidtriage/cli/parser.py`(`--output` 기본값 약 60곳을 지연 해석 표식으로), 〔정정〕 `rapidtriage/artifacts/mobile/vendor.py`(`:345` 제안 경로 문자열만 `[확인: 수집 로직 불변, 문자열만]`), `tests/test_cli_output_guard.py` | — | 4 | 증거 폴더(또는 그 하위)가 cwd이고 `--output`이 없으면 종료 코드 2 + `CLI_OUTPUT_INSIDE_EVIDENCE` 문장(기존 `core/output_guard.py` 재사용), 증거 밖 cwd에서는 현행 기본 파일명 그대로(호환). 대표 12명령(QA-004 목록) 단위 테스트 + 전 명령 매개변수화 테스트(파서에서 `--output` 가진 명령 전수) | GAP-002·006 / IS-068 | QA-004 |
| T-129 | 증거 해시 표시 정직화(승인 전, 표시 계층) `[확인: 메시지 문구만, 상태값·스키마·해시 계산 불변]` | `frontend/src/features/dashboard/caseCards.tsx`(해시 상태 라벨·색 맵 `:55-75`만 — T-144가 끝난 뒤), `frontend/src/features/case/EvidenceFields.tsx`(기대 해시 라벨 `:154`), `rapidtriage/api/app/case_workspace.py`(`_hash_worker` 메시지 `:257-262`만) | T-144 | 3 | E01·Ex01 증거에서 상태가 `mismatched`일 때 화면은 빨강 "해시 불일치"가 아니라 호박 "컨테이너 해시가 입력값과 다름 — 매체 해시 미대조" + 설명 "E01 파일 자체의 해시입니다. 취득 로그의 매체(디스크) 해시와는 값이 다른 것이 정상입니다". `matched`는 "컨테이너 해시 일치", `computed`는 "컨테이너 해시 계산됨". 입력 라벨: "기대 해시(선택 · E01 **파일 자체**의 MD5/SHA-1/SHA-256 — 취득 로그의 매체 해시 아님)". 단일 파일(dd·raw) 증거는 현행 문구 유지 | GAP-191·007·008 / IS-069·003 | QA-106 |
| T-131 | 케이스 DB 동시 쓰기(두 창) `[확인: PRAGMA·재시도만, 스키마 불변]` | `rapidtriage/core/case_db/database.py`(연결 설정 `:270-282`에 `busy_timeout`, 쓰기 재시도), `frontend/src/features/grid/reviewMap.ts`(다른 창의 변경 감지 시 알림 — T-036 뒤) | T-029·T-036 | 4 | `PRAGMA busy_timeout=5000`, `database is locked`는 3회 지수 재시도 뒤에만 오류. 창 2개가 같은 100행에 교차 표시(QA-012): 유실 0, 이력 200건, 마지막 쓰기가 현재 값. 다른 창이 바꾼 행은 다음 조회에서 "다른 창에서 변경됨" 토스트 1회(같은 종류 합침) | GAP-017·205 / IS-076 | QA-012 |
| T-132 | 산출물·감사 시각에 시간대 포함(35곳) `[확인: 시각 문자열 형식만, 로직 불변]` | 신규 `rapidtriage/core/clock.py`(`now_local_iso()` = 오프셋 포함 ISO), `datetime.now().isoformat()` 호출 35곳(`grep -rn "datetime.now()" rapidtriage`로 전수; `core/audit.py`는 T-029 소유라 제외) | T-029 | 3 | `grep -rn "datetime.now()" rapidtriage` 결과 0(전부 `now_local_iso()` 또는 `datetime.now(timezone.utc)`), 산출 JSON의 `generated_at`이 정규식 `[+-]\d\d:\d\d$\|Z$`에 전부 일치, 서버 시간대를 UTC·뉴욕으로 바꿔 만든 보고서의 표시 시각이 같은 순간을 가리킴. 시각을 **읽는** 쪽(오프셋 없는 옛 산출물)은 계속 읽힘(호환 테스트) | GAP-015·177·196 / IS-071·049 | QA-109 |
| T-133 | 읽기 전용 결과: 색인·캐시 지연 쓰기 차단 | `rapidtriage/api/app/timeline_index.py`(`:886,1023`), `geo_index.py`(`:470`), `families.py`(`:592`), `fs_tree.py`, `files_ntfs.py`, `registry_tree.py`, `artifact_sort.py`, `timeline_hist.py`, `files_index.py` | T-032 | 4 | 위 9파일의 디스크 쓰기 지점 전부가 `may_persist(output_dir)`를 거친다(쓰기 호출 직접 사용 0 — 테스트가 AST로 검사). 읽기 전용 처리에서 타임라인·지도·계열·폴더 탐색기·레지스트리 탐색기·정렬을 연 뒤 결과 폴더 스냅샷 동일, 기능은 메모리로 동작 | GAP-192·003·175 / IS-068 | QA-005·108 |
| T-134 | 읽기 전용 결과: 그 밖의 지연 쓰기 차단 | `rapidtriage/api/app/media_similar.py`, `media.py`, `sqlite.py`, `previews.py`(`write_json_file` `:21`), `triage_flags.py`, `row_conditions.py`, `search_index_service.py`(검색 이력·색인 생성 거부) | T-032 | 4 | 위 7파일 동일 규칙. 읽기 전용 처리에서 미디어 유사·SQLite 미리보기(WAL 임시 복사는 OS 임시 폴더)·특이사항·조건·검색을 쓴 뒤 스냅샷 동일. 색인이 없으면 "읽기 전용 결과라 색인을 만들 수 없습니다 — 결과 폴더를 증거 밖으로 옮긴 뒤 다시 가져오세요" | GAP-192·003·175 / IS-068 | QA-005·108 |

> T-129는 `caseCards.tsx`를 T-144(W1-d)와 나눠 쓴다(블록이 다르고 묶음이 달라 충돌 없음).

### W1-f 〔2차 신규 묶음〕 (1)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-130 | 〔T-035에서 분리〕 4xx 재시도 금지·유휴 폴링·숨은 탭 | `frontend/src/main.tsx`(`:33-38` retry), `frontend/src/api/runsProgress.ts`(`IDLE_POLL_MS` `:58`), `frontend/src/features/analysis/store.ts`(`:83` `refetchIntervalInBackground`) | T-008 | 2 | 4xx(400~499)는 재시도 0(408·429 제외), 5xx·네트워크만 2회. 유휴 폴링 5 s → 30 s, 문서가 숨겨지면(`visibilitychange`) 0. 유휴 5분 요청 수 ≤ 10, 숨은 탭 5분 0 | GAP-066 / IS-082 | QA-101 |

### W2 실데이터 기준선(QA 담당 Sonnet, 코드 변경 없음)

| ID | 제목 | 산출물(Git 밖 `D:\rapid-qa\derived\r8\w2\`) | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-037 | C1 재처리와 수정분 브라우저 재확인(AD1·2·4·5, 출력 가드, 가져오기) | 스크린샷·events.jsonl·요약 md | W1 | 4 | QA-002·003·037·086 통과 기록, 증거 전/후 동일 | GAP-001·052·179 / IS-125 | QA-001~003·037·086·087 |
| T-038 | C2 100% 재처리 **[D24]** 〔2차: 사전 조건 수치〕 | 처리 로그·추출 통계·시간·출력 크기 | W1, 사전 조건: 출력 볼륨 여유 ≥ 500 GB(예상 출력 약 230 GB + 임시 약 2배; 11-11 실측 여유 453 GB → **D40 정리 또는 다른 볼륨 지정이 먼저**), `RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES=2000000` | 4(+무인 7~9: 31%에 143분 실측을 파일 수 비례로 환산) | 추출 범위 ≥99%(`stats.truncated == 0`), 원본 불변, 단계별 시간·메모리 표. 조건 미충족이면 중간안 C2-60(상한 40만, 여유 ≥ 300 GB)으로 내리고 사유 기록 — 부록 E.7 | GAP-046·026(측정)·202 / IS-122 | QA-001·017 |
| T-039 | C2 전수 순회 재실행(건수 계약·타이밍·원시값) | `tree-sweep.json`·`timing.json`·`cells.json` | T-038(없으면 C2-31) | 4 | 부록 E의 QA-020·021·044·045·100을 현 화면 기준선으로 기록(실패 목록이 W3~W7의 입력) | GAP-032·059·089·090·053·054·055·180·181 | QA-020·021·044·045·100·054·055 |
| T-040 | C4 AI 스캔 런과 콘솔 확인(앱 종료 뒤 전/후 해시) | 건수표·스크린샷 | — | 4 | 13노드 순회, CLI 건수 = 콘솔 건수, 원본 불변 확정 | GAP-048·022 / IS-055 | QA-015·072 |
| T-041 | C3 구축 **[D32]** 〔2차: 주 경로를 VM 시나리오로, 기준선 재처리는 선택〕 | 구축 절차 md(식별자 없음), 시나리오 스크립트(가짜 계정), 건수표 | D32. (선택) D24 | 4(+무인 2~3) | **주 경로 C3-VM**: 일회용 Windows VM(디스크 60 GB 이하)에서 시나리오 12단계(USB 연결·파일 복사·웹메일 업로드·압축·삭제·메신저 설치/대화·브라우저 방문/다운로드·클라우드 동기화·LNK·공개 메일 표본 MBOX 배치·복원 지점·로그 삭제 없음) → E01 취득 → 상한 해제 처리. 수용: 메신저·이메일·USB·브라우저 방문·다운로드·클라우드·LNK 7종 각각 행 ≥ 10. **선택 C3-R**(기준선 일반 모드 재처리)은 실측 28시간·120만 파일이라 기본으로 하지 않는다 — 대신 T-138(C3-0) | GAP-049·056·050·202 / IS-122 | QA-047·043 |
| T-042 | 미실행 분석 실행: OCR·VSS·NTFS 메타(TSK 설치)·교차 사건·메모리 | 분석별 결과·오류 | T-038·T-041 | 4 | 각 분석 "성공/부분/실패+사유" 기록, 실패는 GAP 추가. 증거 추가·재처리 뒤 파생 결과가 오래됐음을 화면이 말하는지 기록(GAP-199) | GAP-047·199 / IS-123 | QA-024·088 |
| T-043 | C5 A등급 양성 데이터 **[D32]** | 규칙별 양성 표 | D32 | 4 | 7규칙 중 양성 확보 수, 미확보는 "검증 전" 대상 | GAP-044 / IS-124 | QA-032 |
| T-044 | 기준선 종합과 재계획 입력(Fable) `RV` | `docs/research/r8-w2-baseline.md`(건수만) | T-037~043·T-138 | 3 | coverage-matrix 갱신, 새 결함을 **GAP-209 이후**로 등록(191~208은 2차 리뷰가 사용), W3~W8 과제 조정안, 부록 E.7의 "미검증으로 남는 QA" 목록 확정 | GAP-058·162·173·203 / IS-121·123 | QA-105 |
| T-138 | 〔2차 신규〕 C3-0: 기존 R8 기준선 산출물을 콘솔에 가져오기(재처리 없음, 승인 불필요) | 가져오기 기록·건수표·스크린샷 | T-031·T-032(결과 폴더가 증거 안이면 읽기 전용으로 열림) | 3 | 기준선 결과 폴더를 QA 서버에 가져오기 → 대화 보기 메시지 수 = CLI 산출 1,044, 장치 5대, 계정·클라우드 행 > 0. 처리 중 쓰기가 필요한 화면(색인 생성 등)은 "읽기 전용" 사유 표시. 복구 모드라 브라우저·실행 흔적 0 → 0건 사유 `not_collected_mode` 화면의 실데이터 표본으로 쓴다 | GAP-049·202·203 / IS-122·123 | QA-112·047 |

### W3-a 백엔드: 브리핑·분류 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-045 | 카탈로그 분류 키와 검증기 | `rapidtriage/core/triage_rules/catalog/*.yaml`(키 추가만), `catalog/type_defaults.yaml`(신규), `rapidtriage/core/triage_rules/catalog.py`, 검증 테스트 | — | 4 | 131계열 + IMG-B·기준선 유형 전부 `tier`·`card`·`section` 해석, 누락은 오류, 기존 화면 동작 변화 0 | GAP-087 / IS-019 | QA-020 |
| T-046 | `/brief` 엔드포인트(골격·건수·통합) | `rapidtriage/api/app/brief.py`(신규), `rapidtriage/api/app/routes_brief.py`(신규), 라우터 등록은 코디네이터(F.1 화면 장착 규칙), `tests/test_brief_count_contract.py` | T-021·T-023·T-025·T-045·T-047·T-048(F.6: W3-a 2단계) | 4 | 부록 D.6 스키마, 30 KB·200 ms(IMG-B), 카드·검토·특이사항 수 = 목록 total(계약 테스트) | GAP-071·144·034 / IS-001·005·111 | QA-033·103·029 |
| T-047 | 0건 사유 판정기 | `rapidtriage/api/app/zero_reason.py`(신규), 테스트 | T-045 | 4 | 8코드 판정 규칙(수집기 상태·모드·범위·대상 존재) 단위 테스트 24종, `none_found`는 완료+대상 읽음일 때만 | GAP-038·169·037·158 / IS-006·089 | QA-023 |
| T-048 | 사용 기간·주요 프로그램·다음 할 일 산정 | `rapidtriage/api/app/brief_insights.py`(신규), 테스트 | T-045 | 4 | Tier 1 사용자 행위만으로 기간 산정, 폴더 증거는 `unavailable`, 프로그램 상위 3은 OS 구성 요소 제외, `next_action` 규칙 5종 | GAP-171 / IS-001 | QA-033 |
| T-049 | `/summary`·`/runs/{id}` 다이어트, 압축·ETag | `rapidtriage/api/app/routes_runs.py`(summary·run 상세만), `rapidtriage/api/app/factory.py`(gzip) | T-007 | 4 | `?fields=`·ETag·304, 1 KB 초과 응답 gzip, 런 상세 ≤100 KB, 스냅샷 호환 | GAP-062·063 / IS-079 | QA-101 |
| T-050 | `CLI brief --json` | `rapidtriage/cli/brief.py`(신규), `rapidtriage/cli/parser.py`(등록 블록만) | T-046 | 2 | 봉투·종료 코드, `/brief`와 같은 값 | GAP-144 / IS-111 | QA-103 |

### W3-b 백엔드: 성능·필터 (병렬 5)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-051 | 유형 색인(artifact_type → 오프셋)과 캐시 | `rapidtriage/api/app/artifact_type_index.py`(신규), `rapidtriage/api/app/artifact_filter.py`(색인 사용 분기) | T-019 | 4 | 레지스트리 유형 필터 ≤1 s(IMG-B), total 확정, 색인은 결과 폴더(읽기 전용이면 메모리), 결과 행 동일(전/후 비교) | GAP-059·061 / IS-078 | QA-100 |
| T-052 | 검색 `lang:`·`list:`·부정 조건 구동·예산 고지 | `rapidtriage/core/search_index/engine.py`, `rapidtriage/api/app/routes_search_index.py`, 테스트 | — | 4 | `-lang:ko 계약`·`list:execution` ≤3 s(IMG-B), 후처리도 예산 안, 초과 시 `notice` | GAP-060·108·163 / IS-032 | QA-058·059 |
| T-053 | 파일 목록 서버 필터(확장자 등)·정렬 키 검증 | `rapidtriage/api/app/files_index.py`, `frontend/src/features/filters/filterModel.ts` | — | 4 | `ext=` 서버 처리, 건수 = 전수 집계, 무효 `sort` 422(봉투), "불러온 행에서만" 경로 제거 | GAP-043 / IS-028 | QA-027 |
| T-054 | 백그라운드 작업 틀(202·진행·취소) | `rapidtriage/api/app/bg_jobs.py`(신규), `rapidtriage/api/app/routes_bg_jobs.py`(신규), 테스트 | — | 4 | 등록·진행률·취소·직전 결과 반환 계약, 프로세스 재시작 시 "중단됨" | GAP-065·070 / IS-081 | QA-102 |
| T-055 | 계열·중복·예외·케이스 DB 준비·추출 zip을 작업으로 | `rapidtriage/api/app/routes_families.py`(`:218-245` dedup·irregular summary, `:113`·`:184` 계열), `rapidtriage/api/app/routes_case_db.py`(ensure만), `rapidtriage/api/app/routes_runs.py`(extract만) | T-054(F.6: W3-b 2단계) | 4 | 요청 응답 ≤1 s, 직전 결과 + "다시 계산 중" | GAP-065 / IS-081 | QA-102 |
| T-056 | 개체 요약 상한·진행·오류 | `rapidtriage/api/app/routes_search_index.py`(entities는 T-052와 충돌 → **W3-c로 이동**) | — | — | (아래 T-060으로 대체) | — | — |

> T-056은 파일 충돌로 폐기 번호다(번호 재사용 금지). 묶음 W3-b는 5개로 진행한다.

### W3-c 백엔드: 읽는 단위·정직성 (병렬 4)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-057 | 문서 단위 검색 응답 | `rapidtriage/api/app/search_documents.py`(신규), `rapidtriage/api/app/routes_search_index.py`(등록·호출) | T-052 | 4 | 한 파일 = 한 그룹(적중 수·위치·관련 행), 스니펫 ≥40자·가림, 숨긴 Tier 3 적중 수 | GAP-103·106 / IS-031·033·035 | QA-057·031 |
| T-058 | 사람·장치 롤업 파생 표 | `rapidtriage/core/derived/tables_people_devices.py`(신규), `rapidtriage/core/derived/engine.py`(등록만) `[확인: 파생 표는 수집기 불변]` | T-045 | 4 | 계정 묶음(시스템 숨김 규칙)·장치 병합(시리얼 키) 표, 기준선에서 장치 5대 = 5줄 | GAP-088·161 / IS-030 | QA-043 |
| T-059 | 확장자 위장 잡음 분리(표시 계층)·복구본 내용 상태(미리보기) | `rapidtriage/api/app/tree.py`(예외·불일치 집계), `rapidtriage/api/app/previews.py`, `rapidtriage/api/app/irregular_view.py`(신규) | T-045 | 4 | `_deleted_mft` 유래·0 채움·고엔트로피를 "내용 복구 불가"로 분리 집계, 미리보기 응답에 `content_state`, 수집기 출력 불변(D33 기본값) | GAP-040·041·176 / IS-022·023 | QA-025·026 |
| T-060 | 개체 요약 작업화·검색 색인 분석 건수 | `rapidtriage/api/app/entity_summary.py`(신규), `rapidtriage/api/app/analysis_kinds.py`(`run_search_index` `:2458-2494`의 건수 기록만), `rapidtriage/api/app/routes_search_index.py`(`POST …/search/entities` 처리기만 — T-057이 끝난 뒤, F.6: W3-c 2단계) | T-054·T-057 | 3 | 개체 요약 202+진행, IMG-B에서 성공, 색인 분석이 문서 수를 건수로 표시 | GAP-051·035 / IS-037·089 | QA-061 |

### W4-a 디자인 시스템 1 (병렬 6, W3와 동시 가능)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-061 | 토큰 v3(글자 7단·간격·색 역할 4계열·테마 system) | `frontend/src/tokens/tokens.css`, `frontend/src/state/slices/prefs.ts`(`systemTheme` `:48-60,92`), 〔2차: `themeBoot.ts`는 없다〕 `frontend/index.html`(`:14` 부근 인라인 테마 부트 스크립트), `frontend/src/app/themeBoot.test.ts`(부트 스크립트를 읽는 기존 테스트 — 기대값 갱신) | T-002(F.6: W4-a 1단계 단독) | 4 | 새 토큰은 추가(옛 토큰은 별칭), OS 테마 추종 + 리스너, 대비 검사 통과, `tnum` 실측 결과 기록 | GAP-135·136·138 / IS-105·106·108 | QA-093·097 |
| T-062 | `Chip`·`CountBadge` | `frontend/src/components/ui/Chip.tsx`·`CountBadge.tsx`·css·테스트(신규 폴더) | T-061 | 4 | 6종 kind, 색+모양+글자, 줄임 규칙·접근성 이름 | GAP-137 / IS-107 | QA-095·098 |
| T-063 | `EmptyState`·`InlineAlert`·`Skeleton`·`PartialBanner`·`HiddenBanner` | `frontend/src/components/ui/feedback/*`(신규) | T-061 | 4 | 빈 상태 5유형·알림 4종, 오류 틀(무슨 일/영향/할 일/기술 정보), 카드·패널 단위 오류 경계 `SectionBoundary` | GAP-127·128 / IS-092 | QA-084·085 |
| T-064 | `Dialog`(포커스 규칙·위험·폭 3종) | `frontend/src/components/ui/Dialog.tsx`(신규)·테스트 | T-061 | 4 | 트랩·기본 포커스·복귀, 단계 전환에도 위치 고정 | GAP-137·129 / IS-094·107 | QA-086 |
| T-065 | `Button`·`Checkbox`·`Radio`·`Switch`·`Tabs` | `frontend/src/components/ui/controls/*`(신규) | T-061 | 4 | 4변형, 점선 0, 타깃 ≥28, 부모 선택자에 덮이지 않음 | GAP-137·133·139 / IS-107·109 | QA-093·095 |
| T-066 | `TimeText`·`HashValue`·`PathText`·`CopyButton` | `frontend/src/components/ui/values/*`(신규), `frontend/src/utils/time.ts`(단일 포맷터 정리) | T-061 | 4 | 표시 시간대 한 형식 + UTC title + 사본 시각 표식, 중복 `formatDuration` 제거 | GAP-116 / IS-049 | QA-071 |

### W4-b 디자인 시스템 2 (병렬 4)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-067 | `Menu` 단일화(행·뷰어·카드) | `frontend/src/components/ui/Menu.tsx`(신규), `frontend/src/components/MenuButton.tsx`(위임) | T-014 | 4 | 세 메뉴가 한 구현, 타입어헤드, 항목 ≥24px | GAP-137 / IS-107 | QA-049 |
| T-068 | `PageHeader`·`StatRow`·`ZeroReason`·`Disclosure`·`EvidenceStrip` | `frontend/src/components/ui/page/*`(신규) | T-062·T-063 | 4 | 숫자=링크+`data-count`, 무결성 4상태 표현 | IS-003·005·017 | QA-033 |
| T-069 | 전역 링크·입력·포커스 스타일 | `frontend/src/tokens/controls.css`, `frontend/src/tokens/base.css`(신규; `frontend/src/main.tsx`의 import 1줄 포함) | T-061 | 3 | 방문 색 없음, 라이트 입력 회색 채움 0, 포커스 링 통일 | GAP-133·134·099 / IS-101 | QA-093 |
| T-070 | 인쇄 스타일·화면 복사용 보기 | `frontend/src/tokens/print.css`(신규) | T-061 | 2 | 인쇄 시 패널·도구 막대 숨김, 본문 전폭 | GAP-124·189 / IS-108 | QA-082·117 |

### W5-a 셸·브리핑 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-071 | 주소 추가·구 주소 변환(`home`·`tools/*`·`review/set|one`·`report/preview`) | `frontend/src/router.ts`(`parseHash` `:334`, `serializeRoute` `:492`, `canonicalizeHash` `:611`), 〔2차: 경로 정정〕 `frontend/src/features/stages/stages.ts`, 계약 테스트 갱신 | T-001 | 4 | 부록 D.1 표 전부 왕복, 쿼리 키 불변 | GAP-172 / IS-015 | QA-041 |
| T-072 | 전역 내비 4·⚙ 메뉴·상태바·역할 모드 | 〔2차: 경로 정정〕 `frontend/src/features/stages/StageRail.tsx`, `frontend/src/shell/TopBar.tsx`, `frontend/src/shell/StatusBar.tsx`, `frontend/src/state/slices/role.ts`(신규), `frontend/src/state/store.ts`(slice 등록) | T-061·T-067 | 4 | 4항목 + ⚙, 모드 기억, 상태바에 처리 ID 없음, 상태바 연결 표시(끊기면 5 s 안에 "연결이 끊겼습니다" 띠, 복구되면 새로고침 없이 자동 복구 — QA-089), 기존 e2e는 분석 담당 모드로 통과 | GAP-080·086·072·170 / IS-011·018·097 | QA-040·035·089 |
| T-073 | 사건 브리핑 화면 | `frontend/src/features/brief/*`(신규), `frontend/src/api/brief.ts`(신규), `frontend/src/app/IntakePane.tsx`(홈 분기 — 이 묶음에서 이 파일의 유일한 주인) | T-046·T-068 | 4 | 부록 C (2) 와이어, 1440×900 스크롤 0, 6문항 DOM, 상태 5종 | GAP-071·074 / IS-001~006 | QA-033·017·023·117 |
| T-074 | 랜딩·토큰 화면 | `frontend/src/features/case/Landing.tsx`, `frontend/src/app/TokenGate.tsx` | T-065 | 3 | 주 동작 2 + 최근 사건 + 준비물, 토큰 안내 문장 | GAP-075·186 / IS-007 | QA-037·118 |
| T-075 | 처리 진행 띠·처리 중 409 제거 | `frontend/src/shell/ProgressStrip.tsx`(신규), `frontend/src/api/runPlan.ts`, `frontend/src/shell/Layout.tsx`(띠 삽입만) | T-022 | 4 | 한국어 단계·n/m·경과, 409 0, 중지는 실행 중만 | GAP-077·066·184 / IS-009 | QA-039·090 |
| T-076 | 다중 증거·케이스 미연결 홈 | `frontend/src/features/brief/EvidenceSwitcher.tsx`·`AllEvidenceTable.tsx`(신규, T-073 폴더와 파일 분리) | T-073(인터페이스 합의) | 3 | 증거 전환·비교 표·"사건에 연결" 머리줄 | GAP-079 / IS-010 | QA-036 |

### W5-b 내비·접수 흐름 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-077 | 살펴보기 범주 내비(검토자 모드) | `frontend/src/features/nav/CategoryNav.tsx`(신규), `frontend/src/features/tree/useTreeModel.ts`(카탈로그 분류 사용) | T-045·T-062·T-072 | 4 | 기본 ≤12, 0건=사유, 숨김 건수, 분석 담당 모드는 기존 트리 | GAP-080·081·083·084 / IS-012·013 | QA-040·020·042 |
| T-078 | 분류 사본 제거(`categories.ts` 폐기, `domains.ts` 생성화) | `frontend/src/features/tree/domains.ts`, 〔2차: 경로 정정〕 `frontend/src/features/tree/categories.ts`, `scripts/gen-domains.py`(신규), `rapidtriage/core/artifact_domains.py`(생성물 `[확인: 표시용 분류표, 수집 불변]`) | T-045 | 4 | 생성 스크립트 + 동기화 테스트, 노드 id 불변(계약) | GAP-087 / IS-019 | QA-041 |
| T-079 | 새 사건 2단계·경로 사전 검사·폴더 선택기·여유 공간 | `frontend/src/features/case/CaseWizard.tsx`, 〔2차: 새 `PathPicker`를 만들지 않는다〕 기존 `frontend/src/features/case/BrowsePanel.tsx`·`EvidenceFields.tsx`(선택기를 필드 옆 "고르기" 버튼으로 승격, 결과 폴더에도 적용), `rapidtriage/api/app/routes_cases.py`(output-check 응답에 `free_bytes`·`estimated_bytes` 추가) | T-064·T-065 | 4 | 입력 ≤5, 고아 0, 필드 옆 오류, 모달 위치 고정 | GAP-076·183·141 / IS-008·095 | QA-037·038 |
| T-080 | 새 처리 대화상자(입력 5 + 세부 설정) | `frontend/src/features/case/RunDialog.tsx`, `frontend/src/features/case/RunPlanGroupsField.tsx` | T-064 | 4 | 처리 깊이 3·프리셋·세부 설정 접힘, `ai_read_mb`·`org_email_domain` 입력, 프로필 한국어명 | GAP-076·190 / IS-008 | QA-037 |
| T-081 | ⚙ 처리 이력·더 분석하기·작업 센터 | `frontend/src/features/stages/ProcessStage.tsx`, `frontend/src/features/stages/RunPlanTable.tsx`, `frontend/src/features/jobs/JobCenter.tsx`(신규), `frontend/src/shell/TopBar.tsx`(작업 센터 아이콘 1개 — T-072 뒤) | T-054·T-062·T-072 | 4 | 상태 6종 글자+모양, X 제거(글자 "중지"), 분석 목록형(미실행/부분/실패 사유), 작업 진행·취소, 증거 추가·재처리 뒤 오래된 파생 결과(계열·중복·통합 보기·검색 색인)에 "다시 계산 필요" 표시(서버 stale 판정 사용), 예외 항목 표는 `StatRow`(합계와 내역 분리) | GAP-077·078·036·020·199·201 / IS-070·081·089 | QA-016·024·102 |
| T-082 | 설정 화면 | `frontend/src/features/settings/*`(신규) | T-061·T-065 | 3 | 표시·검토·처리 기본값·보안·고급 5절 | GAP-155 / IS-108 | QA-097 |

### W6-a 목록·뷰어 1 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-083 | DataGrid 분해(동작 불변) | `frontend/src/features/grid/DataGrid.tsx` → `GridBody`·`GridHeader`·`GridFooter`·`useGridKeyboard` | T-020 | 4 | 기존 grid vitest 341건·e2e 통과, 파일 ≤600줄 | GAP-150·143·132 / IS-117 | QA-104·099 |
| T-084 | 카드별 열 정의(6열)·그리드 값 라벨 단일 출처 〔2차: 나머지 라벨 맵 4곳은 T-139로 분리 — 4 h 초과〕 | 카탈로그 `card_columns`·`value_labels`(YAML 블록), `frontend/src/features/grid/columns/*`(생성물 사용), `frontend/src/features/grid/valueLabels.ts`(생성물), `scripts/gen-labels.py`(신규) | T-045 | 4 | 하위 탭마다 ≤6열, 그리드 값 라벨이 생성물(손 편집 금지 머리말 + 동기화 테스트), 원시 슬러그 요약 0(`artifactSummary.ts:123-124` 포함) | GAP-089·090 / IS-020·021 | QA-044·045 |
| T-085 | 뷰어 머리·판단 버튼 줄·메모 영역 | `frontend/src/features/viewer/ViewerToolbar.tsx`, `frontend/src/features/viewer/viewer.css` | T-065·T-067 | 4 | 판단 버튼 3 + 보고서 포함 토글(P), 메모가 머리를 밀지 않음, 반영 ≤200 ms(낙관적) | GAP-096·069 / IS-039·046 | QA-064 |
| T-086 | 뷰어 탭(가능한 것만)·보류 사유·이진 안내 | `frontend/src/features/viewer/modes.ts`, `frontend/src/features/viewer/ModeTabs.tsx`, `frontend/src/api/viewer.ts`, `frontend/src/features/viewer/views/SourceView.tsx` | T-059·T-063 | 4 | 평균 탭 ≤4, `withheld`·`content_state` 문장, 원본 가림 + 해제 감사, 탭 전환 ≤ 500 ms(이미 받은 탭은 재요청 없음) | GAP-092·093·019·206 / IS-024·053 | QA-046·014 |
| T-087 | 메타 12필드·출처 구역 | `frontend/src/features/viewer/views/MetaView.tsx` → `MetaSummary`·`MetaTech`·`ProvenancePanel` | T-066·T-084 | 4 | 첫 화면 ≤12, 출처 고정, 영문 키 0 | GAP-094 / IS-025 | QA-048 |
| T-088 | 트리 단일 구현 | `frontend/src/components/ui/Tree.tsx`(신규), `frontend/src/features/explorers/ExplorerTree.tsx`(위임) | T-015 | 4 | 탐색기 트리가 공용 구현 사용, 동작 불변 | GAP-137 / IS-107 | QA-052 |

### W6-b 목록·뷰어 2 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-089 | 목록 머리(제목·설명·건수 1회)·숨김 띠·보기 메뉴 | `frontend/src/features/grid/GridToolbar.tsx`, `frontend/src/app/ViewSwitch.tsx` | T-063·T-083 | 4 | h1 + 건수 한 번, "n건 숨김", `보기: 표 ▾` | GAP-085·045·097 / IS-017·027·072 | QA-031·051·054 |
| T-090 | 행·뷰어 메뉴 8 + 더 보기, 일괄 막대 | `frontend/src/features/grid/RowMenu.tsx`, `frontend/src/features/grid/BatchBar.tsx`, `frontend/src/features/grid/gridCommands.ts` | T-067 | 4 | 두 메뉴 동일 목록, 비활성 미노출, 막대가 행을 가리지 않음, 라벨 정본 import | GAP-095·101·109 / IS-026·044·039 | QA-049·064 |
| T-091 | 조건 띠(칩 5)·날짜 입력 | `frontend/src/features/filters/FilterBar.tsx` → `ChipFilterBar`·`ConditionDrawer` | T-065 | 4 | 그리드를 덮지 않음, 칩 5 + 더 보기, 파일 ≤600줄 | GAP-100 / IS-034 | QA-044 |
| T-092 | 복구본 표식·기본 정렬·폴더 트리 가상 위치 | `frontend/src/features/grid/columns/files.ts`, `frontend/src/features/explorers/FsExplorer.tsx` | T-059 | 3 | 복구본 칩, 기본 정렬 첫 화면 복구본 0, "복구된 항목(가상)" | GAP-042 / IS-023 | QA-026 |
| T-139 | 〔2차 신규〕 라벨 맵 단일 출처 — 나머지 4곳(`metaLabels`·`stepLabels`·`fieldSheets`·유형 라벨) | `frontend/src/features/viewer/metaLabels.ts`, `frontend/src/features/stages/stepLabels.ts`, `frontend/src/features/grid/columns/fieldSheets.ts`, 유형 라벨 맵(착수 때 `grep -rl typeLabels frontend/src`로 위치 확정), `scripts/gen-labels.py`(T-084 뒤 확장) | T-084 | 4 | 네 맵이 카탈로그 생성물(동기화 테스트 4개), 기존 라벨 문자열 diff 0(생성 전/후 스냅샷 동일 — 문구 변경은 이 과제에서 하지 않는다), 영문 원어 잔존 목록(GAP-091)만 한국어 병기로 교체 | GAP-154·091 / IS-021·096 | QA-045 |
| T-143 | 〔2차 신규〕 그리드 페이지 윈도 상한(메모리 고정) | `frontend/src/features/grid/useCollectionQuery.ts`(`:428-432` 페이지 집합이 늘기만 함) | T-083 | 3 | 보이는 범위 ± 4페이지만 유지(나머지 페이지는 해제 후 재요청), 54만 행 끝까지 스크롤에서 JS 힙 ≤ 1.5 GB·스크롤 p95 ≤ 100 ms, 선택·검토 표시 상태는 페이지 해제와 무관하게 유지 | GAP-067 / IS-083 | QA-056 |

### W7-a 검색·검토 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-093 | 문서 단위 검색 화면 | `frontend/src/features/search/*`(신규), `frontend/src/api/search.ts` | T-057·T-063 | 4 | 한 파일 한 행·펼침, 전부 색인 경로, "전문가 항목에 n건" | GAP-103·104 / IS-031·032·035 | QA-057·058 |
| T-094 | 검색 옵션·도움말 예시 | `frontend/src/features/case/SearchOptionsPopover.tsx`, `frontend/src/shell/SearchHelp.tsx`(신규) | T-065 | 3 | 범위 칩 3 + 접힘, 예시 5 | GAP-105·106 / IS-034·036 | QA-060·063 |
| T-095 | 개체 패널 | `frontend/src/features/case/EntityPanel.tsx`, `frontend/src/api/searchEntities.ts` | T-060·T-063 | 3 | 진행률·성공, 오류 봉투 | GAP-051 / IS-037 | QA-061 |
| T-096 | 검토 묶음 v1(저장 검색 기반) | `frontend/src/features/review/sets/*`(신규), `frontend/src/api/caseDb.ts` | T-093 | 4 | 묶음 생성·진행률·다음 미검토, 스키마 불변 | GAP-111 / IS-040 | QA-066 |
| T-097 | 한 건 보기 | `frontend/src/features/review/one/*`(신규) | T-085·T-096 | 4 | 50건 키보드만·건당 ≤2조작, 모순 경고 | GAP-111·112 / IS-041·045 | QA-066·068·119 |
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

### W7-c 보강 〔2차 신규 묶음〕 (병렬 3)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-135 | "검증 전" 규칙 표시(팝오버 밖) | `frontend/src/features/flags/FlagCell.tsx`(칩), `frontend/src/features/flags/flags.ts`·`catalog.ts`(규칙 상태 조회), `rapidtriage/core/case_report.py`는 건드리지 않는다(보고서 표기는 T-109) | T-062·T-077 | 3 | `status: provisional` 규칙(현재 55) 또는 실데이터 참양성 기록이 없는 A등급 규칙(T-043 결과표 기준)의 칩 옆에 `검증 전` 보조 글자(색·점선 없음), 내비 "먼저 확인할 것" 건수는 `검증됨 n · 검증 전 m`으로 나눠 표기, 브리핑은 `findings.top[].validated=false` 항목에 같은 글자. A등급 "즉시 확인" 문구는 검증된 규칙에만 | GAP-197·044 / IS-124 | QA-110·032 |
| T-136 | 질문형 진입점 8개(D41) | `rapidtriage/core/triage_rules/catalog/questions.yaml`(신규: 질문 → 범주·조건·열, 이 묶음에서 카탈로그의 유일한 주인), `frontend/src/features/nav/QuestionEntry.tsx`(신규), `rapidtriage/api/app/brief.py`(`questions[]` 추가 — T-104 뒤) | T-077·T-104 | 4 | v1 4.5의 8문항(예: "무엇을 가지고 나갔나"·"무엇을 지웠나"·"누구와 연락했나"·"어떤 문서를 열었나"·"어떤 프로그램을 썼나"·"언제 PC를 썼나"·"어디에 접속했나"·"AI 도구를 썼나") 각각이 조건이 걸린 목록 주소를 연다(주소 공유 가능, 쿼리 키는 부록 D.1 기존 키만). 0건이면 0건 사유. 살펴보기 내비 상단 "질문으로 찾기 ▾" 메뉴(브리핑 본문에는 넣지 않는다 — 스크롤 0 유지) | GAP-198 / IS-012·013 | QA-113 |
| T-137 | 단축키 끄기 스위치·범례 | `frontend/src/shortcuts.ts`(전역 가드 1곳 — T-035 뒤), `frontend/src/shell/HelpOverlay.tsx`(범례 인쇄 보기), `frontend/src/features/settings/ShortcutsSection.tsx`(신규) | T-035·T-082 | 2 | 설정 "글자 키 단축키 사용" 끄면 R·I·X·B·P·J·K·1~9 발화 0(`Ctrl+K`·`Esc`·`/`는 유지), 기본값 켬, 값은 `rapidtriage.v3.shortcuts`. 도움말에 "인쇄" → 한 쪽 범례 | GAP-200 / IS-099 | QA-120 |

### W8 보고서 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-105 | 보고서 미리보기 API(절 구조 JSON) | `rapidtriage/api/app/report_preview.py`(신규), `rapidtriage/api/app/routes_reports.py`(등록만) | T-027·T-030 | 4 | 미리보기 구조 = 내보낸 파일 제목 구조(테스트), 절 선택·순서·의견·범위 | GAP-120·124 / IS-056 | QA-076 |
| T-106 | 보고서 화면(구성·종이·점검) | `frontend/src/features/report/*`(신규), `frontend/src/api/reports.ts` | T-105·T-068 | 4 | 부록 C (8), 0건 빈 상태, 주 버튼 1 | GAP-120·121·123 / IS-056·057·062 | QA-075·077·080·119 |
| T-107 | 제출 전 점검 계산 | `rapidtriage/api/app/report_checks.py`(신규) | T-025·T-023 | 3 | 7항목(무결성·사건 번호·담당자·메모 없음·모순·제한·가림 수) | GAP-123·112·174 / IS-062·045 | QA-080·068 |
| T-108 | PDF 한글 글꼴 포함·줄바꿈·실제 표 | `rapidtriage/core/report_pdf.py`(신규: `case_report.py:640-700` PDF 부분 분리 — 이 묶음에서 `case_report.py`의 1단계 주인), 글꼴 자산(Pretendard 서브셋, 라이선스 OFL 고지 포함) | T-027 | 4 | `pdffonts` 출력에 `emb yes` 글꼴 1개 이상·`HYGoThic-Medium` 0, 해시 64자·경로를 복사하면 원값(줄바꿈은 글자 수가 아니라 폭 기준, 소프트 줄바꿈), 증거 표가 세로선 문자가 아닌 표 그리기 | GAP-023·122 / IS-061 | QA-079 |
| T-109 | 보고서 프로파일·머리글/바닥글·AI 절 전 템플릿·DOCX 실제 표 | `rapidtriage/core/report_profiles.py`(신규), `rapidtriage/core/case_report.py`(템플릿 데이터 `:279-283`·DOCX 생성부 — T-108이 끝난 뒤, F.6: W8 2단계) | T-027·T-108 | 4 | 3프로파일, 기밀 문구 반복, `korean-expert`·`hash-only`에 AI 절 | GAP-124 / IS-056·058 | QA-074·078·114 |
| T-110 | 내보내기 이력·파일 해시·알림 한 줄 | `frontend/src/features/case/ReportDialog.tsx`, `frontend/src/features/case/WriteConfirm.tsx` | T-029 | 3 | 이력에 해시 앞 8자·복사, 알림 한 줄 + 폴더 열기, "확인 중" 고착 0 | GAP-123·125·188 / IS-063·065 | QA-082·077 |

### W9-a AX·정리 (병렬 6)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-111 | CLI `--json` 100%·봉투·종료 코드 〔2차: 추가 방식. 예시·그룹·`--dry-run`은 T-141, `--lang ko`는 T-142로 분리 — 4 h 초과〕 | `rapidtriage/cli/helpers.py`(공용 `emit_json`·`exit_code`), `rapidtriage/cli/parser.py`(누락 12명령에 `--json`: docs·manifest·artifacts·cloud-collect·files·extract·timeline·search·case·run·run-control·web), 각 명령 출력부(`cli/web.py` 제외 — T-112 소유) | T-033·T-050 | 4 | 89명령 `--json` 스냅샷 테스트. 기존 77명령의 **최상위 키는 그대로** + `status`·`warnings`·`errors` 추가(부록 D.8 개정). `search --json` 동작. 종료 코드 0/1/2/3/4 표와 일치, 이름 불변(D16 수정안) | GAP-145·195 / IS-112 | QA-103·116 |
| T-112 | `web --read-only`·`--no-browser` 기본·로컬 토큰 | `rapidtriage/cli/web.py`(`:55-60` 토큰 출처, `:89-96` 토큰 출력, `:115-124` 브라우저), `rapidtriage/cli/parser.py`(web 하위 파서 블록만 — T-111과 블록 분리), `rapidtriage/api/app/readonly_mode.py`(신규: T-032의 미들웨어를 서버 단위로 재사용) | T-007·T-032 | 3 | 허용 목록 밖 비-GET 403, 비터미널·CI에서 브라우저 미실행(D27), 토큰은 터미널일 때만 출력 | GAP-148·178·153 / IS-115 | QA-011·116 |
| T-113 | OpenAPI 태그·설명 100% 〔2차: 빈 응답 스키마 36개는 T-140으로 분리〕 | `rapidtriage/api/app/routes_*.py`의 데코레이터 인자(`tags=`·`summary=`·`description=`)만(코디네이터가 묶음 끝 단독 수행) | W3·W8 | 4 | 165 + 신규 연산 전부 태그 1개 이상(태그 12종 이하)·한국어 요약, 설명 없는 연산 0, 스냅샷 게이트 | GAP-146 / IS-113 | QA-103 |
| T-114 | 미호출 라우트 정리 | `docs/api-surface.md`(신규: 자동화용 문서화), 죽은 8개 제거는 **T-113 뒤 단독** | T-113 | 3 | 45개 각각 "자동화용/삭제/콘솔 연결" 판정, 삭제분 스냅샷 반영 | GAP-147 / IS-114 | QA-103 |
| T-115 | 저장 키 v3 이관·누적 정리 | `frontend/src/state/storageMigration.ts`(신규), `frontend/src/features/review/BaselineHistogram.tsx` | T-061 | 3 | 1회 이관·옛 키 삭제·LRU 20, `authToken` localStorage 미사용 | GAP-153 / IS-120 | QA-104 |
| T-116 | 코드 분할(전문가 화면 지연 로드) | `frontend/vite.config.ts`, `frontend/src/app/ViewSwitch.tsx`의 import 지점, `frontend/src/app/lazyViews.ts`(신규) | T-089 | 4 | 첫 화면 JS ≤1.0 MB, 번들 예산 게이트 | GAP-064 / IS-080 | QA-101 |

### W9-b 잔여 (6: T-117 단독 선행 → T-118·T-119·T-140·T-141 병렬 → T-142)

| ID | 제목 | 파일 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-117 | 옛 컴포넌트·옛 토큰·임시 파일 삭제, 용어 lint 오류 승격 | 옛 `StatusChip`·`ToneChip`·`Badge`·`GridEmpty`·`ViewState`·`CardEmpty`·`Modal` 등, `frontend/rt-shot*.mjs`, CI 설정 | W4~W8 전부 | 4 | 옛 import 0, lint 위반 0, 600줄 초과 0 | GAP-137·150·130 / IS-107·117·096 | QA-098·104 |
| T-118 | 콘솔 S3 45건·P 계열 전수 재확인과 잔여 수정 | (Sonnet이 재확인 표 작성 → 잔여만 Opus가 파일별 소과제로) | W7 | 4 | C-xx·P1~P8 각각 "해소/잔여" 표, 잔여 0 | GAP-142·102 / IS-096·100 | QA-091·094·053 |
| T-119 | 에이전트 안내 문서·known-limitations 정합 | `docs/agent-guide.md`(신규), `docs/rapidtriage-known-limitations.md` | T-111 | 3 | 권장 순서·봉투·오류 코드·용어 대응표, AI 절 drift 3건 수정, 미검증 기능 목록 | GAP-148·119·165·185·187 / IS-115 | — |

| T-140 | 〔2차 신규〕 OpenAPI 빈 200 응답 스키마 36개 | `rapidtriage/api/app/models.py`(응답 모델 추가), `routes_*.py`의 `response_model=` 인자만 | T-113 | 4 | 빈 200 스키마 0, 응답 본문 불변(기존 API 계약 테스트 `tests/test_rapidtriage_api_contract.py` 통과 — 모델은 `extra="allow"`로 필드 누락·추가를 막지 않는다) | GAP-146 / IS-113 | QA-103 |
| T-141 | 〔2차 신규〕 CLI 예시 100%·`dev`/`qa` 도움말 그룹·쓰기 명령 `--dry-run` | `rapidtriage/cli/parser.py`(epilog·그룹), 쓰기 명령 출력부 | T-111 | 4 | 예시 없는 36명령 0, `--help` 첫 화면에 핵심 20명령 이하(검증·벤치 약 35개는 `dev`·`qa` 그룹), 쓰기 명령(파일을 만드는 명령) 전부 `--dry-run`(쓸 경로만 출력, 파일 0) | GAP-145 / IS-112·098 | QA-103 |
| T-142 | 〔2차 신규〕 CLI `--lang ko` 도움말 | `rapidtriage/cli/help_ko.py`(신규: 명령·옵션 설명 사전), `rapidtriage/cli/parser.py`(사전 적용 훅 — T-141 뒤) | T-141 | 4 | `--lang ko`(또는 `RAPIDTRIAGE_LANG=ko`)에서 89명령 설명·605옵션 도움말 한국어 100%(사전 누락은 테스트 실패), 기본(영문) 출력 불변, 용어는 부록 C.7 표준 | GAP-145 / IS-098 | QA-103 |

> W9-b는 6개다. T-117이 전역 삭제라 단독으로 먼저, 그 뒤 T-118·T-119·T-140·T-141 병렬, T-142는 T-141 뒤(`parser.py` 공유).

### W10 엔진·수집기 **[승인 필요]** (승인 시점에 삽입)

| ID | 제목 | 파일 | 결정 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-120 | E01 추출 스파이크(처리량·1패스 바이트 측정) | 측정 스크립트만 | D24 | 4 | 바이트·파일 수 기준 처리량 표, 목표(15분/90분) 확정 또는 수정 | GAP-068 / IS-084 | — |
| T-121 | 2패스 우선순위 추출·목록화 100%·삭제 sweep 상한 분리 | `rapidtriage/core/e01_native.py`, `rapidtriage/core/e01.py` | D6·D7 | 4×3(하위 과제 3개로 분할: 목록화 / 우선순위 / 삭제 상한) | `fls` 대비 누락 ≤0.5%, 사용자 프로필 100%, 원본 불변, 잘림 시 단계 "부분" | GAP-026·028·160 / IS-084·085 | QA-017·001 |
| T-122 | 시그니처 판정 재사용 + 복구본 제외 | `rapidtriage/artifacts/windows/filesystem.py`, `rapidtriage/core/files.py`(`content_state` 기록) | D6·D33 | 4 | 3,508 s → ≤120 s, 전/후 행 비교(복구본 제외분만 차이), `content_state` 목록 노출 | GAP-040·041·068 / IS-022·023 | QA-025·026 |
| T-123 | 레지스트리 키 트리 분리 저장 | `rapidtriage/artifacts/windows/registry.py` 출력부 | D10 | 4 | 1,391 s → ≤400 s, 탐색기 동일(e2e) | GAP-068 / IS-084 | QA-052·100 |
| T-124 | 침묵 실패 점검 전체 대상 | `rapidtriage/core/silent_failure.py` | D6a | 3 | 대상 100%, IMG-B 이벤트 로그 오판 0, 설명 한국어 | GAP-030 / IS-087 | QA-030 |
| T-125 | 매체 해시 계산·E01 내장 해시 대조 | `rapidtriage/core/e01_hash.py`, `rapidtriage/api/app/case_workspace.py`, `rapidtriage/core/case_db/intake.py`(상태값 추가) | D34 | 4 | 컨테이너/매체 구분, 내장 해시 대조, 거짓 불일치 0 | GAP-007·008·168 / IS-069·003 | QA-007·008 |
| T-126 | PST/OST 선택 구성 요소·단계 상태 매핑(`failed_isolated`→부분)·타임라인 매핑 | 〔2차: 경로 정정〕 `rapidtriage/artifacts/email_pst.py`·`email_external.py`·`email.py`, `rapidtriage/core/run/steps.py`(`:142` 상태값)·`core/run/progress.py`, `rapidtriage/core/timeline.py` | D8·D6 | 4×3 | 메일 표본 메시지 > 0, 진행 기록에 부분 상태, 미매핑 3,200행 해소 | GAP-157·029·115 / IS-006·086·048 | QA-047·019·070 |

한국 환경 수집기(GAP-159)·카카오톡 메타 조사(GAP-158)는 v1 R8-6의 6-A를 그대로 승계하되 이 계획의 물결 밖(다음 계획)으로 둔다. 이번에는 0건 사유 화면(T-047)과 국내 호스트 분류(T-104의 YAML)만 한다.

### W11 1:1 최종 검증

| ID | 제목 | 담당 | 의존 | h | 수용 검사 | GAP/IS | QA |
|---|---|---|---|---|---|---|---|
| T-127 | 전 QA(QA-001~120) 실데이터 일괄 실행과 추적표 채우기 | Sonnet ×6(코퍼스·영역별 분담: ①무결성·방어 001~016·106~109 ②범위·수치 017~032·110 ③브리핑·내비·목록·뷰어 033~056·113 ④검색·검토·시간순·AI 057~074 ⑤보고서·페르소나 075~082·114~119 ⑥오류·접근성·성능·AX 083~105·111·112·120) | W1~W9 | 4×6 | 부록 E 전부 결과 기록(QA마다 증거 폴더 `D:\rapid-qa\derived\r8\w11\QA-xxx\`), coverage-matrix 미확인 칸 수 0(잔여는 E.5·E.7 사유) | GAP-046 / IS-121·123 | QA-001~120 |
| T-128 | 적대적 최종 리뷰와 불일치 재계획 | Fable | T-127 | 4 | IS 125개 각각 "일치/불일치", 불일치는 새 T-xxx로 등록(마스터 9절 루프), 사람 테스트(QA-034) 결과 반영, R7 이월(단계 4·5) 범위 결정 반영 | GAP-164·166 / IS-121 | QA-034 |

## F.4 과제 수 검산

W0 12 · W1 31 · W2 9 · W3 15(T-056 폐기 번호 제외) · W4 10 · W5 12 · W6 12 · W7 15 · W8 6 · W9 12 · W10 7 · W11 2 = **143개 유효 과제**(번호는 T-001~T-144, T-056 결번). 1차 127개 + 2차 추가 16개(T-129~T-144: 신규 9 — 129·131·132·135·136·137·138·140·142, 과대 과제 분리 7 — 130·133·134·139·141·143·144). T-121·T-126은 착수 때 각 3개 하위 과제로 나눈다(4시간 상한 준수).

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

## F.6 묶음 안 단계표 〔2차 신규〕

같은 묶음의 과제는 파일이 겹치지 않지만, 아래 묶음에는 선후 의존이 있어 **한 번에 6개를 띄우지 않는다**. "선합의"는 카드에 적힌 인터페이스를 고정하고 병렬로 구현해도 된다는 뜻이고, 그 밖은 앞 단계가 통합 브랜치에 들어간 뒤 시작한다. 표에 없는 묶음(W0-a, W1-c, W1-f, W2-b, W4-b, W7-b, W10, W11)은 전부 1단계다.

| 묶음 | 1단계(동시) | 2단계 | 3단계 | 실제 최대 동시 수 · 최소 벽시계(구현만) |
|---|---|---|---|---|
| W0-b | T-007·T-008(선합의 D.7)·T-009·T-010·T-011·T-012 | — | — | 6 · 4 h |
| W1-a | T-013·T-014·T-015·T-016·T-017·T-018(T-017↔T-018 선합의: 204 = 미리보기 불가) | — | — | 6 · 4 h |
| W1-b | T-019·T-021·T-023 | T-020·T-022·T-024 | — | 3 · 8 h |
| W1-d | T-031·T-034·T-035·T-036·T-144 | T-032 | — | 5 · 8 h |
| W1-e | T-033·T-129·T-131·T-132·T-133·T-134 | — | — | 6 · 4 h |
| W2-a | T-037·T-040(자기 PC, 승인 불필요)·T-038(승인 시) | T-039·T-041 | T-042 | 3 · 무인 처리 시간 지배 |
| W3-a | T-045·T-049 + T-047·T-048(선합의: 카드 id 12개 = 부록 C.2) | T-046 | T-050 | 4 · 10 h |
| W3-b | T-051·T-052·T-053·T-054 | T-055 | — | 4 · 8 h |
| W3-c | T-057·T-058·T-059 | T-060 | — | 3 · 7 h |
| W4-a | T-061 | T-062·T-063·T-064·T-065·T-066 | — | 5 · 8 h |
| W5-a | T-071·T-072·T-073·T-074·T-075 | T-076 | — | 5 · 7 h |
| W5-b | T-078·T-079·T-080·T-081·T-082 + T-077(T-078과 선합의: 노드 id 불변) | — | — | 6 · 4 h |
| W6-a | T-083·T-084·T-085·T-086·T-088 | T-087 | — | 5 · 8 h |
| W6-b | T-089·T-090·T-091·T-092·T-139·T-143 | — | — | 6 · 4 h |
| W7-a | T-093·T-094·T-095·T-098 | T-096 | T-097 | 4 · 12 h |
| W7-c | T-135·T-137 | T-136 | — | 2 · 7 h |
| W8 | T-105·T-107·T-108·T-110 | T-106·T-109 | — | 4 · 8 h |
| W9-a | T-111·T-112·T-115·T-116 | T-113 | T-114 | 4 · 11 h |
| W9-b | T-117 | T-118·T-119·T-140·T-141 | T-142 | 4 · 12 h |

W3와 W4는 서로 파일이 겹치지 않으므로 동시에 진행할 수 있지만, 동시 6개 상한은 **두 물결의 합**에 적용한다(예: W3-a 1단계 4개 + W4-a 1단계 1개).

## F.7 2차 리뷰가 찾은 묶음 안 파일 충돌과 해소 〔2차 신규〕

| 충돌 | 1차 계획 | 해소 |
|---|---|---|
| `rapidtriage/api/app/runops.py` — T-028(검증 상태)·T-029(감사 입력) | 같은 묶음 W1-c, T-029 파일 목록에 누락 | 감사 입력(케이스 DB 추가)을 T-028로 옮김. T-029는 `core/audit.py`만 |
| `core/case_db/database.py` — T-029(`tool_version`)·동시성 | T-029 한 과제에 두 일 | 동시성은 T-131(W1-e)로 분리 |
| `frontend/src/features/dashboard/caseCards.tsx` — T-036(메모)·해시 라벨 | 해시 표시 과제 자체가 없었음 | T-144(W1-d, 메모 블록) → T-129(W1-e, 해시 라벨 맵). 묶음이 달라 직렬 |
| `rapidtriage/api/app/factory.py` — T-046(라우터 등록)·T-049(gzip) | 같은 묶음 W3-a | 라우터 등록은 코디네이터(F.1 화면 장착 규칙), T-049만 직접 수정 |
| `rapidtriage/api/app/routes_search_index.py` — T-057·T-060 | T-060 파일 목록에 누락(개체 요약 처리기가 이 파일에 있음) | T-060을 W3-c 2단계로 |
| `rapidtriage/core/case_report.py` — T-108(PDF 분리)·T-109(템플릿 데이터) | 같은 묶음 W8 | T-109를 2단계로, 이 파일을 금지 구역에 추가 |
| `rapidtriage/cli/*` — T-111(전체)·T-112(`web.py`) | 같은 묶음 W9-a | T-111에서 `web.py` 제외, `parser.py`는 하위 파서 블록 단위로 분리(금지 구역 추가) |
| `frontend/src/app/registerSlots.tsx`·`ViewSwitch.tsx`·`IntakePane.tsx` — 새 화면 장착(T-073·076·077·081·082·093·097·099·102·103·106) | 어느 과제의 파일에도 없음 | 금지 구역에 추가 + 코디네이터 장착(F.1). T-073만 `IntakePane.tsx` 직접 |
| `frontend/src/shell/TopBar.tsx` — T-072(W5-a)·T-081(작업 센터 아이콘, W5-b) | T-081 파일 목록에 누락 | 묶음이 달라 충돌 없음. T-081 카드에 `TopBar.tsx`(아이콘 1개) 추가 |
| 없는 파일 9개(`cli/vendor.py`, `cli/runops.py`(감사·검증), `app/themeBoot.ts`, `shell/StageRail.tsx`, `shell/ToastRegion.tsx`, `src/stages.ts`, `dashboard/categories.ts`, `views/thumb.css`, `artifacts/email/*`) | 하위 보고서의 경로를 다시 열지 않음 | 실제 경로로 정정(각 행의 〔2차〕) |
