# R8 부록 H — 과제 상세 카드 (v2에서 온 과제의 동작 명세) · 계획 v3

2차 적대적 리뷰(Fable, 2026-11-11)가 더한 부록이다. 부록 F의 한 줄 표를, 구현자(Opus)가 **질문 없이 시작**하고 검증자(Sonnet)가 **같은 기준으로 다시 잴** 수 있게 풀어 썼다. (v2에서는 표와 카드가 다르면 카드가 우선이었다. v3에서는 아래 "읽는 법"대로 부록 F 표가 정본이다.)

**v3(2026-11-12) 읽는 법**: 이 부록은 v2의 카드를 그대로 싣는다. ① 과제의 물결·묶음·의존·QA·모델은 **부록 F 표가 정본**이다(카드 제목의 `W0-a` 같은 v2 묶음 이름은 무시한다 — 각 카드 끝의 〔v3〕 줄이 새 위치다). ② v3가 재정의한 과제 13개(001·005·006·009·023·024·026·038·041·071·072·082·096)의 카드는 지웠다 — 부록 F 표의 수용 기준이 전부다. ③ v3 신규 과제(T-145 이후)는 카드가 없고 부록 F 표의 **동작**·**수용**이 명세다. ④ 카드 본문의 "C2"는 IMG-B의 현재 처리 결과다(v2의 부분 추출본 별칭은 폐기). 한 숫자 범위("볼륨의 n%")를 전제로 한 문장이 남아 있으면 부록 F의 T-023·T-024가 우선한다. ⑤ 카드의 기준 화면 1440×900은 **1280×720**으로 읽는다(D61). ⑥ 카드의 "검토자 모드/분석 담당 모드"는 "검토자 기본값/분석 담당 기본값"으로 읽는다(화면은 하나, IS-018). ⑦ 카드가 의존으로 적은 공용 컴포넌트(T-062·064·065·067)는 WH로 갔다 — 화면 과제는 기존 컴포넌트로 만들고 수렴은 마지막에 한다(D70).

## H.0 읽는 법과 공통 규칙

- 카드 항목: **대상**(배타 파일과 함수·줄, 기준 커밋 ffab479) · **할 일**(동작 명세) · **수용**(수치로 판정하는 검사 — 전부 통과해야 닫힘) · **검증**(이 과제에만 해당하는 명령·스펙; 공통 명령은 부록 F.1) · **주의**(깨질 수 있는 기존 테스트, 하지 말 것, 승인 경계).
- 줄 번호는 2차 리뷰에서 다시 연 것만 적었다. `착수 때 확인`이라고 적힌 위치는 열어 보지 않은 곳이다 — 추측으로 진행하지 말고 먼저 열어 본 뒤 다르면 카드를 고친다(마스터 12절 "이 계획의 사실 오류").
- 공통 수용(모든 과제): ① 부록 F.1 공통 검증 명령 통과 ② 계약 테스트(부록 D) 통과 ③ 기존 테스트의 삭제·`skip` 0 ④ 화면 과제는 실데이터 스크린샷 1장 이상(`D:\rapid-qa\derived\r8\w{물결}\T-xxx\`) ⑤ 증거·식별자가 diff·커밋 메시지·스크린샷 설명에 없음.
- 공통 금지: 복구 엔진·파서·수집기 출력·DB 스키마 변경(W10 승인 과제 제외), 사용자 계약(주소·인용·단축키·저장 키·접근성 이름·랜드마크) 변경 — testid는 `frontend/src/contracts/testIds.ts` 상수에서 테스트와 함께 바꾼다(D65), 다른 과제의 배타 파일 수정, 서버 포트 8710 접촉, `taskkill /IM`.
- 스펙 실행: `cd frontend && npm run e2e -- <스펙 파일>`(= `playwright test --config e2e/playwright.config.ts`). 파이썬 단일 모듈: `python -m unittest tests.<모듈명>`.
- 실데이터 서버(검증자): `RAPIDTRIAGE_NO_BROWSER=1 python -m rapidtriage web --port <QA 포트 8990~8999>` + 상태 복사본. 시작 전·후 `python scripts/r8-evidence-snapshot.py`(T-003 이후).

---

## W0 — 계약·측정·기반

**T-002 토큰 lint·대비 검사 확장** (3 h · W0-a)
- 대상: `frontend/scripts/check-tokens.mjs`(신규), `frontend/scripts/check-contrast.mjs`(기존), `frontend/package.json`(scripts: `check:tokens` 추가).
- 할 일: CSS 21파일·TSX inline style에서 토큰 밖 값(색 hex·`border-radius` 직접값·px 간격·`font-size` 직접값·`box-shadow`·`z-index`·`!important`)을 세어 `frontend/scripts/token-baseline.json`에 기록하고, 기준선보다 늘면 실패. 대비 검사는 부록 C.5 색 역할표의 조합(글자 1·2·3 × 배경 0·1·2, 칩 글자 × 칩 배경, 강조 × 배경)을 라이트·다크 모두 계산.
- 수용: 기준선이 UI 인벤토리 수치와 일치(색 hex 0 · radius 42 · px 간격 124 · font-size 9 · box-shadow 27 · inline style 68 · z-index 17종 · `!important` 5). 새 위반 1개를 넣으면 실패. 대비: 본문 글자 ≥ 4.5:1, 비활성·테두리 ≥ 3:1 미달 조합을 목록으로 출력.
- 검증: `cd frontend && npm run check:tokens && npm run check:contrast`.
- 주의: 기존 위반을 고치지 않는다(T-061·T-117의 일). `biome` 설정은 건드리지 않는다.
- 〔v3〕 T-002 → WA-1(부록 F 표 우선)

**T-003 증거 스냅샷·로그 스캔·보고서 감사·추적표 감사 스크립트** (4 h · W0-a)
- 대상: `scripts/r8-evidence-snapshot.py`, `scripts/r8-log-scan.py`, `scripts/r8-report-audit.py`, `scripts/r8-trace-audit.py`, `tests/test_r8_qa_scripts.py`(전부 신규).
- 할 일: ① snapshot: 폴더(또는 파일 목록)의 상대 경로·크기·mtime_ns·SHA-256을 JSON으로, `--compare a.json b.json`은 변경·신규·삭제를 나열하고 차이가 있으면 종료 코드 1. 식별자가 나오지 않게 `--redact-names`(경로를 해시로). ② log-scan: 정규식 묶음(사용자 폴더 경로 `[A-Za-z]:\\Users\\[^\\]+`, 키·토큰 패턴, 주민번호·카드 패턴)으로 로그·오류 응답을 스캔, 적중 수만 출력. ③ report-audit: 내보낸 md·html·docx·pdf·json에서 텍스트를 뽑아 필수 필드(도구 버전·카탈로그 버전·증거 해시·처리 범위·실패/부분 단계·시간대·조건)와 금지 문자열(영문 제목 목록, `status=`, 단정 문구)을 검사. ④ trace-audit: 부록 A·B·E·F를 읽어 부록 G를 다시 만들고 구멍(부록 F T-003 행의 a·b·c)을 실패로.
- 수용: 합성 폴더에서 1바이트 변경·신규 1파일·삭제 1파일을 각각 검출. 가짜 비밀 3종·가짜 경로 2종 검출, 깨끗한 로그에서 적중 0. 필드 1개를 뺀 보고서에서 실패. 현재 부록으로 trace-audit 실행 시 구멍 0.
- 검증: `python -m unittest tests.test_r8_qa_scripts && python scripts/r8-trace-audit.py --check`.
- 주의: 스크립트는 읽기 전용(증거 폴더에 임시 파일 금지 — 출력은 `--output` 필수).
- 〔v3〕 T-003 → WA-1(부록 F 표 우선; `r8-trace-audit.py`는 v3 추적표 규칙(고아 0)을 물결마다 다시 검사 〔리뷰〕 `r8-trace-audit.py`에 검사 둘을 더한다: 검증 명령의 테스트 모듈이 "파일" 열이나 저장소에 있는가, 동작·수용에 "같음"이 없는가.)

**T-004 합성 풍부 픽스처 생성기** (4 h · W0-a)
- 대상: `scripts/make-r8-fixture.py`, `tests/fixtures/r8_rich/`(생성 스크립트 입력·매니페스트만 커밋), `frontend/e2e/r8_fixture.py`(e2e용 처리 결과 폴더 생성 — 기존 `e2e/ai_fixture.py` 방식 답습).
- 할 일: 가짜 값만으로 처리 결과 폴더(run summary + 종류별 JSONL)를 만든다. Tier 1 카드 9종(문서·이메일·메신저·웹·반출 경로·프로그램 실행·삭제·복구·계정·로그온·AI 사용) 전부 행 > 0, 가짜 비밀(키 패턴)·가짜 개체(주민번호 형식이나 체크섬 불일치인 값, `example.com` 메일) 포함, 취득 사본 시각 행·`failed_isolated` 단계 1개·예산 중단을 유발할 큰 종류 1개 포함.
- 수용: 생성 ≤ 60 s, 결과 폴더 ≤ 50 MB, 카드 9종 행 > 0, `scripts/r8-log-scan.py`의 실데이터 패턴 적중 0(가짜 패턴만), 같은 시드로 두 번 만들면 바이트 동일.
- 검증: `python scripts/make-r8-fixture.py --output <임시> --seed 8 && python -m unittest tests.test_r8_qa_scripts`.
- 주의: SYN은 CI 게이트 전용이다. **완료 판정에 쓰지 않는다**(IS-121). 실제 E01·실사용 파일을 섞지 않는다(AGENTS.md).
- 〔v3〕 T-004 → WA-2

**T-007 서버 오류 봉투(추가 방식)와 500 경로 제거** (4 h · W0-b)
- 대상: `rapidtriage/api/app/errors.py`(신규), `rapidtriage/api/app/factory.py`(예외 처리기 등록, 500 본문 `:192-198`, 기존 422 처리기 `:124-132`), `docs/api-error-codes.md`(신규), `tests/test_error_envelope.py`(신규).
- 할 일: `HTTPException`·`RequestValidationError`·미들웨어 401·403·처리되지 않은 예외에 대한 처리기에서 본문을 `{...기존 본문 그대로, "code", "message", "hint"}`로 만든다. `code`: `detail`이 `{code,…}` 객체면 그 값(출력 가드 등), 아니면 `errors.py`의 대응표(영문 리터럴 36종 → 코드·한국어 문장·힌트), 없으면 상태 코드 기본값(`NOT_FOUND`·`VALIDATION_FAILED`·`UNAUTHORIZED`·`FORBIDDEN`·`CONFLICT`·`INTERNAL_ERROR`). `message`: 대응표의 한국어 문장, `detail`이 이미 한국어 문자열이면 그대로. 500: `crash_report` 절대경로를 본문에서 빼고 `crash_id`만(경로는 서버 로그에).
- 수용: 기존 `tests/`의 `["detail"]` 단언 190곳(32파일) **무수정 통과**. 오류 40종(QA-083 목록) 응답에 `code`·`message`·`hint` 100%, `message`의 한글 포함률 100%, 500 본문에 드라이브 문자·사용자 폴더 패턴 0. `python scripts/update-api-snapshot.py` 뒤 스냅샷 diff는 오류 스키마 추가뿐.
- 검증: `python -m unittest tests.test_error_envelope tests.test_rapidtriage_api_contract tests.test_rapidtriage_api_security`.
- 주의: `detail`의 형·값을 바꾸지 않는다(GAP-193). 라우트 파일(396개 `HTTPException(` 지점)은 건드리지 않는다 — 처리기 한 곳에서 한다. `detail=str(exc)`로 올라오는 core 영문 예외는 `message`를 "요청을 처리하지 못했습니다" + `hint`로 감싸고 원문은 `detail`에만.
- 〔v3〕 T-007 → WA-6(부록 F 표 우선)

**T-008 프런트 오류 정규화** (3 h · W0-b, T-007과 선합의)
- 대상: `frontend/src/api/client.ts`(`:43` 토큰 읽기는 건드리지 않음 — T-115, `:60-95` 오류 생성부), `frontend/src/api/errors.ts`(신규), `frontend/src/api/client.test.ts`(있으면 확장, 없으면 신규).
- 할 일: `ApiError`에 `code`·`hint` 추가. 본문 해석 순서: 최상위 `message` → `detail.message` → 문자열 `detail` → 상태별 한국어 기본문. `fetch`가 던지는 `TypeError`는 `NETWORK_UNREACHABLE`("서버에 연결하지 못했습니다" + "서버 창이 켜져 있는지 확인하세요"), `AbortError`는 `REQUEST_ABORTED`(호출부가 무시할 수 있게 `isAbort` 표시), 시간 초과는 `REQUEST_TIMEOUT`.
- 수용: `grep -rn "Failed to fetch\|Request failed" frontend/src --include=*.ts --include=*.tsx`에서 테스트 밖 0. 영문 `detail`("Not Found" 등)을 받아도 `error.message`에 한글. 기존 `error.status` 사용처 동작 불변(`main.tsx:33-38` 재시도 판정 포함).
- 검증: `cd frontend && npx vitest run src/api`.
- 주의: 화면의 오류 표시 컴포넌트는 바꾸지 않는다(T-063). `EntityPanel.tsx:68-71`의 `errorText`는 그대로 두어도 한국어가 나와야 한다.
- 〔v3〕 T-008 → WA-7 · T-007 → WA-6(부록 F 표 우선)

**T-010 비결정·기준 실패 테스트 4건 수정** (4 h · W0-b) `[확인]`
- 대상: `rapidtriage/core/derived/stage.py`(`:77-79` — `new_run_stage_analysis_id`가 같은 초에 같은 이름을 만들어 WinError 183), 실패 테스트가 든 `tests/` 3파일(`test_rapidtriage_email_external…`, `test_rapidtriage_derived_engine`, `test_rapidtriage_triage_rules`), `frontend/src/features/**/qaRealData*.test.tsx` 3파일.
- 할 일: 4건 각각 원인을 한 문단으로 기록(`docs/research/r8-test-flakes.md`)하고 고친다. 폴더 이름 충돌은 `mkdir(exist_ok=False)` 실패 시 접미사 재시도. vitest hang은 타이머·미해결 프라미스 정리.
- 수용: 4건 각각 20회 연속 통과(반복 스크립트 로그 첨부). `test_rapidtriage_email_external…` 기준 실패의 원인이 "테스트 결함/제품 결함" 중 하나로 판정돼 있음(제품 결함이면 GAP 등록).
- 검증: `for i in $(seq 20); do python -m unittest tests.test_rapidtriage_derived_engine || break; done` 등.
- 주의: 파생 표의 **내용**은 바꾸지 않는다(이름 충돌만).
- 〔v3〕 T-010 → WA-3(부록 F 표 우선; CI 실패 4건(T-145)과 겹치지 않는 비결정 3건·기준 실패 1건만)

**T-011 과제 측정 하네스(T1~T5 골격·지표 수집)** (4 h · W0-b)
- 대상: `frontend/e2e/tasks/`(신규: `harness.ts`, `t1-brief.spec.ts`~`t5-report.spec.ts` 골격), `scripts/r8-measure.py`(신규).
- 할 일: 조작 수(클릭·키)·경과 시간·화면 전환 수·Tab 횟수·셀 잘림 비율(`scrollWidth > clientWidth`)·내비 노드 수를 재는 공용 도우미. 실데이터 서버 주소·처리 ID는 환경 변수(`R8_BASE_URL`, `R8_RUN_C1` …)로 받고, 없으면 SYN으로 실행(건너뛰지 않는다).
- 수용: 현 화면에서 UX 감사 수치를 ±10%로 재현한 `baseline.json`: 트리 노드 366~377, 셀 잘림 29~37%, 그리드 첫 행까지 Tab 32, T2(검색→3건 태그) 40 s 안팎.
- 검증: `cd frontend && npm run e2e -- e2e/tasks`.
- 주의: 이 단계의 스펙은 **측정만** 하고 목표 미달로 실패시키지 않는다(목표 단언은 W5~W8 과제가 켠다).
- 〔v3〕 T-011 → WA-2

**T-012 e2e CSS 클래스 선택자 제거** (4 h · W0-b)
- 대상: `frontend/e2e/*.spec.ts` 13개, testid 추가는 `ChatView.tsx`·`EntityPanel.tsx`·`ImageView.tsx`만.
- 할 일: `locator('.…')` 약 25곳을 testid·역할 선택자로 교체. `boundingBox`·`getComputedStyle` 단언은 `grid-layout.spec.ts`의 레이아웃 계약(가로 넘침 0, 시각 열 폭 ≥ 176)만 남긴다.
- 수용: `grep -n "locator('\\.\|locator(\"\\." frontend/e2e/*.spec.ts` 0. 13스펙의 테스트 수(44)·통과 수 변화 없음. 새 testid는 `uiContract.ts`에 등록.
- 검증: `cd frontend && npm run e2e`.
- 주의: 스펙의 검증 의미를 약하게 만들지 않는다(선택자만 바꾼다).
- 〔v3〕 T-012 → WA-2(부록 F 표 우선)

---

## W1 — 깨진 것·거짓 표시·방어 가능성

**T-013 검색 옵션 체크박스가 빈 막대로 그려지는 결함** (2 h · W1-a)
- 대상: `frontend/src/app/shell.css`(`.global-search input` `:309-313`, `:444-448`), `frontend/src/tokens/controls.css`(`:213` `:where(input[type="checkbox"], …)`).
- 할 일: `.global-search input` 선택자를 검색 입력 하나(`.global-search input[type="search"]` 또는 전용 클래스)로 좁힌다. 체크박스·라디오 규칙의 특이도가 부모 규칙에 지지 않게 한다.
- 수용: 검색 옵션의 체크박스 `boundingBox().width ≤ 24`·높이 ≤ 24, 라벨이 상자 오른쪽(x 좌표 비교), 켜짐·꺼짐이 스크린샷으로 구분. 라이트·다크 각 1장. 검색 입력의 폭·안쪽 여백 변화 0(전/후 boundingBox 동일).
- 검증: `cd frontend && npx vitest run src/shell src/features/case/SearchOptions.test.tsx && npm run e2e -- e2e/workbench.spec.ts`.
- 주의: `shell/scrollLayout.test.ts`가 `shell.css`를 직접 읽는다 — 통과 유지.
- 〔v3〕 T-013 → WB-1

**T-014 메뉴 포털·충돌 보정** (4 h · W1-a)
- 대상: `frontend/src/components/MenuButton.tsx`, `Popover.tsx`, `popover.css`.
- 할 일: 메뉴 목록을 `document.body` 포털로 그리고, 기준 버튼 사각형에서 위치를 계산해 뷰포트 밖으로 나가면 뒤집거나 밀어 넣는다(`.pane-frame{overflow:clip}` `shell.css:93`의 영향을 벗어남). Esc·바깥 클릭 닫기, 닫힌 뒤 버튼으로 포커스 복귀, 방향키 이동 유지.
- 수용: 뷰어 최소 폭·880·1280 폭에서 뷰어 `…` 메뉴의 `boundingBox`가 뷰포트 안(왼쪽 ≥ 0, 오른쪽 ≤ 폭). 메뉴 항목 첫 글자 잘림 0. `viewer-actions-menu` testid·접근성 이름 "더보기" 유지.
- 검증: `cd frontend && npx vitest run src/components/MenuButton.test.tsx && npm run e2e -- e2e/viewer-families.spec.ts`.
- 주의: 메뉴 항목 구성은 바꾸지 않는다(T-090). 포털 안에서도 테마 속성(`data-theme`)이 적용되는지 확인.
- 〔v3〕 T-014 → WB-1

**T-015 트리 건수 잘림·가로 스크롤·이탤릭·검색 공백** (4 h · W1-a)
- 대상: `frontend/src/features/tree/tree.css`(`:71-75` 이탤릭, `:161-170` `.badge`), `frontend/src/features/tree/EvidenceTree.tsx`, `frontend/src/features/case/case.css`(`.case-tree` 블록만).
- 할 일: 건수 배지에 `flex: none`·`min-width: 7ch`, 스크롤바 거터 예약(`scrollbar-gutter: stable`). 라벨은 줄임(`min-width: 0` + ellipsis), 가로 스크롤 제거. 이탤릭 제거, 자료 없는 노드는 건수 자리에 글자 "자료 없음". 검색 결과 사이의 빈 공간 제거.
- 수용: IMG-B(C2) 트리 전 노드에서 배지 `scrollWidth == clientWidth`(잘림 0), 트리 컨테이너 `scrollWidth <= clientWidth`. `getComputedStyle(...).fontStyle === "italic"` 0. 검색 결과 행 사이 간격 ≤ 행 높이. 1280·1440·1920 3폭.
- 검증: `cd frontend && npx vitest run src/features/tree src/shell/treePane.test.tsx`.
- 주의: 노드 id·순서·접근성 이름 "케이스 탐색 트리"·`tree-empty-toggle` 불변. `treePane.test.tsx`의 폭 상수 단언은 유지.
- 〔v3〕 T-015 → WB-1

**T-016 추가 분석 카드 글자 겹침·격자 구멍** (2 h · W1-a)
- 대상: `frontend/src/features/stages/stages.css`(`.process-card` `:221-264`, `.analysis-cards` `:404-424`).
- 할 일: 카드 높이 고정(58px)을 `min-height`로, 제목 2줄 허용(행 높이 자동). `.analysis-cards`를 고정 열 격자로(메이슨리 금지), 상태 칩 우측 정렬.
- 수용: 880~1920 6폭에서 카드 안 요소 사각형 교차 0(제목·설명·칩), 격자의 빈 칸은 마지막 행에만.
- 검증: `cd frontend && npx vitest run src/features/stages && npm run e2e -- e2e/analysis.spec.ts`.
- 주의: `analysis-*`·`process-*` testid 불변.
- 〔v3〕 T-016 → WB-2

**T-017 미디어 길이 문구·썸네일 대체 글리프** (3 h · W1-a, T-018과 선합의)
- 대상: `frontend/src/features/viewer/views/MediaView.tsx`(`:97`), `frontend/src/features/views/ThumbnailView.tsx`, `frontend/src/features/views/views.css`(`.thumb*`).
- 할 일: `duration_seconds`가 없으면 "길이 정보 없음", 있으면 `mm:ss`. 썸네일 요청이 204 또는 4xx면 형식 글리프(이미지·영상·문서) + "미리보기 없음"을 그리고 콘솔에 오류를 남기지 않는다(`onError`에서 `src` 교체, 재시도 없음).
- 수용: "알 수 없음초" 0. C2 썸네일 보기에서 빈 사각형 0, 브라우저 콘솔 error 0(깨진 삭제 이미지 25건 포함).
- 검증: `cd frontend && npx vitest run src/features/views src/features/viewer`.
- 주의: 민감 미디어 흐림(`mediaBlur`) 동작 불변.
- 〔v3〕 T-017 → WB-3 · T-018 → WB-2

**T-018 썸네일 415를 정상 응답으로** (3 h · W1-a)
- 대상: `rapidtriage/api/app/routes_media.py`(썸네일 처리기), `rapidtriage/api/app/thumbnail.py`(`render_thumbnail_jpeg` `:40`, `cached_thumbnail` `:87`).
- 할 일: 디코드 실패(깨진 헤더·0 채움)는 204 No Content + 헤더 `X-RapidTriage-Thumbnail: unavailable`. 서버 로그는 1줄(경로 없이 확장자·크기만). 지원하지 않는 형식(진짜 415)은 유지하되 본문은 봉투.
- 수용: 깨진 JPG·GIF 픽스처 3종에 204, 정상 이미지에 200·바이트 동일(전/후), 서버 로그에 경로 0.
- 검증: `python -m unittest tests.test_rapidtriage_media_image`.
- 주의: 캐시 쓰기 위치·이름 불변(T-032가 관문을 붙인다).
- 〔v3〕 T-018 → WB-2

**T-019 목록 응답 부분 결과 계약(서버)** (4 h · W1-b 1단계)
- 대상: `rapidtriage/api/app/artifact_filter.py`(`filter_artifact_page` `:132-216`; 여러 종류 스캔 `:350` 부근), `rapidtriage/api/app/pagination.py`(`paginate_payload` `:28`).
- 할 일: `pagination`에 `total_lower_bound`(확정이면 `total`과 같고, 미확정이면 `offset + returned + (1 if has_more else 0)`, 예산 중단이면 지금까지 일치한 수), `budget_stopped`(항상 불리언), 최상위 `notice: {code, message}`(`SCAN_BUDGET_STOPPED`: "시간 제한(20초) 안에 n행까지만 확인했습니다" / `TOTAL_NOT_COUNTED`: "전체 건수는 세지 않았습니다 — n건 이상")를 추가한다.
- 수용: 기존 필드 이름·값 불변(응답 스냅샷 diff는 추가 필드뿐). 예산 0.01 s로 낮춘 테스트에서 `rows=[]`·`budget_stopped=true`·`notice.code=SCAN_BUDGET_STOPPED`. `has_more=true`·`total=null`이면 `total_lower_bound ≥ offset + returned + 1`.
- 검증: `python -m unittest tests.test_rapidtriage_api_field_filters tests.test_rapidtriage_api_row_conditions tests.test_rapidtriage_api_contract`.
- 주의: 스캔 순서·일치 판정은 바꾸지 않는다(성능은 T-051).
- 〔v3〕 T-019 → WB-2

**T-020 부분 결과 띠와 정직한 빈 상태(프런트)** (4 h · W1-b 2단계)
- 대상: `frontend/src/api/collections.ts`(pagination 타입), `frontend/src/features/grid/GridToolbar.tsx`(`:420-425`), `frontend/src/features/grid/DataGrid.tsx`(`:1441-1453`, `:1467-1518`만).
- 할 일: 부록 F 표의 수용 그대로. 띠는 임시 구현(인라인 알림 한 줄, `data-testid="r8-partial-banner"`) — W4의 `PartialBanner`가 나오면 T-089가 교체한다.
- 수용: 예산 1 s 서버 + C2에서 시작 프로그램 등 5노드: "표시할 행이 없습니다" 0, 띠 표시 5/5, "다시 시도"가 같은 요청을 다시 보냄. 약 35개 "미확정" 노드에서 "세는 중" 고착 0. 문자열 "전체 건수 미확정"·"전체 미확인" grep 0.
- 검증: `cd frontend && npx vitest run src/features/grid`(`r7GridHonesty.test.tsx`·`DataGrid.test.tsx` 포함).
- 주의: `DataGrid.tsx`는 금지 구역 — 적힌 줄 범위 밖을 건드리지 않는다. `r7GridHonesty.test.tsx`가 고정한 문구 중 계약표에 없는 것은 testid 단언으로 옮긴다.
- 〔v3〕 T-020 → WB-3

**T-021 단계 상태 집계 단일 함수(서버)** (3 h · W1-b 1단계)
- 대상·수용: 부록 F 표. 함수 `summarize_steps(summary: Mapping) -> dict`는 순수 함수로 두고 `/dashboard`·`/brief`(T-046)·보고서(T-027)가 같이 쓴다.
- 검증: `python -m unittest tests.test_rapidtriage_run_plan tests.test_r7_l4_shell_api` + 신규 `tests/test_r8_steps_summary.py`(상태 조합 12종).
- 주의: `core/run/*`은 건드리지 않는다(단계 상태값 자체의 변경은 T-126 승인 과제).
- 〔v3〕 T-021 → WB-2

**T-022 접수·처리 화면이 같은 집계를 쓰게** (3 h · W1-b 2단계)
- 대상: `frontend/src/features/dashboard/model.ts`(`stageRows` `:45-71`은 유지, 요약 수치만 교체), `frontend/src/features/dashboard/cards.tsx`, `frontend/src/features/stages/ProcessStage.tsx`(상단 집계 문구만).
- 수용: C2에서 접수 카드·처리 화면·문제 목록의 "단계 n · 완료 n · 부분 n · 실패 n"이 문자 단위로 같다(4곳 텍스트 추출 비교). "12/12 완료·오류 0" 문자열 재현 불가. 수집기 수(12)는 "수집기 12" 라벨로 따로.
- 검증: `cd frontend && npx vitest run src/features/dashboard src/features/stages`.
- 주의: `CaseDashboard` 테스트가 고정한 문구 30개 중 바뀌는 것만 testid로 옮긴다.
- 〔v3〕 T-022 → WB-3

**T-025 보고서 포함 수 단일 출처** (3 h · W1-c)
- 대상·수용: 부록 F 표. 함수 하나(`report_candidate_count`)를 보고서 생성(`build_run_case_report` 경로)·`/review-counts`·(이후) `/brief.review.include_in_report`가 호출한다.
- 검증: 신규 `tests/test_r8_report_candidates.py`(DB만·JSON만·둘 다·중복·DB 손상 5경우) + `python -m unittest tests.test_r7s1_rereview_reports tests.test_rapidtriage_case_db`.
- 주의: 응답의 기존 키(`include_in_report`, `case_json`, `report_candidates`)는 이름 유지. 프런트 `ReportDialog.tsx:136`은 `report_candidates:null`을 "확인 실패 — 다시 시도"로 보여야 한다(프런트 반영은 T-110, 그 전까지는 "확인 중" 대신 오류가 보이도록 `error` 필드만 추가).
- 〔v3〕 T-025 → WB-1(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: 한 판정 함수 `is_report_candidate`(`core/report_candidates.py:15`)를 사건 요약·매니페스트·감정서·`/review-counts`가 같이 쓴다. 5건 픽스처 → 3, `CASE_DB_UNREADABLE` + `report_candidates:null`, `truncated`, 보고서 줄 "케이스 DB 표시 n건 중 최근 5,000건만 반영함". **계획과 다른 이름(코드가 정본)**: 함수는 `report_candidate_count(store, run_id)`, 반환 키는 `count`·`case_db`·`case_json`·`truncated`·`error`. **남은 것**: ① 중복 제거 키가 `bookmark_id`라 DB와 JSON에 같은 대상이 다른 id로 있으면 2로 센다 → 인용 id로 바꾸고 시험 1건 ② 카드의 5경우 중 DB만·JSON만·중복 3경우 시험(현재 2/5) ③ `by_status`·`include_in_report`·`cleared`가 SQLite 오류에서 조용히 0 → `null` + `error` ④ 실데이터 QA-075·176)

**T-027 사건 보고서 영문 제거·방어 필드 추가** (4 h · W1-c)
- 대상·수용: 부록 F 표(줄 목록 포함).
- 할 일 보충: 허용 목록(고유명사 `RapidTriage`·`Windows`·`SHA-256`·`MD5`·파일명·경로) 밖의 ASCII 단어 3자 이상이 제목·필드 라벨에 0. `status= report= tags= note=`는 "판단 · 보고서 포함 · 태그 · 메모" 표 열로. 작성자 기본 `web-ui`는 "(작성자 미지정)".
- 검증: `python -m unittest tests.test_r7s1_rereview_reports tests.test_rapidtriage_output_samples` + `python scripts/r8-report-audit.py <샘플 폴더>`.
- 주의: `case_report.py`는 금지 구역. 템플릿 id(`executive-summary` 등)와 요청 스키마는 바꾸지 않는다. 표 그리기(세로선 문자)는 T-108·T-109.
- 〔v3〕 T-027 → WB-8(부록 F 표 우선; 〔리뷰〕 병합분이 `case_report.py:127`에 범위 고지 줄을 넣어 줄 번호가 +2 밀렸다(부록 B의 고친 번호를 본다).)

**T-028 번들·검증 패키지가 케이스 DB 검토 반영 + 감사 입력에 케이스 DB** (3 h · W1-c) — 부록 F 표. 검증: `python -m unittest tests.test_rapidtriage_case_export tests.test_r7s1_rereview_reports tests.test_rapidtriage_audit`. 주의: `api/app/runops.py`는 이 묶음에서 이 과제만.
- 〔v3〕 T-028 → WB-3(부록 F 표 우선; v3: 번들 보고서에 `run_summary` 전달(공란 0))

**T-029 내보내기 감사 누적·시간대·도구 버전** (3 h · W1-c)
- 대상·수용: 부록 F 표.
- 할 일 보충: 누적 파일은 줄 단위 추가(`open(..., "a")` + `flush` + `os.fsync`), 한 줄 = JSON 1건. 사이드카 확장자가 `.md`인데 내용이 JSON인 문제는 **이름을 바꾸지 않고**(계약) 누적 파일로 해결하고, known-limitations에 "사이드카는 최신 1건, 이력은 `rapidtriage-export-audit.jsonl`"을 적는다(T-119).
- 검증: `python -m unittest tests.test_rapidtriage_audit tests.test_rapidtriage_reviewer_attribution`.
- 주의: `core/audit.py:125`의 시각만 이 과제가 고친다(나머지 34곳은 T-132). 읽기 전용 처리에서는 누적 파일도 쓰지 않는다(T-032 관문).
- 〔v3〕 T-029 → WB-4(부록 F 표 우선; 〔리뷰〕 검증 함수는 사슬 필드가 없는 옛 줄을 "사슬 이전 n줄"로 센다(깨짐이 아니다 — T-355가 시험한다). `audit_event` 표에는 수정·삭제 금지 트리거가 이미 있다(`core/case_db/constants.py:799-809`). 이 과제의 대상은 내보내기 감사 파일이다. 검증 명령은 T-359.)

**T-030 GET이 쓰지 않게(6경로)** (4 h · W1-c)
- 대상·수용: 부록 F 표.
- 할 일 보충: 프런트 다운로드 흐름 — "내보내기" 확인 → POST(쓰기, `written[]` 응답) → 저장본 GET으로 내려받기. 기존 다운로드 링크(접수의 5개)는 저장본이 없으면 "아직 내보내지 않았습니다 — 내보내기" 상태로.
- 검증: `python -m unittest tests.test_r7s1_rereview_reports tests.test_rapidtriage_api_contract` + 신규 `tests/test_r8_get_is_readonly.py`(OpenAPI의 GET 전수를 TestClient로 호출하고 결과 폴더 스냅샷 비교) + `cd frontend && npx vitest run src/features/case/r7s1Exports.test.tsx`.
- 주의: `routes_reports.py`는 금지 구역. 응답 본문 모양(매니페스트·패키지 JSON)은 불변.
- 〔v3〕 T-030 → WB-1(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: 보고서 7경로 GET이 쓰지 않는다 — 조회 둘은 메모리 계산(`routes_reports.py:96,153`), 파일 다섯은 저장본 또는 404 `EXPORT_NOT_WRITTEN`(`:67-78,146,192,221,228,283`), 생성은 POST(`:107`). 추출 zip 생성도 POST로 옮겼다. **남은 것**: ① 프런트에 `EXPORT_NOT_WRITTEN` 처리가 없다 → "아직 내보내지 않았습니다 — 내보내기" 상태 1개 ② `/saved` GET 둘의 404에 오류 코드 ③ 전후 스냅샷 시험을 7경로 전부로(현재 6 + 조회 2 + 추출) ④ 위 수용의 "OpenAPI의 모든 GET"은 보통 처리에서 성립하지 않는다(썸네일·지연 색인 캐시 — GAP-361). 그 문장은 T-349로 옮겼고 이 과제의 수용은 보고서 7경로 7/7이다)

**T-031 가져오기·샘플·찾아보기 경로 범위** (4 h · W1-d 1단계) — 부록 F 표가 명세 전부다. 검증: `python -m unittest tests.test_rapidtriage_sample_case tests.test_rapidtriage_browse tests.test_rapidtriage_remote_mode tests.test_r7_no_output_in_evidence` + 신규 `tests/test_api_path_scope.py`. 주의: 샘플 삭제 조건 변경은 CLI `sample` 명령에도 적용된다 — CLI에서 `--overwrite`를 명시하면 표식 파일이 있을 때만 삭제.
- 〔v3〕 T-031 → WB-2(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: (1) 샘플 — `~/.rapidtriage`/`RAPIDTRIAGE_SAMPLE_ROOT` 밖 403(`routes_case_db.py:89-104`), 기본 `overwrite=False`(`models.py:79`), 표식이 있을 때 샘플 항목만 삭제·아니면 409(`core/sample_case.py:53-80`), 증거와 겹치면 422. (2) 가져오기 — `output_dir`를 실제 폴더로 고정, 폴더 밖 `outputs`는 `IMPORT_OUTPUT_OUTSIDE_FOLDER`, 증거 안이면 `readonly_reason="OUTPUT_INSIDE_EVIDENCE"`(`core/jobs.py:793,2391-2431`). 계획이 적은 `output_inside_evidence=True`는 쓰지 않는다(코드 이름이 정본). **남은 것**: (3) 찾아보기 범위 전부 — `--browse-root`가 어디에도 없고 `routes_meta.py`·`core/browse.py`는 병합에서 바뀌지 않았다. 3모드(루프백 전체 / 원격 루트 안 200 / 원격 루트 밖 403) 시험 3/3. 가져온 요약의 읽기 루트 신뢰는 T-350)

**T-032 읽기 전용 결과 모드 — 관문** (4 h · W1-d 2단계)
- 대상·수용: 부록 F 표.
- 할 일 보충: `run_readonly_reason(job)`는 (a) T-031이 기록한 `readonly_reason`, (b) 서버 단위 읽기 전용(T-112가 나중에 켬), (c) 결과 폴더가 그 처리의 증거 경로 안/같음(`core/output_guard.check_output_outside_evidence` 재사용, 가져오기 시점 1회 계산해 처리에 저장)을 본다. `may_persist(output_dir)`는 처리 → 사유 조회 캐시(O(1)).
- 검증: 신규 `tests/test_r8_readonly_run.py`(비-GET 전수 409, GET 후 스냅샷 동일 — 색인류는 T-133·T-134 뒤에 완전 통과하므로 이 과제에서는 썸네일·메모·미들웨어만 단언) + `python -m unittest tests.test_r7_no_output_in_evidence`.
- 주의: 미들웨어는 경로에서 처리 ID를 뽑는다(`/api/runs/{id}/…`, `/api/cases/{id}/…`는 사건의 처리 중 하나라도 읽기 전용이면 해당 처리 쓰기만 거부). 일반 처리의 지연 ≤ 1 ms(요청당).
- 〔v3〕 T-032 → WB-3(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: 미들웨어 409 `RUN_READ_ONLY`(`factory.py:89-108,230`), `/api/case-db/*`의 본문 지정 DB 거부(`:197-203`), `GET /api/runs/{id}`에 `readonly_reason`(`core/jobs.py:301`), 썸네일 메모리 응답, 메모 409, 프로세스 감사 훅(`core/readonly_runs.py:158`), 복원된 옛 처리 소급 표시(`jobs.py:1075-1079`). **계획과 다른 이름(코드가 정본)**: `api/app/readonly_run.py`는 없다. 판정은 `core/readonly_runs.py`의 `may_persist`. **남은 것**: ① 허용 POST 4개(`/search/count`·`query`·`entities`·`hashes` — 읽기 질의, `factory.py:86`)를 부록 D.10과 시험에 명시(위 "허용 목록: 없음"을 이것으로 고친다) ② `/api/cases/{id}/…` 쓰기를 경로에서 거부 ③ OpenAPI 비-GET 전수 시험(현재 8건) ④ 훅이 못 막는 둘(이미 있는 SQLite 파일 쓰기·삭제)의 차단과 시험 ⑤ 일반 처리 타이밍 ±5% 측정 1회. `/dashboard`의 `readonly_reason`과 화면 띠는 T-348)

**T-033 CLI 단일 파일 출력 기본 위치 가드** (4 h · W1-e) — 부록 F 표. 보충: "증거 폴더"의 판정은 명령이 받은 입력 경로(루트·이미지) 기준으로 cwd가 그 안/같음일 때. 입력 경로가 없는 명령(`doctor` 등)은 cwd에 증거 확장자 파일(E01 계열 등, `core/browse.py`의 `EVIDENCE_FILE_SUFFIXES`)이 있으면 경고만. 검증: `python -m unittest tests.test_cli_output_guard tests.test_rapidtriage_artifacts_cli tests.test_r7_no_output_in_evidence`.
- 〔v3〕 T-033 → WB-4

**T-034 파괴적 동작 표현·기본 포커스** (3 h · W1-d)
- 대상: `frontend/src/features/case/Modal.tsx`(포커스 트랩 `:39-57`), `CasePicker.tsx`(삭제 대화상자 `:217-236`), `commands.ts`(`:196`).
- 수용: 삭제 버튼은 `button danger`(primary 아님), 대화상자가 열리면 `document.activeElement`가 "취소". 명령 라벨 = 대화상자 제목("처리 결과 삭제…" 한 표현). Tab 순환에서 `aria-disabled="true"`·`hidden`·`display:none` 요소 제외(단위 테스트 4경우).
- 검증: `cd frontend && npx vitest run src/features/case`.
- 주의: 삭제 대상·API 호출은 불변. `Modal`은 W4의 `Dialog`로 대체될 때까지 유지.
- 〔v3〕 T-034 → WB-4

**T-035 한글 모드 단축키·팔레트 순위** (3 h · W1-d) — 부록 F 표. 검증: `cd frontend && npx vitest run src/shell/CommandPalette.test.tsx src/commands` + 신규 `src/shortcuts.ime.test.ts`(이벤트 12종: `Process`+`Slash`+Shift, 자모+`KeyR`, 숫자 `Digit1`, 조합 중). 주의: `KEY_MAP` 33개의 뜻 불변.
- 〔v3〕 T-035 → WB-4(부록 F 표 우선)

**T-036 표시 해제 = 직전 상태, 실행 취소, 작성자** (4 h · W1-d) — 부록 F 표. 검증: `cd frontend && npx vitest run src/features/grid/reviewActions.test.ts src/components/ToastRegion.test.tsx src/features/review` + QA-065 스펙 골격. 주의: 실행 취소 스택은 새로고침하면 사라진다(문구 "방금 한 표시만 되돌릴 수 있습니다"). 일괄 표시(n건)는 한 단위로 되돌린다.
- 〔v3〕 T-036 → WB-5(부록 F 표 우선)

**T-144 메모 보호·태그 관리 작성자 칸** (3 h · W1-d) — 부록 F 표. 검증: `cd frontend && npx vitest run src/features/dashboard src/features/review`. 주의: `caseCards.tsx`의 메모 블록 밖(증거·해시 라벨)은 T-129.
- 〔v3〕 T-144 → WB-6 · T-129 → WB-9(부록 F 표 우선; v3: 세그먼트별 값을 주로 표시, 기록된 취득 해시(T-181)가 있으면 세 번째 줄로)

**T-129 증거 해시 표시 정직화** (3 h · W1-e) `[확인]`
- 대상·수용: 부록 F 표.
- 할 일 보충: 판정에 필요한 "E01 계열인가"는 서버가 이미 `hash_scope.scope`(`ewf-container-segment-bytes` / `file-bytes`, `core/e01_hash.py:134-138`)로 준다 — 프런트는 이 값으로 문구를 고른다. 서버 메시지(`case_workspace.py:259-260`)는 "E01 컨테이너 파일 바이트 {알고리즘} 기대값 … / 계산값 … (매체 해시와는 비교하지 않았습니다)"로.
- 검증: `python -m unittest tests.test_rapidtriage_e01_hash tests.test_rapidtriage_case_intake` + `cd frontend && npx vitest run src/features/dashboard src/features/case/caseIntake.test.tsx`.
- 주의: 상태값 문자열(`matched`·`mismatched`·`computed`·`failed`)·DB 열·해시 계산은 불변. 매체 해시 계산·내장 해시 대조는 T-125(승인).
- 〔v3〕 T-129 → WB-9(부록 F 표 우선; v3: 세그먼트별 값을 주로 표시, 기록된 취득 해시(T-181)가 있으면 세 번째 줄로)

**T-131 케이스 DB 동시 쓰기** (4 h · W1-e) `[확인]` — 부록 F 표. 검증: `python -m unittest tests.test_rapidtriage_case_db tests.test_axiom_e3_review_tools` + 신규 `tests/test_r8_case_db_concurrency.py`(스레드 2개 × 100행 교차, 유실 0·이력 200) + QA-012 스펙. 주의: `bulk_load` 경로(`journal_mode=MEMORY`)는 건드리지 않는다.
- 〔v3〕 T-131 → WB-8(부록 F 표 우선)

**T-132 산출물·감사 시각에 시간대 포함(35곳)** (3 h · W1-e) `[확인]` — 부록 F 표. 보충: 치환은 기계적(`dt.datetime.now().isoformat()` → `now_local_iso()`), 파일별 1커밋이 아니라 한 PR에 목록 표. 출력 샘플·스냅샷 테스트가 시각 형식을 고정하면 정규식 단언으로 바꾼다. 검증: `python -m unittest tests.test_rapidtriage_timeline tests.test_rapidtriage_audit tests.test_rapidtriage_output_samples`.
- 〔v3〕 T-132 → WB-5

**T-133·T-134 읽기 전용 결과: 지연 쓰기 차단** (각 4 h · W1-e) — 부록 F 표. 공통 검증: `tests/test_r8_readonly_run.py`에 화면별 시나리오(타임라인·지도·계열·폴더·레지스트리·정렬 / 미디어 유사·SQLite·특이사항·조건·검색)를 더하고, AST 검사(대상 파일에서 `write_text`·`write_bytes`·`open(…, "w")`·`mkdir`·쓰기용 `sqlite3.connect`가 `may_persist` 분기 밖에 0)를 테스트로 둔다. 주의: 일반 처리의 캐시 파일 이름·형식 불변(전/후 바이트 동일).
- 〔v3〕 T-133 → WB-4(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: 9파일의 디스크 쓰기는 전부 `index_persist_enabled(path)` → `may_persist`를 거친다(`timeline_index.py:886,1023`, `geo_index.py:470`, `families.py:592`, `index_cache.py:23-30`). 나머지 6파일에는 HEAD에 디스크 쓰기 지점이 없다. 위 수용의 "`may_persist(output_dir)`를 거친다"는 `index_persist_enabled` 경유를 포함한다. **남은 것**: ① AST 시험(쓰기 호출 직접 사용 0, 9/9 파일) ② 화면 6종(타임라인·지도·계열·폴더·레지스트리·정렬)을 연 뒤 스냅샷 동일 6/6 ③ 일반 처리의 캐시 파일 목록이 병합 전과 같음 1회) · T-134 → WB-4(부록 F 표 우선; **병합분(bc6c970, 코드 확인)**: 검색 이력·저장 건수 쓰기 가드(`search_index_service.py:457,732`). `media_similar`·`media`·`sqlite`·`triage_flags`·`row_conditions`에는 HEAD에 디스크 쓰기 지점이 없고, `previews.write_json_file`은 내보내기 POST에서만 불려 관문이 막는다. **남은 것**: ① 색인 생성 요청의 전용 문장이 없다(일반 `RUN_READ_ONLY` 문구가 나온다) ② 이력 `_write` 자체 가드(호출자 가드와 훅에만 기댄다) ③ AST 시험 7/7 파일 ④ 화면 5종(미디어 유사·SQLite 미리보기·특이사항·조건·검색) 스냅샷 동일 5/5)

**T-130 4xx 재시도 금지·유휴 폴링·숨은 탭** (2 h · W1-f) — 부록 F 표. 검증: `cd frontend && npx vitest run src/api src/features/analysis` + QA-101 네트워크 예산 스펙 골격. 주의: 처리 중(`queued`·`running`) 폴링 1.5 s는 유지.
- 〔v3〕 T-130 → WB-5

---

## W2 — 실데이터 기준선(코드 변경 없음)

공통: 산출물은 Git 밖 `D:\rapid-qa\derived\r8\w2\T-xxx\`. 저장소에는 `docs/research/r8-w2-baseline.md`(건수만, T-044). 각 과제는 시작·종료 시 증거 스냅샷을 남긴다. 승인이 없을 때의 경로는 부록 E.7.

**T-037 C1 재처리와 수정분 브라우저 재확인** (4 h) — 절차: ① C1을 콘솔 새 사건으로 2회 처리(결과 폴더는 증거 밖) ② QA-002·003(가드)·QA-037(마법사 AD4·AD5)·QA-086(삭제 AD1)·리뷰어 번들(AD2)·필드 검색(AD3)을 스크립트로 ③ 각 결함 번호에 스크린샷 1장 + `events.jsonl`. 수용: AD1~AD5·AD6·AD18·출력 가드 각각 "재확인됨/재현됨" 표, 증거 전/후 동일.
- 〔v3〕 T-037 → WC-1(부록 F 표 우선; v3: 재처리 뒤 기존 표시가 같은 대상에 붙는지 확인(QA-187))

**T-039 C2 전수 순회 재실행** (4 h) — imgb-sweep 스크립트(`D:\rapid-qa\derived\r8-review\imgb-sweep\scripts\`)를 재사용해 `tree-sweep.json`(노드별 내비 건수·목록 total·API total)·`timing.json`(콜드 1·웜 3)·`cells.json`(잘림 비율·원시 토큰)을 만든다. 추가(GAP-181): 값 정확성 대조를 2건 → 30건으로 — 레지스트리 값 10(추출된 하이브를 `scripts/registry-reference-diff.py` 또는 외부 도구로), 이벤트 로그 레코드 10(`scripts/evtx-reference-diff.py`), Prefetch 5·LNK 5. 수용: 불일치 목록이 W3~W7 과제의 입력으로 T-044에 전달.
- 〔v3〕 T-039 → WC-3(부록 F 표 우선)

**T-040 C4 AI 스캔 런과 콘솔 확인** (4 h) — AI 도구를 모두 종료 → 홈 AI 폴더 스냅샷 → `run`(AI 읽기 예산 4 GiB) → 스냅샷 비교 → 콘솔 13노드 순회·세션 뷰어·파일 접촉 피벗. 수용: CLI 건수 = 콘솔 건수(노드별), 원본 불변 확정(WAL 임시 복사는 결과 폴더에만).
- 〔v3〕 T-040 → WC-1(부록 F 표 우선; v3: 어댑터별 시간·최대 메모리·행 수 측정 포함("약 45분"은 근거 없음))

**T-042 미실행 분석 실행** (4 h) — OCR(Tesseract 설치 시)·VSS·NTFS 메타(TSK 설치 시)·교차 사건(C1 × C2)·메모리(표본 있을 때). 도구가 없으면 "구성 요소 없음" 화면을 QA-088로 기록.
- 〔v3〕 T-042 → WC-4(부록 F 표 우선)

**T-043 C5 A등급 양성 데이터** (4 h) — C3-VM에서 A규칙 7개의 조건을 하나씩 만든다(예: 보안 로그 지우기, 실행 파일에 대체 데이터 스트림, 시각 조작). 수용: 규칙별 "양성 확보/미확보" 표 — 미확보 규칙은 T-135가 "검증 전"으로 표시.
- 〔v3〕 T-043 → WC-4(부록 F 표 우선; C5의 공개 공격 이벤트 로그 표본 사용) · T-135 → WF-6(부록 F 표 우선)

**T-138 C3-0: 기존 기준선 산출물 가져오기** (3 h) — 부록 F 표. 재처리·승인 없이 대화 보기·사람·장치를 실데이터로 처음 확인하는 경로다.
- 〔v3〕 T-138 → WC-1(부록 F 표 우선)

**T-044 기준선 종합과 재계획 입력** (3 h, Fable) — 부록 F 표.
- 〔v3〕 T-044 → WC-8(부록 F 표 우선)

---

## W3 — 백엔드 지원

**T-045 카탈로그 분류 키와 검증기** (4 h · W3-a 1단계)
- 대상: `rapidtriage/core/triage_rules/catalog/*.yaml` 21개(키 추가만), `catalog/type_defaults.yaml`(신규: 계열 없는 유형 37개의 `tier`·`card`), `rapidtriage/core/triage_rules/catalog.py`(검증·조회 `classify(artifact_type|kind) -> {tier, card, section}`).
- 할 일: 계열마다 `tier: 1|2|3`, `card: <부록 C.2의 12개 id 중 하나 | null>`, `section`. 카드 id 12개: `findings`·`documents`·`email`·`messenger`·`web`·`exfil`·`programs`·`deleted`·`accounts`·`ai`·`timeline`·`people_devices`.
- 수용: 131계열 + C2·기준선에 나온 유형 전부 분류(미분류 0, 검증기가 누락을 오류로). 프런트 fallback JSON(`npm run gen:families`) 재생성. 기존 트리·그리드 동작 변화 0(e2e 13스펙).
- 검증: `python -m unittest tests.test_rapidtriage_triage_rules tests.test_r7_l3_catalog_sources tests.test_rapidtriage_catalog_security && cd frontend && npm run gen:families`.
- 주의: 카탈로그 YAML은 금지 구역. 규칙(`rules`)·열 정의는 건드리지 않는다.
- 〔v3〕 T-045 → WD-1

**T-046 `/brief` 엔드포인트** (4 h · W3-a 2단계) — 계약은 부록 D.6 전부. 구현 순서: 골격(case·evidence·run·review·limits) → 카드 건수(목록 API와 같은 계수 함수 호출) → T-047·T-048 결과 끼우기. 수용: 응답 ≤ 30 KB·서버 처리 ≤ 200 ms(C2, 웜 3회 중앙값; 초과 시 사전 계산 파일을 처리 끝에 만들고 GET은 읽기만 — GET은 쓰지 않는다), `cards[].count`·`findings.counts`·`review.*`가 `link`가 여는 목록 total과 같음(계약 테스트가 SYN 전수 + 실데이터 스크립트). 검증: `python -m unittest tests.test_brief_count_contract`.
- 〔v3〕 T-046 → WD-3(부록 F 표 우선) · T-047 → WD-2(부록 F 표 우선) · T-048 → WD-2

**T-047 0건 사유 판정기** (4 h · W3-a 1단계, 선합의)
- 대상: `rapidtriage/api/app/zero_reason.py`(신규: `zero_reason(card_id, summary, scope) -> {code, message, action}`).
- 판정 순서(먼저 맞는 것): `not_run`(해당 분석·수집기가 계획에 없음) → `not_collected_mode`(처리 모드가 그 수집기를 뺌) → `collector_failed`(수집기 상태 error/`failed-isolated`) → `scope_truncated`(범위 축 중 100% 미만이고 대상 경로가 미처리 영역일 수 있음) → `container_only`(컨테이너 파일은 있으나 내용 미해석: PST·OST) → `encrypted_store`(암호화 저장소 후보 존재) → `no_input`(대상 파일 자체가 없음) → `none_found`(수집기 완료 + 대상 파일을 읽음 + 0행).
- 수용: 단위 테스트 24종(코드 8 × 3경우). `none_found`는 "완료 + 대상 읽음" 증거가 요약에 있을 때만 — 없으면 `no_input` 또는 `not_run`. C2 수동 대조(QA-023): 브라우저 방문 `none_found`, USB `none_found`, 이메일 `container_only`.
- 검증: 신규 `tests/test_r8_zero_reason.py`.
- 〔v3〕 T-047 → WD-2(부록 F 표 우선)

**T-048 사용 기간·주요 프로그램·다음 할 일 산정** (4 h · W3-a 1단계, 선합의) — 부록 F 표. 보충: `next_action` 규칙 5종 우선순위 = ① 무결성 불일치 → "증거 확인" ② 범위 축 중 100% 미만 → "처리 범위 보기" ③ 실패 단계 → "실패 단계 다시 시도" ④ 미검토 특이사항 → "먼저 확인할 것 검토" ⑤ 보고서 포함 ≥ 1 → "보고서 미리보기". 검증: 신규 `tests/test_r8_brief_insights.py`.
- 〔v3〕 T-048 → WD-2

**T-049 `/summary`·`/runs/{id}` 다이어트, 압축·ETag** (4 h · W3-a 1단계) — 부록 F 표. 보충: gzip은 `GZipMiddleware(minimum_size=1024)`, ETag는 요약 파일 mtime_ns + 크기. `?fields=` 없는 기존 호출의 본문은 불변(호환). 수용: 첫 로드 전송 합계 측정(QA-101)에서 `/api/runs/{id}` ≤ 100 KB(기본 응답에서 큰 목록을 `compact` 기본으로 바꾸는 것은 **금지** — 프런트가 `?fields=`를 쓰게 한다, 프런트 변경은 T-073·T-116). 검증: `python -m unittest tests.test_rapidtriage_api tests.test_rapidtriage_api_contract`.
- 〔v3〕 T-049 → WD-1 · T-073 → WF-1(부록 F 표 우선) · T-116 → WH-2(부록 F 표 우선; v3: 번들 예산을 1.0 MB로 내린다(T-156 기준선 갱신))

**T-050 CLI `brief --json`** (2 h · W3-a 3단계) — `/brief`와 같은 함수 호출, 봉투·종료 코드는 부록 D.8. 검증: 신규 `tests/test_r8_cli_brief.py`.
- 〔v3〕 T-050 → WD-4(부록 F 표 우선; 파서 분할(T-159) 뒤 `cli/parsers/run.py`에 등록)

**T-051 유형 색인과 캐시** (4 h · W3-b 1단계)
- 대상: `rapidtriage/api/app/artifact_type_index.py`(신규), `rapidtriage/api/app/artifact_filter.py`(유형 필터만 걸린 요청의 색인 분기).
- 할 일: 종류별 JSONL을 한 번 훑어 `artifact_type → [바이트 오프셋]`을 만들고(`SingleFlightIndexCache` 재사용, 저장은 `may_persist`가 허용할 때 결과 폴더에), 유형 필터 요청은 오프셋으로 직접 읽는다. 다른 조건이 함께 있으면 색인으로 후보를 좁힌 뒤 기존 판정.
- 수용: C2(또는 C2) 레지스트리 유형 노드 23개 전부 ≤ 1.0 s(웜)·첫 요청 ≤ 2.0 s(색인이 처리 끝에 미리 만들어진 경우), `total` 확정(null 0), 색인 전/후 결과 행 동일(노드 23개 × 첫 250행 해시 비교).
- 검증: `python -m unittest tests.test_rapidtriage_api_field_filters tests.test_r6_s3_files_cache` + `scripts/perf-r6.py` 방식의 타이밍 기록.
- 주의: GET 요청 안에서 색인을 **쓰지 않는다**(IS-066) — 색인 생성은 처리 끝 사전 계산 또는 T-054 작업. 색인이 없으면 기존 스캔 + `notice`.
- 〔v3〕 T-051 → WD-1

**T-052 검색 `lang:`·`list:`·부정 조건 구동·예산 고지** (4 h · W3-b 1단계) — 대상: `core/search_index/engine.py`(`field_lang` `:1154-1163`, `field_list` `:1183-1209`), `api/app/routes_search_index.py`(`:397-429` 후처리). 할 일: 부정 필드 조건이 전체 문서를 훑지 않게 구동 조건(양의 조건) 또는 문서 id 범위로 나눠 평가, 후처리(관련 행 붙이기)도 같은 마감 시각 안에서. 수용: C2에서 `-lang:ko 계약`·`list:execution`·`pdf OR docx` 각 ≤ 3 s, 어떤 질의도 15 s 안에 응답(초과분은 `notice`), 결과 집합 불변(전/후 문서 id 비교 — 빨라진 질의 10종). 검증: `python -m unittest tests.test_search_query tests.test_search_api tests.test_r7_search_latency tests.test_r7_p2_search_v2`.
- 〔v3〕 T-052 → WD-2(부록 F 표 우선; 원인 확정(T-216) 뒤 수정)

**T-053 파일 목록 서버 필터·정렬 키 검증** (4 h · W3-b 1단계) — 대상: `api/app/files_index.py`(`extension_bits` `:310` 활용), `frontend/src/features/filters/filterModel.ts`(`:386-391`). 수용: `ext=docx,mp4,sqlite,eml` 서버 처리, 건수 = JSONL 직접 집계(QA-027), 무효 `sort` 키는 422 + 봉투(조용히 버리지 않음), "불러온 행에서만" 배너 코드 경로 삭제. 검증: `python -m unittest tests.test_r6_files_sections tests.test_r7_files_sort` + `cd frontend && npx vitest run src/features/filters`.
- 〔v3〕 T-053 → WD-1

**T-054 백그라운드 작업 틀** (4 h · W3-b 1단계) — 대상: `api/app/bg_jobs.py`·`routes_bg_jobs.py`(신규). 계약: `POST …` → 202 `{job_id, status:"queued"}`, `GET /api/jobs/{id}` → `{status: queued|running|completed|failed|cancelled|interrupted, progress: 0..1, message, result_url, started_at, finished_at}`, `POST /api/jobs/{id}/cancel`, `GET /api/runs/{id}/jobs`(목록). 직전 결과가 있으면 요청 응답에 `previous_result_url`. 서버 재시작 시 실행 중이던 작업은 `interrupted`. 수용: 단위 테스트(등록·진행·취소·실패·재시작) + 동시 3개 제한. 검증: 신규 `tests/test_r8_bg_jobs.py`.
- 〔v3〕 T-054 → WD-1

**T-055 계열·중복·예외·케이스 DB 준비·추출 zip을 작업으로** (4 h · W3-b 2단계) — 수용: 다섯 요청 모두 응답 ≤ 1 s(C2; 계산 중이면 202 + 직전 결과), 완료 뒤 결과가 동기 계산과 동일(바이트 비교), 읽기 전용 처리에서는 메모리 계산 + 저장 없음. 프런트는 202를 "다시 계산 중" 띠로(임시; 작업 센터는 T-081). 검증: `python -m unittest tests.test_r7_a_dedup tests.test_r7_a_families tests.test_r7_a_irregular tests.test_rapidtriage_extract`.
- 〔v3〕 T-055 → WD-2(부록 F 표 우선; 〔리뷰〕 병합분이 추출 zip 생성을 `POST /extract` 안의 동기 작업으로 옮겼다(`routes_runs.py:1680`, `POST /extract/{name}/zip` 추가). 이 과제는 그 POST를 작업으로 바꾼다(GET은 이미 저장본만 준다).) · T-081 → WF-2(부록 F 표 우선)

**T-057 문서 단위 검색 응답** (4 h · W3-c 1단계) — 대상: `api/app/search_documents.py`(신규), `routes_search_index.py`(등록·호출). 응답: `documents[]: {doc_key(파일 경로 또는 대화 id), title, hit_count, snippets[≤3](≥40자, 가림 적용), locations[], related_rows[], time}` + `hidden_expert_hits`(Tier 3 적중 수) + 기존 pagination·notice. 수용: 같은 파일이 두 번 나오지 않음(1,000건 표본 중복 0), 스니펫 길이 ≥ 40자(본문이 더 짧으면 전체), 비밀 패턴 원문 0. 검증: `python -m unittest tests.test_search_hits tests.test_search_api` + 신규 `tests/test_r8_search_documents.py`.
- 〔v3〕 T-057 → WD-3(부록 F 표 우선; v3: 응답에 `partial`(예산 중단 여부)을 실어 묶음·보고서가 기록)

**T-058 사람·장치 롤업 파생 표** (4 h · W3-c 1단계) `[확인]` — 대상: `core/derived/tables_people_devices.py`(신규), `core/derived/engine.py`(등록만). 규칙: 계정은 SID 뿌리로 묶고 시스템·서비스 계정은 `hidden:true`(대화형 로그온이 있는 내장 계정은 보임), 장치는 시리얼 키로 USB 3출처(레지스트리·setupapi·이벤트) 병합. 수용: C3-0(기준선)에서 장치 5대 = 5줄, 숨긴 시스템 계정 수 표시, 수집기 출력 불변(전/후 JSONL 해시). 검증: `python -m unittest tests.test_rapidtriage_derived_engine tests.test_rapidtriage_derived_api`.
- 〔v3〕 T-058 → WD-2

**T-059 확장자 위장 잡음 분리·복구본 내용 상태** (4 h · W3-c 1단계) — 대상: `api/app/tree.py`(예외·불일치 집계 지점), `api/app/previews.py`, `api/app/irregular_view.py`(신규). 규칙: 경로가 `_deleted_mft/`로 시작하거나 서명 종류가 `zero-filled`·`high-entropy-binary`·`binary-unknown`인 불일치는 "확장자 위장"에서 빼고 "내용 복구 불가"로 따로 센다. 미리보기 응답에 `content_state: "ok"|"partial"|"unrecoverable"|"empty"`(앞 4 KB가 전부 0이면 unrecoverable, 길이 0이면 empty). 수용: C2에서 확장자 위장 건수 22,954 → 사용자 폴더 문서·압축·이미지 서명 불일치만(잡음 3종 0), 분리 수의 합 = 원래 수(QA-025). 검증: `python -m unittest tests.test_rapidtriage_files_signature tests.test_r7_a_irregular`. 주의: `tree.py`의 노드 id·`KIND_LABELS` 불변, 수집기 출력 불변(D33 (a)).
- 〔v3〕 T-059 → WD-2(부록 F 표 우선; 판정은 `core/content_state.py`(T-185) 사용)

**T-060 개체 요약 작업화·검색 색인 분석 건수** (3 h · W3-c 2단계) — 수용: `POST …/search/entities` body `{}`가 202 + 진행(또는 캐시된 직전 결과 200), C2에서 완료, 색인 분석 카드가 "완료 n건"(n = 색인 문서 수, 약 76.5만). 검증: `python -m unittest tests.test_r7_b_patterns tests.test_search_index_build`.
- 〔v3〕 T-060 → WD-4

---

## W4 — 디자인 시스템(추가 방식)

공통: 새 컴포넌트는 `frontend/src/components/ui/`에 두고 **기존 화면을 바꾸지 않는다**(교체는 W5~W7 과제). 각 컴포넌트는 `*.test.tsx`(역할·이름·키보드)와 스토리 대용 `ui/_gallery.tsx`(개발 전용 경로) 한 칸을 가진다. 사양은 부록 C.5(토큰 값)·C.6(속성 표). 검증 공통: `cd frontend && npx vitest run src/components/ui && npm run check:tokens && npm run check:contrast`.

**T-061 토큰 v3** (4 h · W4-a 1단계 단독) — 부록 C.5의 토큰 표를 `tokens.css`에 **추가**하고 옛 토큰(`--fs-*`, `--surface-*`, `--status-*`)은 값 그대로 둔다(이름 별칭만: 새 토큰이 주인, 옛 토큰이 `var(--새토큰)`을 가리키게 바꾸는 것은 색 값이 같은 것만). 테마: `prefs.ts`의 `theme: "system"|"light"|"dark"`(기본 `system`), `index.html` 부트 스크립트가 저장값이 없거나 `system`이면 `prefers-color-scheme`을 따르고 변경 리스너를 단다. 수용: 저장값 없는 새 프로필에서 OS 라이트 → 라이트로 시작, OS 전환 시 300 ms 안에 반영, 기존 저장값(`light`·`dark`) 존중, 대비 검사 통과, `tnum` 실측 결과(Pretendard 서브셋에 `tnum` 유무)를 PR에 기록 — 없으면 숫자 열에 `--font-mono`. 주의: `app/themeBoot.test.ts`·`StatusChip.test.tsx`가 색·속성을 읽는다.
- 〔v3〕 T-061 → WE-1(부록 F 표 우선; 릴리스 이름 토큰 금지(D70))

**T-062 `Chip`·`CountBadge`** — 수용: `kind` 6종 × 상태 전부가 색 + 모양(아이콘) + 글자를 가짐(아이콘만·색만 0), `CountBadge`는 10,000 이상에서 `1.2만` 표기 + `aria-label`에 정확한 수 + `data-count`, 배지 잘림 0(부모 폭 120px 테스트).
- 〔v3〕 T-062 → WH-1(부록 F 표 우선; 수렴은 마지막 물결(D70))

**T-063 `EmptyState`·`InlineAlert`·`Skeleton`·`PartialBanner`·`HiddenBanner`·`SectionBoundary`** — 수용: `EmptyState type` 5종(none·filtered·error·not-run·partial) 각각 아이콘 40 + 제목 + 이유 + 동작 1, `InlineAlert` 4종, 오류 틀 4칸(무슨 일·영향·할 일·접힌 기술 정보), `Skeleton`은 300 ms 미만이면 표시 안 함, `SectionBoundary`는 자식 오류를 잡고 "이 부분을 표시하지 못했습니다 — 다시 시도"(나머지 화면 동작).
- 〔v3〕 T-063 → WE-2

**T-064 `Dialog`** — 수용: 폭 480·640·800, 높이 고정(뷰포트 80% 상한, 내용 스크롤), 포커스 트랩이 `aria-disabled`·숨김 제외, 기본 포커스 = 첫 입력 → 없으면 "취소", 닫으면 연 요소로 복귀, `danger`일 때만 확인 버튼 빨강 채움, 단계 전환에서 위치(`top`·`left`) 불변.
- 〔v3〕 T-064 → WH-1(부록 F 표 우선)

**T-065 `Button`·`Checkbox`·`Radio`·`Switch`·`Tabs`** — 수용: 버튼 4변형·높이 32(대화상자 36)·점선 테두리 0, 조작 대상 ≥ 28×28(체크박스 상자 16 + 타깃 28), 부모의 `input` 선택자에 덮이지 않음(`.global-search` 안에 넣는 테스트), `Tabs`는 방향키·Home·End.
- 〔v3〕 T-065 → WH-1(부록 F 표 우선)

**T-066 `TimeText`·`HashValue`·`PathText`·`CopyButton`** — 대상에 `frontend/src/utils/time.ts`(단일 포맷터: `formatGridTime` `:246`·뷰어용 `:208-236`를 한 함수의 옵션으로, `formatDuration` 중복 제거). 수용: 같은 순간이 그리드·뷰어·대화·히스토그램에서 같은 문자열(표시 시간대 KST·UTC·뉴욕 3종 테스트), `title`에 UTC ISO, 사본 시각은 시계 아이콘 + "증거 시각 아님"(이탤릭 0), 해시는 앞 8…뒤 4 + 복사 시 전체.
- 〔v3〕 T-066 → WE-2

**T-067 `Menu` 단일화** — 수용: 행 메뉴·뷰어 메뉴·카드 메뉴가 `Menu` 하나를 쓰고(`MenuButton`은 위임), 타입어헤드, 항목 높이 ≥ 24, T-014의 포털·충돌 보정 유지. 기존 `MenuButton.test.tsx` 통과.
- 〔v3〕 T-067 → WH-1(부록 F 표 우선) · T-014 → WB-1

**T-068 `PageHeader`·`StatRow`·`ZeroReason`·`Disclosure`·`EvidenceStrip`** — 수용: `StatRow`의 숫자는 링크(`<a href>`)이고 `data-count` 보유, `ZeroReason`은 코드 8종 문구 사전(부록 C.3 (2)) + 역할별 행동 1개, `EvidenceStrip`은 무결성 표현 5종(컨테이너 일치·계산됨·미계산·입력값과 다름(호박)·매체 불일치(빨강, T-125 뒤에만))·범위 띠.
- 〔v3〕 T-068 → WE-3(부록 F 표 우선; 화면(브리핑 v0)이 끌어내는 첫 묶음) · T-125 → WP1-1(부록 F 표 우선)

**T-069 전역 링크·입력·포커스 스타일** — 수용: 방문 링크 색 = 일반 링크 색, 라이트 입력 배경 = 배경 1(회색 채움 0), 포커스 링 2px + 간격 2px 통일(키보드 포커스에서만).
- 〔v3〕 T-069 → WE-2

**T-070 인쇄 스타일·화면 복사용 보기** — 수용: 인쇄 미리보기에서 내비·도구 막대·패널 `display:none`, 본문 전폭, 다크에서도 인쇄는 라이트(검정 글자 대비 ≥ 7:1), 브리핑 1장이 A4 세로 1쪽.
- 〔v3〕 T-070 → WE-2(부록 F 표 우선)

---

## W5 — 셸·브리핑·내비·접수 흐름

**T-073 사건 브리핑 화면** (4 h) — 와이어는 부록 C.3 (2), 상태는 C.3.13 표. 수용: 1440×900에서 `document.scrollingElement.scrollHeight <= innerHeight`, 6문항 답 요소 6개(`r8-brief-q1`~`q6`), 숫자 요소 전부 `data-count` + 링크, 상태 5종(로딩 골격·처리 중·미연결·오류·부분) 스크린샷, `/brief` 한 번만 호출(`/summary` 0회). 검증: `cd frontend && npx vitest run src/features/brief && npm run e2e -- e2e/tasks/t1-brief.spec.ts`.
- 〔v3〕 T-073 → WF-1(부록 F 표 우선)

**T-074 랜딩·토큰 화면** (3 h) — 수용: 주 버튼 1("새 사건 만들기") + "사건 열기" 목록 + 준비물 3줄 + 접힌 "다른 방법"(가져오기·빠른 처리·샘플), `landing-*` testid 4개는 대응 요소에 유지. 토큰 화면: 안내 2문장 + 입력 1 + "링크를 받지 못했나요?" 접힘. 잘못된 토큰은 봉투 문장.
- 〔v3〕 T-074 → WF-1(부록 F 표 우선)

**T-075 처리 진행 띠·처리 중 409 제거** (4 h) — 수용: 처리 중에만 띠(단계 한국어명·n/m·경과), "중지"는 실행 중일 때만, 처리 중 계획 조회가 409를 받지 않음(처리 중이면 프런트가 그 엔드포인트를 부르지 않거나 서버가 200 + `locked:true`) — 네트워크 로그 409 0(QA-039). `Layout.tsx`는 띠 삽입 1곳만.
- 〔v3〕 T-075 → WF-1(부록 F 표 우선)

**T-076 다중 증거·케이스 미연결 홈** (3 h · 2단계) — 수용: 증거 2개 사건(C1 + S)에서 증거 전환 시 브리핑이 그 증거의 `/brief`로 바뀜, "전체"는 증거별 한 줄 비교 표(건수·기간·범위·제한), 미연결 처리에는 머리줄 "사건 정보 없음 — 사건에 연결".
- 〔v3〕 T-076 → WF-2

**T-077 살펴보기 범주 내비(검토자 모드)** (4 h) — 수용: 검토자 모드 기본 항목 ≤ 12(부록 C.2), 각 항목 건수 = 목록 total(QA-020), 0건은 "자료 없음 ⓘ" + 사유, "전문가 항목 n건 숨김"의 n = Tier 3 행 수, 분석 담당 모드는 기존 트리 그대로(노드 수 377, id 불변). 프리셋(사건 유형)에 따라 조건부 카드(사진·영상, 위치) 순서만 바뀜. `tree-region`·"케이스 탐색 트리" 유지.
- 〔v3〕 T-077 → WF-2(부록 F 표 우선)

**T-078 분류 사본 제거** (4 h) — 수용: `features/tree/categories.ts` 삭제(import 0), `domains.ts`는 `scripts/gen-domains.py` 생성물(머리말 "손 편집 금지" + 동기화 테스트), 생성 전/후 노드 id·순서·라벨 diff 0(스냅샷), `core/artifact_domains.py`도 같은 출처에서 생성.
- 〔v3〕 T-078 → WF-1

**T-079 새 사건 2단계** (4 h) — 수용: 기본 입력 ≤ 5(사건명·담당자·증거 위치·결과 폴더·처리 깊이), 조작 ≤ 12로 처리 시작, 잘못된 경로 3종이 생성 전 차단·고아 사건 0(사건 목록 API 전/후 동일), 결과 폴더 옆에 "예상 약 n GB · 여유 n GB", 여유 < 예상이면 경고. `wizard-*` testid는 대응 필드에 유지(없어진 단계는 별칭).
- 〔v3〕 T-079 → WF-2(부록 F 표 우선; 디스크 여유 점검은 T-186의 응답 사용)

**T-080 새 처리 대화상자** (4 h) — 수용: 처리 깊이 3(표준·빠른 1차·정밀)·사건 유형 프리셋 6·접힌 세부 설정(그룹 26·상한·`ai_read_mb`·`org_email_domain`), 프로필 표시명 한국어("Fast first pass" 0).
- 〔v3〕 T-080 → WF-2(부록 F 표 우선; AI 입력 3칸(T-191)이 "세부 설정" 안에 들어온다)

**T-081 ⚙ 처리 이력·더 분석하기·작업 센터** (4 h) — 수용: 상태 6종 글자 + 모양, 라벨 없는 X 0(글자 "중지", Tab 도달 가능), 분석 목록 상태 5종(미실행·실행 중 n%·완료 n건·부분 n%·실패 + 할 일), 작업 센터에 T-054 작업 진행·취소, "다시 계산 필요" 표시(GAP-199), `process-*`·`analysis-*` testid 유지.
- 〔v3〕 T-081 → WF-2(부록 F 표 우선) · T-054 → WD-1

---

## W6 — 목록·뷰어

**T-083 DataGrid 분해(동작 불변)** (4 h) — 수용: `DataGrid.tsx` ≤ 600줄, `GridBody`·`GridHeader`·`GridFooter`·`useGridKeyboard`·`gridEmptyState`로 분리, grid 폴더 vitest 전부·e2e 13스펙 통과, 렌더 횟수 회귀 없음(1,000행 스크롤 프로파일 ±10%). 주의: **기능 변경 0** — 동작을 고치고 싶으면 별도 과제로.
- 〔v3〕 T-083 → WF-3

**T-084 카드별 6열·그리드 값 라벨** (4 h) — 부록 F 표. 열 정의는 v1 4.4의 카드별 6열을 카탈로그 `card_columns`로 옮긴 것. 수용: 검토자 모드 전 범주·하위 탭 열 ≤ 6, 시각 열 176px, 같은 값 열 0, 잘림 ≤ 10%(1440·뷰어 열림, QA-044).
- 〔v3〕 T-084 → WF-3

**T-085 뷰어 머리·판단 버튼 줄·메모 영역** (4 h) — 수용: 판단 버튼 3(관련 있음 R·재검토 I·제외 X) + 보고서 포함 토글(P) + 북마크, 누른 뒤 목록·뷰어·건수 반영 ≤ 200 ms(낙관적 갱신, 실패 시 되돌림 + 알림), 메모는 아래로 펼쳐지고 머리 높이 불변. `KEY_MAP`에 `P` 추가(계약 D.5).
- 〔v3〕 T-085 → WF-3(부록 F 표 우선)

**T-086 뷰어 탭(가능한 것만)·보류 사유·이진 안내·원본 가림** (4 h) — 수용: 11종 표본(QA-046)에서 탭 평균 ≤ 4, `withheld`는 사유 문장(자격 증명 파일 등) + 대안, 이진은 "텍스트로 표시할 수 없는 파일입니다 — 헥스로 보기", 원본 탭의 키·토큰 `[가림:종류]` + 해제는 확인 + 감사 1건(케이스 DB 없으면 해제 불가), 탭 전환 ≤ 500 ms.
- 〔v3〕 T-086 → WB-5(부록 F 표 우선)

**T-087 메타 12필드·출처 구역** (4 h · 2단계) — 수용: 첫 화면 필드 ≤ 12, "기술 정보" 접힘, 출처 구역(원본 위치·시각 현지 + UTC·해석 범위) 하단 고정·스크롤 없이 보임, 영문 키 0, `MetaView.tsx` ≤ 600줄. 주의: MetaView 테스트가 문구 40개를 고정 — 계약표 밖은 testid로.
- 〔v3〕 T-087 → WF-4(부록 F 표 우선; 출처 구역은 T-172가 먼저 고친다(같은 파일))

**T-088 트리 단일 구현** (4 h) — 수용: `ExplorerTree`가 `ui/Tree` 사용, 키보드(방향키·Home·End·타입어헤드)·가상화 동작 불변, 탐색기 e2e 통과.
- 〔v3〕 T-088 → WH-1

**T-089 목록 머리·숨김 띠·보기 메뉴** (4 h) — 수용: 화면당 h1 1개, 건수 표기 1회(`1–250 / 1,204건`·`250건 이상`), 숨김 띠 "n건 숨김: 사유별 — 모두 보기", `보기: 표 ▾`(가능한 보기만), T-020의 임시 띠를 `PartialBanner`로 교체.
- 〔v3〕 T-089 → WF-4 · T-020 → WB-3

**T-090 행·뷰어 메뉴 8 + 더 보기, 일괄 막대** (4 h) — 수용: 두 메뉴 항목 동일(열기·관련 있음·제외·태그·보고서 포함·전후 시각·같은 파일·더 보기), 비활성 항목 0, 일괄 막대가 마지막 행을 가리지 않음(마지막 행 `boundingBox` 아래에 막대), 주 동작 1, 라벨은 `citation.ts`의 정본 import.
- 〔v3〕 T-090 → WB-5(부록 F 표 우선)

**T-091 조건 띠(칩 5)·날짜 입력** (4 h) — 수용: 조건 영역이 그리드를 덮지 않음(그리드 `top` 이동), 칩 5 + "조건 더 보기", 날짜는 직접 입력(YYYY-MM-DD) + 달력, `FilterBar.tsx` ≤ 600줄, `filter-popover-button`·"조건"·"적용된 조건" 유지.
- 〔v3〕 T-091 → WF-3(부록 F 표 우선)

**T-092 복구본 표식·기본 정렬·폴더 트리 가상 위치** (3 h) — 부록 F 표.
- 〔v3〕 T-092 → WF-4(부록 F 표 우선)

**T-139 라벨 맵 단일 출처 — 나머지 4곳** (4 h) · **T-143 그리드 페이지 윈도 상한** (3 h) — 부록 F 표.
- 〔v3〕 T-139 → WF-6(부록 F 표 우선) · T-143 → WF-6

---

## W7 — 검색·검토·시간순·AI·사람·장치

**T-093 문서 단위 검색 화면** (4 h · 1단계) — 수용: 한 파일 한 행·펼침(적중 위치·관련 행), 스니펫 ≥ 40자·강조, "전문가 항목에 n건 더 있음"(n = `hidden_expert_hits`), 색인 없으면 "색인 준비 중 n%"(작업), "v2 색인 없음" 문구 0, T2 조작 ≤ 15·≤ 60 s(QA-057).
- 〔v3〕 T-093 → WF-3(부록 F 표 우선; 결과에서 뷰어를 열면 첫 적중 위치로 스크롤(T-228의 적중 이동 사용))

**T-094 검색 옵션·도움말 예시** (3 h) — 수용: 범위 칩 3 + 접힌 옵션, 예시 5개 클릭 → 실행, `created_by:"web-ui"`(`SearchOptionsPopover.tsx:140`) → 담당자.
- 〔v3〕 T-094 → WF-3(부록 F 표 우선)

**T-095 개체 패널** (3 h) — 수용: 진행률 또는 ≤ 3 s 표시, 실패는 봉투 문장 + 다시 시도, "Failed to fetch" 0, C2에서 card·email·ip 칩 각각 목록 열림.
- 〔v3〕 T-095 → WF-4

**T-097 한 건 보기** (4 h · 3단계) — 수용: 50건 키보드만·건당 ≤ 2조작, `J`·`K`·`G`(다음 미검토), 제외 + 보고서 포함이면 경고, 진행률 정확.
- 〔v3〕 T-097 → WF-5(부록 F 표 우선; v3: 1440 미만에서 판단은 아래 고정 막대(56px), 판단 직후 다음 미검토로 자동 이동(설정에서 끔))

**T-098 검토 색·라벨 정본·토스트** (3 h) — 수용: 라벨 정의 1곳(`viewer/citation.ts` `MARK_LABELS`), `reviewActions.ts`·`gridCommands.ts`는 import, "관련"·"선별 해제" 문자열 0, 색 역할표 적용(D35 — 미결이면 색 변경만 보류하고 나머지 진행), 토스트 동시 ≤ 2·성공 초록 체크.
- 〔v3〕 T-098 → WF-4(부록 F 표 우선; 판단 색은 보라 계열(T-221))

**T-099 하루 보기** (4 h) — 수용: 막대 + 목록 한 화면, 막대 합계 = 목록 건수(같은 조건), 축·눈금·값, ◀▶·달력·직접 입력, "다음 기록 있는 날", T3 ≤ 3조작·≤ 15 s.
- 〔v3〕 T-099 → WF-5(부록 F 표 우선; v3: 날짜 없이 열면 기록이 있는 마지막 날)

**T-100 타임라인 기본 "사용자 행위만"·사본 시각 표식** (4 h) — 수용: 기본 조건 Tier 1, 유형 한국어, 폴더 증거(S)에서 사본 시각 아이콘 + 증거 시각 조건에서 제외 사유 문장.
- 〔v3〕 T-100 → WF-5

**T-101 대화 보기 시각·서브에이전트 관계** (3 h) — 수용: `ChatView.tsx:142,357`의 ISO Z 원문 0(`TimeText`), 표시 시간대 일치.
- 〔v3〕 T-101 → WF-5

**T-102 AI 사용 개요** (4 h) — 수용: 개요 1화면(도구 × 계정 × 기간·건드린 파일 상위 10·AI 특이사항), T4 ≤ 2조작·≤ 20 s, 0건 문구, `aiSampleRows.ts`를 `frontend/tests/fixtures/`로 이동(번들에서 제외 확인), `ai-usage-*` 유지.
- 〔v3〕 T-102 → WF-5(부록 F 표 우선)

**T-103 사람·장치 화면** (4 h) — 수용: 계정 묶음 표·장치 표·"시스템·서비스 계정 n개 숨김", 행 → 그 사람·장치로 조건 건 범주 목록.
- 〔v3〕 T-103 → WF-5

**T-104 한국어 기본 키워드·사건 키워드·팩 적중** (4 h) `[확인]` — 수용: 프리셋 6종에 한국어 키워드(초안 표식, D4), 브리핑 `keywords[].hits` = 검색 결과 수, 국내 서비스 호스트 분류 YAML. 주의: `core/run/profiles.py`는 키워드 **추가만**(기존 영문 유지).
- 〔v3〕 T-104 → WF-6

**T-135·T-136·T-137** — 부록 F 표(W7-c).
- 〔v3〕 T-135 → WF-6(부록 F 표 우선) · T-136 → WF-7 · T-137 → WF-6

---

## W8 — 보고서

**T-105 보고서 미리보기 API** (4 h · 1단계) — 응답: `{sections:[{id,title,included,order,items[]}], profile, opinion, scope, checks_url}`. 수용: 미리보기의 절 제목 목록 = 같은 요청으로 내보낸 md의 제목 목록(테스트), GET은 쓰지 않음.
- 〔v3〕 T-105 → WG-1

**T-106 보고서 화면** (4 h · 2단계) — 와이어 부록 C.3 (8). 수용: 3단(구성·종이·점검), 후보 0건이면 빈 상태 + "검토로 이동"·내보내기 비활성, 주 버튼 1, 표시 → 미리보기 ≤ 3조작, 5곳 수치 일치(QA-075).
- 〔v3〕 T-106 → WG-2(부록 F 표 우선; v3: 1280에서 점검은 종이 위 접이식 띠)

**T-107 제출 전 점검 계산** (3 h · 1단계) — 7항목: 무결성 상태, 사건 번호·담당자, 메모 없는 항목 수, 제외 + 포함 모순 수, 처리 범위·제한(빠른 1차만 한 결과면 경고 — GAP-174), 가림 수, 숨긴 전문가 항목 수. 각 항목 `{code, level: ok|warn|block, count, link}`.
- 〔v3〕 T-107 → WG-1(부록 F 표 우선; v3: 점검에 "원값 열람 n건"·"검색이 일부 결과였음")

**T-108 PDF 한글 글꼴·줄바꿈·실제 표** (4 h · 1단계) · **T-109 프로파일·머리글/바닥글·AI 절·DOCX 표** (4 h · 2단계) · **T-110 내보내기 이력·파일 해시·알림 한 줄** (3 h · 1단계) — 부록 F 표. T-110 보충: `ReportDialog.tsx:136` "확인 중" 고착 제거(`report_candidates:null` → "확인 실패 — 다시 시도"), 성공 알림 1줄 + "폴더 열기"(`:93-101`).
- 〔v3〕 T-108 → WG-1(부록 F 표 우선) · T-109 → WG-2(부록 F 표 우선; v3: AI 절에 검사관이 태그한 AI 증거 인용 포함) · T-110 → WG-1(부록 F 표 우선; 〔리뷰〕 병합분: 서버가 읽기 실패를 `error`로 주면 사유를 보인다(`fe/api/caseDb.ts:28-34`, `ReportDialog.tsx:135`). 남은 것: 요청 자체가 실패할 때의 "확인 중" 고착, 이력 해시, 알림 한 줄.)

---

## W9 — AX·정리·잔여

**T-111·T-141·T-142(CLI)**, **T-112(`web --read-only`)**, **T-113·T-140(OpenAPI)**, **T-114(미호출 라우트)**, **T-115(저장 키 이관)**, **T-116(코드 분할)**, **T-117(옛 것 삭제)**, **T-118(S3 전수 재확인)**, **T-119(문서)** — 부록 F 표. 보충:
- T-111: 〔v3〕 봉투는 `_envelope` 한 키(부록 D.8 v3). 89명령을 T-111·246·247·249로 나눴다. 스냅샷 테스트는 `--help`가 아니라 **합성 입력으로 실제 실행한 `--json` 출력의 키 집합**을 고정한다.
- T-112: `--no-browser`는 명시 옵션으로 추가(환경 변수 `RAPIDTRIAGE_NO_BROWSER`는 유지). 비대화형(`not sys.stdout.isatty()`)·CI(`CI` 환경 변수)·`--read-only`에서는 브라우저를 열지 않고 토큰도 출력하지 않는다(파일 `--token-file` 또는 환경 변수로만).
- T-115: 〔v3〕 일괄 이관은 하지 않는다(부록 F: 누적 키 정리만, 옛 키는 그 기능을 고칠 때). `rapidtriage.authToken`(localStorage)은 읽지 않고 발견 시 삭제.
- T-116: 수용 = 첫 화면 JS ≤ 1.0 MB(비압축), 전문가 화면(헥스·SQLite·레지스트리 탐색기·지도·그래프)은 동적 import, 번들 예산 스크립트가 초과 시 실패.
- T-117: 삭제 전에 `grep`으로 import 0 확인, 한 PR에서 새 것 도입과 옛 것 삭제를 같이 하지 않는다(부록 C.8 3항).
- T-118: 재확인 표(`docs/research/r8-s3-recheck.md`)의 행 = 콘솔 리뷰 S3 45건 + P1·P3·P5·P7·P8 + GAP-201. "해소"는 스크린샷 필수.
- 〔v3〕 T-111 → WH-1(부록 F 표 우선; 89명령 한 과제는 불가능 → T-246·247·249로 분리) · T-141 → WH-5(부록 F 표 우선) · T-142 → WH-6(부록 F 표 우선; 인자 654개 전부 번역은 하지 않는다) · T-112 → WB-5(부록 F 표 우선; 〔리뷰〕 재사용할 관문은 병합분의 `api/app/factory.py:89-108`이다(`readonly_run.py`는 없다). 서버 단위 사유 코드 `SERVER_READ_ONLY`를 더한다. 토큰은 로그 파일·비대화형 출력에서 0으로 하되 대화형 터미널의 접속 주소 한 줄은 T-351(링크 복사·토큰 유지·폐기)이 들어갈 때까지 남긴다. 원격 TLS 인증서를 마련하는 절차 10줄을 `docs/rapidtriage-admin-deployment-guide.md`에 적는다(T-119).) · T-113 → WH-2(부록 F 표 우선; 나머지 5개는 T-250~254) · T-140 → WH-8(부록 F 표 우선) · T-114 → WH-8(부록 F 표 우선) · T-115 → WH-2(부록 F 표 우선) · T-116 → WH-2(부록 F 표 우선; v3: 번들 예산을 1.0 MB로 내린다(T-156 기준선 갱신)) · T-117 → WH-2(부록 F 표 우선) · T-118 → WH-2 · T-119 → WH-2(부록 F 표 우선)

---

## W10 — 엔진·수집기(승인 필요) · W11 — 최종 검증

W10(T-120~T-126)은 승인 뒤 착수 시 Fable이 카드로 푼다(각 과제 3개 이하 하위 과제, 전/후 행 비교·`fls-coverage-diff`·`mft-reference-diff`·원본 불변을 수용에 포함). 승인 전에는 카드를 쓰지 않는다 — 스파이크(T-120) 결과에 따라 목표 수치가 바뀌기 때문이다.

W11(T-127·T-128)은 부록 F 표와 마스터 9절이 명세 전부다. T-127의 여섯 분담과 증거 폴더 규칙은 부록 F T-127 행, 판정 규칙은 마스터 9.2.
