# R8 부록 D — 계약표 (주소·인용·testid·접근성 이름·저장 키·오류·`/brief`)

마스터 5절·9절. 이 표는 재설계 동안 **바뀌지 않는 것**의 목록이다. T-001이 이 표를 `frontend/src/contracts/uiContract.ts`(기계가 읽는 형태)와 계약 테스트로 옮기고, 그 뒤 모든 과제는 이 표를 깨면 실패한다. 표에 없는 문구·클래스·레이아웃 상수는 바꿔도 된다(테스트가 그것에 묶여 있으면 〔정정: T-002가 아니라〕 e2e는 T-012가, vitest는 그 화면을 바꾸는 과제가 같은 PR에서 testid·역할 선택자로 옮긴다 — 부록 F.1 "기존 테스트" 규칙).

**2차 적대적 리뷰(2026-11-11) 개정 요지**: ① 오류 봉투와 CLI 봉투를 **추가 방식**으로 바꿨다(D.7·D.8) — 1차안은 기존 테스트 단언 190곳과 기존 자동화를 깬다. ② 접근성 이름 계약을 "7개"에서 "e2e·vitest가 쓰는 이름 전수"로 넓혔다(D.4). ③ 빠져 있던 표면(sessionStorage·팝아웃 메시지·내보내기 파일명·처리 요약 키)을 D.11에 더했다. ④ GET 쓰기 금지의 대상 경로를 3개에서 6개로 고쳤다(D.10).

## D.1 주소(딥링크) 계약

문법(유지): `#/case/{runId}/{stage}/{view}[/{sub}]?query`. 구현 `frontend/src/router.ts`(`parseHash` 334, `serializeRoute` 492, `canonicalizeHash` 611, `captureLaunchToken` 642).

| 구 주소(영구 지원) | R8 정규 주소 | 규칙 |
|---|---|---|
| `…/intake` | `…/home` | 변환, 쿼리 유지 |
| `…/process[/kind]` | `…/tools/process[/kind]` | 변환 |
| `…/explore/{files\|docs\|artifacts\|timeline\|indicators\|search\|analysis\|derived\|registry}[/{sub}]` | 동일 | 변경 없음. 9개 view id 고정 |
| `…/review/board[/status]`, `…/review/flags` | 동일 + 신규 `review/set/{id}`, `review/one/{id}` | 추가만 |
| `…/report/outputs` | `…/tools/outputs` | 변환. 신규 `report/preview`, `report/history` |
| `?popout=viewer` | 동일 | — |
| R6 이전 레거시(`canonicalizeHash`가 이미 변환하는 형태) | 동일 | 기존 변환 표 유지 |

쿼리 키(이름·뜻·인코딩 고정, 삭제 금지): `q, row, mode, from, to, tz, view, category, path, sort, id, cf, cols, status, types, tags, ext, flag, flag_grade, browser, service, note, dir, rec, special, key, wd, hours, offhours, partial, content, geo, family, dup, dup_mode, irregular`. 신규 키는 추가만: `card`, `section`, `day`, `set`, `role`(무시 가능한 힌트).

`row=` 인코딩(`collection:kind:locator`)과 `#token=` 처리(읽은 뒤 주소에서 제거, sessionStorage)는 그대로.

계약 테스트: `frontend/src/contracts/deeplink.contract.test.ts` — 표의 각 구 주소 + 대표 쿼리 30종을 `parseHash → serializeRoute → parseHash`로 왕복, 대상 컬렉션·행·조건이 같아야 한다. e2e `deeplink-compat.spec.ts`가 실제 화면에서 30개를 연다.

## D.2 인용 계약

형식(유지, `frontend/src/features/viewer/citation.ts:76`):
`사건=…; 증거=…; 원본=…; sha256=…; 위치=collection:kind:locator; 레코드=…; 시각=…; 런=…; 통합=…; 특이사항=id@ver (k=v); 바이트=…; 테이블=…`
+ `flagCitation`(`features/flags/flags.ts:172`) + 레지스트리 인용(`features/explorers/RegistryExplorer.tsx:53`).

- 키 이름·순서·구분자(`; `)는 바꾸지 않는다. **`런=` 키는 화면 용어가 "처리"로 바뀌어도 유지**한다(이미 보고서·메모에 붙어 있는 문자열과의 호환). 새 정보는 끝에 추가만: `도구=RapidTriage x.y.z; 규칙=catalog@ver`.
- 검토 판단 라벨은 인용에 "관련 있음·재검토·제외·보고서 포함·북마크"(현 `citation.ts:22-28`)를 정본으로 하고, `grid/reviewActions.ts`·`grid/gridCommands.ts`의 사본은 이 정본을 import한다.
- 계약 테스트: 기존 `viewer/redesign.test.ts`·`r7s1Labels`·`stepLabels`·`valueLabels`·`metaLabels` 테스트의 인용 단언을 `citation.contract.test.ts` 하나로 모은다(문자열 스냅샷 12종).

## D.3 testid 계약

현재 `data-testid` 285곳(고유 약 250), e2e가 쓰는 것 약 70. **e2e·자동화가 쓰는 아래 이름은 새 화면에서도 같은 역할의 요소에 붙는다.** 나머지는 T-001의 추출 스크립트(`scripts/extract-ui-contract.mjs`)가 전수 목록을 만들고 "유지/이름 변경(별칭 1릴리스)/삭제" 열을 채운다.

| testid(유지) | 역할 | 새 화면의 위치 |
|---|---|---|
| `workbench-shell` | 앱 최상위 | 동일 |
| `topbar`, `statusbar`, `stage-rail` | 상단바·상태바·전역 내비 | `stage-rail`은 새 4항목 내비에 유지 |
| `tree-region`, `grid-region`, `viewer-region` | 3영역 | 살펴보기 내비·목록·뷰어 |
| `tree-empty-toggle` | 자료 없는 범주 보기 | 분석 담당 모드 내비 하단 |
| `filter-popover-button` | 조건 열기 | "+조건" 버튼 |
| `viewer-actions-menu` | 뷰어 … 메뉴 | 동일 |
| `theme-toggle` | 테마 | ⚙ 메뉴 안에서도 같은 id |
| `landing-*`(4) | 랜딩 동작 | 새 랜딩의 대응 동작(빠른 처리·샘플은 "다른 방법" 안) |
| `wizard-*` | 새 사건 단계·필드 | 2단계로 줄어도 필드 id 유지, 없어진 단계는 별칭 |
| `analysis-*` | 더 분석하기 | 동일 |
| `ai-usage-*` | AI 사용 | 개요·하위 탭 |
| `derived-*` | 통합 보기 표 | 주인 범주로 옮겨도 표 id 유지 |
| `hist-compare*` | 히스토그램 기준선 | 동일 |
| `tag-*` | 태그 관리 | 동일 |
| `process-*` | 처리 이력 | 동일 |
| `popout-shell` | 뷰어 새 창 | 동일 |

신규 testid 명명: `r8-{화면}-{요소}`(예: `r8-brief-evidence`, `r8-brief-stat-documents`, `r8-zero-reason`, `r8-hidden-banner`, `r8-partial-banner`, `r8-report-preview`, `r8-report-checks`, `r8-review-one`, `r8-day-strip`, `r8-role-toggle`, `r8-job-center`). 숫자를 담는 요소는 `data-count="정수"` 속성을 함께 둔다(계약 테스트·AX가 화면 표기와 무관하게 읽는다).

금지: e2e에서 CSS 클래스 선택자(`.grid-row-stripe`, `.grid-scroll`, `.chat-*`, `.dash-*`, `.hist-cat-label`, `.flag-popover`, `.entity-rows`, `.image-view`, `.thumb-view`) — 〔정정〕 T-012가 testid·역할 선택자로 교체. `boundingBox`·`getComputedStyle` 단언은 `grid-layout.spec.ts`의 레이아웃 계약(가로 넘침 0, 시각 열 폭 ≥176)만 남긴다. 레이아웃 상수 테스트(TREE_DEFAULT 260, VIEWER_DEFAULT 440, 레일 36, 1200/900/1600)는 "범위" 단언으로 완화한다.

## D.4 접근성 이름 계약(한글, 유지)

| 접근성 이름 | 대상 | 비고 |
|---|---|---|
| `원본 뷰어` | 뷰어 영역(`#viewer`) | 랜드마크 |
| `케이스 탐색 트리` | 내비 트리 | 기본 뷰 문구가 "사건"으로 바뀌어도 이 이름은 1릴리스 유지 뒤 `살펴보기 범주`로 별칭 전환 |
| `작업 단계` | 전역 내비 | 유지 |
| `적용된 조건`, `조건` | 조건 칩 영역·버튼 | 유지 |
| `더보기` | 메뉴 버튼 | 유지(행 메뉴는 `더보기 — {항목명}`으로 행 식별 추가) |
| `태그 관리` | 대화상자·버튼 | 유지 |
| 랜드마크 id | `#main`, `#viewer`, `#stage-heading`, `#global-search` | 유지 |

〔2차〕 위 7개는 **대표**다. 계약의 실제 범위는 "e2e 13스펙과 vitest가 `getByRole`·`getByLabel`로 쓰는 이름 전수"(e2e `getByRole` 173회·`getByLabel` 27회, vitest `getByRole` 536회)이고, T-001의 추출기가 고유 이름 표를 `uiContract.ts`에 만든다. 분류: e2e가 쓰는 이름 = `keep`(접근성 이름은 요소당 하나라 별칭을 병기할 수 없다 → **R8 안에서는 바꾸지 않는다.** 전환은 다음 릴리스에서 e2e와 함께), vitest만 쓰는 이름 = `alias`(그 화면을 바꾸는 과제가 테스트와 함께 고칠 수 있다), 아무 테스트도 쓰지 않는 이름 = `free`. 용어 변경(런 → 처리, 케이스 → 사건)이 `keep` 이름과 부딪히면 화면에 보이는 글자만 바꾸고 접근성 이름은 유지한다.

신규 규칙: 표는 `role=grid` + 접근 가능한 이름(범주명) + `aria-rowcount`/`aria-rowindex`/`aria-sort`(현행 유지). 잘린 셀의 전체 값은 접근성 이름에. 페이지 로딩·정렬 변경은 라이브 리전(750 ms 미만은 알리지 않음). 건수 줄임(`1.2만`)의 정확한 수는 접근성 이름에.

## D.5 단축키 계약

`frontend/src/contracts/command.ts`의 `KEY_MAP` 33개가 유일 출처(유지). 기존 키의 뜻은 바꾸지 않는다. 추가: `P`(보고서 포함), `Ctrl+Z`(표시 실행 취소), `G`(다음 미검토 — 한 건 보기에서만). `Alt+1~5`의 5는 보고서 별칭. 글자·숫자 키 단축키는 설정의 "글자 키 단축키 사용"(기본 켬, T-137)으로 한꺼번에 끌 수 있고, 꺼도 `Ctrl+K`·`/`·`Esc`·`Alt+…`·`Ctrl+…`는 동작한다. 한글 입력 상태의 물리 키 폴백 범위는 `Key*`·`Digit*`·`Slash`·`Backquote`(T-035). 용어집의 "보고서 포함(B)" 표기는 오류다(코드에서 B는 북마크) → 용어집을 고친다(D21 보강).

## D.6 `GET /api/runs/{id}/brief` 계약(신규, 30 KB·200 ms 이하)

```json
{
  "schema": "brief.v1", "catalog_version": "…", "tool_version": "…", "generated_at": "…+09:00",
  "case": {"name": "…", "number": "…", "preset": "leak", "owner": "…", "linked": true},
  "evidence": [{"label": "E-01", "kind": "e01", "size_bytes": 0,
     "integrity": {"container": "computed|matched|mismatched|not-requested|failed", "media": "matched|mismatched|not-compared", "computed_at": "…"},
     "scope": {"percent": 31.0, "files_listed": 0, "files_extracted": 0, "files_skipped": 0, "file_limit": 200000, "basis": "native-extraction-stats"}}],
  "run": {"ordinal": 2, "profile_label": "표준", "status": "completed|partial|running|failed", "elapsed_seconds": 0,
          "steps": {"total": 42, "completed": 40, "partial": 1, "failed": 1, "skipped": 0}},
  "machine": {"os": "…", "timezone": "KST", "usage_period": {"from": "…", "to": "…", "basis": "tier1-user-events|unavailable"}},
  "accounts": {"total": 2, "primary": 1, "logons": 153, "hidden_system": 37},
  "programs_top": [{"label": "…", "runs": 0, "link": "#/…"}],
  "activity": {"daily": [["2026-10-12", 157]], "busiest": ["…"]},
  "findings": {"counts": {"A": 0, "B": 6, "C": 35}, "top": [{"grade": "B", "title": "…", "count": 6, "from": "…", "to": "…", "validated": false, "link": "#/…"}]},
  "cards": [{"id": "documents", "label": "문서", "count": 1204, "period": ["…", "…"], "top": [], "link": "#/…",
             "zero_reason": null}],
  "keywords": [{"term": "계좌", "hits": 12, "link": "#/…"}],
  "review": {"relevant": 12, "needs_review": 4, "excluded": 31, "include_in_report": 9, "reviewed_findings": 16, "total_findings": 42},
  "limits": [{"code": "SCOPE_TRUNCATED", "message": "볼륨의 31%만 처리했습니다", "count": 430000, "link": "#/…"}],
  "hidden": {"expert_rows": 432118},
  "next_action": {"code": "process_remaining", "label": "나머지 69% 처리 요청", "link": "#/…"}
}
```
규칙: `cards[].count`·`findings.counts`·`review.*`·`keywords[].hits`는 `link`가 여는 목록의 총건수와 같다(계약 테스트 `test_brief_count_contract.py`가 합성·실데이터에서 전수 비교). `zero_reason` = `{code, message, action:{label, role:"reviewer|examiner", link|copy_text}}`, code는 IS-006의 8종(판정 순서는 부록 H T-047).

〔2차 보강〕 필드 규칙:
- `evidence[].integrity`: `container`는 케이스 DB의 해시 상태값 그대로(`computed|matched|mismatched|not-requested|failed`), `scope`(`"ewf-container"|"file"`, `core/e01_hash.py`의 `hash_scope.scope`에서)를 더한다. `media`는 T-125(승인) 전에는 항상 `"not-compared"`. 화면 표현: `scope=ewf-container`이고 `container=mismatched`·`media=not-compared`면 **호박 "컨테이너 해시가 입력값과 다름 — 매체 해시 미대조"**(빨강 금지, GAP-191). 빨강 "불일치"는 `media=mismatched` 또는 `scope=file`의 `mismatched`에만.
- `evidence[].scope`: 통계가 없으면 `null`이 아니라 `{percent:null, basis:"unavailable"}` — 화면은 "처리 범위 산정 정보 없음".
- `run.readonly_reason`: 읽기 전용 결과면 사유 코드(`OUTPUT_INSIDE_EVIDENCE`·`SERVER_READ_ONLY`), 아니면 `null`.
- `findings.top[].validated`: 카탈로그 `status: verified`이고 (A등급이면) 실데이터 참양성 기록이 있을 때만 `true`. `findings.counts_validated: {"A":0,"B":4,"C":30}`를 더해 "검증됨 n · 검증 전 m" 표기에 쓴다.
- `questions[]`(T-136): `{id, label, count, link, zero_reason}` 8개 이하.
- `generated_at`은 오프셋 포함. 모든 `link`는 부록 D.1 문법의 해시 주소(쿼리 키는 기존 키만).
- 크기 예산 30 KB를 넘기지 않도록 `activity.daily`는 최대 400일, `cards[].top`은 3개, `findings.top`은 5개. `review.include_in_report`는 보고서·`/review-counts`·접수 카드와 같은 함수 하나에서 나온다(GAP-012). `?redact=1`이면 식별자 가림.

## D.7 오류 봉투 계약(신규)

〔2차 개정: 추가 방식〕 모든 4xx·5xx 본문은 **기존 본문을 그대로 두고** 최상위에 `"code": "UPPER_SNAKE"`, `"message": "한국어 문장"`, `"hint": "다음 행동(한국어)"` 세 키를 **더한다**. `detail`은 형과 값을 바꾸지 않는다 — 지금 문자열인 곳은 문자열, 422의 배열은 배열, 출력 가드의 `{code,message}` 객체는 객체 그대로다(`detail_text` 병기는 하지 않는다). 이유: `tests/`에 `["detail"]` 단언이 190곳(32파일), 프런트 `client.ts:79`와 외부 자동화가 `detail`을 읽는다(GAP-193). `detail` 제거는 R9 이후 별도 결정.

`code` 결정 순서: ① `detail`이 `{code}` 객체면 그 값 ② `errors.py` 대응표(영문 리터럴 36종·자주 쓰는 한국어 문장) ③ 상태 코드 기본값(400 `BAD_REQUEST`·401 `UNAUTHORIZED`·403 `FORBIDDEN`·404 `NOT_FOUND`·409 `CONFLICT`·415 `UNSUPPORTED_MEDIA`·422 `VALIDATION_FAILED`·500 `INTERNAL_ERROR`). 신규 코드: `RUN_READ_ONLY`(409), `PATH_OUTSIDE_ALLOWED_ROOT`(403), `EXPORT_NOT_WRITTEN`(404), `CASE_DB_UNREADABLE`(본문 필드), `REVIEW_CONFLICT`(알림용), `SCAN_BUDGET_STOPPED`·`TOTAL_NOT_COUNTED`(목록 `notice`), `NETWORK_UNREACHABLE`·`REQUEST_TIMEOUT`·`REQUEST_ABORTED`(프런트 전용). 500 본문은 `crash_id`만 남기고 `crash_report` 절대경로를 뺀다(이 한 필드만 제거 — 콘솔·테스트 사용처는 T-007이 확인). 코드표 `docs/api-error-codes.md`. 프런트 `api()`는 네트워크 실패(`TypeError`)·중단·시간 초과도 같은 모양(`NETWORK_UNREACHABLE` 등)으로 바꾼다. 기존 출력 가드 코드(`OUTPUT_INSIDE_EVIDENCE`, `EVIDENCE_INSIDE_OUTPUT`)는 그대로 흡수.

목록 응답의 부분 결과 계약: `pagination: {total: int|null, total_lower_bound: int, truncated: bool, budget_stopped: bool, scanned: int}` + `notice: {code, message}`. 〔2차〕 `truncated`·`scanned`·`budget_stopped`(참일 때만)는 **이미 응답에 있다**(`api/app/artifact_filter.py:213-215`) — 추가하는 것은 `total_lower_bound`, `budget_stopped`의 상시 불리언화, `notice`뿐이고 기존 필드는 이름·값 불변이다. 프런트는 `budget_stopped`·`truncated`를 반드시 `PartialBanner`로 표시한다. 표시 규칙: `total` 있음 → "총 n건" / `total=null`이고 `has_more` → "n건 이상"(`total_lower_bound`) / `budget_stopped` → 호박 띠 + "n행 확인"(`scanned`).

## D.8 CLI 봉투·종료 코드(신규, v1 7.1 승계)

〔2차 개정: 추가 방식〕 이미 `--json`을 내는 77개 명령은 **지금의 최상위 키를 그대로 두고** `"status": "ok|partial|error"`, `"warnings": []`, `"errors": [{"code","message","hint"}]` 세 키를 더한다(`command` 키는 이미 있다). `data`로 감싸지 않는다 — 기존 자동화·테스트·`frontend/e2e/ai_fixture.py`가 최상위 키를 읽는다(GAP-195). 새로 `--json`을 얻는 12개 명령(docs·manifest·artifacts·cloud-collect·files·extract·timeline·search·case·run·run-control·web)과 신규 `brief`도 같은 모양(`command` + 결과 키 + 세 키). 감싼 모양이 필요하면 R9에서 `--envelope v2` 옵트인으로. 종료 0 성공 / 1 실패 / 2 사용법 / 3 부분 성공 / 4 대상 없음. 명령 이름은 유지(D16 수정안). `--json`일 때 표준 출력에는 JSON 한 덩어리만, 사람용 문장은 표준 오류로.

## D.9 브라우저 저장 키 계약

| 현재 | R8 | 이관 |
|---|---|---|
| `rapidtriage.v2.{theme,density,timezone,panels,popout.bounds,tree.showEmpty,treeCollapsed,viewerCollapsed,conditions.saved,conditions.recentRanges}` | `rapidtriage.v3.*` 같은 이름 | 1회 복사 후 삭제. `theme`는 `"system"` 기본 |
| `rapidtriage.{classicSplit,classicSplitLayout,grid.preset,mediaBlur,reveal-reason,reviewer}` | `rapidtriage.v3.*` | 동일 |
| `rapidtriage.grid.fieldColumns.{artifacts\|analysis}.<kind>` | `rapidtriage.v3.grid.fieldColumns.*` | 동일 |
| `rapidtriage.histBaseline.<runId>` | `rapidtriage.v3.histBaseline`(맵, LRU 20) | 합치고 초과분 삭제 |
| `rt.dashboard.layout.v1/v2` | 삭제(새 홈은 고정 배치) | 삭제 |
| `rapidtriage.authToken`(localStorage, v1 호환) | 읽지 않음. sessionStorage만 | 발견 시 삭제 |
| (신규) | `rapidtriage.v3.role`, `rapidtriage.v3.fontScale`, `rapidtriage.v3.shortcuts`(글자 키 단축키 켬/끔), `rapidtriage.v3.reviewer`(담당자 이름 — 기존 `rapidtriage.reviewer` 이관) | — |
| 〔2차〕 sessionStorage: 토큰 키(`api/client.ts`의 `TOKEN_KEY`), `rapidtriage.reveal-reason`(개체 원값 보기 사유, `EntityPanel.tsx:44-52`), 트리·뷰어 접힘 키 2개(`state/slices/overlays.ts`) | 이름·뜻 그대로(세션 한정이라 이관 없음) | 팝아웃 창이 토큰을 `window.opener`에서만 받는 규칙 유지 |

## D.10 서버 쓰기 계약

- 어떤 요청도 증거 경로 아래에 쓰지 않는다. `core/output_guard.py`의 두 코드가 모든 쓰기 진입점의 공통 관문이다(새 처리·재시도·사건 처리·증거 추가·분석·가져오기·샘플·CLI).
- GET은 쓰지 않는다. 예외 없이 색인·캐시 생성은 (a) 처리 끝의 사전 계산 또는 (b) POST 202 작업으로만. 〔2차〕 지금 쓰는 GET은 보고서 계열 6개(`/submission-manifest`, `/submission-manifest/file`, `/validation-package`, `/validation-package/file`, `/case-report/file`, `/case-report/file/{format}` — T-030)와 지연 색인·캐시(타임라인·지도·계열·폴더 트리·썸네일 등 — T-133·T-134)다. 회귀 게이트: QA-108(OpenAPI의 GET 전수 호출 전/후 결과 폴더 스냅샷 동일).
- 읽기 전용 처리(`readonly_reason`이 있는 처리)에 대한 비-GET 요청은 미들웨어 한 곳에서 409 `RUN_READ_ONLY`로 거부한다(T-032). 서버 단위 읽기 전용(`web --read-only`, T-112)은 같은 미들웨어를 모든 처리에 적용한다(허용 목록: 로그인·토큰 확인뿐).
- 임의 경로를 받는 쓰기(`/api/sample-case/run`의 `output_dir`)는 허용 루트(`~/.rapidtriage/`) 밖을 거부하고, 폴더 삭제는 샘플 표식 파일이 있을 때만 한다(GAP-004).
- `/api/browse`: 루프백 서버는 전체 디스크(분석 담당이 증거를 골라야 한다), `--remote` 서버는 `--browse-root` 안만(GAP-207).
- 과거 결과가 증거 안에 있으면 "읽기 전용으로 열기"(지연 쓰기 전부 비활성, 메모리 계산, 상단 경고) — 결정 D37.

## D.11 그 밖의 고정 표면 〔2차 신규〕

1차 계약표에 없어서 재설계 중에 조용히 깨질 수 있던 것들이다. T-001의 추출기와 계약 테스트가 함께 고정한다.

| 표면 | 고정하는 것 | 근거(현재 위치) | 바꿔도 되는 것 |
|---|---|---|---|
| 팝아웃 뷰어 메시지 | 주 창 → 새 창: `state`·`main-closed`. 새 창 → 주 창: `hello`·`history`·`mode`·`command`·`invalidate`·`navigate`·`return`·`closed`. 토큰은 `window.opener`에서만 받는다 | `frontend/src/features/viewer/popout/protocol.ts:51-81` | 메시지에 필드 추가(기존 필드 불변) |
| 내보내기 파일 이름 | 보고서 4형식·내보내기 매니페스트·제출 매니페스트·검증 패키지·리뷰어 번들의 기본 파일 이름과, 감사 사이드카 이름 규칙 `<이름>.audit.<확장자>`(`core/audit.py:24-27`) | `api/app/runops.py`의 `default_*_path`, `core/case_report.py`의 `case_report_export_paths` | 누적 감사 파일 `rapidtriage-export-audit.jsonl` **추가**(T-029) |
| 처리 요약(run summary) | 필수 15키와 `outputs`·`steps[].name`·`steps[].status` 값 집합(`completed`·`failed_isolated`·`skipped`·`error`) | `rapidtriage/schemas/`, `core/run/steps.py:142` | 키 추가. 상태값 추가·변경은 T-126(승인) |
| 케이스 DB | 표 22개의 스키마, 해시 상태값 문자열, 검토 상태값(`relevant`·`needs-review`·`excluded`·`unreviewed`) | `core/case_db/` | 없음(스키마 변경은 승인 사항) |
| 서버 응답의 `detail` | 형(문자열·배열·객체)과 값 | D.7 | 최상위 키 추가 |
| CLI `--json` | 77개 명령의 최상위 키 집합 | D.8 | 키 추가 |
| 인용에 들어가는 판단 라벨 | "관련 있음·재검토·제외·보고서 포함·북마크" | `viewer/citation.ts:22-28` | 화면 색·아이콘 |
| 테스트가 문구로 고정한 화면 | MetaView 40·CaseDashboard 30·a11y 23·DataGrid 22·Viewer 21·stages 20·caseCards 19(UI-24) | vitest | 계약표의 접근성 이름이 아니면 testid로 옮긴 뒤 변경(부록 F.1) |
| CSS를 직접 읽는 테스트 | `shell/scrollLayout.test.ts`, `DataGrid.test.tsx:396`, `app/themeBoot.test.ts`, StatusChip, CaseDashboard | vitest | 해당 CSS·`index.html`을 고치는 과제(T-013·T-015·T-061)가 같은 PR에서 기대값을 갱신하고 PR에 적는다 |
| 레이아웃 상수 | TREE_DEFAULT 260, VIEWER_DEFAULT 440, 레일 36, 분기 1200/900/1600 | `gridLayout`·`responsiveColumns`·`treePane`·`viewerPane` 테스트 | 값 변경 시 테스트를 "범위" 단언으로(D.3) — 분석 담당 모드의 기본값은 유지 |

회귀 위험 요약(1,559 vitest + e2e 44건 기준): 가장 큰 표면은 ① 한글 접근성 이름(vitest 536·e2e 173회) ② 문구 단언(vitest 566·e2e 40) ③ 오류 본문의 `detail`(파이썬 190곳) ④ CSS·상수 직접 단언이다. ①③은 이 부록의 추가 방식으로 **깨지지 않게** 했고, ②④는 "그 화면을 바꾸는 과제가 같은 PR에서 testid로 옮긴다"는 규칙과 분석 담당 모드 회귀(e2e 13스펙)로 잡는다. 물결마다 `vitest` 전체의 통과 수가 줄면(삭제·skip) 물결 실패다.
