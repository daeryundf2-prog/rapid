# R8 부록 D — 계약표 (주소·인용·testid·접근성 이름·저장 키·오류·`/brief`)

마스터 5절·9절. 이 표는 재설계 동안 **바뀌지 않는 것**의 목록이다. T-001이 이 표를 `frontend/src/contracts/uiContract.ts`(기계가 읽는 형태)와 계약 테스트로 옮기고, 그 뒤 모든 과제는 이 표를 깨면 실패한다. 표에 없는 문구·클래스·레이아웃 상수는 바꿔도 된다(테스트가 그것에 묶여 있으면 T-002가 testid로 옮긴다).

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

금지: e2e에서 CSS 클래스 선택자(`.grid-row-stripe`, `.grid-scroll`, `.chat-*`, `.dash-*`, `.hist-cat-label`, `.flag-popover`, `.entity-rows`, `.image-view`, `.thumb-view`) — T-002가 testid·역할 선택자로 교체. `boundingBox`·`getComputedStyle` 단언은 `grid-layout.spec.ts`의 레이아웃 계약(가로 넘침 0, 시각 열 폭 ≥176)만 남긴다. 레이아웃 상수 테스트(TREE_DEFAULT 260, VIEWER_DEFAULT 440, 레일 36, 1200/900/1600)는 "범위" 단언으로 완화한다.

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

신규 규칙: 표는 `role=grid` + 접근 가능한 이름(범주명) + `aria-rowcount`/`aria-rowindex`/`aria-sort`(현행 유지). 잘린 셀의 전체 값은 접근성 이름에. 페이지 로딩·정렬 변경은 라이브 리전(750 ms 미만은 알리지 않음). 건수 줄임(`1.2만`)의 정확한 수는 접근성 이름에.

## D.5 단축키 계약

`frontend/src/contracts/command.ts`의 `KEY_MAP` 33개가 유일 출처(유지). 기존 키의 뜻은 바꾸지 않는다. 추가: `P`(보고서 포함), `Ctrl+Z`(표시 실행 취소), `G`(다음 미검토). `Alt+1~5`의 5는 보고서 별칭. 용어집의 "보고서 포함(B)" 표기는 오류다(코드에서 B는 북마크) → 용어집을 고친다(D21 보강).

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
규칙: `cards[].count`·`findings.counts`·`review.*`·`keywords[].hits`는 `link`가 여는 목록의 총건수와 같다(계약 테스트 `test_brief_count_contract.py`가 합성·실데이터에서 전수 비교). `zero_reason` = `{code, message, action:{label, role:"reviewer|examiner", link|copy_text}}`, code는 IS-006의 8종. `review.include_in_report`는 보고서·`/review-counts`·접수 카드와 같은 함수 하나에서 나온다(GAP-012). `?redact=1`이면 식별자 가림.

## D.7 오류 봉투 계약(신규)

모든 4xx·5xx 본문: `{"code": "UPPER_SNAKE", "message": "한국어 문장", "hint": "다음 행동(한국어)", "detail": {…선택…}}`. 기존 `detail` 문자열을 기대하는 클라이언트를 위해 1릴리스 동안 `detail_text`에 옛 문자열을 병기한다. 코드표 `docs/api-error-codes.md`. 프런트 `api()`는 네트워크 실패(`TypeError`)·중단·시간 초과도 같은 모양(`NETWORK_UNREACHABLE` 등)으로 바꾼다. 기존 출력 가드 코드(`OUTPUT_INSIDE_EVIDENCE`, `EVIDENCE_INSIDE_OUTPUT`)는 그대로 흡수.

목록 응답의 부분 결과 계약: `pagination: {total: int|null, total_lower_bound: int, truncated: bool, budget_stopped: bool, scanned: int}` + `notice: {code, message}`. 프런트는 `budget_stopped`·`truncated`를 반드시 `PartialBanner`로 표시한다.

## D.8 CLI 봉투·종료 코드(신규, v1 7.1 승계)

`{"command","status","data","warnings":[],"errors":[{"code","message","hint"}]}`; 종료 0 성공 / 1 실패 / 2 사용법 / 3 부분 성공 / 4 대상 없음. 명령 이름은 유지(D16 수정안).

## D.9 브라우저 저장 키 계약

| 현재 | R8 | 이관 |
|---|---|---|
| `rapidtriage.v2.{theme,density,timezone,panels,popout.bounds,tree.showEmpty,treeCollapsed,viewerCollapsed,conditions.saved,conditions.recentRanges}` | `rapidtriage.v3.*` 같은 이름 | 1회 복사 후 삭제. `theme`는 `"system"` 기본 |
| `rapidtriage.{classicSplit,classicSplitLayout,grid.preset,mediaBlur,reveal-reason,reviewer}` | `rapidtriage.v3.*` | 동일 |
| `rapidtriage.grid.fieldColumns.{artifacts\|analysis}.<kind>` | `rapidtriage.v3.grid.fieldColumns.*` | 동일 |
| `rapidtriage.histBaseline.<runId>` | `rapidtriage.v3.histBaseline`(맵, LRU 20) | 합치고 초과분 삭제 |
| `rt.dashboard.layout.v1/v2` | 삭제(새 홈은 고정 배치) | 삭제 |
| `rapidtriage.authToken`(localStorage, v1 호환) | 읽지 않음. sessionStorage만 | 발견 시 삭제 |
| (신규) | `rapidtriage.v3.role`, `rapidtriage.v3.fontScale` | — |

## D.10 서버 쓰기 계약

- 어떤 요청도 증거 경로 아래에 쓰지 않는다. `core/output_guard.py`의 두 코드가 모든 쓰기 진입점의 공통 관문이다(새 처리·재시도·사건 처리·증거 추가·분석·가져오기·샘플·CLI).
- GET은 쓰지 않는다. 예외 없이 색인·캐시 생성은 (a) 처리 끝의 사전 계산 또는 (b) POST 202 작업으로만.
- 과거 결과가 증거 안에 있으면 "읽기 전용으로 열기"(지연 쓰기 전부 비활성, 메모리 계산, 상단 경고) — 결정 D37.
