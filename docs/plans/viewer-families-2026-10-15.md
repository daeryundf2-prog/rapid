# 뷰어 라운드 2 — 설정 자동 숨김 · 원본 뷰어 창 모드 · 계열별 핵심 열과 특이사항 (2026-10-15)

사용자 요청(원문 요지): ① 케이스 옆의 검색어·시간·경로 포함·열 구성은 한 번 설정하면 오래 안 보니 설정을 바꿀 때만 보이게. ② 원본 뷰어는 창 모드(듀얼 모니터)가 되게. ③ 케이스를 열면 증거 소스·파일·운영체제·계정 등이 나오는데, 각각 인터넷의 포렌식 검토 항목을 조사해 필요한 항목을 셀별로 구현하고(메신저: 시간·대화·첨부·상대·발화자, 이미지·이벤트 로그의 특징 등) 항목별 특이사항을 구분해 분석이 편하게.

조사 결과(출처 포함): `docs/research/forensic-field-catalog-windows-2026-10-15.md`(이벤트 로그·RDP·레지스트리·실행 흔적·LNK/JumpList·OS/계정·NTFS·USB), `docs/research/forensic-field-catalog-apps-media-2026-10-15.md`(메신저·이메일·브라우저·클라우드·이미지/동영상·문서·압축/암호 컨테이너·모바일). [G]/[K]/[!] 표시 항목은 실데이터(`D:\rapid-qa\derived\run-subset10`)로 검증 후 반영.

## 1. 최종 사용자가 보는 문제

- 그리드 위 4~5줄(검색어·시간 범위·유형·상태·태그·확장자·경로·열 구성·밀도)이 항상 펼쳐져 있어 화면 1/4을 먹는다. 실제로는 케이스당 한두 번 만진다.
- 원본 뷰어가 세 번째 열에 갇혀 있어 와이드 모니터에서도 원본·헥스·메타를 크게 볼 수 없다. 검사관은 보통 2대 모니터를 쓴다.
- 아티팩트 유형마다 "무엇을 봐야 하는지"가 열에 반영되지 않는다. 이벤트 로그는 로그온 유형·원격 IP·명령줄, 메신저는 대화방·발화자·방향·첨부·삭제 여부, 이미지는 촬영 시각·GPS·편집 SW·pHash 중복, 문서는 작성자·마지막 저장자·편집 시간·인쇄일이 핵심인데 지금은 계열 무관한 열 세트다. "특이사항"(로그 삭제 1102, $SI<$FN, 외부 IP RDP, SPF 실패, EXIF≠파일 시각…)을 셀에서 바로 알아볼 수 없다.

## 2. 이상 상태

- **U-F1 설정 자동 숨김**: 그리드 위에는 한 줄만 남는다 — 검색 입력 + "조건" 버튼(적용 중인 조건 수 배지) + 적용된 조건 칩(검색어·시간·유형·상태·태그·확장자·경로·열 프리셋·밀도 중 기본값이 아닌 것만, 각 칩 ×로 해제) + 결과 건수. "조건" 버튼(단축키 F)이나 칩 클릭으로 설정 패널(팝오버)이 열리고, 바꾸면 즉시 적용되며 Esc/바깥 클릭으로 닫힌다. 조건이 하나도 없으면 칩 줄은 비고 한 줄 높이(32 px)만 쓴다. 상태는 URL에 그대로(기존 `q,from,to,types,status,tags,ext,path,cols,cf`).
- **U-F2 뷰어 창 모드**: 뷰어 툴바와 명령 팔레트에 "뷰어를 새 창으로"(Ctrl+Shift+V). 새 브라우저 창에 뷰어 전체(모드 탭·툴바·배너·메타)가 뜨고, 메인 창 그리드에서 행을 옮기면 즉시 따라온다. 메인 창의 뷰어 열은 "새 창에서 보는 중 · 되돌리기" 레일로 접힌다. 새 창을 닫으면 자동으로 되돌아온다. 창 크기·위치는 기억(localStorage). 메인 창이 닫히면 새 창도 닫힌다. 키보드: 새 창 안에서 Alt+←/→(히스토리), 1~8(모드), R/X/I/B(표시)가 그대로 동작하고, 메인 창의 J/K는 메인 그리드에 남는다. 두 창 모두 접근성 트리가 완전하다(새 창 `title`="뷰어 — <행 제목>").
- **U-F3 계열별 핵심 열**: 아티팩트 유형(= `fieldSheets.ts`의 계열 48개)마다 조사 카탈로그의 "핵심 열" 순서대로 기본 열이 잡힌다(예: 이벤트 로그 = 시각(logged)·채널·EventID+요약·컴퓨터·주체/대상 계정·로그온 유형·원격 IP·프로세스/명령줄·LogonId·RecordID). 시각 열은 종류 칩(`ts_kind`)을 셀에 같이 보여 준다($SI/$FN, source/target, key LastWrite vs 값 시각). 보조 열은 열 선택에서 한 번에 켤 수 있다("카탈로그 보조 열 모두 추가"). 계열이 섞인 kind(예: windows-system)는 행마다 계열 열을 쓰지 않고 kind의 다수 계열 기준 + 유형 칩.
- **U-F4 특이사항**: 카탈로그의 지표(이벤트 로그 12, RDP 6, 레지스트리 7, 실행 흔적 7, LNK 6, OS/계정 7, NTFS 9, USB 6, 메신저 9, 이메일 13, 브라우저 10, 클라우드 7, 이미지 11, 문서 12, 압축 8, 모바일 8 = 약 138개)가 규칙 라이브러리로 구현되어, 각 행에 `flags[]`(id, 등급 A/B/C, 한글명, 근거 문장, 오탐 주의, 출처)가 붙는다. 그리드 "특이사항" 열에 등급색 칩(A 빨강·B 주황·C 회색), 클릭하면 근거 팝오버. 필터 바 조건에 "특이사항 ≥ 등급 / 특정 지표"가 있고, 탐색 트리에 "특이사항" 섹션(등급별·지표별 건수, 도메인 노드에도 배지)이 있다. 뷰어 배너 맨 위에 그 행의 지표와 근거·출처 링크. 정책 의존 아티팩트(4688/4104/USB 로그 등)는 "부재 ≠ 미발생" 배너.
- **U-F5 교차 지표**: USB VSN↔LNK VSN↔MountedDevices, Prefetch/Amcache/BAM↔MFT 존재, 4625 폭주→4624, 이메일 Date↔Received, EXIF↔파일 시각처럼 행 간·계열 간 상관이 필요한 지표도 같은 `flags[]`로 나온다(런 단위 사전 계산).
- **U-F7 빈 계열 숨김**(사용자 추가 요청): 계열이 많으므로 이 런에서 결과가 없거나(0건) 분석이 안 된 계열·노드는 기본적으로 트리에 보이지 않는다. 자식이 모두 숨겨진 도메인도 숨긴다. 트리 바닥의 "빈 계열 표시 (n개 숨김)" 토글(T, localStorage 기억)로 흐리게·사유와 함께 드러낸다. 전체 보기 그룹과 특이사항 섹션도 같은 규칙. 트리 검색은 숨긴 노드도 찾아 드러내고, 숨긴 노드를 가리키는 링크는 그 노드를 일시적으로 드러낸다.
- **U-F6 검증 가능성**: 모든 지표는 규칙 id·버전·출처를 가진다. 보고서 인용 시 "지표 id@버전 + 근거 필드값"이 함께 나간다. [G]/[!] 지표는 `status: "provisional"`로 표기되어 UI에서 "검증 필요" 꼬리표가 붙는다.

## 3. 설계

### 3.1 백엔드 — 지표 엔진 (`rapidtriage/core/triage_rules/`)
- `base.py`: `Rule(id, family, grade: "A"|"B"|"C", label_ko, rationale_ko, false_positive_ko, sources[], version, status: "verified"|"provisional", params: dict)`, `RuleResult(rule_id, grade, evidence: {field: value}, note)`. 행 단위 규칙은 `apply(row: Mapping) -> RuleResult|None`; 교차 규칙은 `prepare(context)`(런 전체 1회: USB VSN 집합, MFT 경로 집합, 4625 버킷, 계정별 시각 분포 등)와 `apply(row, context)`.
- 계열 모듈: `eventlog.py, rdp.py, registry.py, execution.py, lnk.py, accounts.py, ntfs.py, usb.py, messenger.py, email.py, browser.py, cloud.py, media.py, documents.py, archives.py, mobile.py` — 카탈로그 표를 1:1로 옮기고 임계값은 `params`(기본: 4625 폭주 10건/5분, EXIF-FS 차 1일, pHash 거리 8, 로그온 시간대는 계정별 분포에서 드문 시각(그 계정 대화형/원격 로그온 20건 이상 중 비율 3% 미만, UTC+9 가정 — `eventlog.off_hours_logon`), Date-Received 1일)로 둔다. 모든 규칙에 픽스처 테스트(양성 1·오탐 1).
- 실행 지점: ① 런의 persist 단계 끝에 `triage-flags` 단계로 자동 실행(새 런), ② 기존 런은 P1 분석 작업 kind `triage-flags`로 수동 실행. 출력 `analyses/<id>/flags.jsonl`(행: `{kind, record_index, flags: [...]}`) + `summary.json`(지표별·등급별·kind별 건수, 규칙 버전 목록). 런 디렉터리 밖에는 쓰지 않는다.
- 조인: 아티팩트/파일/분석 행 페이지에 `flags` 필드를 붙인다(NTFS 조인과 같은 LRU 인덱스, (kind, record_index) 키, 단일 실행, 메모리 상한). 서버 필터 `flag=<id>`(반복)·`flag_grade=A|B|C`(이상)와 정렬 `sort=flags`(등급 우선). `/tree`에 `flags` 섹션(등급·지표별 건수)과 도메인 노드 `flag_counts`.
- 계열 기본 열 메타: `GET /api/meta/families` — 계열 id → {핵심 열 키·라벨·ts_kind, 보조 열, 지표 id 목록, 출처}. 카탈로그를 YAML(`rapidtriage/core/triage_rules/catalog/*.yaml`)로 두고 프런트·백엔드가 같은 파일을 읽는다(빌드 시 프런트로 복사).

### 3.2 프런트엔드
- **설정 자동 숨김**(U-F1): `GridToolbar`를 "조건 줄"로 교체 — 검색 입력, 조건 버튼(+배지, F), 칩(각 ×), 결과 건수, 밀도/열 프리셋은 조건 패널 안으로. `FilterBar`는 팝오버 내부 컴포넌트가 된다(기존 테스트 이식). 열 머리 필터(`cf=`)와 열 선택은 그대로. Q-A3 규칙 유지. 열 구성·밀도는 검색 조건이 아니라 **표시 설정**이다: 조건 수·굵은 라벨·"조건 지우기"에 들어가지 않고, 기본값이 아니면 조건 칩과 구분된 점선 칩 목록("표시 설정", ×는 기본값으로 되돌리기)으로 보인다.
- **창 모드**(U-F2): `features/viewer/popout/`: `window.open(location.origin + '/?popout=viewer', 'rapidforensic-viewer', 'popup,width=…')` 로 같은 번들을 띄우고, 상태는 `BroadcastChannel('rapidforensic.viewer')`로 동기화(메인 → 새 창: viewerTarget/row/mode/tz/theme; 새 창 → 메인: 표시 명령·히스토리·닫힘). 새 창은 토큰을 메인에서 메시지로 받아 sessionStorage에만 둔다. 메인 창은 `viewerPane: "popout"` 상태로 레일 표시. 창 좌표 기억, `beforeunload`에서 상호 닫기. 이유: 포털 방식은 React 19에서도 가능하지만 스타일·포커스·키맵이 두 문서에 걸쳐 꼬이므로, 독립 인스턴스 + 채널이 더 안전하다.
- **계열별 열**(U-F3): `grid/columns/families.ts`가 YAML 카탈로그에서 계열 → 열 정의를 만들고, `artifacts.ts`의 KIND_COLUMNS는 "kind의 다수 계열" 폴백으로만 남긴다. 시각 셀에 `ts_kind` 칩. 열 선택에 "카탈로그 보조 열 모두 추가/제거".
- **특이사항**(U-F4): `특이사항` 열(칩, 등급색, 접근성 이름 "특이사항 A 2건: 로그 삭제, 외부 IP RDP"), 근거 팝오버(근거 필드·오탐 주의·출처 링크·"검증 필요" 꼬리표), 필터 조건(등급/지표), 트리 "특이사항" 섹션, 뷰어 배너, 리뷰보드에 "특이사항 A 전체 보기" 바로가기, 정책 의존 부재 배너.
- 모든 라벨 한국어, 명령 등록, DisabledReason, polite 영역 1개, 대비 게이트.

### 3.3 작업 분할과 순서
1. **D1(백엔드, Opus)**: 카탈로그 YAML + 규칙 라이브러리 + 테스트 + `triage-flags` 단계/분석 kind + 조인·필터·트리 + `/api/meta/families`. 실데이터 `run-subset10`으로 지표 건수·오탐 샘플 20건 검토.
2. **D2(프런트, Opus)**: U-F1 → U-F2 → U-F3/U-F4(계약 §3.1 mock) 순. e2e: 조건 패널 키보드, 창 모드(Playwright popup 컨텍스트), 계열 열, 특이사항 필터.
3. 통합 → 실데이터 QA → 적대적 리뷰(백/프런트) → 수정 → PR.
전제: 열린 PR 스택(#6→#7→#8→#9→#10)을 먼저 main에 머지해 하나의 기준점을 만든다(프런트는 #7, 파서/검색은 #10에 있어 두 계보가 갈라져 있음). 머지 전이면 통합 브랜치(#10 head + #7 merge)에서 시작한다.


### U-F8 AXIOM 실행 관찰 반영 (2026-10-17, `docs/research/axiom-case-model-2026-10-17.md` §7)
- 그리드 행 좌측 6 px 리뷰 스트라이프(관련=연두·제외=회색·보고서 포함=빨강, 토큰 색), 스크롤 중 항상 표시.
- 혼합 kind 격자(도메인 노드가 여러 artifact_type을 합칠 때): "요약 열 4개(주요·지원·추가·시각) + 셀 안 라벨/값 2줄" 모드, 단일 계열이면 U-F3 카탈로그 열로 자동 전환.
- 뷰어 메타 시트 고정 꼬리 섹션: 소스(파티션·경로) · 복구 방법(파싱/카빙) · 삭제된 출처 · 위치(오프셋) · 증거 번호 · 파서 버전 · 원본 행 링크(파생 행).
- 조건 줄: 적용된 조건은 버튼 라벨 자체로 치환(굵게) + "조건 저장/지우기", 날짜 팝오버에 최근 조건 3개.
- 지표 `timestamp_out_of_range`(C등급: 1980년 이전·현재+1일 이후 시각) — 카빙 LNK의 1628년 시각 같은 쓰레기 값 표시.
- QA Q-F13: 혼합 노드(예: 실행 흔적)에서 라벨 2줄 셀, 단일 계열 노드에서 카탈로그 열; Q-F14: 리뷰 스트라이프가 R/X/B 마크와 1:1; Q-F15: 꼬리 섹션 6항목이 모든 kind에서 채워지거나 "없음" 사유.

## 4. QA 시나리오
| # | 시나리오 | 기준 |
|---|---|---|
| Q-F1 | 케이스 열기 → 아티팩트 | 그리드 위 1줄(≤32 px), 조건 0개면 칩 없음; F로 패널, Esc 닫힘, 포커스 복귀 |
| Q-F2 | 시간 범위+유형 설정 → 닫기 → 새로고침 | 칩 2개 유지, URL 동일, 칩 × 해제 시 즉시 재조회 |
| Q-F3 | Ctrl+Shift+V | 새 창에 뷰어, 메인 뷰어 열 레일로; 메인에서 J/K 이동 시 새 창 ≤200 ms 갱신; 새 창에서 R 표시 → 메인 그리드 칩 반영 |
| Q-F4 | 새 창 닫기 / 메인 닫기 | 각각 되돌리기/동반 종료, 토큰이 URL에 노출되지 않음 |
| Q-F5 | 이벤트 로그 kind | 기본 열이 카탈로그 핵심 열 순서, 시각 칩 "logged", 4624 행에 로그온 유형·원격 IP 채워짐 |
| Q-F6 | 메신저(kakaotalk/mobile) | 대화방·발화자·방향·첨부·삭제 여부 열, 빈 열 과반 금지(run-subset10 50행) |
| Q-F7 | 이미지 | 촬영 시각·카메라·GPS·편집 SW·pHash 열, `exif_vs_fs_time` 지표 샘플 검증 |
| Q-F8 | 특이사항 엔진 | run-subset10에서 A등급 지표 ≥1종 발생(예: SI<FN, 로그 삭제, 외부 IP), 지표별 샘플 20건 수동 검토 오탐률 기록 |
| Q-F9 | 특이사항 필터·트리 | `flag_grade=A` 서버 필터, 트리 건수 = 그리드 건수, 뷰어 배너 근거·출처 링크 |
| Q-F10 | 인용 | 지표 id@버전 + 근거 필드 포함 |
| Q-F12 | 빈 계열 숨김 | run-subset10에서 0건 도메인·노드가 기본 숨김, 토글 텍스트의 n과 실제 숨김 수 일치, 토글 상태 새로고침 후 유지, 검색·링크로 드러남, a11y 규칙 0 |
| Q-F11 | 게이트 | unittest/ruff/vulture/compileall/doc-refs/OpenAPI, vitest/tsc/biome/contrast, e2e(팝업 포함), 적대적 리뷰 0 미해결 |

## 5. 결과 기록

### 5.1 백엔드(D1) — 구현된 계약 (2026-10-17)
- **엔진**: `rapidtriage/core/triage_rules/` — 카탈로그 YAML 17개(계열 54, 규칙 140: A 5 · B 60 · C 75), 계열 모듈 17개(교차 계열 `generic` 포함), `engine.run_triage_flags`(모든 행 소스 1회 스트리밍, 규칙별 20만·전체 200만 행 상한, 규칙 예외 격리, `flags.jsonl`·`summary.json`은 임시 파일 + `os.replace`). 규칙마다 양성 1·오탐 1 픽스처(`tests/triage_cases/`, 전체 엔진으로 실행).
- **실행 지점**: ① 새 런은 `persist` 뒤 `triage-flags` 단계가 `analyses/run-triage-flags/`(analysis.json `kind=triage-flags`, `status=completed`)에 쓰고 런 요약 `steps`에 `{name: "triage-flags", status, flagged_rows, flag_count, rows_by_best_grade, catalog_version, elapsed_seconds}`를 남긴다(실패는 `failed_isolated` + 한국어 경고, 런은 계속). ② 기존 런은 분석 kind `triage-flags`(옵션 `incident_start`/`incident_end` ISO-8601, `include_analyses`; 진행 단위 = 행 소스, 취소는 소스 사이·2,000행마다, 같은 kind 동시 실행 409).
- **조인**: 가장 최근 완료된 `triage-flags` 결과 하나를 런당 LRU(최대 4런, 단일 빌드, 256 MB 초과 파일은 `too_large`)로 색인. `GET /artifacts`·`/files`·`/analyses/{id}/rows`의 모든 행에 `flags: [{id, grade, label, evidence, note?, version, citation: "<id>@<version>", status}]`, 응답에 `flags_join: {status: joined|no_source|too_large|skipped, source, analysis_id, generated_at, catalog_version, reason?}`.
- **필터·정렬**: `flag=<rule id>`(반복, 하나라도), `flag_grade=A|B|C`(가장 센 지표가 그 등급 이상), `sort=flags`(A→B→C→무지표, 등급 안은 레코드 순; artifacts는 kind 하나). `limit>0` 필요(400), 모르는 지표·등급은 422(한국어), 특이사항 결과 없이 필터하면 409. artifacts에서는 `kind`·`artifact_type`·`path_contains`·필드 정렬(`sort=details.x`)과 함께 쓰이고, kind가 0개/여러 개면 `cross_kind`(+`cross_kind.flags`)로 넘긴다. 페이지 `pagination.flags = {flag, flag_grade}`.
- **트리**: `GET /tree` 최상위 `flags = {total, by_grade, by_rule: [{id, label, grade, status, count}], policy: [{id, label, count, note}], versions, catalog_version, source}`(결과 없으면 키 없음), kind 노드·도메인 그룹·`files` 노드 `flag_counts: {A,B,C}`, 분석 작업 그룹에 `analysis:triage-flags` 노드.
- **메타·인용**: `GET /api/meta/families` = `{version, families: [{id, label, types, kinds?, prefixes?, suffixes?, core_columns, aux_columns, rules}], rules: [...]}`; `GET /api/runs/{id}/flags`(트리 섹션 + `flags_join`); `GET /api/runs/{id}/flags/row?kind=&record_index=` → `citations: [{id, version, citation, grade, label, status, evidence, note?, text: "<id>@<version> (필드=값, …)"}]`.

### 5.2 실데이터 (`D:\rapid-qa\derived\run-subset10`, 분석 kind `triage-flags`)
- 행 소스 26개(이벤트 로그 294,456행·레지스트리 251,138행·Prefetch 70,946행 포함), 벽시계 **58.9 s**, 프로세스 RSS 최대 **309 MB**(시작 128 MB). 규칙 오류 0, 상한 억제 0. API: eventlog `flag_grade=B` 1.0 s, `sort=flags` 0.7 s, `/tree` 0.9 s(500 MB JSONL, 첫 색인 포함).
- 결과(당시 카탈로그 `95ed78b7a80fe46a`; U-F8 반영 후 `9f7eec09a917a1c2`도 같은 건수, 58.8 s · 310 MB; 현재 카탈로그 버전은 아래 5.2 끝 줄): 지표가 붙은 행 2,288(가장 센 등급 A 0 · B 152 · C 2,136), 지표 3,191건. 정책 의존 소스: 4688 44건, 4104 407건, USB 장치 로그 221건, Sysmon 0건.
- 규칙별: browser.dl_missing_file 188 · browser.dl_dangerous 64 · browser.dl_from_filesharing 39 · browser.incognito_gap 2 · documents.modified_vs_fs 459 · documents.lastsaved_ne_author 284 · documents.meta_scrubbed 269 · documents.printed_present 113 · documents.external_template_url 10 · documents.meta_tool_name_user 5 · documents.created_after_modified 1 · documents.macro_or_ole 1 · media.phash_dup_cross_folder 625 · media.exif_stripped 406 · media.screenshot_flag 234 · media.exif_vs_fs_time 22 · media.editing_software 12 · media.gps_present 3 · registry.shellbag_removable_network 327 · registry.userassist_path 10 · registry.usb_serial_cross 4 · registry.typedpaths_unc 2 · lnk.target_missing 57 · lnk.removable_target 17 · lnk.timestamp_anomaly 15 · lnk.network_target 15 · lnk.user_path_exec 1 · execution.suspicious_path 2 · execution.runcount_spike 1 · usb.mass_storage_activity 1 · usb.serial_missing 1 · archives.ext_mismatch_container 1.
- **A등급 0건(Q-F8 미충족, 데이터 사유)**: 이 하위 집합에는 1102/Eventlog 104(로그 삭제)가 없고(104는 Kernel-Cache·VolumeSnapshot 등 다른 공급자뿐 — 규칙이 정상 제외), 4624 원격 IP는 모두 사설(192.168.x, fe80::)이며 1149 없음, `$MFT`가 없어 ntfs-meta 분석이 없으므로 SI<FN·ADS 규칙은 입력이 없다. A 규칙 실데이터 검증은 MFT를 포함한 전체 이미지 런에서 다시 한다.
- **수동 검토(규칙별 표본 12~20건)와 조정**(바뀐 규칙은 version 2):
  - eventlog.new_service: 48건 전부 Defender(`ProgramData\Microsoft\Windows Defender\Platform|Definition Updates`) → `allowed_path_prefixes`로 사용자 쓰기 경로 사유만 제외 → 0건.
  - browser.dl_dangerous: 177건 대부분 정부·은행 사이트 PDF/HWP의 `MAYBE_DANGEROUS_CONTENT` → 강한 유형은 항상, 약한 유형은 실행 확장자일 때만 → 64건(전부 .exe, 대부분 공인인증·보안 플러그인 설치 파일: 오탐 주의 문구 유지).
  - documents.macro_or_ole: 10건 중 9건이 모든 HWPX에 있는 기본 `Scripts/headerScripts.js`·`sourceScripts.js` → 제외 → 1건(.doc VBA, 정탐).
  - documents.created_after_modified: 같은 날 5~9시간 차(시간대 혼용) → `tolerance_hours: 14` → 1건.
  - lnk.network_target: 150건 중 135건이 검사 대상 PC 자신의 공유(`\\<호스트명>\Users`) → 자기 호스트 제외 → 15건(사설 LAN 공유, C등급).
  - lnk.foreign_machine: 2건 모두 기본 PowerShell 시작 메뉴 바로 가기 → Windows/Program Files 대상 제외 → 0건.
  - registry.userassist_path: 34건 중 24건이 바탕 화면·공용 바탕 화면 `.lnk` → 제외 → 10건(Downloads 설치 파일·AppData 실행).
  - registry.run_user_path: Slack Squirrel 자동 시작 1건 → `com.squirrel.` 허용 → 0건. usb.non_storage_hid: PS/2·동시 설치 HID 4건 → 제외 → 0건.
  - archives.ext_mismatch_container: Windows 10 Prefetch(.pf, MAM 압축이 gzip으로 감지) 제외(`ignored_extensions`) → 1건(.xls 이름의 OOXML).
  - 남은 C등급 다수(pHash 중복 625, EXIF 없음 406, 문서 시각 차 459 등)는 설계상 약한 단서라 유지. browser.dl_missing_file·lnk.target_missing은 수집 하위 집합 런이라 파일 목록이 부분적이어서 많다(전체 이미지 런에서 재평가).
- 픽스처 작성 중 고친 규칙 버그: accounts.task_suspicious(시작 지연을 반복으로 오인, 기본 숨김 SYSTEM 작업), mobile.app_installed_recent(키워드 부분 일치 `wire`→Wireless), cloud.external_share(조직 내부 공유), ntfs.ads_executable(`windows-pe` 서명 종류), archives(`zip-ooxml`·`content_entropy`·`last_modified` 필드), documents.pdf_creator_producer_odd(정규화 메타 위치), lnk(`remote` 드라이브 유형), usb.non_storage_hid(Amcache 필드명).
- 남은 일: 프런트 `families.fallback.json` 재생성(카탈로그 params·version 변경 반영, D2), A 규칙 실데이터 검증(MFT 포함 런), 일부 규칙이 읽는 필드를 아직 어떤 파서도 만들지 않음(archives `header_encrypted`/`nested_depth`/`sfx`, documents `pdf_eof_count`/`tracked_change_authors`/`ole_object_count`/`dde_present`, LNK `modified_at`).
- **U-F8 백엔드**: ① 교차 계열 C등급 `generic.timestamp_out_of_range`(provisional) — 행의 최상위 시각 필드(`*_at`/`*_time`/`*_timestamp`/`*_date`/`timestamp`) 값이 1980-01-01 이전이거나 현재+1일 이후. FILETIME/Unix/DOS 0과 그 시간대 밀림 값, 만료·생일·예약·PE 링크 시각·드라이버 버전 날짜 필드(`excluded_key_terms`)는 제외. run-subset10 첫 실행 416건은 전부 Amcache `link_date`/`driver_link_time`(재현 빌드 해시)·`driver_version_date` → 제외 후 3건 남은 LNK `1979-12-31T15:00Z`(= DOS 0, KST) → 제외 후 **0건**(이 하위 집합에는 카빙 LNK가 없음). ② `summary.json`(및 분석 상태 요약)에 `rule_set = {catalog_version, files: {YAML 이름: SHA-256}, rule_versions}`. ③ 조인 행의 각 flag에 `provenance = {kind, record_index, recovery_method: parsed|carved|recovered|unknown, recovery_detail?, parser?, parser_version?, source_path?, source_offset?, deleted?}`(행이 이미 가진 `artifact_record`·`evtx_record_state`·`recovery_method`·`deletion_state`에서만), `GET /flags/row` 인용에 `provenance`와 `text` 꼬리 `[<복구 방법>, <파서>@<버전>, #<record_index>]`.
- **적대적 리뷰 반영(2026-10-17)**: 런 단계는 매번 새 세대 `analyses/run-triage-flags-<UTC 시각>/`에 쓰고(상태 파일은 마지막, `os.replace` 재시도, 이전 세대는 사후 삭제) API 리더가 연 파일을 덮어쓰지 않는다. 소스를 끝까지 못 읽으면(읽기 실패·`record_count`보다 적게 도달) `summary.status = "partial"` + `coverage = {complete, incomplete, sources}`, `flags_join = {status: joined, coverage: "partial", incomplete_sources, reason}`·트리 `flags.source`에도 같은 값, 런 단계 경고. 등급이 A/B/C가 아닌 지표는 건너뛰고 `flags_join.skipped_flags`로 센다. 파일 목록 문맥은 최대 1,000,000행(`summary.files_context`), 넘으면 목록을 "모름"으로 두어 대상 없음 규칙이 침묵; files 출력은 API 프로세스에서 통째로 읽지 않고 스트리밍; 문서 mtime은 문서 확장자만. 소스 목록은 런당 2초 캐시(분석 완료 시 즉시 무효화). `sort=flags` 단독은 필터가 아니라 재정렬이므로 `filtered: false`·`total = record_count`, 필드 정렬 + 지표 필터 페이지에도 `pagination.flags`. `/files`의 flags 외 `sort`는 예전처럼 무시. `/flags/row`는 런에 없는 kind·0 미만/정수 아닌 `record_index`를 한국어 422(입력값을 되돌려 쓰지 않음). `incident_start > incident_end`는 한국어 422. UI에 닿는 카탈로그 라벨은 모두 한국어(고유 명사는 괄호, 예: "앱 ID (AppID)", "시스템 자원 사용 (SRUM)").
- **교차 등재 규칙 15개**(규칙은 계열 하나에 속하고, 그 행을 보여 주는 다른 계열의 `rules` 목록에도 필터용으로 올라 있음): sam-account → accounts.new_account · browser-visit → browser.incognito_gap, browser.history_cleared · prefetch-file → execution.suspicious_path, execution.name_mismatch, execution.deleted_executable, execution.multi_source · shortcut → usb.cross_match · jumplist → lnk.removable_target · mft → ntfs.deletion_trace · file → archives.ext_mismatch_container · registry → rdp.enabled, accounts.task_mismatch · service → registry.persistence_lastwrite_window · mounted-device → registry.usb_serial_cross. 건수는 규칙 기준이며 계열별로 중복 집계하지 않는다.
- **현재 카탈로그 버전: `b9313948d4289c0c`** (규칙 140, 계열 54; 프런트 `families.fallback.json` 동일).

### 5.3 프런트엔드(D2) — 구현 (2026-10-17)
- **U-F1 조건 줄**: 그리드 위 한 줄(`.filter-bar` 32 px, 행 28 px) = 보기 전환 · 검색 · "조건"(F, 적용 수 배지) · 기본값이 아닌 조건만 칩(× 즉시 재조회) · 결과 건수 · 열 설정. 조건 패널(팝오버) = 시간 범위 · 유형 · 상태 · 태그 · 확장자 · 경로 · 특이사항(등급/지표) · 표시(열 구성 · 밀도). 열고 나면 제목에 포커스, Esc/바깥 클릭으로 닫히고 포커스는 "조건" 버튼으로. URL 상태 그대로(`flag=`/`flag_grade=` 추가). 명령 `grid.conditions`(조건 줄이 없으면 DisabledReason).
- **U-F2 뷰어 창**: `features/viewer/popout/`(protocol · host · PopoutApp). Ctrl+Shift+V·뷰어 머리 버튼·팔레트 "뷰어를 새 창으로" → `window.open(<origin><bundle path>?popout=viewer&host=<id>, "rapidforensic-viewer", "popup,…")`(창 좌표 localStorage `rapidtriage.v2.popout.bounds`). 동기화 `BroadcastChannel("rapidforensic.viewer")`, 모든 메시지에 `host`(콘솔 탭마다 난수 — 다른 탭의 창을 조종하지 않음). 토큰은 채널·URL에 싣지 않고 메인이 연 창에만 `postMessage(…, origin)`, 창은 `event.source === window.opener`일 때만 받아 sessionStorage에 둔다. 창 안 키: Alt+←/→(창의 이력 → 메인 URL `row=`), 1~8(모드 → 메인 `mode=`), R/X/I/B·"같은 출처의 다른 행"(메인이 같은 행에 실행 → 그리드 칩 반영), 도구 모음 표시는 메인 그리드 재조회 요청. 메인 뷰어 열은 "창으로 보는 중 · 되돌리기" 레일로 접히고 메인 뷰어는 언마운트(미리보기·해시 중복 요청 없음). 창 닫힘 → 레일 해제(창 새로고침은 1.5 s 유예로 닫힘이 아님), 메인 종료(beforeunload/pagehide) → 창도 닫힘. 팝업 차단 → 토스트·assertive 안내, 좁은 화면(서랍)·뷰어 없는 단계 → DisabledReason. 창 제목 "뷰어 — <행 제목>".
- **U-F3 계열 열**: 카탈로그(`GET /api/meta/families`, 실패 시 번들 사본) 계열 해석 순서는 백엔드와 같음(접미사 → 정확한 유형 → 가장 긴 접두사). kind는 카탈로그가 정확히 하나로 주장하면 그 계열, 아니면 `/tree` 유형별 건수로 행의 과반을 차지하는 계열(kakaotalk-windows → kakaotalk), 그래도 없으면 KIND_COLUMNS. 레이아웃 = 시각 · 항목 · 특이사항 · 핵심 열(카탈로그 순) · 선별 · 유형, 보조 열은 숨김("카탈로그 보조 열 모두 추가/제거"), 파서는 원본 프리셋으로. 시각 셀에 한국어 시각 종류 칩(기록 시각 · 키 마지막 기록 · 대상 생성 …, 원래 `ts_kind`는 툴팁). 번들 사본 `families.fallback.json`은 `npm run build`의 prebuild가 백엔드 로더로 재생성(파이썬 없으면 기존 사본 유지, `npm run gen:families -- --check`로 오래됨 검사). vitest는 고정 목업(`frontend/scripts/families-mock.mjs`)을 쓴다.
- **U-F4 특이사항**: `특이사항` 열(등급색 칩, 이름 "특이사항 A 1건, B 1건: …", 서버 정렬 `sort=flags`), 근거 팝오버(근거 필드 · 오탐 주의 · 출처 링크 · "검증 필요"), 조건 패널 등급/지표 → 서버 `flag_grade=`/`flag=`(artifacts · files · analysis; 그 밖은 불러온 행), 탐색 트리 "특이사항" 섹션(A 등급 · B 등급 이상 · C 등급 이상 누적, 지표별 노드, 검증 필요 표시)과 kind·도메인 노드 등급 배지, 뷰어 맨 위 배너(A면 펼침), 리뷰보드 "특이사항 A 전체 보기 / B 이상 보기", 특이사항 결과 없는 런의 필터 안내, 정책 의존 소스 0건이면 "부재 ≠ 미발생" 안내. 행의 `version`·`status`가 카탈로그보다 우선.
- **U-F6 인용**: 뷰어 "인용 복사"에 `특이사항=<id>@<version> (필드=값, …) | …`.
- **U-F7 빈 계열 숨김**: 0건·분석 안 됨·런에 없는 kind 노드, 자식이 모두 숨은 도메인, 0건 전체 보기 뷰, 결과 없는 특이사항 섹션을 기본 숨김. 트리 바닥 "결과 없는 계열 n개 표시/숨김"(T, localStorage `rapidtriage.v2.tree.showEmpty`, `/tree` 응답 뒤에만 표시해 n이 확정값), n = 숨은 최상위 노드 수(숨은 도메인은 1개). 표시하면 흐리게 + "결과 없음: <사유>"(aria-description). 트리 검색·딥 링크(선택 노드와 조상)는 숨은 노드를 드러낸다.

- **U-F8 AXIOM 관찰 반영**: ① 행 왼쪽 6 px 리뷰 스트라이프(선택 열과 함께 고정, 상태 토큰 색: 관련·제외·재검토·보고서 포함, 상태 없으면 북마크 태그), 행 `aria-description` "검토 표시: …". ② 혼합 계열 격자(전체 아티팩트·범주/도메인 노드·여러 계열에 걸친 유형 필터): 유형 · 항목 · 특이사항 · 주요/지원/추가 세부 정보 · 날짜 및 시각 — 셀마다 위 작은 라벨 + 아래 값(행 자신의 계열 카탈로그 핵심 열 순서에서 값이 있는 첫 세 항목 + 첫 시각), 한 계열로 좁혀지면 카탈로그 열. 모든 열 머리에 전체 이름 툴팁. ③ 뷰어 메타 끝 고정 "증거 정보": 소스(파티션·경로) · 복구 방법 · 삭제된 출처 · 위치(복구 오프셋, 없으면 레코드 바이트 위치) · 증거 번호 · 파서 버전 · 원본 행(타임라인 → 원본 아티팩트 행 링크), 값이 없으면 "없음 — 사유". ④ 조건 줄: 적용된 조건이 "조건" 버튼 라벨을 대신함(굵게, "외 n", 접근성 이름은 "조건: …"), "조건 저장"(조건 패널 "저장한 조건"에서 적용·삭제, localStorage `rapidtriage.v2.conditions.saved` 최대 10) · "조건 지우기", 시간 범위에 최근 3개(`rapidtriage.v2.conditions.recentRanges`, 저장 실패는 무시). 유형 목록은 한국어 이름 순(이름 없는 id는 뒤).

### 5.4 프런트엔드 실데이터 QA (run-subset10, 카탈로그 `95ed78b7a80fe46a`, 1600×1000)
| # | 결과 |
|---|---|
| Q-F1 | 통과: 조건 줄 32 px(행 28 px), 조건 0개면 칩 없음, F → 패널 제목 포커스, Esc → 닫힘 + "조건" 버튼 포커스 |
| Q-F2 | 통과: 7일 + 유형 → 칩 2개, 새로고침 후 칩 2개·URL 동일, 칩 × → 270 ms 안에 재조회·칩 1개 |
| Q-F3 | 통과: Ctrl+Shift+V → 창(`?popout=viewer&host=…`), 메인 레일; J → 창 갱신은 메인 URL 갱신과 0~1 ms 차(메인 자체 J 처리 110~540 ms, 첫 두 번이 느림); 창에서 8 → 메타, 메인 `mode=meta`; R → 메인 그리드 "관련 있음"(e2e 표본 케이스 — 실데이터 리뷰 DB는 건드리지 않음) |
| Q-F4 | 통과: 토큰이 두 창 URL 모두에 없음, 창 sessionStorage에만; 창 닫기 → 레일 해제·메인 뷰어 복귀; 메인 닫기 → 창 동반 종료 |
| Q-F5 | 통과: eventlog 기본 열 = 시각(기록) · 항목 · 채널 · 이벤트 ID · 요약 · 컴퓨터 · 주체/대상 계정 · 로그온 유형 · 원격 IP · 프로세스 · LogonId · 레코드 ID · 유형(카탈로그 순, 값 없는 열은 반응형 숨김), 시각 칩 "기록 시각"; Security 4624 42행 모두 로그온 유형("5 — 서비스")·원격 IP·계정·프로세스·LogonId 채워짐 |
| Q-F6 | **부분**: kakaotalk-windows 149행은 실제로 레지스트리 문자열 흔적(146행 source-candidate)이라 카탈로그 kakaotalk 계열 열이 적용됨. 12열 중 10열 90~100% 채움, `field_names` 1/149 · `values_redacted` 2/149가 과반 비어 있음 → 카탈로그(D1)에서 두 열을 보조 열로 옮기면 충족 |
| Q-F7 | 통과(데이터 특성 기록): 1,007행, 촬영 시각 · 파일 수정 · 제조사 · 모델 · 위도 · 경도 · 편집 SW · 해상도 · 형식 · pHash 열; EXIF 열은 PNG 아이콘이 많아 3~5%만 값(데이터 특성), 수정 시각·형식·pHash 99~100%; `media.exif_vs_fs_time` 22건 표본 5건 모두 EXIF 촬영 시각 < 파일 수정 시각(1,268~7,583 h, 복사 흔적) |
| Q-F9 | 통과: 트리 "B 등급 이상 152건" = 그리드 `flag_grade=B` 총 152건, 칩 "특이사항 B 이상", 셀·팝오버·뷰어 배너에 근거(danger_type · url · target_path)·오탐 주의·출처 링크·검증 필요 |
| Q-F12 | 통과: "결과 없는 계열 47개 표시"(숨김 47 = 토글 n), T → "47개 숨김"·흐린 노드, 새로고침 후 유지, `#…/artifacts/email`(0건) 딥 링크가 숨은 노드를 드러내 선택, "카카오톡" 검색이 숨은 카카오톡(macOS) 노드를 드러냄; a11y 자체 규칙(e2e) 위반 0 |
| Q-F13 | 통과: 특이사항 C 이상 전체 아티팩트(혼합) → 주요/지원/추가/날짜 및 시각 4열이 보이는 43행 모두 라벨+값 2줄(예: 다운로드 행 "URL / 탭 URL / 참조 URL / 다운로드 시작"); `artifacts/browser`(한 계열) → 카탈로그 열로 전환(e2e) |
| Q-F14 | 통과(e2e 표본 케이스 — 실데이터 리뷰 DB는 건드리지 않음): R → 스트라이프 `relevant` 6 px·"검토 표시: 관련 있음", X → `excluded`, 스트라이프는 행마다 1개 |
| Q-F15 | 통과: eventlog·파일·타임라인 행 모두 7항목, 값 또는 "없음 — 사유"(eventlog 위치 0x1200 = 레코드 오프셋, 파서 windows-eventlog-evtx-native eventlog-normalized-v21; 타임라인 → "원본 아티팩트 행으로 이동"); 이 런은 폴더 증거라 파티션은 "파티션 정보 없음(폴더·논리 증거)" |
- 게이트(최종): biome · tsc · vitest 77 파일 876건 · 대비 검사 0 실패 · Playwright 35건(새 `viewer-families.spec.ts` 8건 + a11y 1건 포함) 통과. 번들(`rapidtriage/web/static/v2`)과 그 안의 카탈로그 사본(`families.fallback.json`)은 PR 시점에 그때의 카탈로그로 다시 빌드한다(`npm run build`의 prebuild가 백엔드 로더로 재생성) — 여기 적힌 카탈로그 해시는 QA 당시 값일 뿐이다.
- (이전 기록) 게이트: biome · tsc · vitest 76 파일 869건 · 대비 검사 0 실패 · Playwright 33건(새 `viewer-families.spec.ts` 6건 + a11y 1건 포함) 통과, `npm run build` → `rapidtriage/web/static/v2`.
