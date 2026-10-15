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
- **U-F6 검증 가능성**: 모든 지표는 규칙 id·버전·출처를 가진다. 보고서 인용 시 "지표 id@버전 + 근거 필드값"이 함께 나간다. [G]/[!] 지표는 `status: "provisional"`로 표기되어 UI에서 "검증 필요" 꼬리표가 붙는다.

## 3. 설계

### 3.1 백엔드 — 지표 엔진 (`rapidtriage/core/triage_rules/`)
- `base.py`: `Rule(id, family, grade: "A"|"B"|"C", label_ko, rationale_ko, false_positive_ko, sources[], version, status: "verified"|"provisional", params: dict)`, `RuleResult(rule_id, grade, evidence: {field: value}, note)`. 행 단위 규칙은 `apply(row: Mapping) -> RuleResult|None`; 교차 규칙은 `prepare(context)`(런 전체 1회: USB VSN 집합, MFT 경로 집합, 4625 버킷, 계정별 시각 분포 등)와 `apply(row, context)`.
- 계열 모듈: `eventlog.py, rdp.py, registry.py, execution.py, lnk.py, accounts.py, ntfs.py, usb.py, messenger.py, email.py, browser.py, cloud.py, media.py, documents.py, archives.py, mobile.py` — 카탈로그 표를 1:1로 옮기고 임계값은 `params`(기본: 4625 폭주 10건/5분, EXIF-FS 차 1일, pHash 거리 8, 야간 00–05시, Date-Received 1일)로 둔다. 모든 규칙에 픽스처 테스트(양성 1·오탐 1).
- 실행 지점: ① 런의 persist 단계 끝에 `triage-flags` 단계로 자동 실행(새 런), ② 기존 런은 P1 분석 작업 kind `triage-flags`로 수동 실행. 출력 `analyses/<id>/flags.jsonl`(행: `{kind, record_index, flags: [...]}`) + `summary.json`(지표별·등급별·kind별 건수, 규칙 버전 목록). 런 디렉터리 밖에는 쓰지 않는다.
- 조인: 아티팩트/파일/분석 행 페이지에 `flags` 필드를 붙인다(NTFS 조인과 같은 LRU 인덱스, (kind, record_index) 키, 단일 실행, 메모리 상한). 서버 필터 `flag=<id>`(반복)·`flag_grade=A|B|C`(이상)와 정렬 `sort=flags`(등급 우선). `/tree`에 `flags` 섹션(등급·지표별 건수)과 도메인 노드 `flag_counts`.
- 계열 기본 열 메타: `GET /api/meta/families` — 계열 id → {핵심 열 키·라벨·ts_kind, 보조 열, 지표 id 목록, 출처}. 카탈로그를 YAML(`rapidtriage/core/triage_rules/catalog/*.yaml`)로 두고 프런트·백엔드가 같은 파일을 읽는다(빌드 시 프런트로 복사).

### 3.2 프런트엔드
- **설정 자동 숨김**(U-F1): `GridToolbar`를 "조건 줄"로 교체 — 검색 입력, 조건 버튼(+배지, F), 칩(각 ×), 결과 건수, 밀도/열 프리셋은 조건 패널 안으로. `FilterBar`는 팝오버 내부 컴포넌트가 된다(기존 테스트 이식). 열 머리 필터(`cf=`)와 열 선택은 그대로. Q-A3 규칙 유지.
- **창 모드**(U-F2): `features/viewer/popout/`: `window.open(location.origin + '/?popout=viewer', 'rapidforensic-viewer', 'popup,width=…')` 로 같은 번들을 띄우고, 상태는 `BroadcastChannel('rapidforensic.viewer')`로 동기화(메인 → 새 창: viewerTarget/row/mode/tz/theme; 새 창 → 메인: 표시 명령·히스토리·닫힘). 새 창은 토큰을 메인에서 메시지로 받아 sessionStorage에만 둔다. 메인 창은 `viewerPane: "popout"` 상태로 레일 표시. 창 좌표 기억, `beforeunload`에서 상호 닫기. 이유: 포털 방식은 React 19에서도 가능하지만 스타일·포커스·키맵이 두 문서에 걸쳐 꼬이므로, 독립 인스턴스 + 채널이 더 안전하다.
- **계열별 열**(U-F3): `grid/columns/families.ts`가 YAML 카탈로그에서 계열 → 열 정의를 만들고, `artifacts.ts`의 KIND_COLUMNS는 "kind의 다수 계열" 폴백으로만 남긴다. 시각 셀에 `ts_kind` 칩. 열 선택에 "카탈로그 보조 열 모두 추가/제거".
- **특이사항**(U-F4): `특이사항` 열(칩, 등급색, 접근성 이름 "특이사항 A 2건: 로그 삭제, 외부 IP RDP"), 근거 팝오버(근거 필드·오탐 주의·출처 링크·"검증 필요" 꼬리표), 필터 조건(등급/지표), 트리 "특이사항" 섹션, 뷰어 배너, 리뷰보드에 "특이사항 A 전체 보기" 바로가기, 정책 의존 부재 배너.
- 모든 라벨 한국어, 명령 등록, DisabledReason, polite 영역 1개, 대비 게이트.

### 3.3 작업 분할과 순서
1. **D1(백엔드, Opus)**: 카탈로그 YAML + 규칙 라이브러리 + 테스트 + `triage-flags` 단계/분석 kind + 조인·필터·트리 + `/api/meta/families`. 실데이터 `run-subset10`으로 지표 건수·오탐 샘플 20건 검토.
2. **D2(프런트, Opus)**: U-F1 → U-F2 → U-F3/U-F4(계약 §3.1 mock) 순. e2e: 조건 패널 키보드, 창 모드(Playwright popup 컨텍스트), 계열 열, 특이사항 필터.
3. 통합 → 실데이터 QA → 적대적 리뷰(백/프런트) → 수정 → PR.
전제: 열린 PR 스택(#6→#7→#8→#9→#10)을 먼저 main에 머지해 하나의 기준점을 만든다(프런트는 #7, 파서/검색은 #10에 있어 두 계보가 갈라져 있음). 머지 전이면 통합 브랜치(#10 head + #7 merge)에서 시작한다.

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
| Q-F11 | 게이트 | unittest/ruff/vulture/compileall/doc-refs/OpenAPI, vitest/tsc/biome/contrast, e2e(팝업 포함), 적대적 리뷰 0 미해결 |

## 5. 결과 기록
(구현 후)
