# R4 — 처리 계획표·탐색기·뷰·필터 라운드 (2026-10-18)

근거: `docs/plans/axiom-parity-roadmap-2026-10-17.md` §2 R4, `docs/research/axiom-parity-matrix-2026-10-17.md` Table B(B1 탐색기·B2 뷰·B3 필터 "없음/부분"), 갭 16·17. 실행 모델의 상세 설계는 `docs/plans/run-model-p2-2026-10-12.md`(P2)를 그대로 따른다. 완료 기준: 탐색기 7/7, 뷰 7/7(지도는 표 대체를 명시), 필터 바 AXIOM 항목 전부, 처리 계획표 U-P2-1~7.

## 1. 최종 사용자가 보는 문제
- 3일짜리 E01 런의 진행·부분 완료·개별 취소가 보이지 않고, 끝난 계열부터 볼 수 없다(P2 §1).
- 파일 시스템을 폴더 계층으로 내려가며 볼 수 없고, 슬랙·미할당·고아 노드가 없다. 레지스트리를 키/값 트리로 탐색할 수 없다.
- 카드형 행 보기, 위치 데이터의 지도 대체, 통합 보기 값 ↔ 행 ↔ 값의 연결 그래프가 없다.
- 날짜 필터는 절대 범위뿐이다(최근 n일·요일·시간대 없음). 파서 오류 행만 모아 보는 "부분 결과" 필터가 없다. 콘텐츠 유형 전역 필터가 없다.
- 미디어 탐색기(관련 미디어 묶음·유사 사진 찾기·미디어 범주)가 부분적이다.

## 2. 이상 상태와 설계 — 3갈래

### 2.1 V1 — 처리 계획표(P2 전체) — 백엔드+처리 단계
`run-model-p2-2026-10-12.md` §2 U-P2-1~7, §3 설계를 그대로 구현한다: `core/run/plan.py` 그룹 카탈로그(R2·R3로 늘어난 공급자 — windows-messenger·cloud-sync·카카오톡 메시지·PST·캐시·레지스트리 심화·PCA·안티 포렌식·triage-flags·derived — 를 그룹에 반영), `rapidtriage-run-plan.json`, 15초 심장박동, 태스크/그룹 취소·건너뛰기·완료, 런 시작 전 그룹 선택, 완료된 공급자부터 열람(런 실행 중 `/tree`·`/artifacts`가 끝난 kind를 반환), 서버 재시작 시 "중단됨" + 완료 태스크 재사용 재개, `canceled`/`cancelled` 철자 통일, CLI `run --skip-group/--skip-task/--print-plan`, `run-plan`, `run-control`. 처리 단계 중앙에 그룹→태스크 표(상태·건수·소요·막대·그룹별 ×, "모두 취소 / 지금까지로 마치기").

### 2.2 V2 — 탐색기 3종(파일 시스템·레지스트리·미디어) — 백엔드+프런트
- **파일 시스템 탐색기**: `/api/runs/{id}/fs-tree?path=`(한 단계 자식 폴더·파일 수·크기 합, 정렬·페이지), 노드: 볼륨/파티션 → 폴더 계층(지연 로드), 특수 노드 슬랙·미할당 공간·고아 파일(파일 목록·NTFS 메타 분석에 있으면), 폴더 선택 → 그리드는 그 폴더의 직속/하위 파일(`path_prefix=` 서버 필터). 브레드크럼, 키보드(←/→ 펼침, Enter 열기).
- **레지스트리 탐색기**: 하이브 → 키 트리(`/api/runs/{id}/registry-tree?hive=&key=` — 수집된 레지스트리 행에서 키 계층을 인덱싱, 키마다 값 목록·마지막 기록 시각), 값 표(이름·형식·데이터·디코딩), 키 경로 복사·인용, 해당 키에서 나온 아티팩트 행으로 점프.
- **미디어 탐색기**: 썸네일 그리드에 "관련 미디어"(같은 해시·pHash 거리 ≤ 8) 묶음 패널, "유사 사진 찾기"(선택 이미지 → pHash 근접 목록, 서버 `/api/runs/{id}/media/similar?ref=`), EXIF 카메라·촬영일 그룹, 흐리게·범주 태그와 연동.

### 2.3 V3 — 뷰 3종·필터 — 프런트(+소량 API)
- **행(카드) 뷰**(Alt+Shift+6 자리): 제목(대표 값) · 종류·계열 부제 · 핵심 시각 · 우측 날짜 · 특이사항 칩 · 호버 인라인 액션(인용·원본 열기·태그). 가상화, 키보드 J/K.
- **지도 대체 뷰**: 위치 열(위도·경도)이 있는 행을 좌표 표 + 근접 클러스터 목록(격자 0.01°)으로 보여 준다. 로컬 타일·외부 지도 호출 없음(정책). 클러스터 클릭 → 해당 행 필터.
- **연결 그래프 라이트**: 통합 보기 값 하나를 중심으로 "값 → 원본 행(계열별) → 그 행의 다른 식별자 값" 2홉을 SVG 노드-링크로(최대 200 노드, 순수 SVG, 외부 라이브러리 없음). 노드 클릭 → 해당 표/그리드.
- **필터**: 날짜 팝오버에 상대 범위(최근 1/7/30일, 사고 시각 ± n시간), 요일·시간대(업무 외 시간) 조건 — 서버 시간 필터로 변환; "부분 결과" 조건(파서 오류·잘림·복호 실패 행: `parse_status`/`*_truncated`/`coverage` 필드 서버 필터); 전역 "콘텐츠 유형"(문서/이미지/영상/음성/압축/실행/DB/메일) 칩 — 파일·아티팩트 공통 매핑.

## 3. QA 시나리오
| # | 시나리오 | 기준 |
|---|---|---|
| Q-R4-1 | 계획표 | 런 시작 시 계획 파일·그룹/태스크 표, 15초 내 진행 반영, 그룹 건너뛰기·취소·마치기 동작, 감사·요약·보고서 반영(P2 Q 전부) |
| Q-R4-2 | 진행 중 열람 | 실행 중 런에서 끝난 kind가 트리·그리드에 건수와 함께 열림, 미완료는 흐림+사유 |
| Q-R4-3 | 재시작 | 서버 재시작 → "중단됨", 재개 시 완료 태스크 재사용 |
| Q-R4-4 | 파일 시스템 탐색기 | run-subset10에서 폴더 계층 탐색, 폴더 선택 → 그리드 하위 파일 건수 = fs-tree 집계 |
| Q-R4-5 | 레지스트리 탐색기 | NTUSER/SYSTEM 키 트리, 값 표, 키 → 아티팩트 점프 |
| Q-R4-6 | 미디어 | 관련 미디어 n = 같은 해시/pHash 근접 수, 유사 사진 목록 |
| Q-R4-7 | 뷰 | 카드 뷰·지도 대체·연결 그래프가 키보드·스크린 리더로 사용 가능(a11y 0), 대용량에서 가상화 |
| Q-R4-8 | 필터 | 상대 날짜·요일·업무 외 시간·부분 결과·콘텐츠 유형이 서버 필터로 동작, 칩 한국어, URL 복원 |
| Q-R4-9 | 게이트·리뷰 | 대상 모듈 게이트, 전체 스위트·Playwright는 Antigravity 위임 결과로 확인, 적대적 리뷰 0 미해결 |

## 4. 결과 기록
(구현 후)

### 4.2 V2 — 탐색기 3종 (브랜치 `feat/r4-v2-explorers`, 2026-10-18)

**구현**
- API: `rapidtriage/api/app/fs_tree.py`, `registry_tree.py`, `media_similar.py`, `routes_explorers.py`(+ `GET /files?path_prefix=&recursive=&special=` — `routes_runs.py`, `triage_flags.filter_files_rows(restrict=)`). 테스트 `tests/test_rapidtriage_explorers_api.py`(18건: 폴더 수치 = 그리드 합계(양 범위·직속/하위), 커서 페이지, 경로 한정 403, 한국어 422, 색인 상한 3종, 출력 갱신 시 재색인, 레지스트리 값 디코딩·인용·점프 행·이름만 대체, pHash 거리·같은 해시·그룹).
  - `GET /api/runs/{id}/fs-tree?path=&scope=&limit=&after=`: 한 단계 자식 폴더(직속·하위 파일 수/크기 합), 볼륨 루트(파티션 시작 섹터는 ntfs-meta 분석이 있을 때), 특수 노드 고아 파일·미할당 공간·슬랙(파일 목록 → ntfs-meta·카빙 분석 순, 없으면 `hidden_special_nodes`에 사유). 증거 루트 밖·상대 경로 불명 행은 트리에 넣지 않고 `index.outside_root`로 보고.
  - `GET /api/runs/{id}/registry-tree?hive=&key=` / `registry-values?hive=&key=`: `registry-key-tree-node` 행으로 하이브→키 색인(60만 키 상한, 출력 서명별 캐시), 값은 증거 루트 안의 하이브 파일에서 `NativeRegistryHive`로 디코딩(읽지 못하면 수집된 값 이름만 + 사유), 인용 문장, 키에서 나온 `windows-registry`·`windows-shellbags`·`windows-os-account` 행(점프 대상).
  - `GET /api/runs/{id}/media/similar?ref=&max_distance=&limit=`(pHash 해밍 거리 0–16, 기본 8) · `media/groups?by=camera|date[&key=]`.
- 콘솔: `frontend/src/features/explorers/`(지연 로드 ARIA 트리 `ExplorerTree`, `FsExplorer`, `RegistryExplorer`, `MediaExplorerPanel`, `explorer.fs`·`explorer.registry` 명령), 라우트 `#/case/{run}/explore/files?dir=/<폴더>[&rec=1|&special=]`, `#/case/{run}/explore/registry/{hive}?key=`. 진입: 전체 보기 › 파일 시스템 · 레지스트리 탐색기, 파일시스템 계열 › 폴더 탐색기, 레지스트리 계열 › 레지스트리 탐색기(키·값), 명령 팔레트. 썸네일 보기 툴바: 관련 미디어 · 유사 사진 찾기 · 카메라·촬영일 그룹, "격자에 이 묶음만"(흐리게 유지), "이 묶음 선택(태그용)" → 선택 막대 태그. 키보드: ↑/↓·←/→(펼침/접기·부모/첫 자식)·Home/End·Enter 열기, 펼침/열기는 셸의 polite 라이브 영역 하나로만 알림. vitest `src/features/views/explorers.test.tsx`(11건) + `views.test.tsx` 썸네일 패널 1건.

**실데이터 (run-subset10, 읽기 전용 증거 `D:\rapid-qa\bsh-subset`, API :8941 + Vite :8942)**

| # | 확인 | 결과 |
|---|---|---|
| Q-R4-4 | 폴더 수치 = 그리드 합계 (후보 4,935 / 인벤토리 14,094, 폴더 1,080, 루트 밖 0) | `Users/user/Desktop` 직속 39 = 39, 하위 1,655 = 1,655 · `Users/user/AppData/Local/Microsoft/Edge/User Data/Default` 직속 29 = 29, 하위 1,662 = 1,662 · `Windows/System32/config` 직속 1 = 1, 하위 533 = 533(콘솔 "총 533건" = "하위 포함 533개") · 인벤토리 `Windows/System32/winevt/Logs` 183 = 183. 키보드로 Documents → Koino 열기, 그리드 1건. 특수 노드 3종은 숨김 + 사유(이 런은 디렉터리 증거라 고아·미할당·슬랙 행 없음, ntfs-meta·카빙 분석 없음). `..` → 422, `C:\Windows` → 403 |
| Q-R4-5 | NTUSER/SYSTEM 키 트리·값·점프 | 하이브 14개(키 248,904, 첫 색인 8.4 s, 이후 0.01 s; 연결 행 3,121). NTUSER(…-1001) 루트 자식 12개; `…\CurrentVersion\Run` 값 8개 REG_SZ 디코딩(OneDrive·KakaoTalk·Slack 등), 연결 행 8건(`registry-persistence-entry`) → "KakaoTalk 행 열기"가 `windows-registry` 그리드 119쪽 행 + 뷰어 레코드로 이동. SYSTEM `ControlSet001\Services` 자식 853개(커서 페이지; 깊은 링크 `Services\WinDefend`는 첫 200개 밖이라 트리가 다음 쪽을 스스로 불러 선택 표시, 값 12개), `ComputerName\ComputerName` = `진료실1`, 연결 `windows-computer-name` 1건. 인용 "하이브 경로 › 키 › 마지막 기록 › 셀 오프셋 0x…" |
| Q-R4-6 | 관련 미디어·유사 사진 | 이미지 996개(pHash 994). 의사면허증.jpg: 같은 해시 1(`/related-media` 케이스 DB 1 = similar `same_hash` 1), pHash ≤ 8 근접 4 → 패널 "같은 해시 1 · pHash 근접(≤ 8) 4". 전문의 면허증.jpg 1/2, KakaoTalk_20211224_114349237_01.jpg 0/4. 카메라 그룹 7개(iPhone 13 Pro 13 · iPhone 11 Pro 12 · … · 정보 없음 965), 촬영일 그룹 27개; "Apple iPhone 11 Pro" 묶음으로 폴더 격자 좁히기 → 3건 표시 |

**게이트**: 대상 Python 테스트(신규 + api·api_contract·media_image·windows_artifacts)·ruff·vulture·compileall·check-doc-refs·API 스냅샷, 프런트 lint·typecheck·vitest(tree·views·grid·shell·api)·check:contrast 통과(원문은 작업 보고). 전체 스위트·Playwright는 위임 대상.

### 4.3 V3 — 뷰 3종·필터 (브랜치 `feat/r4-v3-views-filters`)

**구현**
- 행(카드) 보기 `features/views/CardView.tsx`(Alt+Shift+5 — AXIOM의 6번 자리 대신 비어 있던 5/6을 차례로 씀): 가상화 `role="list"`/`listitem`(aria-setsize·posinset), 제목·유형—계열 부제·시각·경로·우측 굵은 날짜·특이사항/리뷰/태그 칩, 호버·포커스 시 인용·원본 열기·태그(북마크). J/K·↑↓·Home/End·PageUp/Down, Enter 뷰어, Space 선택, R/X/I/B/1–9는 공용 검토 명령.
- 지도 대체 보기 `features/views/MapView.tsx`(Alt+Shift+6, 아티팩트 노드): 서버에 `geo=-90,-180,90,180`(좌표 있는 행만)을 요청해 좌표 표 + 0.01° 근접 묶음(건수·처음/마지막 시각, GPS 시각 우선). 묶음 → `geo=<칸 상자>` 조건 + 열 보기. 빈 상태·상단 안내에 "지도 타일·외부 지도 서비스 없음(정책)".
- 연결 그래프 라이트 `features/derived/DerivedGraph.tsx` + `GET /api/runs/{id}/derived/{table}/graph?value=&max_nodes=`(10–200, 기본 200): 값 → 표본 원본 행(≤20, 계열별) → 그 행의 다른 식별자 값(파생 단계와 같은 열 규칙 `core.derived.engine.collect_row`, 자격 증명은 가린 값). 3열 계층 SVG(외부 라이브러리 없음), 로빙 tabindex·↑↓/←→/Home/End·Enter, 행 → 계열 표의 그 행, 값 → 그 표(`q=`). 통합 보기 도구줄 "원본 행 | 연결 그래프".
- 행 조건 `rapidtriage/api/app/row_conditions.py` → `GET /artifacts`·`/files`·`/timeline`: `from`/`to`, `weekday`, `hours`(HH-HH, 자정 넘김), `offhours=1`(hours 또는 weekday, 기본 18–09·토·일), `tz`(UTC·±HH:MM·IANA), `partial=1`, `content`(문서·이미지·영상·음성·압축·실행·DB·메일), `/artifacts`만 `geo`. 잘못된 값은 한국어 422, `limit=0`이면 400, 페이지에 `conditions` 반향. channel·browser/service·flag·category·sort와 AND.
- 콘솔: 조건 패널에 최근 1/7/30일, 사건 시각 ± n시간(최신 특이사항 분석의 `incident_start/end` 미리 채움), 요일·시간대·업무 외 시간(표시 시간대), 콘텐츠 유형 칩, 부분 결과. URL `wd=`·`hours=`·`offhours=1`·`partial=1`·`content=`·`geo=` 왕복, 저장한 조건에 포함, 칩은 한국어("업무 외 시간 18–09시·토·일", "콘텐츠 문서", "부분 결과만", "위치 … 부근"). 시간 범위는 이제 artifacts/files/timeline에서 서버 필터(그 밖은 불러온 행).

**실데이터** (`D:\rapid-qa\derived\run-subset10`, 런 `b5fabbe09f18`, API 8963 + Vite 8964, 증거 읽기 전용, `tz=Asia/Seoul`)
- 업무 외 시간 이벤트 로그: 서버 202,445건 = 수동 집계 202,445건(294,456행 중 시각 없음 186, 주말 72,205). Security 채널 + 업무 외 20,355. 브라우저 업무 외 4,561, 주말(`weekday=sat,sun`) 1,939, 브라우저 업무 외 + 실행 파일 다운로드 37건(그리드). 타임라인 업무 외 216,333 / 부분 결과 1,575 / 2025-05-23~30 KST 102,379(요청당 약 5 s).
- 부분 결과(전체 아티팩트) 34,195건, 콘텐츠 문서 4,108 · 이미지 3,707 · 실행 41,764(Prefetch 참조 DLL/EXE 포함). 파일: 문서 2,267(= 문서 범주), 업무 외 0(모든 파일이 취득 사본이고 NTFS 분석 없음 — 한계 문서화).
- 카드 보기: 이벤트 로그 노드 250장 중 11장만 마운트(가상화), J로 다음 카드·뷰어 행 동기, 접근 이름 "5615 application Microsoft-Windows-WMI, EVTX 이벤트 — 이벤트 로그, 시각 2025-02-23 22:47:22 KST". 브라우저 노드 + 업무 외 시간 카드 확인(월 08:49·토 14:30 등).
- 지도: media-image 위치 행 3건 → 묶음 2개(37.48,126.94 칸 2건, 37.20,127.10 칸 1건), 묶음 클릭 → 그리드 2건. 전체 아티팩트 지도는 3건(64만 행 훑기 38 s).
- 연결 그래프 `people/user`: 41 노드(원본 행 19 = SAM 계정·그룹·이벤트·로그온 세션·탐지·브라우저·문서·LNK·점프 목록 11계열, 값 21 = 사람 8·장치 4·경로 5·URL 4, 표에 있는 값 22), 간선 57, 0.98 s. `people/S-1-5-18`: 29 노드, 0.7 s. 키보드 → 행 → 값 이동 확인.

**게이트**: targeted pytest(신규 row_conditions 14 + api·api_contract·derived_api(+그래프 3)·timeline·field_filters·derived_engine 130 passed, parser_quality_integration·triage_flags_api 43, ntfs_r3·analyses 118), ruff·vulture·compileall·check-doc-refs 통과, OpenAPI 스냅샷 갱신(122 경로/139 작업). 프런트 lint·typecheck·check:contrast 통과, vitest(views·filters·derived·grid·api) 33 파일 363 통과 + shortcuts·shell·app 64 통과. 전체 스위트·Playwright는 위임(Q-R4-9).

### 4.4 적대적 리뷰 수정 — 백엔드 (브랜치 `fix/r4-backend-review`)

- **이어서 실행 체인**: 이전 계획의 `outcome`이 `complete`가 아니면(partial·cancelled·failed·끝나지 않아 `None`=중단) 단계 출력(manifest·docs·files·timeline·indicators)을 재사용하지 않는다. 재사용 후보 페이로드에 `plan_status`(자리표시) 또는 `inputs_partial`이 있으면 언제나 버린다(`load_reusable_json`). 부분 공급자 입력으로 만든 manifest도 `inputs_partial`을 단다.
- **같은 출력 폴더 동시 실행 금지**: 대기·실행 중인 런이 쓰는 폴더로의 제출·재실행·이어서 실행은 409(“같은 출력 폴더를 쓰는 런(…)이 대기·실행 중입니다…”). 재실행한 원래 런에는 `retried_by`, 같은 폴더를 이어받은 경우 `superseded_by`가 남고, 그 런의 진행·계획 조회는 새 런의 실시간 상태 대신 `superseded_by` 안내를 돌려준다.
- **새로 실행(fresh retry)**: `resume=false`로 실행하며 새 폴더에 쓴다 — 출력 폴더를 지정하지 않은 런은 런별 기본 폴더, 지정한 런은 옆에 `<폴더>-retry-<id>`. 원래 런의 출력은 그대로 남는다.
- **제어 타이밍**: 런은 제출 시각 이후에 쓰인 제어 요청을 감시자 시작 전이라도 적용한다(빠른 “모두 취소”). 대기 중인 런의 계획 제어는 409(“대기 중인 런은 시작한 뒤에 제어할 수 있습니다”), 실행 중이지만 아직 이전 런의 진행 파일만 있는 경우도 409. 대기 중 런의 계획표는 요청으로 만든 골격(ETag 고정)이다.
- **늦은 모두 취소**: 요약·보고서 단계가 시작된 뒤의 `cancel_all`/`finish`는 “이미 끝난 태스크입니다…”로 거부된다. 진행 파일 상태는 `plan.outcome`에서 정해져 계획 파일·요약과 항상 일치한다.
- **제어 파일**: 읽기-수정-쓰기를 `O_EXCL` 잠금 파일(30초 지나면 낡은 잠금 제거)로 감싼다. 읽을 수 없는 제어 파일은 덮어쓰지 않고 오류(“실행 제어 파일을 읽을 수 없어…”)를 낸다. 감시자는 읽기에 성공한 뒤에만 파일 도장을 기록한다.
- 그 밖: 옛 상태 파일의 `canceled` 단계·전이 철자 정규화, 탐색기 색인 캐시(파일 시스템·레지스트리·미디어)의 단일 비행·실패 시 잠금 정리, 레지스트리 마운트 추정 보정, `/files?path_prefix` 폴더 행 위치 캐시, 런 종료 시 최종 상태를 쓴 뒤 활성 목록에서 제거.
