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
