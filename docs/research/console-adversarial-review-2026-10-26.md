# RapidTriage v2 콘솔 전체 적대적 리뷰 (feat/r6-ux @169c4ab, 2026-10-26)

리뷰 모델: Fable. 증거(스크린샷 259장·DOM 감사 JSON·서버 로그)는 로컬 임시 폴더에만 있고 Git에는 넣지 않는다.

**방법:** 자체 API(`RAPIDTRIAGE_INDEX_PERSIST=0`, 토큰 고정) + Playwright(Chromium headless, ko-KR, Asia/Seoul). 1280×720·1920×1000 양 테마, 880×700·1024×768 드로어. 모든 비-GET `/api` 요청은 403으로 차단(허용: `case-db/ensure`, `saved-searches/list`). 차단된 쓰기 시도(모두 UI 동작의 부작용): `POST sample-case/run`(샘플 버튼), `POST case-db/review-batch`(R/B/1 키), `POST runs/{id}/analyses`(다시 만들기). 두 QA 런(`run-subset10` b5fa, `qa-case1` af54) 폴더를 before/after 스냅샷으로 비교했다.

**폴더 변경:** `-shm/-wal` mtime(known) 외에 af54 런에 `rapidforensic-run-validation-package.json`·`.audit.json` 2개가 생성됐다 — 보고 단계 "검증 패키지 내보내기" 한 번 클릭의 결과(확인 없이 `GET /validation-package/file`이 런 폴더에 쓴다, `routes_reports.py:111-115`). 두 파일은 리뷰 후 삭제했다. 아래 C-G7/C-R1.

심각도: **S1** 치명/오해 유발 · **S2** 주요 · **S3** 경미.

## A. CONFIRMED 결함

### A0. 전역·셸

| # | 심각도 | 화면 | 결함 | 위치 | 제안 |
|---|---|---|---|---|---|
| C-G1 | S1 | 처리 단계 | 완료된 런인데 "처리 계획" 표가 25개 그룹 전부 **대기**, "완료 0 · 건너뜀 3", 활성 ✕(건너뛰기) 버튼. `/plan`이 stale(queued 23)인데 UI가 그대로 신뢰 | `ProcessStage.tsx:611`, `RunPlanTable.tsx:150-200,75-76` | `completed && !live && counts.completed===0`이면 단계표로 대체 또는 "계획 기록 없음(이전 형식)" 배너; 완료·실패 런에서 ✕/모두 취소 숨김 |
| C-G2 | S1 | 처리 런 목록 "소요" | 가져온 런의 소요가 31:32:13 등 — `created_at→updated_at` 차이, 실제 처리(41분)와 무관 | `ProcessStage.tsx:54-63` | imported면 summary started/completed, 없으면 "—" |
| C-G3 | S1 | 랜딩·처리·접수 | 같은 런 날짜가 화면마다 다름(가져온 시각 vs 실행 시각, 2일 차이) | `Landing.tsx:96-99`, `dashboard/model.ts:79-83` | 대표 시각 = summary started_at, 가져오기 시각은 툴팁 |
| C-G4 | S2 | 전역 날짜 포맷 | 접수는 `toLocaleString`(시간대 무시), 나머지는 `YYYY-MM-DD HH:mm:ss KST`, 레지스트리 "마지막 기록"·뷰어 메타는 ISO 원문 | `dashboard/model.ts`, `RegistryExplorer.tsx`, `metaLabels.ts` | `formatTimestamp(value, timezone)` 하나로 |
| C-G5 | S2 | 상태바 | "케이스 40건"(실제 런 40·케이스 1); 선택기 "케이스:"에 런; 교차 케이스 "현재 케이스 … (af54ff24)" | `StatusBar.tsx:273`, `CasePickerCombobox.tsx`, `AnalysisDialog.tsx` | "런 40건 · 케이스 1건"; "런:" |
| C-G6 | S2 | 랜딩 "샘플" | 즉시 `POST sample-case/run`, 확인·진행 없음, 실패 시 서버 detail 원문 토스트 | `case/commands.ts:118-131`, `RunDialog.tsx:155-162` | 확인 대화상자 + 스피너 |
| C-G7 | S2 | 보고 "검증 패키지 내보내기" | 확인 없이 런 폴더에 2파일 즉시 생성, 피드백 없음 | `ReviewReportStage.tsx`, `api/reports.ts:51-54`, `routes_reports.py:111-115` | 내보내기 대화상자 + 완료 토스트(경로) |
| C-G8 | S2 | 보고 좌측 | "보고서 내보내기…"·"보고서 내보내기" 두 버튼이 같은 대화상자 | `ReviewReportStage.tsx:199`, `commands.ts:172` | 하나로 |
| C-G9 | S2 | 상단바 "실행" | 케이스 열린 상태에서 "케이스 없이 빠른 런" 대화상자 | `TopBar.tsx`, `RunDialog.tsx` | 케이스 열렸으면 "이 케이스에 런 추가" |
| C-G10 | S2 | 스테이지 레일 | 트리 접기 토글 라벨 "탐색" = 위 "탐색" 단계와 동일 글자 | `StageRail.tsx:83` | "패널" 또는 아이콘+툴팁 |
| C-G11 | S2 | 명령 팔레트(케이스 없음) | 수백 개 "이동: …" 비활성 항목 전부 나열; 비활성 이유 문구 2종 | `commands/builtin.ts`, `case/commands.ts`, `tree/domains.ts` | 케이스 없을 땐 이동 명령 숨김 |
| C-G12 | S3 | 토스트 | "알림 닫기 (Esc)"지만 Esc는 토스트 포커스 때만; 오류 토스트가 단계 전환 후에도 잔존 | `ToastRegion.tsx:20-41` | 전역 Esc(다이얼로그 없을 때) |
| C-G13 | S3 | 리뷰 표시 토스트 | DB가 이미 있어도 "케이스 DB 준비 중…" 매번 | `reviewActions.ts:204-236` | run 응답의 case_db 플래그로 생략 |
| C-G14 | S3 | 도움말 vs 실제 | `T` 설명 "표시/숨김" vs 토스트 "흐리게" vs 트리 "N개 표시/숨김" | `shortcuts.ts`, `EvidenceTree.tsx:397-404` | 통일 |
| C-G15 | S3 | 검색 옵션 팝오버 | 키워드 팩 영문 id, "known-good 숨기기" | `SearchOptionsPopover.tsx` | 한글명+툴팁 |
| C-G16 | S3 | 환경 점검 | 영/한 혼재 | 서버 doctor 메시지, `DoctorDialog` | 키별 한글 매핑 |
| C-G17 | S3 | 라우팅 | `?row=` 파라미터가 뷰어 없는 단계로 가도 해시에 잔존 | `router.ts`, `stages.ts` | 제거 |

### A1. 랜딩·케이스 마법사·대화상자

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-L1 | S2 | "케이스 열기" → 제목 "케이스 전환"; 런 칩에 날짜·모드·ID 없어 동일 행 구분 불가; 모든 행에 "삭제" 노출 | `CasePicker.tsx:83-162` | 제목 "케이스 열기", 칩 `모드 · 시작 시각 · id8`, 삭제는 ⋯ 메뉴 |
| C-L2 | S2 | 마법사 "사건 유형" 자유 입력(datalist); "검사관" 용어 | `CaseWizard.tsx:106-107,409` | select(+기타) |
| C-L3 | S3 | 랜딩 최근 케이스 경로 머리·꼬리 공백 분리; 4항목 이름 동일 | `Landing.tsx:115`, `controls.css:717-740` | whole 모드 gap 0 |
| C-L4 | S3 | 마법사·빠른 런: 열자마자 "…입력하세요." 상시 노출 | `CaseWizard.tsx`, `RunDialog.tsx` | hover/focus 툴팁 |
| C-L5 | S3 | 빠른 런 "· 필수", "(태스크 3)", 수집 프로필 영문 id | `RunPlanGroupsField.tsx:173-174`, `RunDialog.tsx` | 한글명 |
| C-L6 | S3 | 랜딩 "최근 케이스" 아래 항목은 런 | `Landing.tsx:80` | "최근 런" |

### A2. 접수(카드 그리드 제외)

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-I1 | S2 | 첫 접수 로드 12.2 s/8.9 s 동안 스켈레톤만 | `CaseDashboard.tsx` | 카드별 skeleton + 진행 |
| C-I2 | S2 | "공개 사항 › 상한·절단"에 원시 키(`summary.size_caps.truncated`, `row-truncation:recent-files`…) | `dashboard/disclosures.ts` | 키→한글 사유 |
| C-I3 | S3 | 접수 좌측이 탐색 트리 전체 | `Layout.tsx`, `stages.ts` | 접수 전용 패널 |
| C-I4 | S3 | 880에서 다른 카드 세트(두 구현 `cards.tsx` vs `caseCards.tsx`), 수치·문구 상이("문서 52" = matched만) | | 단일 구현, "키워드 일치 문서 52" |
| C-I5 | S3 | 메모/노트 textarea 접근성 이름 없음 | `caseCards.tsx:710,759,819` | aria-labelledby |

### A3. 탐색 — 증거 트리

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-T1 | S2 | 전체 파일/파일 시스템/폴더 탐색기/전체 파일(인벤토리)/파일시스템 아티팩트 — 비슷한 이름 6개, 수치 중복 | `domains.ts:758-760`, `tree/model.ts` | "파일 목록"·"폴더 탐색기" 각 1개, 도메인 "NTFS·파일시스템 아티팩트" |
| C-T2 | S2 | "레지스트리 탐색기 248,904" 세 군데 | `domains.ts:852`, `model.ts:599` | 1곳 |
| C-T3 | S3 | "검색 결과" 노드 건수 없음, 빈 페이지 | | 마지막 검색어·건수 |
| C-T4 | S3 | 하이브 트리 라벨 잘림, BBI 구분 어려움 | `RegistryExplorer.tsx`, `ExplorerTree.tsx` | SID→user, 2행/툴팁 |
| C-T5 | S3 | 빈 계열 토글 시 "A 등급 0" 이탤릭 | `EvidenceTree.tsx:404` | |

### A4. 탐색 — 그리드·필터·조건

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-D1 | S1 | 파일 목록 정렬·검색어 필터가 불러온 페이지(500/2,000행)에만 적용; 툴바 건수는 로드 행 수 | `DataGrid.tsx:1171-1176`, `useCollectionQuery`, files API | 서버 정렬/필터 또는 명시 배너 |
| C-D2 | S1 | 열 헤더(정렬) 클릭이 첫 행을 선택해 뷰어를 염 → 그리드 504px → 정렬한 열이 숨겨짐 | `DataGrid.tsx:1155-1176` | 정렬은 선택 변경 없이; 정렬 열은 숨김 제외 |
| C-D3 | S2 | 툴바 "조건"·"조건 저장" 2줄 꺾임(뷰어 열림) | `FilterBar.tsx:726,842` | nowrap + 아이콘 |
| C-D4 | S2 | 조건 팝오버가 뷰어 패널 아래로 깔려 잘림 | `popover.css`, FilterBar | portal/z-index, flip |
| C-D5 | S2 | "오늘/최근 N일"이 현재 벽시계 기준 → 2025년 증거에서 0건 | `FilterBar.tsx:162-200`, `conditionValues.ts` | 증거 최신 시각 기준 |
| C-D6 | S2 | "수정" 150px → 초 잘림; "마지막 방문" 칩 접두어로 잘림 | `columns/files.ts:366-368`, `artifacts.ts` | 시각 열 ≥180px, 칩은 헤더/툴팁 |
| C-D7 | S2 | 1920에서도 고정폭 합 1,576px로 가로 스크롤; URL 150px, 빈 "특이사항" 170px | `artifacts.ts`, `DataGrid.tsx` | 남는 폭 title/URL 배분, 빈 열 자동 숨김 |
| C-D8 | S2 | 경로 중간 생략이 머리만 남김 | `MiddlePath.tsx`, `controls.css:727-740` | 꼬리 우선 |
| C-D9 | S2 | 영문·원시 값(`ip/url`, `global/network`, `cleartext-url`, `registry-string-trace`, `History/Default`, `edge`, `documents/artifacts`, JSON 미리보기, `아티팩트: android-apk`) | `indicators.ts:39,50`, `artifacts.ts`, `search.ts`, `outputs.tsx:38-43`, `valueLabels` | 값 라벨 테이블, 패밀리 한글명 |
| C-D10 | S2 | 지표 3번째 열 "선별"(리뷰 열 이름)에 분류 값 | `common.ts:181`, `indicators.ts` | 리뷰 열 "검토", 분류 열 "범위" |
| C-D11 | S3 | 문서/메일 기본 열 4개가 항상 "—" | `columns/docs.ts` | matched일 때만 |
| C-D12 | S3 | "NTFS 생성 → 실행" 링크 상시 노출(폴더 입력에서 불가) | `files.ts:30,385` | 이미지 입력일 때만 |
| C-D13 | S3 | 타임라인 "요약"에 이전 형식 접두(`Artifact event: …`) | `timeline.ts:311` | 표시 단계 접두 제거 |
| C-D14 | S3 | "시각 종류" 110px 잘림 | `timeline.ts:249-252` | 140px |
| C-D15 | S2 | 뷰어 열리면 타임라인 시각·요약 2열만 | `timeline.ts:139` | 대상·시각 종류 우선 |
| C-D16 | S3 | 빈 상태 문구 동일; footer "FTS 4.0s"/"none 0ms" 원시 | `DataGrid.tsx` | 검색어 포함 문구, footer 숨김 |
| C-D17 | S3 | 전체 검색 4 s 동안 진행 표시 없음 | `TopBar.tsx` | 스피너+취소 |
| C-D18 | S3 | 헤더·보기 전환 버튼 각각 Tab 정지; 정렬 라이브 알림 없음 | `DataGrid.tsx:1534`, `ViewSwitch.tsx` | roving tabindex |
| C-D19 | S3 | 880에서 URL 숨기고 빈 "특이사항" 유지 | `artifacts.ts flagsColumn` | 빈 열 자동 숨김 |

### A5. 카드·히스토그램·지도·대화

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-V1 | S2 | 히스토그램 같은 라벨 중복("레지스트리 하이브"×3, "실행 흔적"×3) | `HistogramView.tsx`, `families.ts` | 고유 한글명 |
| C-V2 | S2 | 타임라인 히스토그램 482버킷/460px; 헤더 "UTC" vs 표시 KST; 범위 조건이 막대에 미적용 | `HistogramView.tsx` | 폭 맞춤 재집계, 시간대 라벨, 범위 적용 |
| C-V3 | S3 | 카드 1차 정보가 "History", "시각 없음", 전체 경로 | `CardView.tsx` | 제목=항목 |
| C-V4 | S3 | 지도 전환 토스트 4문장; 포커스 튐 | `MapView.tsx`, `builtin.ts` | 짧게 |
| C-V5 | S3 | 대화 불가 노드에서 대화 버튼 활성 | `ChatView.tsx` | 비활성+이유 |

### A6. 뷰어

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-W1 | S1 | SQLite 파일(헥스 `SQLite format 3`)인데 SQLite 탭 비활성 — MIME `octet-stream` 기반 판정 | `viewer/modes.ts:62,104-105,177-178` | 매직 바이트/확장자/파서로 판정; urls 테이블·행 ID로 점프 |
| C-W2 | S2 | 메타 라벨 반번역("출처 database", "최초 seen 시각", "korean 감지된 or 기대"…) | `metaLabels.ts`, `fieldSheets.ts` | 번역 테이블 보강, 미매핑은 "기타 필드" |
| C-W3 | S2 | 내부 QA 메타("상용 대비 격차 ID #59"…)가 증거 필드처럼 | `fieldSheets.ts` media | 검사관 뷰에서 제거 |
| C-W4 | S2 | "visit_count 열로 표시" 원시 키 라벨 | `MetaView` colbtn | 한글 라벨 |
| C-W5 | S3 | UTC 병기 날짜 없음; 마이크로초 상시 | evidenceTime 렌더 | UTC에 날짜, 초 기본 |
| C-W6 | S3 | 뷰어 헤더 경로 머리만 | `Viewer.tsx` | 꼬리 우선 |
| C-W7 | S3 | 원시 식별자("rapidtriage.source-viewer.hex", "artifacts:browser:/artifacts/3") | `fieldSheets.ts`, `Viewer.tsx` | 정리 |
| C-W8 | S3 | ⋯ 메뉴 "같은 해시 행에 전파"/"…태그 전파" 연속 | `ViewerToolbar.tsx:270-330` | 하나로 |
| C-W9 | S3 | 리뷰 상태 칩 "관련 있음 / 미검토" 두 개 | `ViewerToolbar.tsx` | "미검토 ▾" |
| C-W10 | S3 | 인용 복사 실패 토스트 영문 원문 | `builtin.ts` | 한글 |
| C-W11 | S3 | 원본 탭 줄번호가 본문과 붙음 | `TextView` | gutter |

### A7. 통합 보기

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-X1 | S2 | 표가 원본 행 패널에 잘림, 가로 스크롤 없음 | `DerivedPane.tsx` | overflow-x, 하단 분할 |
| C-X2 | S2 | "다시 만들기" 확인 없이 `POST analyses` | `DerivedPane.tsx` | 확인 |
| C-X3 | S3 | 잘 알려진 SID 미해석; 1980-01-01 센티널 표시 | `DerivedPane` | SID 라벨, 센티널 "—" |
| C-X4 | S3 | 200개 이후 더 보기 없음 | `DerivedPane.tsx` | 페이지네이션 |

### A8. 검토·특이사항

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-R1 | S2 | (=C-G7) | | |
| C-R2 | S2 | "특이사항 B 이상 보기" 링크가 탐색 단계로 이동; 그 그리드 Enter는 근거 팝오버 | `ReviewReportStage.tsx:73-90` | 검토 안 특이사항 노드 |
| C-R3 | S2 | 검토 열 "선별"; 빈 상태에 다음 행동 없음 | `columns/review.ts` | 안내+단축키 |
| C-R4 | S3 | 근거 팝오버 원시 키, 보일러플레이트 출처 | `FlagEvidencePopover` | 규칙별 출처 |
| C-R5 | S3 | 칩 잘림; Sysmon 배너가 무관 노드에 | `FlagCell`, 배너 조건 | eventlog만 |
| C-R6 | S3 | 팔레트 "내보내기" 검색에 데이터 노드 우선 | `commands/fuzzy.ts` | 명령 그룹 우선 |

### A9. 보고

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-P1 | S2 | 산출물 "경로" 열 꼬리 안 보임; 이름 `아티팩트: android-apk` | `outputs.tsx:38-51` | 패밀리 한글명+파일명 |
| C-P2 | S3 | "보고 후보 0건" 안내 없음; "분석관 (선택)" | `ReportDialog.tsx:42` | |
| C-P3 | S3 | 비활성 이유 hover 전 안 보임 | `ReviewReportStage` | 인라인 |

### A10. 탐색기

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-E1 | S2 | 파일 시스템 탐색기 중앙에 직속 파일만(루트·Users 빈 그리드) | `FsExplorer.tsx` | 하위 폴더 행+더블클릭 진입 |
| C-E2 | S3 | `special=orphan` 원시 id | `FsExplorer.tsx` | 한글명 |
| C-E3 | S3 | "마지막 기록" ISO 원문, `windows-control-set` 원시 type | `RegistryExplorer.tsx` | |
| C-E4 | S3 | 미디어 그리드 EXIF 열 전부 "—"; "수정" 칩 접두어 | `artifacts.ts` media-image | 값 있을 때만 |
| C-E5 | S3 | 유사 미디어 진입점 없음 | `MediaExplorerPanel.tsx` | "유사 이미지 N개 보기" |

### A11. 분석 워크벤치

| # | 심각도 | 결함 | 위치 | 제안 |
|---|---|---|---|---|
| C-A1 | S3 | 카빙 서명·OCR 언어 체크박스 이름 없음 | `AnalysisDialog.tsx` | label |
| C-A2 | S3 | 분석 결과 페이지에 실행 링크 없음 | `AnalysisResults` | 링크 |
| C-A3 | S3 | 처리 카드 제목 잘림 | `stages.css` | 2줄 |
| C-A4 | S3 | VSS 비활성 이유 툴팁에만 | `ProcessStage` | 인라인 |

## B. PLAUSIBLE

| # | 내용 |
|---|---|
| P1 | 타임라인 첫 로드 3 s+ 스켈레톤(인덱스 미보존 환경), 색인 중 문구 없음 |
| P2 | R 키 한 번에 토스트 2개씩(aria-live 중복 가능) |
| P3 | 보고 산출물에 "케이스 DB 2.3 GB"가 내보내기 대상처럼 |
| P4 | `RUN_MODE_LABEL`에 `quick` 없음 → "quick" 원문 |
| P5 | 교차 케이스 "사용할 수 없는 런 37개" 이유 미표시 |
| P6 | 상태바 시간대가 증거 시스템 시간대(KST −540)를 자동 제안하지 않음 |
| P7 | 우클릭 메뉴와 뷰어 ⋯ 메뉴 항목 구성 상이 |
| P8 | 1024 드로어 초기 포커스가 메타 div |

## C. 용어 지도(권장 단일 용어)

| 개념 | 현재 표기 | 권장 |
|---|---|---|
| 지표(IOC) | 지표 후보 / IOC/위험 / IOC / IOC 목록 / 지표(IOC) 요약 / IOC 일치 | **지표(IOC)** |
| 검토/리뷰 | 검토 / 리뷰 상태 / 리뷰보드 / 선별 / 리뷰 | **검토**(열 이름 "검토", "검토자 번들") |
| 검사관/검사자/분석자/분석관 | 4종 혼용 | **분석관** |
| 케이스/런 | 상태바·랜딩·선택기가 런을 케이스로 | 런은 **런**, 케이스는 **케이스** |
| 파일 목록 | 전체 파일/파일 시스템/폴더 탐색기/전체 파일(인벤토리)/파일시스템/파일·미디어 | **파일 목록**·**폴더 탐색기**·**NTFS·파일시스템 아티팩트** |
| 전체 보기 | 트리 그룹/링크/"N 전체" | **목록** / **모두 보기** / **N (전체)** |
| 검색 결과 | 검색 결과/전체 검색/검색어 필터/그리드 필터/검색 조건 | **전체 검색** / **목록 필터** / 트리 "검색 결과 (마지막: 'x' N건)" |
| 조건/필터 | 조건·적용된 조건·조건 패널·검색어 필터·열 필터 행 | **조건**(패널)·**필터**(입력) |
| 특이사항/위험 | 특이사항/위험 표지/위험 플래그/위험 표시/위험 점수 | **특이사항** / **위험 태그** / **위험 점수** |
| 원본 | 탭 원본/원본 열기/원본 행/원본 아티팩트/원본 경로 | 탭 **내용** / **원본 파일 열기** / **출처 행** |
| 메모/노트 | 케이스 메모/요약 노트/메모…/메모·이력 | **메모**(행) / **케이스 노트** |
| 보기 이름 | 열 보기/행(카드) 보기/지도 대체 보기/대화 보기/AXIOM 스타일 | **표**/**카드**/**위치**/**대화**/"출처 중심(상세)" |
| 산출물/내보내기 | 보고/산출물/내보내기/종류 | 단계 **보고**, 좌측 **내보내기**, 표 **런 산출물** |
| 해시 검증 | 해시 검증 안 함 / 해시 미검증 | **해시 미검증** |

## D. 구조적 UX 개선(우선순위순)

1. 처리 단계는 "결과"를 먼저 — 완료 런은 단계표·공개 사항·다음 할 일; 계획표·취소는 실행 중에만.
2. 그리드의 범위 정직성 — "불러온 N / 전체 M" 뱃지, 서버 정렬/필터 우선 구현.
3. 뷰어를 열어도 분석 열이 살아남게 — 트리 자동 접기 또는 뷰어 360px, 정렬/필터 열·대상·시각 보존.
4. 시간 축 기준 통일 — 상대 프리셋은 증거 최신 시각 기준, 모든 시각 한 포맷, 가져온 런 대표 시각 = 실행 시각, 증거 시간대 자동 제안.
5. 원시 값 0 정책 — e2e에 latin/rawIds 스캔 추가; 값 라벨·패밀리·메타 키 번역 테이블.
6. 파일 시스템 탐색기를 Explorer처럼.
7. 검토 단계 자족성 — 특이사항·메모·북마크를 검토 안에서, 빈 상태 안내, 리뷰 칩 하나.
8. 쓰기 동작에는 항상 확인·피드백.
9. 랜딩·케이스 열기 정보 밀도.
10. 메타/팝오버 가독성 — 핵심 상단, 기술 정보 접힘, 규칙별 출처.
11. 접근성 — roving tabindex, Esc 토스트, 정렬 알림, 팝오버 flip, 드로어 포커스.
12. 보기 전환 가드.
