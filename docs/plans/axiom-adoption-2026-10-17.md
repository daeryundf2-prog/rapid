# AXIOM 적용 라운드 — 케이스 만들기 · 통합 보기 · 검토 도구 (2026-10-17)

근거: `docs/research/axiom-case-model-2026-10-17.md` §1·§2·§4·§5·§7. 목적은 AXIOM을 베끼는 것이 아니라 **더 좋은 것**을 만드는 것이다: AXIOM이 잘한 구조(케이스 4층, 파생 통합 표, 태그 중심 검토, 행 공통 메타)를 가져오고, AXIOM이 못한 것(접근성 이름, 키보드, 한국어 정렬, 상태 전환 공백, 제목 품질)은 우리 규칙으로 막는다.

## 1. 최종 사용자가 보는 문제
1. 검사관이 케이스를 "만들" 수 없다. 첫 화면은 런(이미지 실행)뿐이라 사건 번호·검사관·의뢰처·증거 번호가 어디에도 남지 않고, 증거가 여러 개면 런이 여러 개로 흩어진다. 보고서·인용에 사건/증거 번호가 비어 있다.
2. "이 사람(계정·이메일·전화)이 어디에 나오지?", "이 USB가 어디에 꽂혔지?", "어떤 경로를 열었지?"에 답하려면 계열 16개를 하나씩 열어야 한다. AXIOM의 상세 결과(식별자-사람 3,680건, 로컬 접근 파일 5,341건)에 해당하는 통합 표가 없다.
3. 검토 태그가 4종 고정(관련/재검토/제외/보고서 포함)이라 사건별 분류("DLP 유출 후보", "변호인 검토")를 만들 수 없고, 같은 파일의 다른 흔적(같은 해시)에 태그를 번지게 할 수 없다. 메모에 작성자·시각이 없다.
4. 이벤트 로그 행에 사람이 읽는 요약 문장이 없어 ID를 외워야 한다. RDP 방향, 계정 로그인 수/비활성/자동 로그온, 이미지 Exif 상태처럼 AXIOM이 기본 열로 주는 값이 빠져 있다.
5. 격자 위·세부 아래로 보는 클래식 분할, 런 간 건수 비교(기준선), 미디어 흐리게/관련 미디어가 없다.

## 2. 이상 상태
- 접수 단계에 **케이스 만들기**가 있다: 사건 정보 → 증거 N개(번호·종류·경로·해시 검증) → 처리 옵션 스냅샷 → 실행. 접수 대시보드에 사건 정보·증거 목록(런 상태)·처리 설정·처리 문제(사유별 집계)·케이스 메모(작성자·시각)가 카드로 보인다. 케이스 전환은 "케이스 › 증거 › 런"이다.
- 탐색 트리에 **통합 보기** 도메인이 있다: 사람 식별자 · 장치 식별자 · 접근 경로 · 첨부 · 자격 증명/토큰 · URL 분류. 각 행은 값·정규화 값·건수·출처 계열·처음/마지막 시각을 보여주고, 펼치면 원본 행으로 간다. 카탈로그 열의 **의미 태그**가 이 표를 자동으로 만든다.
- 검토 단계에 **사용자 정의 태그**(색·단축키·설명·작성자)가 있고, "같은 해시 행에 전파"가 한 번의 명령이다. 메모는 작성자·시각·이력을 가진다. 클래식 분할, 기준선 비교 히스토그램, 미디어 흐리게·관련 미디어가 있다.
- 이벤트 로그 행에 **요약 문장**(한국어 템플릿, 상위 60개 ID), RDP 방향, 계정 추가 열, 이미지 Exif 상태 열이 기본 열로 들어간다.
- AXIOM 결함은 재현하지 않는다: 모든 버튼·행·셀에 접근성 이름, 행 단위 키보드 이동, 한국어 라벨 정렬, 로딩 스켈레톤, 제목 "종류 · 대표 값".

## 3. 설계

### 3.1 E1 — 케이스 만들기 (백엔드 + 프런트)
- 케이스 DB: `case_record`에 `case_number`, `case_type`, `requester`(의뢰처) 열 추가(마이그레이션, 기존 DB 호환). 새 테이블 `case_note(id, case_id, author, created_at, updated_at, deleted_at, text)`, `processing_snapshot(run_id, case_id, evidence_citation_id, captured_at, snapshot_json)`.
- API: `POST/GET /api/cases`, `GET /api/cases/{id}`, `PATCH /api/cases/{id}`, `POST /api/cases/{id}/evidence`(번호·표시명·종류 e01|folder|export|mobile·경로·해시 검증 여부 → `evidence_source`), `GET /api/cases/{id}/evidence`, `POST /api/cases/{id}/runs`(= RunCreateRequest + `evidence_citation_id`; 처리 옵션 스냅샷을 `processing_snapshot`과 런 output_dir `processing-snapshot.json`에 저장), `GET /api/cases/{id}/runs`, `GET /api/runs/{id}/processing-snapshot`, `GET /api/runs/{id}/problems`(warnings·parser_errors·silent-failure·steps failed/skipped를 사유별로 집계: `{reason_id, label_ko, count, items[:20]}`), `GET/POST/DELETE /api/cases/{id}/notes`(작성자 = 요청 본문 `author` 또는 케이스 examiner). 경로는 기존 `RAPIDTRIAGE_ANALYSIS_ROOTS`/UNC 거부 규칙 그대로. 한국어 422.
- 프런트: 랜딩 버튼 "케이스 만들기" → 3단계 마법사 모달(사건 정보 / 증거 추가 N·해시 검증 토글 / 처리 옵션 = 기존 RunDialog 폼 재사용 + 요약) → 실행 → 접수 단계로 이동. 접수 대시보드 카드 5개 추가(사건 정보 편집, 증거 목록·런 상태·"런 추가", 처리 설정 스냅샷, 처리 문제 사유별, 케이스 메모 작성자·시각). 케이스 전환기(`case.switch`)는 케이스 › 증거 › 런 트리로. 기존 "이미지 실행"은 유지하되 "케이스 없이 빠른 런"으로 라벨.
- 인용·보고서: `citation` 접두에 사건 번호·증거 번호를 포함(케이스 DB `citation_prefix` 활용).

### 3.2 E2 — 통합 보기 + 이벤트 요약 열 (백엔드 + 프런트)
- 카탈로그 YAML 열에 `semantic:` 태그 추가(`person|person_sender|person_recipient|account|device|path|url|hash|geo|search_term|attachment|credential`), `catalog.py` 검증. 연구 문서의 의미 태그 표(§3-1)를 기준으로 54 계열 전부 태깅.
- 파생 엔진 `rapidtriage/core/derived/`: 런 출력 전부를 스트리밍해 `analyses/run-derived-<ts>/{people,devices,paths,attachments,credentials,urls}.jsonl` + `summary.json`을 만든다. 행: `{value, normalized, semantic, count, kinds: {kind: n}, first_seen, last_seen, samples: [{kind, record_index, field}] (≤20)}`. 정규화: 이메일 소문자, 전화 E.164 시도, 경로 대소문자·구분자, URL 호스트, 해시 소문자. 상한: 값 종류 200k/표, 메모리 상한, 상한 도달 시 `capped`. 자격 증명은 값 자체를 저장하지 않고 **가린 값 + 길이 + 해시**만 저장. 실행: 런 단계(`triage-flags` 뒤) + 분석 kind `derived`.
- API: `GET /api/runs/{id}/derived/{table}?q=&kind=&sort=count|first_seen|last_seen&limit&after`, `GET /api/runs/{id}/derived/{table}/rows?value=`(원본 행 locator 목록), 트리 도메인 `derived`(통합 보기) 6 노드 + 건수. URL 분류는 규칙 파일(`core/derived/url_classes.yaml`: 검색엔진·소셜·클라우드·메신저·구인·금융·성인·악성 의심 도메인 목록, 출처 명시).
- 이벤트 요약 열: `eventlog` 계열에 `summary_ko`(파생, 상위 60 ID 템플릿: 4624/4625/4634/4647/4648/4672/4688/4698/4702/4720/4722/4724/4726/4728/4732/4756/4768/4769/4771/4776/4778/4779/1102/104/7045/7034/7036/4697/1149/21/22/23/24/25/40/41/1000/1001/6005/6006/6008/41/12/13/20001/20003/4100/4103/4104/400/403/800/1116/1117/5001/5007/5140/5145/4663/4656), RDP 계열에 `direction`(인바운드/아웃바운드), 계정 계열에 로그인 수·비활성·자동 로그온·마지막 실패 로그인(SAM F 값 파싱이 이미 있으면 노출, 없으면 "없음 — 파서 미지원"), 이미지 계열에 `exif_status`(완료/없음/오류). 파서가 아직 값을 안 주면 열은 "없음 — 사유"로 보이고 known-limitations에 기록.
- 프런트: 통합 보기 그리드(표별 열 정의, 값 클릭 → 원본 행 목록 패널 → 행 클릭 시 해당 계열 그리드로 이동·선택), 검색 상자, kind 칩 필터, 인용에 `통합:<표>/<정규화 값>` 포함.

### 3.3 E3 — 검토 도구와 뷰 (백엔드 + 프런트)
- 케이스 DB 새 테이블(별도 모듈 `case_db/review_schema.py`에 두고 스키마 목록에 등록, `constants.py`는 건드리지 않음): `case_tag(id, case_id, name UNIQUE per case, color_token, shortcut, description, created_by, created_at, deleted_at)`, `histogram_baseline(id, case_id, name, created_at, created_by, counts_json)`. `review_mark.tags_json`은 태그 id 목록으로 전환(기존 문자열 태그는 마이그레이션으로 `case_tag`에 생성). 메모: `review_mark_history`에 author·시각이 남는지 확인하고 없으면 추가.
- API: `GET/POST/PATCH/DELETE /api/cases/{id}/tags`, `POST /api/case-db/review-batch`에 `tag_ids`·`propagate_by_hash: true`(같은 run의 같은 해시 열 값을 가진 행 전부에 적용, 최대 10,000행, 결과 건수 반환), `GET/POST /api/cases/{id}/histogram-baselines`, `GET /api/runs/{id}/histogram?compare=<baseline_id>`.
- 프런트: 태그 관리 대화상자(이름·색 토큰 8종·단축키 1–9·설명), 뷰어/그리드에서 단축키로 태그, "같은 해시 행에 태그 전파" 명령(결과 토스트), 트리 검토 단계에 태그별 노드, 메모 패널(작성자·시각·이력). 뷰: **클래식 분할**(격자 위·세부 아래, 키 `\``), **히스토그램 기준선** 저장/비교(막대 2색 + 증감), 미디어 갤러리 **흐리게 토글**(키 B, 저장)과 "관련 미디어 n" 배지(같은 해시·duplicate_content_groups). 그리드 선택 **CSV 내보내기**에 고정 꼬리 열(소스·위치·복구 방법·증거 번호·사건 번호·항목 ID·파서 버전).

### 3.4 경계와 공통 규칙
- 라벨 전부 한국어, 모든 컨트롤 접근성 이름, 명령 팔레트 등록 + DisabledReason, polite 영역 1개, 대비 게이트, 한국어 정렬.
- 평가 데이터: `D:\rapid-qa\derived\run-subset10`(런 `b5fabbe09f18`). 증거는 읽기 전용, 저장소에 넣지 않는다.
- 세 작업은 각자 워크트리·브랜치(`feat/axiom-e1-case`, `feat/axiom-e2-derived`, `feat/axiom-e3-review`)에서 진행하고 코디네이터가 `feat/axiom-adoption`에 병합한다. 공유 파일(라우터·명령·트리 도메인·케이스 DB 스키마)은 **추가만** 하고 기존 줄을 옮기지 않는다.

## 4. QA 시나리오 (타협 없음)
| # | 시나리오 | 기준 |
|---|---|---|
| Q-X1 | 케이스 만들기 3단계 → 실행 | 사건 번호 필수 검증(한국어), 증거 2개 추가·1개 삭제, 처리 옵션 요약이 실행 요청과 1:1, 접수 대시보드 5카드 채워짐, 새로고침 후 유지 |
| Q-X2 | 기존 런(케이스 없음) 호환 | 랜딩·대시보드가 깨지지 않고 "케이스 없음 — 케이스에 연결" 액션 제공 |
| Q-X3 | 처리 문제 카드 | run-subset10의 warnings 19건이 사유별로 묶이고 항목 ≤20 미리보기, 전체 보기 링크 |
| Q-X4 | 케이스 메모 | 작성자·시각 표시, 삭제는 soft, 이력 조회 |
| Q-X5 | 통합 보기 › 사람 식별자 | run-subset10에서 ≥1,000 값, 상위 값 클릭 → 원본 행 ≥2 계열, 행 이동 후 선택 일치; 자격 증명 표에 원문 값 없음(가림·해시만) |
| Q-X6 | 통합 보기 성능 | 파생 단계 ≤120 s / ≤400 MB(run-subset10), 표 페이지 ≤300 ms |
| Q-X7 | 이벤트 요약 열 | Security 4624/4625/4672/4688 행에 한국어 요약 문장, 미지원 ID는 "요약 없음 (ID n)" |
| Q-X8 | 사용자 정의 태그 | 태그 3개 생성(색·단축키), 뷰어에서 단축키로 적용, 트리 태그 노드 건수 = 그리드 건수, 삭제 시 soft + 마크에서 제거 |
| Q-X9 | 해시 전파 | 같은 MD5 행 n개에 전파, 결과 토스트 n 일치, 상한 초과 시 거부 사유 |
| Q-X10 | 클래식 분할·기준선·흐리게 | 키 전환·새로고침 유지, 기준선 저장 후 비교 막대·증감, 흐리게 상태 유지·관련 미디어 배지 n 일치 |
| Q-X11 | CSV 내보내기 | 선택 50행, 꼬리 열 7개 전부 채워지거나 "없음", UTF-8 BOM, 엑셀 열림 |
| Q-X12 | 접근성·키보드 | 새 화면 전부 a11y 스윕 0, 행 단위 이동, Esc 복귀, 한국어 정렬 |
| Q-X13 | 게이트 | unittest/ruff/vulture/compileall/doc-refs/OpenAPI, vitest/tsc/biome/contrast/e2e, 적대적 리뷰 0 미해결 |

## 5. 결과 기록
(구현 후)

### E1 — 케이스 만들기 (`feat/axiom-e1-case`, 2026-10-17)

구현: 케이스 DB `core/case_db/intake.py`(추가 마이그레이션, `schema_version` 1 유지) · API `api/app/routes_cases.py`·`case_workspace.py`·`run_problems.py` · 콘솔 `features/case/{CaseWizard,CaseDialogs,EvidenceFields,RunOptionsFields}.tsx`, `features/dashboard/caseCards.tsx` · 계약 `docs/rapidtriage-output-schemas.md` "Case intake" 절. 작업 공간 DB는 `runs.json` 옆 `rapidtriage-cases.db`(`RAPIDTRIAGE_CASES_DB`로 변경). 런마다의 `rapidtriage-case.db`는 그대로.

계획과 다른 점(이유):
- `POST /api/cases/{id}/runs/link` 추가 — 케이스 없는 런의 "케이스에 연결"(Q-X2)에 필요. 스냅샷 `origin: linked-run`, 프로필·안전·자원 상한은 런 요약에서.
- `evidence_source`에 `evidence_number`·`hash_verify`·`hash_expected`·`hash_status`·`hash_message` 열 추가(증거 번호와 해시 검증 상태를 저장할 곳이 없었음). 해시 검증 = `e01_hash.run_e01_streaming_hash`로 컨테이너 바이트 MD5/SHA-1/SHA-256 백그라운드 계산, 기대값을 주면 일치/불일치. 서버 재시작으로 끊긴 계산은 "중단됨"으로 보인다.
- `case_note_history`(추가 전용) — 메모 이력(Q-X4). 삭제는 `deleted_at`/`deleted_by`만 기록.
- 케이스 폴더를 지정하면 케이스 런 출력은 `<케이스 폴더>/<증거 번호>-rapidtriage-run-<모드>-<8hex>`.
- `citation_prefix`는 만들 때 사건 번호에서 한 번 정하고 바꾸지 않는다(이미 붙은 인용 ID 보존). 콘솔 인용은 `사건=…; 증거=…`로 시작(뷰어·그리드), 보고서 대화상자는 사건 번호·분석자를 케이스에서 채운다.

| # | 결과 | 근거 |
|---|---|---|
| Q-X1 | 통과 | e2e `frontend/e2e/case-intake.spec.ts` Q-X1: 사건 번호 비우면 "다음" 비활성 + "사건 번호를 입력하세요." · 증거 2개 추가 → 1개 삭제 · 요약 행 키 = 실제 `POST /api/cases/{id}/runs` 본문 키(wait·evidence_citation_id 제외) · 실행 후 `#/case/<run>/intake` · 5카드 채워짐 · 새로고침 후 동일 · 전환기 "케이스 › 증거 › 런". vitest `caseIntake.test.tsx`(실패 후 재시도는 만든 케이스를 다시 만들지 않음) |
| Q-X2 | 통과 | e2e Q-X2: 샘플 런(케이스 없음) — 랜딩 "케이스 없음", 접수 기존 카드 정상, 사건 정보 카드 "케이스 없음 — 케이스에 연결" → 연결 대화상자 → 사건 정보·경로 표시. vitest `caseCards.test.tsx` |
| Q-X3 | 통과 | run-subset10(`b5fabbe09f18`)을 포트 8941 개발 서버에 가져옴: `GET /problems` 합계 21 = warnings 19 + 건너뛴 단계 2(docs-extract·files-extract). warnings 19 → 사유 8개: 행 단위 절단 3, 상한·절단 적용 2, 비인쇄 문자 1, 파일 수 상한 1, 크기 상한 1, 수집된 행 없음 8, 입력 없음 2, 미리보기 절단 1. 카드: 사유별 `details` 미리보기(≤20), "전체 보기 (n건)" → 대화상자(`reason_id`, limit 5000) → Esc로 닫으면 포커스가 버튼으로 복귀. 응답 시간: 단계 기록상 parser_error 0인 출력은 열지 않아 447 ms → 0.4 ms |
| Q-X4 | 통과 | 같은 서버: 케이스 생성 → 증거 E-01(`D:\rapid-qa\bsh-subset`, 폴더 → 해시 "해당 없음") → 런 연결. 메모 2개(작성자 = 케이스 검사관 "QA검사관" / 본문 author "다른검사관", 시각 ISO) · 삭제 200(soft, `deleted_at`) · 재삭제 409 "이미 삭제된 메모입니다" · 이력 created/created/deleted(작성자 포함) · `case_note_history` UPDATE는 트리거로 거부(단위 테스트) |
| Q-X12 | 통과 | 새 화면 전부 접근성 이름·라벨·중복 id 없음·polite 영역 1개(e2e quickAudit), 마법사 단계 이동 시 단계 제목으로 포커스, Esc 닫기 후 포커스 복귀(전환기·처리 문제 대화상자), 케이스·증거·사건 유형 목록 한국어 자연 정렬(`localeCompare("ko", {numeric})`), 기존 a11y e2e 23개 통과 |
| Q-X13 | 통과 | 아래 게이트 |

적대적 리뷰(읽기 전용 검토자) 후 수정: E01에 기대 해시 비교 금지(컨테이너 바이트 ≠ 획득 매체 해시 → 정상 이미지가 "불일치"로 보였음; API 422, 마법사에서 입력 숨김) · `apply_schema` 현재 스키마 경로는 다시 쓰기 없음(읽기 전용/ACL 잠금 런 DB 보호; 작업 공간 DB만 열 때 `ensure_intake_schema`) · 실행 중 런 연결 409 · 연결 시 런 경로도 경로 규칙 통과, 경로 비교는 Windows 방식(대소문자·구분자) · 사건 번호 대소문자 무시 유일 · 방금 저장한 "해시 계산 중" 행이 "중단됨"으로 깜박이지 않음 · 케이스 없는 런 스냅샷은 작업 공간 DB 오류와 무관 · 대화상자 제출 중 중복 클릭 차단. 남은 것: `wait=true` 케이스 런은 요청이 런 끝까지 막힘(기존 `POST /api/runs`와 같음), 스냅샷 쿼리 도착 전 인용 복사는 사건/증거 접두 없이 복사될 수 있음.

게이트(E1 브랜치 최종): unittest 1761 OK(skipped 7), ruff, vulture, compileall, check-doc-refs, OpenAPI 스냅샷(변화 없음), biome, tsc, vitest 908, contrast 0 실패, e2e 개발 서버 37개 — 출력 원문은 E1 보고서.

실데이터 부수 효과: 런 연결로 `D:\rapid-qa\derived\run-subset10\processing-snapshot.json` 1개가 생김(파생 출력 폴더, 증거 아님). QA 상태 파일은 스크래치(저장소 밖).
