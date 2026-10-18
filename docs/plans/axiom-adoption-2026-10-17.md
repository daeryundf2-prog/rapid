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
- 프런트: 태그 관리 대화상자(이름·색 토큰 8종·단축키 1–9·설명), 뷰어/그리드에서 단축키로 태그, "같은 해시 행에 태그 전파" 명령(결과 토스트; 셸 명령이라 썸네일 보기에서도 동작, 기본은 사용자 태그만 — 북마크·우선순위 제외, 뷰어 더보기에서는 뷰어 행의 태그를 하나씩 골라 전파), 트리 검토 단계에 태그별 노드, 메모 패널(작성자·시각·이력). 뷰: **클래식 분할**(격자 위·세부 아래, 키 `\``, 높이 저장, 분할 중 뷰어 접기는 사유와 함께 비활성), **히스토그램 기준선** 저장/비교(막대 2색 + 증감; 증감은 중립 색, 비교 중에도 막대 클릭으로 노드 열기), 미디어 갤러리 **흐리게 토글**(키 B, 저장)과 "관련 미디어 n" 배지(같은 해시·duplicate_content_groups). 그리드 선택 **CSV 내보내기**에 고정 꼬리 열(소스·위치·복구 방법·증거 번호·사건 번호·항목 ID·파서 버전).

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

적대적 리뷰(읽기 전용 검토자) 후 수정: E01에 기대 해시 비교 금지(컨테이너 바이트 ≠ 획득 매체 해시 → 정상 이미지가 "불일치"로 보였음; API 422, 마법사에서 입력 숨김) · `apply_schema` 현재 스키마 경로는 다시 쓰기 없음(읽기 전용/ACL 잠금 런 DB 보호; 작업 공간 DB만 열 때 `ensure_intake_schema`) · 실행 중 런 연결 409 · 연결 시 런 경로도 경로 규칙 통과, 경로 비교는 Windows 방식(대소문자·구분자) · 사건 번호 대소문자 무시 유일 · 방금 저장한 "해시 계산 중" 행이 "중단됨"으로 깜박이지 않음 · 케이스 없는 런 스냅샷은 작업 공간 DB 오류와 무관 · 대화상자 제출 중 중복 클릭 차단. 남은 것: `wait=true` 케이스 런은 요청이 런 끝까지 막힘(기존 `POST /api/runs`와 같음). (독립 적대적 리뷰 14건은 `fix/axiom-e1-adversarial`에서 수정: 출력 폴더 공유 409, 등록만 증거 사전 검사·`evidence-check`, 연결 시 경로 일치/강제 사유, 사건 번호 유일성 BEGIN IMMEDIATE+표현식 인덱스, 연결 스냅샷은 작업 공간에만, 해시 재계산 API·버튼, 이력 DELETE 트리거, 빈 이름 폴백, 409 재시도 복구, 인용 접두 로딩 중 차단, Enter 진행, 테스트 보강, 임시 폴더 경고.)

게이트(E1 브랜치 최종): unittest 1761 OK(skipped 7), ruff, vulture, compileall, check-doc-refs, OpenAPI 스냅샷(변화 없음), biome, tsc, vitest 908, contrast 0 실패, e2e 개발 서버 37개 — 출력 원문은 E1 보고서.

실데이터 부수 효과: 런 연결로 `D:\rapid-qa\derived\run-subset10\processing-snapshot.json` 1개가 생김(파생 출력 폴더, 증거 아님). QA 상태 파일은 스크래치(저장소 밖).
### 5.2 E2 — 통합 보기 + 이벤트 요약 열 (2026-10-17, `feat/axiom-e2-derived`)

구현: 카탈로그 54계열 전부 검토, 45계열 157열에 `semantic:` 태그(9계열은 식별자 열 없음: EVTX 레코드 후보·합성 미디어·Defender·시스템 로그·문자열 후보·요약·타임라인·지표·표준 시간대; 테스트로 고정). `semantic_when`(자동완성은 `secret-field-name`만 자격 증명), `derive:` 열 4종. 엔진 `rapidtriage/core/derived/`(정규화·상한·가림·부분 계산, 표마다 `<표>.jsonl` + 열 지향 페이지 색인 `<표>.index.json` + `summary.json`), 런 단계 `derived`(`triage-flags` 뒤, 실패 격리), 분석 kind `derived`, API `GET /api/runs/{id}/derived[/{table}[/rows]]`(키셋 커서, 한국어 422), `/tree` 노드 `derived`. 콘솔: 트리 도메인 "통합 보기" 6노드, `#/case/{run}/explore/derived/{표}` 창(검색·출처 칩·정렬·더 불러오기·원본 행 → 계열 표 해당 행 선택), `derived.*` 명령(DisabledReason), 인용 `통합:<표>/<정규화 값>`(뷰어 인용에도), 이벤트 `요약 문장`(60 ID, 채널별), RDP 방향, EXIF 상태, SAM 자동 로그온("없음 — 사유").

실데이터(`D:\rapid-qa\derived\run-subset10`, 런 `b5fabbe09f18`, 행 소스 24개·약 64만 행, 증거 읽기 전용):

| 항목 | 결과 |
|---|---|
| 파생 단계 시간·메모리 | 47.4 s / 최대 작업 집합 365 MB(프로세스 전체, 측정 4회 47–65 s · 320–366 MB) — 기준 ≤120 s / ≤400 MB 충족 |
| 표 크기(값 / 출현) | 사람 273 / 389,582 · 장치 7,225 / 331,641 · 경로 47,165 / 113,973 · 첨부 0 / 0(메일·메신저 첨부 행 없음) · 자격 증명 210 / 345 · URL 828 / 9,437 |
| 파일 크기 | paths.jsonl 35.1 MB + 색인 15.2 MB, devices 5.6 MB, 나머지 ≤1 MB |
| 표 페이지(200행) | 첫 요청(색인 적재) 경로 0.30 s·장치 0.06 s, 이후 0.02–0.06 s(정렬 3종·검색·kind 필터 포함), 원본 행 0.01 s — ≤300 ms 충족 |

QA:
- **Q-X5** — 부분 충족. 사람 식별자 **273값(기준 ≥1,000 미달)**: 이 증거(단일 PC 10폴더 부분 복사)에 메일·메신저 대화·연락처가 없고 브라우저 자동완성 값은 파서가 원문을 남기지 않아(가림 + SHA-256) 사람 표에 넣지 않았다. 기준은 AXIOM 전체 E01(3,680)에서 온 값이라 이 표본에는 맞지 않는다; 의미 태그를 억지로 넓혀 채우지 않았다. 상위 값 `user` 원본 행 20개가 **11개 계열**(이벤트 로그·점프 목록·브라우저 방문/기록/다운로드·LNK·문서 메타데이터·탐지·로그온 세션·SAM 그룹/계정)에 걸침, 표본(LNK #33) 클릭 → `recent-files` 표에서 같은 행(aria-rowindex 35) 포커스 확인. 자격 증명 표: 원문 없음(가린 값·길이·SHA-256만, API·엔진 테스트로 원문 미포함 확인).
- **Q-X6** — 충족(위 표).
- **Q-X7** — 충족. 실데이터 Security 행: 4624 "계정 SYSTEM 로그온 성공 (로그온 유형 5 — 서비스)", 4625 "계정 user 로그온 실패 (로그온 유형 2 — 대화형) — 알 수 없는 사용자 이름 또는 잘못된 암호(%%2313), 상태 잘못된 사용자 이름 또는 인증 정보(0xc000006d), 세부 잘못된 암호(0xc000006a)", 4672 "계정 SYSTEM 로그온에 특수 권한 할당", 4688 "프로세스 생성: Registry", 7045·4104·5007도 문장. 미지원 ID "요약 없음 (ID 1531)", 같은 ID의 다른 채널(Audio 21)도 "요약 없음 (ID 21)". EXIF 상태 1,007행: 완료 123 · 없음 872 · 오류 1 · 동영상/오디오 11("없음 — 사유"). SAM 6계정: 로그온 수·사용 안 함·마지막 실패 로그온 표시, 자동 로그온 "없음 — 파서 미지원".
- **Q-X12** — e2e a11y 스윕에 `explore/derived/people`·`/paths` 추가(0건), 행 단위 J/K·Home/End·Enter(원본 행으로 포커스)·Esc(값으로 복귀), 모든 버튼 이름, 출처 칩 한국어 정렬, polite 영역은 앱의 1개만 사용.
- **Q-X13** — unittest 1,771(실패 1건은 마지막 단계가 `derived`로 바뀐 기대값 → 수정 후 통과), ruff/vulture/compileall/check-doc-refs 통과, OpenAPI 스냅샷 갱신(+3 경로), vitest 908, tsc, biome, 대비 0, e2e 전체 37 통과(derived 2 포함) + a11y 스윕 통합 보기 2경로 통과.

남은 것: 이벤트 로그 파서가 WHEA 42/Partition 1006의 `Owner`를 `user_name`으로 올려 숫자·GUID가 사람 식별자(계정)에 섞임(파서 투영 문제, known-limitations 기록). RDP 계열(`rdp-*`) 파서 없음 → 방향은 이벤트 로그 보조 열 "RDP 방향"에서만. 자동 로그온은 Winlogon 값과 계정 행 결합이 필요(파서 후속).

### 5.3 E3 — 검토 도구와 뷰 (`feat/axiom-e3-review`)

**구현**
- 케이스 DB: `case_db/review_schema.py`(스키마 확장, `schema.register_schema_extension`으로 등록 — `constants.py` 무변경). `case_tag`(이름 케이스별 고유·대소문자 무시, 색 `tag-1..8`, 단축키 1–9 고유, 설명, `created_by/at`, `deleted_at/by` soft, `kind` user/system), `histogram_baseline`, `review_mark.tag_ids_json`(정식 태그 id 목록). 기존 문자열 태그는 첫 apply 때 `case_tag`로 이전(북마크·우선순위 1–5는 기본 태그, 단축키 1–5 유지). `tags_json`은 이름 미러로 남김(검색 `tag:`·보고서·번들·CLI·이력 diff가 이름을 읽음) — 이름 변경·삭제 시 같은 트랜잭션에서 두 열을 함께 고침. 메모 이력: `review_mark_history`에 이미 `actor`·`changed_at`이 있어 열 추가 없이 `GET /api/runs/{id}/review-history`로 노출하고, 콘솔이 작성자(`rapidtriage.reviewer`, 기본 web-ui)를 실어 보낸다.
- API: `GET/POST /api/cases/{id}/tags`, `PATCH/DELETE /api/cases/{id}/tags/{tag_id}`(케이스 DB는 `run_id` 또는 `database`로 지정), `POST /api/case-db/review-batch`의 `tag_ids`·`remove_tag_ids`·`propagate_by_hash`(대상 행의 증거 소스 = 같은 런, 파일 행 MD5/SHA-1/SHA-256 일치, 10,000행 초과 시 422 한국어 거부, `applied_count` 반환), `GET/POST /api/cases/{id}/histogram-baselines`, `GET /api/runs/{id}/histogram?compare=`, `GET /api/runs/{id}/related-media?path=`, `GET /api/runs/{id}/export-context`. 본문 오류는 한국어 422. OpenAPI 스냅샷 갱신.
- 콘솔(`features/review/`): 태그 관리 대화상자, 숫자 키 1–9(바인딩된 태그를 id로 토글), "같은 해시 행에 태그 전파" 명령+토스트, 검토 트리 태그 노드(색·키·건수), 메모·이력 패널, 클래식 분할(`` ` ``, 유지), 히스토그램 기준선 저장/비교(2색 막대+증감), 미디어 흐리게(Shift+B, 유지)·"관련 미디어 n" 배지, 선택 행 CSV(꼬리 7열, UTF-8 BOM, 수식 주입 방지).
- 편차: 흐리게 키는 **Shift+B** — B는 U5 북마크 키이고 레지스트리가 이중 바인딩을 막는다. `commands/review.ts`의 1–5 명령 정의는 태그 키로 교체(같은 id 유지, 기본 바인딩이 우선순위 n이라 기존 동작과 같음) — 숫자 키를 다른 명령이 가질 수 없어서 불가피.

**QA (실데이터: run-subset10의 사본 `D:\rapid-qa\derived\e3-qa\run-subset10`, 런 `e678c38d6a71` — 원본 `b5fabbe09f18`의 케이스 DB에 QA 마크를 남기지 않으려고 쓰기는 사본에서 수행)**

| # | 결과 |
|---|---|
| Q-X8 | e2e `review-tools.spec.ts`: 태그 3개(색·키 6/7/8) 생성, 뷰어에서 키로 적용, 트리 노드 건수 1/1/0 = 필터된 리뷰보드 행 수, 삭제 시 `deleted_at` 남고 마크에서 제거, a11y 부분 감사 0 — 통과 |
| Q-X9 | API: 최대 같은-MD5 그룹 23행 → `applied_count` 23 = SQL 23 (275 ms). UI: 16행 그룹에서 명령 실행 → 토스트 "같은 해시 행 16건…" = SQL 16. 상한 거부는 실데이터 그룹이 모두 상한 미만이라 단위 테스트로 검증 |
| Q-X10 | e2e: `` ` `` 분할·Shift+B 흐리게 새로고침 후 유지, 기준선 저장 후 비교 행 수 = 서버 막대 수·증감 0, 관련 미디어 2 = 같은 해시 파일 2 — 통과. 실데이터 관련 미디어 5건 API = SQL |
| Q-X11 | 실데이터 파일 50행 선택 → CSV: BOM, CRLF 51줄, 열 12개(태그·메모·보이는 열 3·꼬리 7), 꼬리 7열 빈 칸 0(위치·사건 번호·파서 버전은 파일 행이라 "없음", 증거 번호 `RUN-SUBSET10-EVID-000001`) |
| Q-X12 | 새 화면 a11y 부분 감사 0, Esc/저장/취소 후 포커스 복귀, 한국어 정렬, polite 영역 1개 |
| Q-X13 | unittest·ruff·vulture·compileall·doc-refs·OpenAPI, vitest·tsc·biome·contrast·e2e(37) 통과(부하 시 시간 초과 3건은 단독 재실행 통과) |

**남은 것**: 기준선 비교는 같은 케이스 DB 안의 기준선만(런마다 케이스 DB가 다른 현 구조에선 같은 런의 전후 비교) — E1 케이스 통합 후 교차 런 비교 가능. 사건 번호는 E1의 `case_record.case_number`가 생기면 자동으로 채워진다. 숫자 키 토글은 행에 표시된 태그(review-map 오버레이) 기준이라 갱신 전 연타는 추가로 처리된다. 기준선 저장·태그 편집은 케이스 DB가 없으면 먼저 런을 케이스 DB로 가져온다(큰 런은 수 분).

### 5.5 코디네이터 통합 검증 (2026-10-17, `feat/axiom-adoption` d8a1d50, PR #12)
- 병합: E3 → E2 → E1 → E1 적대적 수정 브랜치. 충돌 6건(공유 임포트·스키마 빠른 경로·계획 문서·OpenAPI) 수동 해결; 스키마 빠른 경로는 "핵심 쓰기 없음 + 확장은 쓰기 가능할 때만" 으로 통합. 병합 부작용 2건(임포트 순서, 증거 번호 `COALESCE(NULLIF(evidence_number,''), citation_id)` 폴백) 수정.
- 적대적 리뷰 3건(E2/E3 백엔드 14 · E2/E3 프런트 15 · E1 14) 전부 수정·회귀 테스트.
- 게이트: unittest 전체 OK(skipped 6), ruff/vulture/compileall/doc-refs/OpenAPI(121 paths) 클린; lint/tsc/contrast 클린, vitest 964, 번들 기준 Playwright 45 중 44(부하 플레이키 1건 단독 통과; Q-IA-1은 빈 계열 토글 대기로 테스트 수정).
- 내장 브라우저 실데이터(run-subset10 `b5fabbe09f18`, 번들 서버 8807):
  - Q-X5: 사람 식별자 273값(데이터 한계) → `doctor2` → 원본 행 목록 → 문서 #106 클릭 → 문서 메타데이터 그리드가 그 행을 선택한 채 열림, 뷰어 작성자 doctor2. 통합 보기 도메인 합계 55,701 표시.
  - 클래식 분할(`` ` ``) 전환·복귀, 검토 단계 태그/메모 노드·태그 관리 대화상자(시스템 태그 6·단축키·작성자·새 태그) 확인.
  - Q-X1: 마법사 3단계로 사건 2026-QA-0001 생성, 증거 E-01(폴더, `D:apid-qash-subset`) 등록, 요약 1:1, "실행 (런 1개)" → 런 `af54ff24ed5f`가 케이스 폴더 `D:apid-qa\derived\qa-case1\E-01-rapidtriage-run-fraud-82248df3`에 생성, `processing-snapshot.json` 기록, 접수 5카드 채워짐, 헤더 "2026-QA-0001 › E-01 › af54ff24". 런 완료 후 `/processing-snapshot`은 `source=case-db`, 사건/증거 번호 포함.
  - Q-X3: 완료된 런의 `/problems` 총 21건 = 사유 9종(행 단위 절단 3·상한 절단 2·비인쇄 1·파일 수 상한 1·크기 상한 1·수집된 행 없음 8·입력 없음 2·건너뛴 단계 2·미리보기 절단 1), 경고 8·알림 13.
  - Q-X4: 메모 저장 시 작성자 "QA검사관"(케이스 검사관 기본값)·시각 표시, 이력 1건.
  - 접근성: 내장 브라우저 접근성 트리가 스위치/체크박스 이름을 "on"으로 보고했으나 소스는 라벨 래핑이 되어 있었음(도구의 이름 계산 차이). 명시적 `htmlFor` id와 vitest 단언을 추가.
- 남은 것: Q-X9/Q-X11은 E3의 QA 사본(`D:apid-qa\derived\e3-qa`, 삭제 가능)에서만 실측; 공유 런의 리뷰 이력을 오염시키지 않기 위해 코디네이터는 재실행하지 않음. 사람 식별자 ≥1,000 목표는 전체 이미지 런에서 재평가.
