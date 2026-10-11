# 아티팩트 창 후속 계획 — 필드 열 승격 · 유형별 열 · 긴 값 전체 보기 · 서버 정렬 (2026-10-11)

상위 계획: `docs/plans/console-redesign-2026-10-10.md` (§9-C 백로그에서 분기).
브랜치: `ux/artifact-columns`. 범위: 콘솔(frontend)과 `/api/runs/{run}/artifacts` 읽기 경로. 복구 엔진·파서·DB 스키마는 손대지 않는다.

## 1. 최종 사용자가 보는 문제

검사관이 "아티팩트 › windows-prefetch"를 열면 표에 항목 / 선별 / 유형 / 내용 / 시각 / 파서 … 열만 보인다.
실행 횟수·최근 실행·참조 경로는 오른쪽 메타 탭을 행마다 열어야 보이고, 열로 꺼내 정렬·비교할 수 없다.
AXIOM은 아티팩트 유형마다 전용 열을 주고(“Run count”, “Last run”, “Key last written” …), 어떤 필드든 열로 추가해 정렬한다.
또 메타 탭의 긴 값(이벤트 메시지, URL, 추출 문자열)은 600자에서 `…`로 잘리고 전체를 볼 방법이 없다.
정렬 화살표를 누르면 "불러온 250행만" 정렬되는데 그 사실이 조용히 숨겨져 있다.

## 2. 이상 상태 (U)

- **U-C1 필드 열 승격**: 열 선택 메뉴에서 그 유형의 레코드 필드(details 키) 중 아무거나 골라 열로 추가·제거한다. 메타 탭의 필드 행에서도 "열로 표시"를 바로 누를 수 있다. 추가한 열은 링크(URL)에 실려 공유되고, 유형별로 기억된다.
- **U-C2 유형별 기본 열**: 유형 노드를 열면 그 유형에 맞는 열이 기본으로 나온다(아래 §4 표). 한 파일에 섞인 하위 유형(prefetch-file / prefetch-reference)은 각자 가진 필드로 채운다.
- **U-C3 긴 값**: 600자 넘는 값은 접힌 채 "전체 보기 (N자)" 버튼으로 펼치고, 전체 값을 복사할 수 있다. 검색·복사 텍스트는 잘리지 않는다.
- **U-C4 서버 정렬**: 아티팩트 표에서 시각 열이나 승격한 필드 열의 헤더를 누르면 **전체 레코드** 기준으로 정렬된다. 처음 정렬은 인덱스를 만들며 진행률을 보여주고, 끝나면 그 순서로 페이지가 넘어간다. 서버가 정렬할 수 없는 열(항목처럼 클라이언트에서 합성한 값)은 헤더에 비활성 사유가 뜬다. 조용한 "페이지만 정렬"은 없앤다.
- **U-C5 행 식별 안정성**: 정렬·필터가 바뀌어도 행 locator(`/artifacts/{원본 인덱스}`)는 원본 JSONL 인덱스 그대로다. 리뷰 표시·북마크·링크가 깨지지 않는다.

## 3. 현재와의 차이

| # | 현재 | 목표 |
|---|---|---|
| G1 | 열 선택 = 고정 열 on/off | 레코드 필드 목록(발견된 키, 빈도순, 검색) + 승격 |
| G2 | `columnsFor`는 eventlog만 | §4 유형별 열 세트, TIME_KEYS 확장, 요약 규칙 보강 |
| G3 | `formatValue` 600자 슬라이스, 전체 없음 | `RecordField.full`/`truncated`, 전체 보기·복사 |
| G4 | `sort=` → `sort_supported:false`; 클라이언트는 로드된 행만 정렬 | 서버 정렬 인덱스(메모리 LRU), 상태·진행률, 클라이언트 paged 유지 |
| G5 | `_index = offset + i` (페이지 위치) | 서버가 `record_index`를 내려주고 클라이언트가 그것을 locator로 사용 |

## 4. 설계

### 4.1 API 계약 (`GET /api/runs/{run_id}/artifacts`)

추가 쿼리:
- `sort=<key>`: `timestamp` 또는 `details.<name>` (details 바로 아래 스칼라 키). `timestamp`는 서버가 TIME_KEYS 순서로 첫 값을 고른다. TIME_KEYS = timestamp, time, time_created, last_run_at, last_run_time, last_modified, modified_at, key_last_written_at, last_written_at, event_time, normalized_time, created_at, target_modified_at (클라이언트 `artifacts.ts`와 동일하게 유지).
- `order=asc|desc` (기본 asc). 비교: 숫자는 수치, 문자열은 casefold, 혼합은 문자열, 없음/null은 항상 마지막.
- `sort`는 `kind`가 정확히 하나일 때만 허용. 아니면 400 `{"detail": "sort requires exactly one kind"}`.
- `path_contains`와 함께 쓰면 정렬 순서로 순회하며 필터·페이징(기존 scan budget 적용).

응답(kind별 객체)에 추가:
- 각 행에 `record_index` (원본 JSONL 0-기반 인덱스). 정렬 없을 때도 항상 포함.
- `sort`: `{"key", "order", "status": "ready"|"building"|"unsupported", "progress": 0.0–1.0, "reason"?: str}`.
  `building`이면 `artifacts: []`, `total`은 그대로. 인덱스는 요청 스레드가 아닌 백그라운드 스레드에서 만들고, 클라이언트가 1초 간격으로 다시 요청한다.
  `unsupported`는 인라인(JSONL 아님) payload 또는 비스칼라 키일 때. `sort_supported` 필드는 유지하되 `status` 기준으로 값을 맞춘다.
- 인덱스 저장: 프로세스 메모리 LRU (최대 8개 또는 256 MB). 키 = (run_id, kind, sort key, 파일 size, mtime_ns). 디스크에 쓰지 않는다(run 디렉터리·매니페스트·증거 번들 오염 방지). 인덱스 = 정렬된 `record_index` 배열(`array('q')`) + 행 시작 바이트 오프셋 배열. 페이지는 오프셋 seek로 읽는다.
- 진행률: 빌드 중 읽은 바이트 / 파일 크기.
- `order`: 명시한 `order=`가 `sort=<key>:desc` 접미사보다 우선한다. 대소문자 무시(`DESC` 허용). `sort` 없이 온 `order`는 무시한다(400 아님).
- `locate=<record_index>`: 응답 `sort.position` = 그 레코드의 전체 정렬 순서상 0-기반 위치. `building`/범위 밖/`path_contains` 동반 시 `null`. `locate`를 보내지 않으면 `position` 키 없음.
- 레코드 번호(`record_index`): 정렬·비정렬·`path_contains`·인덱스 빌드가 같은 규칙(`rapidtriage/api/app/jsonl_records.py`)을 쓴다. 빈 줄과 `{`로 시작하지 않는 줄(`[1,2]` 등)은 번호를 쓰지 않고 건너뛴다. `{` 줄은 번호를 하나 쓰며, JSON이 깨졌으면 행 없이 번호만 차지하고(정렬에서는 결측) 줄 번호와 함께 경고 로그를 남긴다.
- 비교: `timestamp`는 ISO-8601→epoch 연대순(오프셋 무관, 오프셋 없는 값은 UTC), 파싱 실패 값은 양 방향 모두 파싱된 값 뒤. 그 외 키는 모든 값이 숫자/숫자 문자열(10진·0x 16진)이면 정수는 정확한 int로 수치 비교, 아니면 casefold 텍스트(앞 256자, 동률은 JSONL 순서). 첫 스캔은 수치만 저장하고 비수치 값을 만나면 텍스트 모드로 한 번 다시 스캔한다(진행률 0부터). NaN/inf는 결측.
- 한도: 레코드 수 `RAPIDTRIAGE_SORT_MAX_RECORDS`(기본 5,000,000), 빌드당 텍스트 키 추정 바이트 `RAPIDTRIAGE_SORT_MAX_TEXT_BYTES`(기본 256 MB), 동시 빌드 2개, 대기 빌드 8개(초과 시 `unsupported` "대기 중인 정렬 요청이 많습니다. 잠시 후 다시 시도하세요", 캐시하지 않음), 정렬 + `path_contains` 스캔 200,000행(`scanned`/`truncated` 표기). 비스칼라 키는 첫 1,000행 프로브로 즉시 `unsupported`.
- 캐시: 준비된 인덱스는 LRU(8개/256 MB), `unsupported` 사유는 별도 표(LRU에 포함 안 됨), 일반 빌드 실패는 60초만 기억. 인덱스는 빌드가 실제로 연 파일의 fstat (size, mtime_ns)로 저장한다. 페이지를 읽다 오프셋이 맞지 않으면(같은 크기·같은 mtime로 다시 쓴 파일) 인덱스를 버리고 409 "정렬 인덱스가 오래되었습니다. 다시 시도하세요".

### 4.2 프런트엔드

- `ColumnSpec`에 `sortKey?: string` 추가. `timestamp` 열 = `"timestamp"`, 승격 필드 열 = `"details.<key>"`, 유형별 열은 첫 details 키로 sortKey 부여(QA 조정): 여러 후보 키를 고르는 열(실행 파일, 계정, 역할, RID, 메시지, 대화, 앱, media 크기 등)도 `details.<첫 키>`로 전체 정렬하고, 정렬 버튼의 `title` + `aria-describedby`(숨긴 요소)로 "실행 파일 정렬 (executable_hint 기준)"처럼 기준 키를 알린다(접근 가능한 이름은 열 제목 그대로). 뒤 후보 키로 채워진 행은 결측으로 마지막에 온다. 미부여(정렬 불가): 항목(`title`)·선별·유형·파서·탐지 규칙·지원·경로·SHA-256·채널(태그에서 계산)·registry 세부(계산 값) → 헤더 정렬 버튼 `aria-disabled` + `DisabledReason` "이 열은 전체 정렬을 지원하지 않습니다". (리뷰 조정) 실데이터에서 값이 목록인 열(shellbags 경로 후보, windows-filesystem 기대 확장자·위험, generic-documents 위험)과 목록 값을 가진 승격 열은 처음부터 sortKey가 없고 사유는 "목록 값은 전체 정렬을 지원하지 않습니다". eventlog 메시지는 불러온 행에 있는 첫 키(`message` → `rendered_message` → `event_message`, 셀이 보여주는 순서)로 정렬하고, `event_message`면 힌트가 "메시지 정렬 (원문 event_message 기준)"이다. 공백·쉼표·콜론이 든 키는 URL에 담을 수 없어 필드 목록에 회색 + 사유로만 보인다.
- `CollectionQuery.sort` (`{key, order}`)를 artifacts fetch에 전달. artifacts 컬렉션은 정렬 중에도 `compactMode`로 떨어지지 않는다(paged 유지). 다른 컬렉션의 기존 동작은 그대로.
- `building` 응답 (QA 조정: 상태줄은 일반 텍스트, 전환은 공용 `announce()`로 알림): 표 상단 상태줄 "전체 정렬 인덱스 생성 중 … n%", 1초 폴링, 완료 시 "정렬: 시각 ▼ (전체 n건)" 안내. `unsupported`는 사유를 상태줄에 보여주고 정렬 해제.
- URL: `sort=details.run_count:desc`, `cols=details.run_count,details.last_run_at` (승격 열). `cols`는 kind별 localStorage(`rapidtriage.grid.fieldColumns.artifacts.<kind>`)에도 저장; URL이 있으면 URL 우선.
- 승격 열 ID = `f:<key>`, 헤더 = 키 이름(§4.3 표에 한국어 라벨이 있으면 그것), 값 = 평탄 문자열(`formatValue` 규칙), 해시 모양이면 mono. 프리셋 전환 시 승격 열은 유지된다.
- 열 선택 메뉴: 기존 체크 목록 아래 "레코드 필드 추가" 섹션 — 검색 입력(`aria-label="필드 검색"`), 로드된 행에서 발견된 스칼라/스칼라 배열 키(빈도순, 기본 열이 이미 다루는 키 제외), 체크로 승격. 키보드만으로 조작 가능, Esc로 닫힘(기존 Esc 스택).
- 메타 탭 필드 행: 끝에 아이콘 버튼 "열로 표시"/"열에서 제거"(토글, `aria-pressed`). artifacts 컬렉션에서만 표시.
- 긴 값: `RecordField { value(600자 clip), full, truncated }`. 렌더: 잘린 텍스트 + 버튼 "전체 보기 (12,340자)" ↔ "접기", 펼치면 `<pre class="viewer-break">` 전체, 옆에 "복사"(전체 값). `value`는 검색·인용 복사에 쓰이므로 full 사용으로 교체.
- 행 locator: `fetchArtifactsPage`는 `record_index`가 있으면 그것을 `_index`로 쓴다(없으면 기존 계산).

### 4.3 유형별 기본 열 (kind → 열; 값 키는 details 기준, 여러 후보면 첫 값)

| kind | 열 (헤더 / 키) |
|---|---|
| eventlog | 기존(이벤트ID, 채널, 메시지) + 레벨 `level`, 컴퓨터 `computer`, 사용자 `user_name` |
| windows-prefetch (리뷰 조정) | 실행 파일 `executable_hint`,`header_executable_name`; 실행 횟수 `run_count`; 최근 실행 `last_run_at`; 참조 경로 `referenced_path`; 파싱 상태 `prefetch_parse_status`,`coverage_status` (prefetch-reference 행은 coverage_status만 가짐) |
| windows-registry (QA 조정) | 하이브 `hive_name`; 셀 종류 `cell_kind` (0/nk/key-node→키, 1/vk/value→값, 그 외 기타; 원값은 툴팁; 정렬 `details.cell_kind`); 이름 `name`; 세부 (값 셀: `value_type` REG_* · `value_data_size` B, 키 셀: 하위키 `subkey_count` · 값 `value_count`; 계산 열이라 전체 정렬 없음); 마지막 기록 `last_written_at`; 셀 오프셋 `cell_offset` |
| windows-shellbags (리뷰 조정) | 경로 후보 `shellbag_path_candidates[0]` (목록, 정렬 불가); 키 경로 `source_key_path`; 마지막 기록 `key_last_written_at`; 신뢰도 `parser_confidence` |
| recent-files (QA 조정) | 대상 경로 `target_path`; 대상 수정 `target_modified_at`; 대상 크기 `target_file_size`; 파싱 상태 `lnk_parse_status`; 작업 폴더 `working_dir` (인수 `command_line_arguments`는 기본에서 제외, 승격 가능) |
| windows-execution | 실행 경로 `executable_path`; 프로그램 `program_name`; 게시자 `publisher`; 버전 `version`; SHA-1 `sha1`; 키 기록 `key_last_written_at` |
| windows-system (QA 조정 → 2026-10-12 복원) | 앱 `application_name`; 앱 경로 `application_path`; 오류 모듈 `fault_module_name`; 이벤트 시각 `event_time`; 보고서 ID `report_id`; 크기 `source_size`; 수정 `modified_at` (+ 시각 열). WER UTF-16 디코딩을 고쳐 네 열을 기본으로 되돌림 |
| windows-os-account (QA 조정) | 계정 `user_name_candidate`,`user_name`,`group_name_candidate`; 역할 `candidate_role`,`account_type_hint`; RID `rid_decimal`,`alias_rid_decimal` (툴팁에 `rid_hex`); 마지막 기록 `last_written_at` (프로필 경로 `profile_path`는 기본에서 제외, 승격 가능) |
| windows-filesystem (리뷰 조정) | 감지 서명 `detected_signature_kind`; 기대 확장자 `expected_extensions` (목록, 정렬 불가); 크기 `source_size`; 수정 `modified_at`; 위험 `risk_flags` (목록, 정렬 불가) |
| media-image (리뷰 조정) | 이름 `entry_name`; 크기 `width`×`height`; 형식 `source_format`; 용량 `source_size`; 유사 묶음 `similarity_bucket` (수정 `modified_at`·분류 `visual_classification`은 파서가 쓰지 않아 제외) |
| mobile-export (리뷰 조정) | 메시지·앱 `message_text_preview`,`message_text`,`candidate_value`,`app_name`; 앱 `source_app_identifier`,`service`,`package`,`candidate_kind`; 이벤트 유형 `event_type`; 출처 도구 `source_tool` (+ 시각). 대화·첨부·참여자는 50행 중 0행이라 제외(승격 가능) |
| cloud-export (리뷰 조정) | 서비스 `service`; 이벤트 유형 `event_type`; 클라우드 `cloud_family` (+ 시각 열; `timestamp`는 이 run에서 빈 값). 요약: `cloud-message` = 메시지 앞부분, 없으면 service · event_type; 보조 줄 cloud_family · chat_id · message_id |
| kakaotalk-windows (리뷰 조정) | 후보 종류 `candidate_kind`; 후보 값 `candidate_value`; 위험 점수 `risk_score`; 원본 오프셋 `source_offset` |
| generic-documents (리뷰 조정) | 항목 수 `entry_count`; 암호화 항목 `encrypted_entry_count`; 크기 `source_size`; 수정 `modified_at`; 위험 `risk_flags` (목록, 정렬 불가). `archive_format`/`document_family`/`author_candidates`는 첫 50행에서 거의 비어(0–3행) 기본에서 제외(승격 가능) |
| 그 외 | 기존 기본 열 |

정렬 키 (QA 조정): 여러 후보 키를 읽는 유형별 열도 첫 키로 전체 정렬한다(`sortKey = details.<첫 키>`). 정렬 버튼 이름·툴팁이 기준 키를 밝힌다(예: "실행 파일 정렬 (executable_hint 기준)"). 정렬하지 않는 열: 항목·선별·유형·파서·탐지 규칙·지원·경로·SHA-256·채널(태그에서 계산), shellbags 경로 후보(목록 원소), registry 세부(계산 값).

요약 규칙(`artifactSummary.ts`) 보강: `registry-hive-cell`(이름 + 셀 종류, 하이브), `wer-report`(앱 · 오류 모듈), `windows-sam-*`(계정 후보 · RID), `file-signature-mismatch`(파일명 · 감지 서명→기대 확장자), `document-metadata-risk`(파일명 · 문서 군), `kakaotalk-windows-*`(candidate_kind · candidate_value 앞부분), `cloud-message`(chat_id · message_id). TIME_KEYS에 `last_written_at`, `target_modified_at` 추가.

## 5. 작업 분할

- **A (frontend)**: §4.2 전부 + §4.3. 단위 테스트(vitest): 필드 열 발견·승격·URL/localStorage 왕복, kind별 열, 요약 규칙, record.ts 긴 값, sortKey/DisabledReason, record_index locator. e2e 1건: prefetch kind에서 필드 승격 → 헤더 정렬 → building→ready → 첫 행 변경 확인(서버 있을 때).
- **B (backend)**: §4.1. `rapidtriage/api/app/artifact_sort.py`(인덱스 빌더·LRU·비교기), `routes_runs.py` 배선, `record_index` 부여, 단위 테스트(건물 중 응답, 완료 후 순서, 숫자/문자/결측 비교, 1 kind 제약, path_contains 조합, 파일 변경 시 무효화, 인라인 payload unsupported), OpenAPI 스냅샷 재생성(`python scripts/update-api-snapshot.py`), 성능 측정 1건(`C:\rapid-qa\run-subset7` eventlog 231 MB 인덱스 빌드 시간·RSS, 보고서에 기록).
- A와 B의 접점은 §4.1 계약뿐이다. A는 계약대로 mock 응답으로 개발하고, 통합은 B 완료 후 실데이터로 확인한다.

## 6. QA 시나리오 (타협 없음)

| # | 시나리오 | 통과 기준 |
|---|---|---|
| Q-C1 | prefetch kind에서 열 선택 → "레코드 필드 추가"에서 `run_count` 검색·체크 | 열 생김, 값 채워짐, URL에 `cols=details.run_count`, 새로고침 후 유지, 다른 kind로 가면 안 보이고 돌아오면 다시 보임 |
| Q-C2 | 메타 탭 필드 행 "열로 표시" 클릭 | 같은 결과, 버튼 `aria-pressed=true`, 다시 누르면 제거 |
| Q-C3 | 각 §4.3 kind 노드 열기 (run-subset7) | 표의 기본 열이 표와 일치, 빈 열이 과반이 아님(샘플 50행) |
| Q-C4 | eventlog 행의 `event_message` 5,000자 | 메타에 600자 + "전체 보기 (5,000자)"; 펼치면 전체, 복사는 전체, 검색은 전체 텍스트에 걸림 |
| Q-C5 | eventlog(231 MB, 30만 행+)에서 시각 ▼ | 상태줄 "생성 중 … %" → 완료 → 첫 페이지가 최신 시각, 100페이지 뒤로 가도 단조 감소, 각 행 locator가 원본 인덱스 |
| Q-C6 | 정렬 중 R(관련 있음) 표시 → 정렬 해제 → 같은 행 찾기 | 표시 유지(locator 동일) |
| Q-C7 | 항목 열 헤더 정렬 시도 | 비활성 + 사유 툴팁, 포커스 가능, 아무 일도 조용히 일어나지 않음 |
| Q-C8 | sort + path_contains | 필터 결과가 정렬 순서, scanned/truncated 표기 유지 |
| Q-C9 | 서버 재시작 후 같은 정렬 | 다시 building → ready, 결과 동일 |
| Q-C10 | 키보드만: 열 선택 열기 → 필드 검색 → 체크 → Esc → 헤더 정렬 | 포커스 흐름 끊기지 않음, a11y.spec 규칙 위반 0 |
| Q-C11 | 게이트 | vitest/tsc/eslint/contrast/e2e, unittest/ruff/vulture/compileall, OpenAPI 스냅샷, `git diff --check` |

## 7. 결과 기록

구현 후 각 Q-C 행에 측정값과 증거(스크린샷 경로, 수치)를 적는다.

### Q-C3 기본 열 채움률 (리뷰 조정, 2026-10-11)

방법: run-subset7, run-subset3의 kind별 첫 50행을 API와 같은 프로필 전개(`iter_artifact_output_rows`)로 읽고, 기본 열마다 값(빈 문자열·null·빈 목록 제외)이 있는 행 수를 셌다. 두 run의 수치는 같았다. 목표: 어떤 기본 열도 50행 중 과반(26행 이상)이 비지 않음 → 모든 kind 충족.

| kind | 열별 채움(50행 중) |
|---|---|
| eventlog | 레벨 50 · 컴퓨터 50 · 사용자 50 · 메시지 50 |
| windows-prefetch | 실행 파일 50 · 실행 횟수 50 · 최근 실행 50 · 참조 경로 49 · 파싱 상태 50 |
| windows-registry | 하이브 50 · 셀 종류 48 · 이름 48 · 세부 48 · 마지막 기록 38 · 셀 오프셋 48 |
| windows-shellbags | 경로 후보 50 · 키 경로 50 · 마지막 기록 50 · 신뢰도 50 |
| recent-files | 대상 경로 38 · 대상 수정 36 · 대상 크기 38 · 파싱 상태 50 · 작업 폴더 26 |
| windows-execution | 실행 경로 49 · 프로그램 49 · 게시자 45 · 버전 47 · SHA-1 49 · 키 기록 49 |
| windows-system | 앱 60 · 앱 경로 60 · 오류 모듈 60 · 이벤트 시각 60 · 보고서 ID 50 · 크기 50 · 수정 50 (앱 4열은 파서 수정 후 bsh-subset에서 `collect_wer_reports` 직접 수집 60행 기준, 2026-10-12) |
| windows-os-account | 계정 27 · 역할 50 · RID 49 · 마지막 기록 49 |
| windows-filesystem | 감지 서명 50 · 기대 확장자 50 · 크기 50 · 수정 50 · 위험 50 |
| media-image | 이름 50 · 크기 49 · 형식 50 · 용량 50 · 유사 묶음 49 |
| mobile-export | 메시지·앱 38 · 앱 38 · 이벤트 유형 50 · 출처 도구 50 |
| cloud-export | 서비스 50 · 이벤트 유형 50 · 클라우드 50 |
| kakaotalk-windows | 후보 종류 50 · 후보 값 50 · 위험 점수 50 · 원본 오프셋 50 |
| generic-documents | 항목 수 47 · 암호화 항목 47 · 크기 47 · 수정 47 · 위험 47 |

### Q-C 시나리오 결과 (2026-10-11, 통합 검증 — 재빌드 번들, 서버 8801/8802, run-subset3 `117340fc6ea4` · run-subset7 `682636ce5605`)

| # | 결과 | 증거 |
|---|---|---|
| Q-C1 | 통과 | prefetch에서 `referenced_extension` 승격 → 열 생성, URL `cols=details.referenced_extension`, localStorage `rapidtriage.grid.fieldColumns.artifacts.windows-prefetch`, Esc 후 포커스 "열 선택" 복귀. 1차 검증에서 빈 값만 있는 키(`volume_device_path` 245/250 빈 문자열)가 목록에서 빠지던 결함 → "빈 값" 표기로 수정 |
| Q-C2 | 통과 | 메타 탭 `coverage_status 열로 표시` → `aria-pressed=true`, 라벨 "열에서 제거", URL 갱신; 재클릭 시 제거. 기본 열과 겹치는 키는 "열로 표시 중"(표시 중일 때만) |
| Q-C3 | 통과(조정) | 위 채움률 표. 1차 검증에서 registry 값 유형 30/35 빈 칸, LNK 인수 35/35, WER 4열 35/35, 계정 프로필 경로 34/35 → 기본 열 조정. WER 4열은 파서 UTF-16 디코딩을 고친 뒤 복원(2026-10-12) |
| Q-C4 | 통과 | registry-hive-strings `extracted_strings` 2,972자: "전체 보기 (2,972자)" → `aria-expanded=true`, `<pre>` 2,972자, "접기", "extracted_strings 복사". 1차 검증의 토글 후 포커스 유실 → 수정 |
| Q-C5 | 통과 | prefetch 51,785행 `details.referenced_extension` ▲: 상태줄 "생성 중 … 0%" → 약 6 s 후 "정렬: … (전체 51,785건)", 첫 행 record_index 31/36/6875(`.0`), 반복 요청 동일 순서. eventlog 216k행은 B 측정 참조 |
| Q-C6 | 통과 | 정렬 상태에서 행 31에 R → `POST /api/case-db/review-batch` 200(8802 로그), 정렬 해제 후 `row=/artifacts/31` 딥링크에서 같은 행(aria-rowindex 33)에 "관련 있음" 표시 |
| Q-C7 | 통과 | 항목/선별/유형/파서 헤더 정렬 버튼 `aria-disabled=true`, 포커스 가능, 사유 "이 열은 전체 정렬을 지원하지 않습니다"는 `aria-describedby`(이름에 섞이지 않음) |
| Q-C8 | 통과 | `sort=details.referenced_extension&order=desc&path_contains=ADOBE` → 정렬 순서로 필터된 5행, 200k 스캔 상한 적용 |
| Q-C9 | 통과 | 8801 종료 → 8802 새 프로세스에서 같은 정렬 building → ready, 첫 행 동일(31, 36) |
| Q-C10 | 통과 | 열 선택 → Tab ×16 → 필드 검색 → 입력 → Tab → 체크박스 → Space → Esc(포커스 복귀). a11y.spec 규칙 위반 0 (1차의 "polite 영역 2개" → 수정) |
| Q-C11 | 통과 | 아래 게이트 기록 참조 |

추가로 발견·수정한 결함(1차 통합): 정렬 전환 시 이전 위치 인덱스의 행이 뷰어로 조용히 발행되고 `row=`가 바뀌는 문제; 케이스 DB 가져오기(`/case-db/ensure`, 영구화 이전 런은 수 분) 동안 R 키가 무반응 → 즉시 안내·대기열 적용; 행 메뉴에 리뷰 항목 누락; e2e Q-A3 행 메뉴 `aria-expanded` 회귀.

알려진 제한: (1) 코어 `case.py`의 북마크 locator는 비어 있지 않은 모든 줄을 세고, API `record_index`는 `{`로 시작하는 줄만 센다 — 객체가 아닌 JSONL 줄이 있는 파일에서만 어긋나며 런 작성기는 객체만 쓴다. (2) 다중 키 열은 첫 키 기준 정렬이며 뒤 키로 채워진 행은 결측으로 뒤에 온다(힌트로 표시). (3) WER 리포트 필드는 2026-10-12 파서 수정으로 채워진다.

### B 측정 (2026-10-11, `C:\rapid-qa\run-subset7` eventlog JSONL 231 MB, 216,234행)

- 요청: `kind=eventlog&sort=timestamp&order=desc&limit=50` (TestClient, store root = run-subset7, 읽기 전용).
- 첫 요청 0.016 s에 `building` 반환(행 0, total 216,234). 1초 폴링 12회, 진행률 0.00 → 0.11 → … → 0.97 → `ready`. 폴링 포함 벽시계 12.6 s; 같은 인덱스를 직접 빌드하면 9.2 s.
- 인덱스 크기(asc+desc+오프셋 `array('q')`) 4.95 MB. 프로세스 working set 130.5 MB → 167.7 MB(+37 MB, 출력 JSON 캐시 포함), 빌드 중 최고 212.3 MB.
- 1페이지: 0.018 s, 50행 시각 단조 감소(2026-10-07T04:22:44 → 2025-05-30T03:39:47), 결측 0, `record_index` 앞부분 203475, 203474, 203473, 203472, 45728.
- 1000페이지(offset 50000): 0.015 s, 50행 단조 감소(2025-05-25T23:53:23 → 23:45:55), 결측 0.
- 비교기 개선 후(시각은 ISO-8601→epoch 연대순, 파싱 실패 값은 양 방향 모두 파싱된 값 뒤; 숫자 문자열·0x 16진은 수치 비교): 같은 인덱스 직접 빌드 9.85 s(이전 9.2 s, +0.65 s ≈ +7%).
- 비스칼라 키는 첫 1,000행 프로브로 즉시 `unsupported`(예: windows-prefetch `details.prefetch_validation_checks` 0.001 s); 1,000행 뒤에서만 나오면 전체 빌드 후 `unsupported`.
- 메모리 경계 적용 후(행마다 원값 대신 압축 정렬 키: epoch/수치 `array('d')` + casefold 256자 텍스트(최대 65,536개 고유값 공유), 레코드 한도 `RAPIDTRIAGE_SORT_MAX_RECORDS` 기본 5,000,000, 동시 빌드 2개): 새 프로세스에서 직접 빌드 — `timestamp` 9.84 s, `details.event_id`(숫자 문자열) 9.45 s, `details.event_message`(텍스트) 7.98 s. 세 경우 모두 working set 114 MB → 122–126 MB(+8–12 MB), 최고 working set은 빌드 전 값 163.6 MB를 넘지 않음. 인덱스 4.95 MB.
- 리뷰 반영 후(공용 레코드 번호, 수치 우선 스캔 + 텍스트 재스캔, 텍스트 바이트 예산, 비유한값 결측, 정확한 정수, 음성 캐시 분리, 대기 큐 상한) 새 프로세스 직접 빌드: `timestamp` 10.27 s(이전 9.84 s), `details.event_message` 10.4 s(첫 행에서 텍스트로 전환되어 재스캔 비용 거의 없음). working set 115 MB → 122–124 MB(+7–9 MB), 최고 working set은 빌드 전 값 163.6 MB를 넘지 않음. 인덱스 4.95 MB.
