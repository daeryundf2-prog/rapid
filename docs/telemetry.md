# 로컬 텔레메트리 (P0)

RapidTriage가 이 PC 안에만 남기는 제품 사용 기록입니다. 목적은 제품 지표 13개와 퍼널 2개를 재는 것입니다. 외부로 보내는 코드는 없습니다. 기록을 다른 사람에게 넘기려면 사용자가 직접 내보내기 번들을 만들어 전달해야 합니다.

## 어디에 남는가

- Windows: `%LOCALAPPDATA%\RapidTriage\telemetry\`
- macOS: `~/Library/Application Support/RapidTriage/telemetry/`
- Linux: `$XDG_DATA_HOME/rapidtriage/telemetry/` (없으면 `~/.local/share/rapidtriage/telemetry/`)
- 위치를 바꾸려면 `RAPIDTRIAGE_TELEMETRY_DIR=<폴더>`를 지정합니다.

| 파일 | 내용 |
|---|---|
| `events-YYYYMMDD.jsonl` | 이벤트 한 줄에 하나(UTC 날짜별, 추가만 함) |
| `salt.bin` | 설치마다 만드는 32바이트 난수. 내보내지 않습니다 |
| `settings.json` | `{"enabled": false}`이면 기록하지 않음 |

케이스 출력 폴더에는 쓰지 않습니다. 출력 폴더의 파일은 모두 실행 감사 목록에 들어가기 때문입니다.

## 언제 기록하는가

`rapidtriage`, `rapidtriage-web` 명령(그리고 `python -m rapidtriage`)으로 앱을 실행했을 때만 기록합니다. 라이브러리로 쓰거나 테스트에서 함수를 직접 부를 때는 기록하지 않습니다.

## 끄는 법

- 환경 변수로 완전히 끄기: `RAPIDTRIAGE_TELEMETRY=off`(`0`, `false`, `no`도 같음). 설정 파일보다 우선합니다.
- 설정으로 끄고 켜기: `rapidtriage telemetry disable` / `rapidtriage telemetry enable`
- 상태 확인: `rapidtriage telemetry status`(기록 여부, 끈 이유, 이벤트 수)

## 무엇을 기록하는가

모든 줄의 공통 필드는 `ts`, `schema_version`, `event`, `install_hid`, `session_id`, `case_hid`, `run_hid`, `app_version`, `os`, `props`입니다.

- `install_hid`, `case_hid`, `run_hid`, `tag_hid`: 원래 ID를 설치별 salt로 HMAC-SHA256한 값의 앞 16자리입니다. salt가 설치 밖으로 나가지 않으므로 다른 설치의 ID와 연결할 수 없습니다.
- `session_id`: 콘솔 페이지를 열 때마다 새로 만드는 난수입니다. 사용자나 PC 정보는 들어 있지 않습니다.

| 이벤트 | 기록 지점 | 속성 |
|---|---|---|
| `case_created` | `POST /api/cases` | evidence_slots, source |
| `evidence_added` | `POST /api/cases/{id}/evidence` | input_kind, size_bucket, format_supported |
| `app_session_started` | 콘솔 시작(`main.tsx`) | app_version, viewport_bucket, locale |
| `run_started` | `run_triage_mode` 시작 | profile, input_kind, resume, memory_cap_source, provider_count, actor |
| `run_stage_completed` | `RunProgress.complete_stage` | stage, duration_ms, status, rows_bucket |
| `provider_finished` | `RunProgress.provider_finished` | provider_kind, status, artifact_count_bucket, parser_error_count, duration_ms |
| `run_finished` | `RunProgress.finish` | status, duration_ms, partial_task_count, parser_error_total, artifact_total_bucket |
| `run_failed` | `RunProgress.fail` | stage, error_class, duration_ms |
| `grid_loaded` | 그리드 첫 페이지 수신(`useCollectionQuery`) | surface, artifact_type, row_count_bucket, latency_ms, server_ms, total_known, truncated |
| `grid_sorted` | 열 정렬(`DataGrid` cycleSort) | surface, column_kind, direction, scope, loaded_rows_bucket, total_rows_bucket |
| `review_stage_entered` | 탐색/검토 단계 진입(`openStage`) | stage, run_status, ms_since_run_finished |
| `review_tag_applied` | 검토 표시 적용(`applyReviewAction`) | action, row_count, source_surface, artifact_type, tag_hid, is_first_in_run |
| `case_report_created` | `POST /api/runs/{id}/case-report` | format, tagged_row_count, duration_ms, status |
| `search_submitted` | `POST /api/runs/{id}/search/query` 첫 페이지 | term_count, term_len_bucket, script, category, scope, from_keyword_pack |
| `search_results_returned` | 같은 요청 | hit_count_bucket, latency_ms, zero_result, backend, truncated |
| `timeline_entered` | `GET /api/runs/{id}/timeline` 첫 페이지 | event_count_bucket, latency_ms |
| `crash_reported` | `write_crash_report` | error_class, component, app_version |

`run_status`, `ms_since_run_finished`, `is_first_in_run`, `app_version`은 브라우저가 아니라 서버가 채웁니다. 건수는 `0`, `1-9`, `10-99`, … `1m+` 구간으로만, 증거 크기는 `<100MB` … `1TB+` 구간으로만 남깁니다.

## 기록하지 않는 것

경로, 파일명, 검색어 원문, 증거 내용과 미리보기, 증거 해시값, 사용자명과 검토자명, 장치명, IP, 케이스명과 메모, 태그명 원문, 예외 메시지는 기록하지 않습니다. 이것은 코드로 막혀 있습니다.

- 이벤트마다 허용 속성 목록(`rapidtriage/core/telemetry/schema.py`)이 있습니다. 목록에 없는 속성은 버립니다. 정해진 값 목록 밖의 문자열은 `other`로 바꿉니다. 종류 이름(`artifact_type`, `provider_kind`, `error_class`)은 코드 식별자 형태만 받습니다.
- 쓰기 직전에 검사기(`privacy_violations`)가 금지 단어가 들어간 속성 이름, 경로처럼 보이는 값, 해시되지 않은 ID를 찾습니다. 하나라도 있으면 그 줄을 쓰지 않고 로컬 경고만 남깁니다.
- 검색은 질의의 모양만 남깁니다(용어 수, 가장 긴 용어의 길이 구간, 문자 종류, 범주). 예외는 클래스 이름만 남깁니다.
- `tests/test_telemetry.py`가 이 규칙을 검사합니다. 모든 이벤트에 경로와 한글 원문을 넣어 기록해 보고, 로그에 하나라도 남으면 실패합니다.

## 지표 보기

```
rapidtriage telemetry metrics          # JSON: 지표 13개 + 퍼널 F1, F2
GET /api/telemetry/metrics             # 같은 내용(인증 토큰 필요)
```

| 키 | 지표 | 계산 |
|---|---|---|
| `wrc` | 주간 보고서 도달 케이스 | 주별 distinct(install_hid, case_hid), case_report_created status=ok |
| `ttv` | 첫 보고서까지 걸린 시간 | median(보고서 시각 - case_created 시각), 케이스 단위 |
| `ttfr` | 첫 검토 진입까지 | 실행별 첫 review_stage_entered.ms_since_run_finished의 중앙값 |
| `ttft` | 첫 태그까지 | median(is_first_in_run 태그 시각 - run_finished 시각) |
| `first_result` | 첫 결과 시간 | grid_loaded.latency_ms의 p50/p95(surface, 행 구간별), timeline_entered.latency_ms |
| `search_latency` | 검색 응답 시간 | search_results_returned.latency_ms의 p50/p95(backend, script별, 그룹마다 0건·절단 비율 포함) |
| `full_scope_share` | 전수 기준 비율 | grid_sorted scope=server 비율, grid_loaded total_known 비율 |
| `truncation_rate` | 절단 결과 비율 | 검색·그리드의 truncated 평균 |
| `time_to_triage` | 처리 시간 | run_finished.duration_ms의 중앙값/p90(input_kind별), 단계 점유율 |
| `run_success` | 실행 성공률 | completed / (run_finished + run_failed), 부분 실행률 |
| `parser_error_rate` | 파서 오류율 | sum(parser_error_count) / count(provider_finished), provider_kind별 |
| `crash_rate` | 크래시율 | crash_reported / app_session_started, app_version별 |
| `active_installs` | 주간 활성 설치 | 주별 distinct install_hid, 설치당 신규 케이스 |

퍼널은 두 가지입니다.

- F1: 케이스 생성 → 실행 시작 → 실행 완료 → 첫 검토 진입 → 첫 태그 → 보고서. 케이스 생성 뒤 14일 안에 각 단계에 도달한 케이스 수와 전환율을 냅니다.
- F2: 검색 → 결과 → 태그. 같은 세션에서 검색 뒤 10분 안에 검색 화면 태그(`source_surface=search`)가 있었던 비율과 0건 비율을 냅니다.

실행 이벤트에 케이스가 없으면 같은 실행의 다른 이벤트에서 케이스를 찾아 연결합니다.

P1 이벤트로 재야 하는 부분은 `"not_collected"`로 표시합니다. 해당하는 부분은 뷰어 로딩 시간, 필터의 전수 기준 비율, 입력 크기별 처리 시간, F2의 결과 열람(search_success)입니다.

## 가설과 답하는 지표

| 가설 | 보는 지표 |
|---|---|
| H1 큰 그리드 정렬은 대부분 불러온 행 기준이다 | `full_scope_share.sort_server_share`, `grid_sorted`의 total_rows_bucket 대비 loaded_rows_bucket, F1 태그 단계(F3는 P1) |
| H2 검색이 2초 안에 오면 검색 횟수와 검색→태그가 오른다 | `search_latency`, F2 `search_to_tag`(세션별로 나눠 비교) |
| H3 한글 검색이 많고 0건·절단 비율이 높다 | `search_latency.by_backend_script`(script별 건수 n, zero_result_rate, truncated_rate) |
| H5 첫 결과가 10초를 넘으면 태그 전환이 낮다 | `first_result.grid_by_surface_rows`, F1 첫 태그 전환 |
| H9 첫 화면 요약이 첫 검토와 첫 태그를 앞당긴다 | `ttfr`, `ttft`(배포 전후 비교) |

## 내보내기

```
rapidtriage telemetry export --out <빈 폴더>
```

빈 폴더에 `events.jsonl`과 `manifest.json`을 씁니다. manifest에는 이벤트 수, 기간, 파일 SHA-256이 들어갑니다. salt는 넣지 않습니다. 내보내기 전에 모든 줄을 개인정보 검사기로 다시 확인하고, 하나라도 걸리면 번들을 만들지 않습니다. 번들은 직접 열어 확인한 뒤 전달하세요.
