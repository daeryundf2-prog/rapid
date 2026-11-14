# 0건 사유 입력 신호 명세 (R8 T-188)

수집기 하나가 0행을 냈을 때 0건 사유 판정기(T-047, rapidtriage/api/app/zero_reason.py 예정 — 아직 없음)가 읽을 **입력 신호 6종**이 수집기마다 어느 파일·어느 키에 기록되는지(또는 아직 기록되지 않는지)를 적는다. 판정기는 이 표에 적힌 출처만 읽는다. 표에 "기록 안 됨"인 칸은 판정기가 그 신호를 추측하지 말고 "모름"으로 다뤄야 한다는 뜻이다. 근거: IS-006, GAP-356, `docs/plans/r8/r8-tasks.md` T-188·T-047.

이 문서는 2026-11-13 코드 기준이다. 모든 위치는 `rapidtriage/` 아래 경로와 줄 번호다. 코드가 바뀌면 이 표를 같이 고친다.

## 1. 신호 6종과 사유 코드

| 신호 | 뜻 | 판정 사유 코드(IS-006) |
|---|---|---|
| `scope_truncated` | 수집기가 본 입력(증거 트리)이 원본보다 좁다. 예: E01 추출이 상한·깊이·읽기 오류로 일부 파일을 만들지 않음 | `scope_truncated` |
| `cap_reached` | 수집기 안의 상한에 닿아 행·파일·바이트 일부를 읽지 않았다 | `cap_reached` |
| `tool_missing` | 외부 도구나 선택 모듈이 없어 일부 또는 전부를 풀지 않았다 | `tool_missing` |
| `mode_excluded` | 실행 모드·`--artifact-kinds`·건너뛰기 요청 때문에 이 수집기가 그 실행의 수집 단계에서 돌지 않았다 | `not_collected_mode` |
| `decrypt_unavailable` | 대상 저장소가 암호화돼 있고 RapidTriage가 풀지 않았다(못 함 또는 정책상 안 함) | `encrypted_store` |
| `parser_failed` | 수집기가 예외로 격리됐거나 행 단위 파서 오류를 냈다 | `collector_failed` |

나머지 사유 코드 `container_only`·`no_input`·`not_run`·`none_found`는 이 6종 밖의 입력(대상 파일 존재, 단계 상태, 컨테이너만 있음)으로 판정한다. 그 입력은 T-047 카드가 정한다. 다만 `none_found`는 "수집기 완료 + 대상 파일을 실제로 읽음"일 때만 쓰므로, 아래 6칸 중 하나라도 "기록됨·참"이면 `none_found`를 쓰면 안 된다.

## 2. 수집기 31종은 어디서 왔나

- 실행 프로필이 고르는 종류: `GENERAL_FORENSIC_ARTIFACT_KINDS` 15종, `WINDOWS_FORENSIC_ARTIFACT_KINDS` 14종, `CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS` 2종 = 31종(`core/run/constants.py:70-109`).
- 등록된 제공자: `artifacts/__init__.py:11-41`에서 가져오는 31개 클래스. 각 클래스의 `collector_kind`가 위 31종과 정확히 같다(2026-11-13 확인: `all_providers()` 31개, 종류 집합 일치).
- 아래 표의 행 순서는 `core/run/constants.py`의 순서다.

## 3. 모든 수집기에 공통인 출처

표의 칸이 짧도록, 31종 모두에 똑같이 적용되는 출처에 이름을 붙인다. 파일 이름은 실행 출력 폴더 기준이다.

- **종류 요약** = `artifacts/rapidtriage-artifacts-<kind>.json`의 `summary`. 키는 `core/artifacts.py:568-584`(스트리밍)과 `:149-160`(메모리 경로)가 만든다: `artifact_count`, `artifact_type_counts`, `parser_error_count`, `collection_status`(`completed`·`skipped`·`failed-isolated`·`cancelled-partial`), `collection_notes`, `skip_reasons`, `skipped_row_count`.
- **단계 행** = `rapidtriage-run-summary.json`의 `steps[]` 중 `name == "artifacts-<kind>"`(`core/run/steps.py:111-151`). `status`, `warning_level`, `warning_messages`, `cap_disclosures`, `row_truncation`, `truncated`, `plan_reason`이 붙는다.
- **처리 문제** = `GET /api/runs/{id}/problems`(`api/app/routes_cases.py:559`, `api/app/run_problems.py`, `api/app/run_problem_limits.py`)의 항목 `reason_id`.
- **행 키(R)** = JSONL 행 `details` 안의 키. 종류 요약에는 올라오지 않는다. 판정기가 행 키를 쓰려면 JSONL 전체를 읽거나(무거움) 수집기가 요약 키를 새로 내야 한다. 이 문서에서 "R만"은 그 상태를 뜻한다.

### 3.1 `scope_truncated` 공통 출처 (ST)

- **ST-E01**: E01/Ex01 네이티브 엔진 실행이면 `rapidtriage-run-summary.json`의 `source.recovered_root_manifest.native_extraction_stats`(`core/run/source.py:144`; 키는 `core/e01_native.py:678-688`): `truncated`(상한 뒤 건너뛴 파일 수), `file_limit`, `depth_skips`(64단계 초과 폴더), `errors`, `deleted_read_errors`. 같은 값이 처리 문제 `e01-extract-cap`·`e01-read-error`·`e01-depth-cap`(`api/app/run_problem_limits.py:104-150`)과 네 축 처리 범위(`api/app/run_scope.py:250-355`, `basis: "inferred"`)로 나온다.
- **ST-EXT**: 외부 엔진(Sleuth Kit) 실행이면 `_e01/extraction-failures.json`·`_e01/extraction-gap-recovery.json`(`core/extraction_failures.py:50,58`). 네이티브 통계 키는 없다.
- **한계(모든 종류 공통)**: 위 값은 실행 전체 하나다. 잘린 파일이 어느 수집기의 대상이었는지는 기록되지 않는다. 판정기는 "이 실행의 입력이 잘렸다"까지만 말할 수 있고 "이 수집기의 대상이 잘렸다"는 말할 수 없다. 폴더 입력에는 RapidTriage가 입력을 자른 기록 자체가 없다(자르지 않음).
- **ST-INV**(8종만): 침묵 실패 검사기의 대상 파일 목록은 20,000개에서 멈춘다(`MAX_TARGET_SCAN_FILES`, `core/silent_failure.py:8`). 멈추면 `rapidtriage-run-summary.json`의 `silent_failure_detection.target_inventory.truncated: true`와 검사 `target-inventory-truncated`(`core/silent_failure.py:79-90`)가 남는다. 이 목록은 대상 규칙이 있는 8종(`eventlog`·`windows-prefetch`·`windows-filesystem`·`windows-execution`·`windows-os-account`·`windows-search-index`·`browser`·`recent-files`, `core/silent_failure.py:18-58`)의 "대상이 있었나" 판단에만 쓰인다. 수집기 자신의 입력을 자르지는 않는다.

### 3.2 `cap_reached` 공통 출처 (CR)

- **CR-ROW**: 시간순 단계가 모든 행을 흘려 읽으며 `*_truncated: true`·`truncated`·`scan_capped`·`capped`와 숫자 `*_truncated_rows`·`*_truncated_count`·`truncated_*`를 종류별로 센다(`core/timeline.py:586-648`). 결과는 `rapidtriage-timeline.json`의 `summary.input_row_truncation.<kind>`(`rows_with_truncation`, `flag_counts`, `count_fields`)이고, 단계 행에 `row_truncation`·`cap_disclosures: ["row-truncation:<kind>"]`·`truncated: true`로 복사된다(`core/run/steps.py:263-319`).
  - 세지 않는 것: `*_limit_reached`(예: `record_limit_reached`·`message_limit_reached`·`string_limit_reached`) 행 키, `*_may_be_truncated`, 표시용 미리보기 잘림(`event_message_truncated` 등, `core/timeline.py:493-496`, 경고 아님).
- **CR-PAY**: 종류 출력의 행 밖(최대 4단계) `truncated`·`*_truncated`·`limit_reached`가 참이거나 `collection_status: partial`이면 단계 행 `cap_disclosures`에 점 경로로 남는다(`collect_cap_disclosures`, `core/run/steps.py:342-363`).
- **CR-UND**: 상한 도달 여부를 결과에 남기지 않는 상한 8개는 처리 문제 `undisclosed-cap` 안내로만 나온다(`UNDISCLOSED_CAPS`, `api/app/run_problem_limits.py:56-65`). 이 안내는 "도달했다"가 아니라 "도달했는지 알 수 없다"이다. 판정기는 이것을 `cap_reached` 참으로 쓰면 안 되고, `none_found`를 막는 근거로만 쓴다.
- **일람**: 수집기별 상한과 고지 여부의 정적 일람은 `python scripts/check-collector-caps.py --json`(T-165). 표의 "무고지 상한 n개"는 그 일람의 `undisclosed_per_file` 값이다(2026-11-13 기준선 `tests/test_collector_caps_inventory.py:66` 이후).

### 3.3 `tool_missing` 공통 출처 (TM)

- **TM-SKIP**: 수집기가 행에 `collection_status`(또는 `status`) `skipped`와 `skip_reason`을 달면 종류 요약의 `skip_reasons`·`skipped_row_count`로 모이고, 모든 행이 그런 행이면 `collection_status: skipped`가 된다(`observe_skipped_row`·`skipped_row_summary`, `core/artifacts.py:174-216`). 단계 행은 `status: skipped`, 메시지 "<kind> 수집 건너뜀: <사유>"(`core/run/steps.py:122-125`).
- E01 엔진 모듈·외부 도구가 없으면 처리 자체가 멈추므로(`core/run/__init__.py:2324-2340`) 수집기 단위 신호가 아니다.

### 3.4 `mode_excluded` 공통 출처 (MX)

- **MX-PROF**: 그 실행이 수집 단계에서 돌린 종류 목록 = `rapidtriage-run-summary.json`의 `profile.artifacts_kinds`(`core/run/summary.py:181`). 목록에 없으면 모드에서 빠진 것이다.
- **MX-PLAN**: `rapidtriage-run-plan.json`의 과제(`id == <kind>`) `status: skipped`와 `reason`(`core/run/plan.py:96-106`): `종류 제한 실행(--artifact-kinds)`, `실행 전 제외`, `검사관 요청` 등. 단계 행에는 `status`·`plan_reason`(`core/run/planned_out.py:187-214`), 매니페스트 행에는 `plan_status`(`core/docs.py:362-375`).
- **주의(모드 밖 종류도 돈다)**: 프로필 밖 종류는 `manifest` 단계가 따로 모아 `artifacts/manifest-only/rapidtriage-artifacts-<kind>.json(l)`에 쓴다(`core/docs.py:273-292`, `MANIFEST_ONLY_RECORDS_DIR` `:380`). 이 행은 실행의 `outputs`·단계 행에 들지 않으므로 화면에서 0건으로 보이지만 행이 실제로 있을 수 있다. 판정기는 `not_collected_mode` 문구에 "매니페스트 전용 출력에 n행"을 함께 적어야 한다. 단, `--artifact-kinds` 실행과 건너뛰기 요청에서는 매니페스트도 그 종류를 모으지 않는다(`core/docs.py:299-301`).
- 프로필별 종류 수: `seizure`·`fraud`·`hacking` 31종 전부, `recovery` 26종(`browser`·`p2p`·`ai-agent`·`windows-execution`·`windows-system` 제외, `core/run/profiles.py:94-141`).

### 3.5 `decrypt_unavailable` 공통 출처

- 공통 출처 없음. 종류 요약에 암호화 관련 키를 올리는 수집기는 하나도 없다(`core/artifacts.py`의 요약 키 목록에 없음). 아래 표의 값은 모두 행 키(R)다. 판정기가 `encrypted_store`를 쓰려면 수집기가 요약 키(예: `encrypted_store_count`)를 내도록 바꾸는 과제가 먼저 필요하다.

### 3.6 `parser_failed` 공통 출처 (PF)

- **PF-ISO**: 수집기가 예외를 내면 행을 모두 버리고 종류 요약 `collection_status: failed-isolated`, `parser_error_count >= 1`, 최상위 `parser_errors[]`(`error_type`, `message`)를 남긴다(`core/artifacts.py:107-121, 496-512`). 단계 행 `status: failed_isolated`, `warning_level: failed`(`core/run/steps.py:119-121, 142`), 침묵 실패 검사 `parser-errors-<kind>`(`core/silent_failure.py` `build_parser_error_checks`), `rapidtriage-parser-crash-isolation.json`.
- **PF-ROW**: 행에 `parser_error: true`가 있으면 그 행도 `parser_errors[]`·`parser_error_count`에 더해진다(`observe_parser_error_row`, `core/artifacts.py:187-210`; 목록은 200개까지 `MAX_ROW_PARSER_ERRORS_LISTED`). 이 경우 행은 남고 단계 상태는 `failed_isolated`가 된다.
- PF-ROW를 내지 않는 수집기에서 파일 하나의 파싱 실패는 그 행의 상태 값(예: `parse_status`)으로만 남고 `parser_error_count`에 들지 않는다.

## 4. 31종 × 6신호 표

칸 읽는 법: 공통 출처 이름(위 3절) + 그 수집기에만 있는 키. "R만"은 행 키뿐이라 요약에 없다는 뜻. "기록 안 됨"은 그 신호가 생길 수 있는데 결과 어디에도 남지 않는다는 뜻(빈틈). "—"는 그 신호가 이 수집기에 해당하지 않는다는 뜻이고 이유를 함께 적는다. 모든 수집기의 `scope_truncated`는 ST-E01/ST-EXT(실행 단위, 수집기 구분 없음)이므로 칸에는 그 밖의 것만 더 적는다.

| # | 수집기 | `scope_truncated` | `cap_reached` | `tool_missing` | `mode_excluded` | `decrypt_unavailable` | `parser_failed` |
|---|---|---|---|---|---|---|---|
| 1 | `browser` | ST-E01/EXT + ST-INV | CR-ROW (예: `inventory_truncated` `artifacts/windows/browser.py:3331`, `entries_truncated` `:4986`); 무고지 상한 17개(`browser.py`) | — 순수 Python(선택 모듈·외부 도구 호출 없음) | MX-PROF/PLAN; `recovery`에서 제외 → manifest-only | R만: `cookie_values_decrypted` `browser.py:2715`, `password_values_decrypted` `:4873`, `value_encrypted` `:7577`, `value_status: encrypted-not-read` `:7604`(정책상 복호 안 함) | PF-ISO + PF-ROW(`browser.py:7317`) |
| 2 | `p2p` | ST-E01/EXT | CR-ROW (`files_truncated` `artifacts/p2p.py:299`, `truncated_after_rows` `:359`) | — 순수 Python | MX-PROF/PLAN; `recovery`에서 제외 → manifest-only | — 대상(.torrent·클라이언트 설정·eMule 목록)에 암호화 저장소 없음 | PF-ISO + PF-ROW(`p2p.py:367`) |
| 3 | `ai-agent` | ST-E01/EXT | 종류 요약 `collection_notes` "AI 기록 읽기 상한 도달"(`artifacts/ai_agents/__init__.py:216-221`) + `rapidtriage-ai-agent-skipped.json`의 `skipped_count`; CR-ROW(`truncated`·`truncated_fields` `ai_agents/base.py:236-237`) | — 순수 Python(`adapters` 패키지 부재 처리 `__init__.py:59`는 도구가 아님) | MX-PROF/PLAN; `recovery`에서 제외 → manifest-only | R만: 자격 증명 파일 행 `credential_kind: encrypted-account-credential`(`ai_agents/adapters/claude_swap.py:69`, 존재만 기록) | PF-ISO + PF-ROW(`ai_agents/__init__.py:76`, `ai-agent-parse-error`) |
| 4 | `recent-files` | ST-E01/EXT + ST-INV | CR-ROW (`destinations_truncated`·`destinations_total` `artifacts/windows/recent_files.py:1126-1127`, `ole_streams_truncated` `:1121`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — LNK·점프 목록은 암호화 저장소가 아님(`ENCRYPTED` `:119`는 대상 파일 속성 표시) | PF-ISO만 |
| 5 | `email` | ST-E01/EXT | CR-ROW (`body_truncated` `artifacts/email.py:484`, `export_truncated` `email_pst.py:975`); CR-UND `CONTAINER_SCAN_LIMIT` | R만: PST/OST 행 `email-container-inventory`의 `status: tool-missing`(`artifacts/email_pst.py:965`, pffexport·readpst 없음). `skipped`가 아니라서 TM-SKIP에 안 잡힘 | MX-PROF/PLAN(네 프로필 모두 포함) | 기록 안 됨: 암호 PST·S/MIME 판별 키 없음(`email.py`·`email_pst.py`·`email_external.py`) | PF-ISO만 |
| 6 | `cloud-export` | ST-E01/EXT | CR-ROW (`archive_manifest_truncated` `artifacts/cloud.py:1021`, `archive_embedded_parse_truncated` `:1025`); CR-UND `CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT`·`CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT` | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | 기록 안 됨: 암호 보관 파일 판별 키 없음(`cloud.py`) | PF-ISO만 |
| 7 | `cloud-sync` | ST-E01/EXT | 종류 요약 `collection_notes` "행 상한 … 도달"(`artifacts/cloud_sync.py:916-917`); CR-ROW(`files_truncated` `:1903`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | R만: `encrypted_stores`·`encrypted_store_count`(`cloud_sync.py:1905-1906`) | PF-ISO만 |
| 8 | `mobile-export` | ST-E01/EXT | CR-ROW (`truncated_by_row_cap` `artifacts/mobile/gates.py:85`, `table_inventory_capped` `mobile/messengers.py:407`, `truncated_by_row_limit` `mobile/ios.py:54`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | R만: adb 백업 `status: encrypted-not-unpacked`(`mobile/adb_backup.py:606-607`), `decryption_attempted: false`(`mobile/collector.py:732`) | PF-ISO만(adb 해제 실패는 `collection_notes`, `mobile/collector.py:186`) |
| 9 | `kakaotalk-macos` | ST-E01/EXT | CR-ROW(`truncated` `artifacts/kakaotalk_macos.py:1210`). `context_limit_reached`·`message_limit_reached`(`:1232,1236`)는 CR-ROW가 세지 않음 | R만: `sqlcipher_probe.tool_available: false`, `message: sqlcipher-not-installed`(`kakaotalk_macos.py:751-766`) | MX-PROF/PLAN(네 프로필 모두 포함) | R만: 요약 행 `encrypted_or_custom_store_count`·`sqlcipher_opened_count`(`kakaotalk_macos.py:1023-1024`) | PF-ISO만 |
| 10 | `kakaotalk-windows` | ST-E01/EXT | CR-ROW (`message_rows_truncated` `artifacts/kakaotalk_messages.py:808`, `chat_databases_truncated` `:821`, `scan_truncated` `kakaotalk_windows.py:802`); CR-UND `PICTURE_ROW_LIMIT`·`KAKAO_APP_DB_LIMIT` | — 복호는 순수 Python `core/aes_cbc.py`(`kakaotalk_messages.py:14,44`) | MX-PROF/PLAN(네 프로필 모두 포함) | R만: `kakaotalk-app-inventory` 행 `decryption_status`·`decrypted_database_count`(`kakaotalk_messages.py:802-806`) | PF-ISO만 |
| 11 | `android-apk` | ST-E01/EXT | 기록 안 됨: 상한 도달 키 없음, 무고지 상한 4개(`artifacts/android.py`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | 기록 안 됨: `encrypted_store_limitation_recorded: true`(`android.py:1976`)는 늘 참인 고정값이라 저장소별 관찰이 아님 | PF-ISO만 |
| 12 | `media-image` | ST-E01/EXT | CR-ROW (`box_inventory_truncated` `artifacts/media.py:1747`, `xmp_truncated` `:1208`). `box_walk_limit_reached`(`:1749`)는 안 셈 | R만: `parse_status: pillow-unavailable`(`media.py:466-468`). OpenCV(`cv2`) 부재(`media.py:20-23`)는 기록 안 됨 | MX-PROF/PLAN(네 프로필 모두 포함) | — 이미지·동영상 형식은 암호화 저장소가 아님 | PF-ISO만 |
| 13 | `generic-documents` | ST-E01/EXT | CR-ROW (`sample_entries_truncated` `artifacts/generic.py:275`, `ole_streams_truncated` `:1288`, `external_references_truncated` `:706`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | R만: `encrypted`·`encrypted_entry_count`(`generic.py:247,188`), `password_encrypted`·`drm_protected`(`:1311,1314`) | PF-ISO만 |
| 14 | `memory-volatility` | ST-E01/EXT | CR-ROW (`scan_truncated`·`pivots_truncated` `artifacts/memory.py:226-229`, 전체 수 없음); CR-UND `MEMORY_DUMP_SCAN_LIMIT` | — Volatility는 실행하지 않고 그 JSON 출력만 읽음, 덤프 검사는 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 메모리 덤프 문자열 검사에 복호 단계 없음 | PF-ISO만 |
| 15 | `synthetic-media` | ST-E01/EXT | CR-ROW `scan_capped`(`artifacts/synthetic_media.py:331`) + 단계 경고 "후보 n개 중 m개 파일 미선별"(`core/run/steps.py:243-251`) | **TM-SKIP**: 행 `collection_status: skipped`, `skip_reason`(`synthetic_media.py:274-287`) → 종류 요약 `skip_reasons`·`collection_status: skipped`. 31종 중 유일하게 요약까지 올라옴 | MX-PROF/PLAN(네 프로필 모두 포함) | — 대상 미디어에 암호화 저장소 없음 | PF-ISO만 |
| 16 | `windows-os-account` | ST-E01/EXT + ST-INV | 기록 안 됨: 상한 도달 키 없음, 무고지 상한 1개(`artifacts/windows/os_account.py`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | R만: `decryption_status`·`secret_decryption_attempted`(`os_account.py:1424,1452`). SECURITY 비밀값은 정책상 복호 안 함(`:1430`) | PF-ISO만 |
| 17 | `eventlog` | ST-E01/EXT + ST-INV | CR-ROW (`events_truncated` `artifacts/windows/eventlog.py:8660`, `native_records_truncated` `:8157`, 숫자 `text_truncated_rows`·`payload_truncated_rows` `:8439-8440`); CR-UND `ETL_SCAN_LIMIT` | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — EVTX·ETL은 암호화 저장소가 아님 | PF-ISO만 |
| 18 | `windows-search-index` | ST-E01/EXT + ST-INV | CR-ROW(`truncated` `artifacts/windows/ese_native.py:933`) | 기록 안 됨: 압축 열 풀기에 쓰는 선택 모듈 `dissect.util`이 없으면 값 없이 넘어감(`ese_native.py:551-554`) | MX-PROF/PLAN(네 프로필 모두 포함) | — Windows.edb·SRUDB.dat은 암호화 저장소가 아님 | PF-ISO만 |
| 19 | `windows-remote-access` | ST-E01/EXT | 기록 안 됨: 상한 도달 키 없음, 무고지 상한 1개(`artifacts/windows/remote_access.py`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 원격 접속 도구 로그·설정은 평문 대상만 읽음 | PF-ISO만 |
| 20 | `windows-messenger` | ST-E01/EXT | 종류 요약 `collection_notes` "<앱>(<사용자>): 상한 도달"(`artifacts/windows/messenger.py:1111`); CR-ROW(`files_truncated` `:1611`, `message_text_truncated` `:915`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | R만: `encryption_state`·`encrypted_store_count`(`messenger.py:1807,1815`) | PF-ISO + PF-ROW(`messenger.py:1128,1776`) |
| 21 | `email-clients` | ST-E01/EXT | 종류 요약 `collection_notes` "<클라이언트>(<사용자>): 상한 도달"(`artifacts/email_clients.py:419`); CR-ROW(`message_truncated` `:489`) | — 순수 Python(PST 외부 도구 경로는 `email`) | MX-PROF/PLAN(네 프로필 모두 포함) | 기록 안 됨: 암호 메일 저장소 판별 키 없음(`email_clients.py`) | PF-ISO + PF-ROW(`email_clients.py:453`) |
| 22 | `media-player` | ST-E01/EXT | 종류 요약 `collection_notes` "<플레이어>(<사용자>): 상한 도달"(`artifacts/windows/media_players.py:284`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 재생 기록 파일은 평문 | PF-ISO + PF-ROW(`media_players.py:328`) |
| 23 | `windows-phone-link` | ST-E01/EXT | 종류 요약 `collection_notes` "휴대폰과 연결(…): 상한 도달"(`artifacts/windows/phone_link.py:230`); CR-ROW(`files_truncated` `:592`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 평문 SQLite만 읽음(known-limitations의 R5 L1 절) | PF-ISO + PF-ROW(`phone_link.py:265`) |
| 24 | `windows-execution` | ST-E01/EXT + ST-INV | CR-ROW (`truncated_by_cap` `artifacts/windows/execution.py:995`, `string_candidate_truncated` `:831`); CR-UND `SHIMCACHE_MAX_ENTRIES` | — 순수 Python | MX-PROF/PLAN; `recovery`에서 제외 → manifest-only | — 하이브·Amcache는 암호화 저장소가 아님 | PF-ISO만 |
| 25 | `windows-registry` | ST-E01/EXT | CR-ROW (`scan_truncated` `artifacts/windows/registry.py:425`). `string_limit_reached`(`:426`)·디코더 `key_budget_exhausted_decoders`는 안 셈 | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 하이브는 암호화 저장소가 아님(`encryptedpassword` `registry_depth.py:944`는 값 이름) | PF-ISO만 |
| 26 | `windows-shellbags` | ST-E01/EXT | CR-ROW (`truncated` `artifacts/windows/shellbags.py:521`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 하이브 값만 읽음 | PF-ISO만 |
| 27 | `windows-prefetch` | ST-E01/EXT + ST-INV | CR-ROW (`reference_rows_truncated` `artifacts/windows/prefetch.py:227`, `directory_strings_truncated` `:791`). `header_executable_name_may_be_truncated`(`:468`)는 안 셈 | — MAM 압축 풀기는 순수 Python(`xpress_huffman.py`) | MX-PROF/PLAN(네 프로필 모두 포함) | — 프리패치는 압축이지 암호화가 아님 | PF-ISO만 |
| 28 | `windows-filesystem` | ST-E01/EXT + ST-INV | 처리 문제 `ntfs-parse-cap`($MFT·USN 5,000건, 16 MiB, `$LogFile` 8 MiB, `api/app/run_problem_limits.py:175-232`). 행 `record_limit_reached`(`artifacts/windows/filesystem.py:1606`)는 CR-ROW가 세지 않음 | 기록 안 됨: Windows에서 ADS 목록을 `powershell`로 얻는데(`filesystem.py:424-453`), Windows가 아니거나 실행 실패·30초 초과면 아무 기록 없이 넘어감. 나머지는 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — NTFS 메타데이터만 읽음(`ENCRYPTED` `:139`는 EFS 파일 속성 표시) | PF-ISO만 |
| 29 | `windows-system` | ST-E01/EXT | CR-ROW (`scan_truncated` `artifacts/windows/system.py:974`, `walk_truncated` `av_ahnlab.py:372`, `minidump_modules_truncated` `system.py:6349`) | — 순수 Python | MX-PROF/PLAN; `recovery`에서 제외 → manifest-only | R만: `protected_store_possible`(`system.py:590`), `dpapi_decrypted: false`(`system_extras.py:1266`, 정책상 복호 안 함), `pkcs8-encrypted`(`system_extras.py:119`) | PF-ISO만 |
| 30 | `linux-system` | ST-E01/EXT(네이티브 E01은 NTFS만이므로 실제로는 폴더 입력) | 기록 안 됨: 상한 도달 키 없음, 무고지 상한 2개(`artifacts/linux.py`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — 평문 로그·설정만 읽음 | PF-ISO만 |
| 31 | `macos-system` | ST-E01/EXT(위와 같음) | 기록 안 됨: 상한 도달 키 없음, 무고지 상한 2개(`artifacts/macos.py`) | — 순수 Python | MX-PROF/PLAN(네 프로필 모두 포함) | — plist·로그·TCC DB는 평문(키체인은 대상 아님) | PF-ISO만 |

## 5. 판정기(T-047)가 알아야 할 빈틈

표에서 드러난, 코드가 아직 신호를 남기지 않는 곳. 판정기는 이 칸을 "모름"으로 다루고, 고칠 과제가 생기면 이 표를 먼저 고친다.

1. **`decrypt_unavailable`은 31종 모두 요약 키가 없다.** 값은 행 키(R)에만 있다(3.5절). `encrypted_store` 판정은 요약 키 추가 전까지 JSONL 전체를 읽어야 한다.
2. **`scope_truncated`는 실행 단위 하나뿐이다.** 잘린 파일이 어느 수집기 대상이었는지 모른다(3.1절).
3. **`tool_missing`이 요약까지 올라오는 것은 `synthetic-media` 하나다.** `email`(`status: tool-missing`)·`kakaotalk-macos`(`sqlcipher-not-installed`)·`media-image`(`pillow-unavailable`)는 행 키에만 있고, `media-image`의 OpenCV, `windows-search-index`의 `dissect.util` 부재와 `windows-filesystem`의 PowerShell ADS 목록 실패는 어디에도 남지 않는다.
4. **CR-ROW는 `*_limit_reached`를 세지 않는다.** `windows-filesystem`(`record_limit_reached`), `kakaotalk-macos`(`context_limit_reached`·`message_limit_reached`), `windows-registry`(`string_limit_reached`), `media-image`(`box_walk_limit_reached`)의 상한 도달이 단계 경고에 오르지 않는다. `windows-filesystem`만 처리 문제 `ntfs-parse-cap`이 따로 메운다.
5. **상한 도달 기록이 아예 없는 수집기 5종**: `android-apk`·`windows-os-account`·`windows-remote-access`·`linux-system`·`macos-system`. 일람상 무고지 상한이 있다(4절 표).
6. **모드 밖 종류도 행이 있을 수 있다.** `recovery` 실행의 5종은 manifest-only 출력에 행이 남는다(3.4절). `not_collected_mode` 문구가 "안 봤음"이라고 단정하면 틀린다.
7. **`CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT`는 겹쳐 말한다.** 행에 `archive_embedded_parse_truncated`가 있는데도 처리 문제 `undisclosed-cap` 목록에 들어 있다(`api/app/run_problem_limits.py:60`).
