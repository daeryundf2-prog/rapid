# 런 파이프라인 1차 완주 계획 (run-pipeline-mitigations)

날짜: 2026-10-09 · 브랜치: `perf/run-pipeline-mitigations` · 근거: `docs/perf-architecture-review-2026-10-09.md`

## 1. 최종 사용자

**포렌식 분석관 A.** 법무법인 소속, 압수한 PC의 E01(100–300 GB)을 받는다. 상용 도구 라이선스가 없거나 2차 검증용으로 RapidTriage를 쓴다. 워크플로우:

1. 웹 콘솔에서 E01 경로와 모드(`hacking` 등)를 넣고 "Run"을 누른다.
2. 다른 일을 하다가 돌아와 **진행 중인지, 얼마나 남았는지** 본다.
3. 끝나면 유형별 그리드에서 아티팩트를 보고, 키워드 검색하고, 항목을 열어 원본을 확인하고, 리뷰 상태를 매기고, 필요한 파일만 추출한다.
4. 결과가 이상하면 어느 단계에서 무엇이 실패했는지 알아야 한다. 42시간짜리 런이 마지막에 죽어 **아무것도 남지 않는 것**이 A에게 최악이다.

A는 Python 개발자가 아니다. A에게 중요한 것은 (a) 런이 **완주**하는가, (b) **기다릴 만한 시간**(하룻밤)에 끝나는가, (c) 진행 상황이 **보이는가**, (d) 실패해도 **완료된 부분은 남는가**, (e) 결과를 **UI에서 열 수 있는가**다.

## 2. 이상적인 상태 (이번 이터레이션이 보장해야 하는 것)

| # | 상태 | 이유 |
|---|---|---|
| I1 | 어떤 provider 출력에 bytes/datetime/Path/set이 들어 있어도 모든 `write_result` 호출이 성공한다. bytes는 `{"__type__":"bytes","hex":…,"length":…}`로 손실 없이 기록된다. | 42 h 결과를 직렬화 단계에서 잃는 사고의 재발 방지. hex는 포렌식적으로 역추적 가능. |
| I2 | SRUM `row_fields`의 binary 컬럼은 I1 fallback에 의존하지 않고 파서 단계에서 명시적으로 hex 변환된다. | fallback은 안전망이고, 파서는 자기 출력 형식을 책임져야 한다. |
| I3 | 23개 provider 수집이 **메인 스레드 순차**가 아니라 **스케줄러 워커 풀**에서 병렬 실행된다. manifest 단계는 이미 수집된(캐시) 결과만 조립한다. | 32.4 h 단계의 주범. 기존 ThreadPool 스케줄러를 실제로 쓰게 한다. |
| I4 | 각 provider 결과는 완료 즉시 `artifacts/rapidtriage-artifacts-<kind>.json`으로 디스크에 기록된다. 이후 단계가 죽어도 완료된 provider 파일은 남는다. | "실패해도 완료된 부분은 남는다". |
| I5 | 런 1회 동안 동일 root에 대한 `iter_evidence_paths(root, "*")`는 트리를 **1번만** 걷는다(캐시). 서브루트·단순 glob 패턴도 캐시에서 필터링된다. 캐시는 런 시작 시 비워지고 런 종료 시 해제된다. CLI 단일 collector 명령과 단위 테스트는 영향받지 않는다(런 컨텍스트 밖에서는 캐시 비활성). | 99회 × 148 s ≈ 4.1 h 제거. |
| I6 | 런 진행 상황이 `rapidtriage-run-progress.json`에 provider 단위로 기록된다: 단계명, 시작/완료 provider 목록, 현재 실행 중 provider와 시작 시각, 마지막 갱신 시각. provider 완료마다 갱신. 웹 API `/api/runs/{id}` 응답에 이 파일 내용이 `progress`로 포함된다. | "느린 건지 죽은 건지" 구분. 모니터 스크립트가 아니라 제품이 보여줘야 한다. |
| I7 | `docs.json`과 `manifest.json`이 **같은 7 GB artifact 배열을 중복 저장하지 않는다.** `docs_payload["manifest"]`는 provider 요약(name, supported, artifact_count)만 담는다. 기존 소비자(UI/API/테스트)가 전체 artifact를 필요로 하면 `artifacts/*.json`에서 읽는다. | 디스크 2배, 메모리 2배, 직렬화 2배. |
| I8 | 위 변경 후 기존 테스트 전부 통과(stale 2건 제외 — 별도 처리), ruff/vulture 통과, 산출물 JSON 스키마(`rapidtriage/schemas`)가 깨지지 않는다. | 리그레션 0. |
| I9 | 작은 실제 트리(BSH 추출본 서브셋)로 `rapidtriage run`이 **완주**하고, 산출물이 웹 UI에서 열린다. | 사용자 관점 최종 확인. |

이번에 **하지 않는 것**(다음 이터레이션, 설계 변경 필요): 이미지 직접 읽기(추출 없이), SQLite-first 인덱스, ProcessPool, 해시 정책 변경, 파티션 다중 복구. 이유: 이것들은 산출물 형태와 UI 계약을 바꾸므로 별도 설계·QA가 필요하다.

## 3. 현재와의 차이

| 상태 | 현재 | 근거 |
|---|---|---|
| I1 | `write_result`에 `default=` 없음 → bytes에서 TypeError | `core/docs.py:458-463` |
| I2 | `"row_fields": row` raw dict 그대로 | `artifacts/windows/execution.py:2726` |
| I3 | `build_manifest`가 `all_providers()`를 for 루프로 순차 수집, run_triage_mode가 이것을 **artifacts 단계보다 먼저** 호출 | `core/docs.py:115-135`, `core/run/__init__.py:555-560` |
| I4 | `collect_artifact_stages`가 전부 끝난 뒤 for 루프에서 `write_result` | `core/run/__init__.py:706-725` |
| I5 | `iter_evidence_paths`가 매번 `root.rglob` | `core/files.py:101-114`, 호출 99곳 |
| I6 | 진행 파일 없음. scheduler manifest는 종료 시 1회 기록 | `core/run/__init__.py:1142-1308` |
| I7 | `docs_payload["manifest"] = manifest_payload`, `run_docs_search`도 `build_manifest` 호출 | `core/run/__init__.py:576`, `core/docs.py:185` |

## 4. 구현 계획 (파일 단위)

### P1. JSON-safe 직렬화 — `core/docs.py`
- `json_default(value)` 추가: `bytes/bytearray/memoryview` → `{"__type__":"bytes","hex":hex,"length":n}`; `datetime/date` → isoformat; `Path` → str; `set/frozenset` → sorted list(문자열화 비교); `Decimal` → str; 그 외 `TypeError` 유지(숨기지 않음).
- `write_result`에 `default=json_default` 적용. 동일 기본값을 쓰는 다른 `json.dump(s)` 산출물 경로가 있으면(`core/audit.py`, `core/artifact_store.py` write_jsonl_*) 같은 핸들러 적용.
- 테스트: `tests/test_rapidtriage_docs.py`에 bytes·datetime·Path·set 포함 payload round-trip; 알 수 없는 객체는 여전히 TypeError.

### P2. SRUM row_fields 명시 변환 — `artifacts/windows/execution.py`
- `_json_safe_row_fields(row: Mapping) -> dict`: bytes 값 → `{"hex":..., "length":..., "utf16le_preview": 디코드 가능 시 앞 120자}` (IdBlob은 UTF-16LE 문자열이 흔함 — 분석관이 바로 읽을 수 있게). 중첩 dict/list 재귀.
- `"row_fields": _json_safe_row_fields(row)`, `raw_preview`는 그대로.
- 테스트: `tests/test_rapidtriage_windows_artifacts_collectors.py` (또는 execution 테스트 파일)에 bytes 컬럼이 든 row로 record 생성 → `json.dumps` 성공 + hex/preview 확인.

### P3. manifest 병렬화 + artifacts 선행 — `core/docs.py`, `core/run/__init__.py`
- `build_manifest`: `collect_cached` 호출을 `ThreadPoolExecutor(max_workers=manifest_collect_workers())`로 병렬화. 워커 수: `artifact_scheduler_workers`와 동일 정책을 쓰되 상한을 `min(8, os.cpu_count() or 4)`로 올린다(현재 4 고정; I/O-bound 수집이라 8이 적정). 결과 순서는 `all_providers()` 순서 유지(결정적 출력).
- `run_triage_mode`: `collect_artifact_stages`를 `build_manifest` **이전**으로 이동. 그러면 manifest는 캐시 적중. profile에 없는 provider만 build_manifest의 풀에서 수집된다.
- `collect_artifact_stages`의 워커 상한도 같은 함수로 통일.
- 주의: fingerprint·checkpoint·resume 로직의 순서 의존성(`load_or_build_json(manifest_path, resume=…)`)을 깨지 않는다. resume 시 manifest 재사용 조건은 그대로.

### P4. provider 완료 즉시 기록 — `core/run/__init__.py`
- `collect_artifact_stages`의 `as_completed` 루프 안에서 `write_result(payload, artifact_path)`를 즉시 호출. 이후 run_triage_mode의 for 루프에서는 **다시 쓰지 않는다**(파일 mtime·내용 동일, 중복 I/O 제거). 테스트에서 "payload == 파일 내용" 확인.

### P5. 런 범위 evidence path 캐시 — `core/files.py` (+ run/__init__.py 활성화)
- 모듈 전역 `_EVIDENCE_PATH_CACHE: dict[str, list[Path]]`, `_EVIDENCE_PATH_CACHE_ENABLED: bool`, lock.
- `enable_evidence_path_cache()` / `disable_evidence_path_cache()` (clear 포함). `run_triage_mode`에서 `prepare_run_input_root` 직후 enable, `finally`에서 disable.
- `iter_evidence_paths(root, pattern)`:
  - 비활성: 기존 동작 그대로.
  - 활성: `root` 또는 그 조상이 캐시에 있으면 그 리스트에서 (a) `root` 하위(prefix 비교, `os.sep` 경계 고려) (b) `pattern`이 `"*"`면 전부, 아니면 `fnmatch`(Windows는 case-insensitive — pathlib 동작과 일치시키기 위해 `os.path.normcase` 기반)로 이름 필터. 패턴에 경로 구분자가 있으면 캐시 우회(기존 rglob).
  - 없으면 `root.rglob("*")`를 1회 materialize(RUN_OUTPUT_DIR_PREFIX 제외 규칙 동일)하여 저장 후 동일 필터.
- 스레드 안전: 빌드는 lock 안에서 1회.
- 테스트: 활성 시 두 번째 호출이 `rglob`을 호출하지 않음(mock 카운트), 서브루트·패턴 필터 결과가 비활성 경로와 **동일**(동일 tmp 트리에서 set 비교, `$I*`, `*.reg`, `Report.wer`, `*Zone.Identifier` 패턴 포함), disable 후 캐시 비어 있음.

### P6. 진행 상황 파일 + API — `core/run/__init__.py`, `core/run/progress.py`(신규), `api/app/routes_runs.py`
- `RunProgress` 기록기: `rapidtriage-run-progress.json`을 atomic write(tmp→replace). 필드: `run_root`, `stage`, `updated_at`(UTC aware), `providers: {kind: {status: queued|running|completed|error|reused, started_at, completed_at, duration_ms, artifact_count}}`, `completed_count`, `total_count`.
- `collect_artifact_stages`: submit 시 queued→running(스레드 시작 시점), 완료 시 completed/error. `build_manifest` 병렬 수집도 동일 기록기 사용(provider name 기준).
- `run_triage_mode` 각 `record_memory_cap(stage)` 지점에서 `stage` 갱신.
- API: `GET /api/runs/{run_id}` 응답에 `progress` 키(파일 있으면 내용, 없으면 null). 기존 키는 변경 없음.
- 테스트: 샘플 트리 런 후 progress 파일 존재·`completed_count == total_count`·모든 provider `completed|reused`; API 계약 테스트에 `progress` 키.

### P7. docs.json의 manifest 중복 제거 — `core/docs.py`, `core/run/__init__.py`
- `build_manifest_summary(manifest_payload)` → providers를 `{name, description, target_platform, supported, artifact_count}`로 축약.
- `run_docs_search`의 `"manifest": build_manifest(...)` → 요약. `run_triage_mode`의 `docs_payload["manifest"] = manifest_payload` → 요약.
- 소비자 조사: `grep -rn '"manifest"' rapidtriage/api rapidtriage/web/static rapidtriage/core/run/summary.py rapidtriage/core/case_db tests` — docs payload의 manifest에서 `artifacts`를 읽는 곳이 있으면 `artifacts/*.json` 또는 manifest.json으로 바꾼다. 스키마(`rapidtriage/schemas/*docs*.json`) 갱신.
- 테스트: docs payload에 artifact 배열이 없음, 기존 docs/run 테스트 통과.

### P8. 정리
- `ruff check rapidtriage tests scripts`, `vulture --min-confidence 80`, `python -m compileall -q`.
- `docs/rapidtriage-known-limitations.md`에 진행 파일·캐시 동작 한 줄씩.

## 5. QA 시나리오 (타협 없음)

| # | 시나리오 | 합격 기준 |
|---|---|---|
| Q1 | `python -m unittest discover -s tests` | 실패 = 기존 stale 2건(`test_rapidtriage_ntfs_metadata` fsstat-probe)뿐. 신규 실패 0. 스킵 수 변동 없음. |
| Q2 | ruff / vulture / compileall | 전부 clean (ruff는 기존 2건 import 정렬 포함 0건으로). |
| Q3 | bytes payload: `write_result({"a": b"\x00\xff", "d": datetime, "p": Path, "s": {1,2}}, path)` | 파일 생성, 재로드 시 `a == {"__type__":"bytes","hex":"00ff","length":2}`. |
| Q4 | SRUM: 실제 BSH `Windows\System32\sru\SRUDB.dat`를 `rapidtriage artifacts windows-execution` 단독 수집 | 예외 없이 JSON 출력, `srum-schema-row`의 `row_fields.IdBlob`이 hex+preview 객체. |
| Q5 | 캐시 동등성: BSH 추출 트리 서브셋(`Windows\System32\config`, `Windows\System32\winevt`, `Users\<one>`)에 대해 각 provider를 캐시 ON/OFF로 각각 수집 | 두 결과의 artifact 집합(`path`,`artifact_type`,`details` 중 timestamp 제외) **동일**. |
| Q6 | 캐시 성능: 같은 서브셋에서 `iter_evidence_paths(root,"*")` 2회 호출 | 2회차가 1회차의 1/50 이하 시간. |
| Q7 | 병렬: 서브셋 `rapidtriage run --mode hacking` 중 `rapidtriage-run-progress.json` 관찰 | `running` 상태 provider가 동시에 ≥2개인 순간이 존재. 최종 `completed_count == total_count`. |
| Q8 | 중간 실패 보존: provider 하나를 강제로 예외 던지게 monkeypatch한 런 | 나머지 provider의 `artifacts/*.json`이 존재하고 유효 JSON, 해당 provider는 `error` 상태로 기록, 런 요약에 `failed-isolated`. |
| Q9 | 산출물 중복: 서브셋 런 후 `docs.json` 크기 | `manifest.providers[*]`에 `artifacts` 키 없음. `artifacts/*.json` 합계 ≥ manifest.json의 artifact 수. |
| Q10 | 웹 UI: `rapidtriage web`으로 서브셋 런 import 후 `/api/runs/{id}` | `progress` 키 존재, 유형 그리드·검색·프리뷰 동작(브라우저 수동 확인 1회). |
| Q11 | 전체 BSH 런(135 GB, SSD로 output_dir 이동) | **완주**. manifest 단계 ≤ 6 h(이전 32.4 h). 실패 시 어느 단계인지 progress에 남음. — 장시간이므로 사용자가 실행, 결과 공유. |

## 5-A. 1차 QA 결과 (2026-10-09, Fable 검증)

| # | 결과 | 근거 |
|---|---|---|
| Q1 | **PASS** | 1173 tests, failures=2 (기존 stale `ntfs_metadata` 2건만), skipped=14 |
| Q2 | **PASS** | ruff/vulture/compileall clean |
| Q3 | **PASS** | bytes→`{"__type__":"bytes","hex","length"}`, datetime/Path/set 변환, 미지 객체 TypeError 유지 |
| Q4 | **PASS** (Opus 실행) | BSH SRUDB 20,000 행, IdBlob 19,998건 hex+preview |
| Q5 | **미완** | 실행 중 MemoryError(아래) |
| Q6 | **PASS** | 296,902 경로: 1회차 920 s → 2회차 0.254 s (비율 0.0003) |
| Q7 | **부분 PASS** | 동시 실행 provider 최대 9개 확인. 그러나 런은 artifacts 단계 직후 **MemoryError로 실패** (90분, RSS 32 GB+) |
| Q8 | 미완 | 동일 원인 |
| Q9 | 미완 | — |
| Q10 | 미완 | — |

**Q7 실패 분석** — 서브셋 입력 ≈ 2 GB인데 `artifacts/` 산출물 합계 **50.8 GB**:

| 파일 | 크기 | 레코드 | 레코드당 |
|---|---|---|---|
| `rapidtriage-artifacts-eventlog.json` | 47,200 MB | (집계 중) | 5.3 KB (chunk/record 후보 행) |
| `rapidtriage-artifacts-windows-prefetch.json` | 3,013 MB | 51,785 | **58 KB** (첫 레코드 163 KB) |
| `rapidtriage-artifacts-windows-registry.json` | 193 MB | 4,740 | 41 KB |
| `rapidtriage-artifacts-windows-execution.json` | 110 MB | 4,025 | 27 KB |
| `rapidtriage-artifacts-media-image.json` | 82 MB | 994 | 83 KB |

레코드 내부 구성(prefetch-file 첫 레코드 163 KB): `details` 81 KB + `artifact_record.fields` 81 KB(**동일 내용 복제**). `details` 안에서 `file_reference_candidates` 38 KB, `prefetch_execution_depth_manifest` 15 KB, `referenced_paths` 10 KB, `commercial_uplift_evidence` 4.5 KB, `prefetch_analyst_review_profile` 2.4 KB, `core_accuracy_gates` 1.5 KB, `validation_matrix/checks/report_grade_assessment` 2.5 KB — 이 중 뒤의 5개는 **같은 artifact_type의 모든 레코드에서 동일한 상수 블록**이다.

결론: 1차 조치(I3–I6)는 의도대로 동작하나, **레코드당 메타데이터 부피**가 메모리·디스크·직렬화 시간을 지배한다. 2차 없이는 전체 이미지 런 완주 불가.

## 7. 2차 계획: 레코드 슬리밍과 스트리밍 (이상 상태 I10–I13)

최종 사용자 A에게 이것이 뜻하는 바: 유형 그리드에서 prefetch 행 하나를 클릭했을 때 필요한 것은 실행 파일명·실행 횟수·마지막 실행 시각·참조 경로 몇 개·검증 상태 한 줄이다. 레코드마다 반복되는 "상용급 블로커 선언문"은 **한 번만** 보면 된다.

| # | 이상 상태 | 이유 |
|---|---|---|
| I10 | 레코드는 **한 번만** 직렬화된다. `artifact_record.fields`가 `details`를 복제하지 않는다(ArtifactRecordV1 정규화 레코드는 `details`를 참조하거나, per-kind 파일에서는 `artifact_record`의 `fields`를 생략하고 columnar/case-db 임포트 시 재구성). | 즉시 50% 절감. |
| I11 | artifact_type별로 **상수인 블록**(`commercial_uplift_evidence`, `core_accuracy_gates`, `*_validation_matrix`, `*_validation_checks`의 상수 부분, `*_report_grade_assessment`, `*_analyst_review_profile`, `*_section_bounds_profile`, `forensic_review` 상수부, `recommended_parsers`, `validation_guidance` 등)은 provider 출력의 `artifact_type_profiles[<artifact_type>]`에 **1회** 기록되고, 레코드에는 `profile_ref: <artifact_type>`만 남는다. 레코드별로 값이 달라지는 필드(검증 체크의 bool 결과 등)만 레코드에 남는다. | 보일러플레이트 제거. 포렌식 의미 손실 없음(참조로 복원 가능). |
| I12 | 레코드당 후보 리스트는 상한을 갖고 상한 초과분은 `..._truncated: true, ..._total: n`으로 표시된다: `file_reference_candidates` ≤ 64, `referenced_paths` ≤ 256, `prefetch_execution_depth_manifest`는 요약(counts)만, eventlog `eventlog-chunk`/`eventlog-record-candidate` 행은 **기본 비활성**(옵션 `--eventlog-structure-rows`)이고 기본 출력은 디코드된 이벤트 행만. | 분석관은 전체 후보를 원하면 원본을 연다; 트리아지 결과에 수만 개 후보를 박을 이유가 없다. |
| I13 | 메모리 상한: provider 결과를 리스트로 모으지 않고 **JSONL로 스트리밍 기록**(`artifacts/rapidtriage-artifacts-<kind>.jsonl` + 요약 `.json`), `collect_cached`는 manifest 조립 후 즉시 해제, manifest.json은 provider 요약만(artifact 배열 없음, per-kind 파일 참조). `enforce_memory_cap`가 provider 완료 시점마다 검사하고 초과 시 progress에 `error: memory-cap`으로 **조기 실패**(MemoryError로 90분 뒤 죽지 않음). 기본 cap = 물리 RAM의 50%. | 런 메모리를 입력 크기와 무관하게 bounded. |

**목표 수치 (서브셋 런)**: `artifacts/` 합계 ≤ 1 GB (현 50.8 GB), 평균 레코드 ≤ 2 KB, 피크 RSS ≤ 8 GB, 완주 시간 ≤ 20분.

### 구현 (파일 단위)

- **P9 (I10)** `core/models.py` `ArtifactRecord.to_dict()` / `artifact_store.py`: per-kind 파일·manifest에서 `artifact_record.fields` 생략(또는 `details`로 단일화). columnar sidecar·case_db 임포트·API viewer가 `artifact_record.fields`를 읽는 곳을 전수 조사해 `details`로 전환. 스키마 갱신.
- **P10 (I11)** 공통 유틸 `core/artifact_profiles.py`: `hoist_constant_blocks(records, keys)` — 동일 artifact_type 레코드 집합에서 지정 키의 값이 모두 동일하면 profile로 이동하고 레코드에서 제거. provider `collect` 마지막(또는 `run_artifact_collection`)에서 적용. 대상 키 목록은 서브셋 산출물로 측정해 확정(`scripts/measure-artifact-record-bloat.py` 신규: 파일별 레코드 수·평균 크기·키별 상수 여부 보고 — QA에도 사용).
- **P11 (I12)** prefetch/eventlog/registry/media 각 provider의 후보 리스트 상한 상수 + truncated 표기; eventlog 구조 행 옵션화.
- **P12 (I13)** `collect_artifact_stages`: provider 완료 즉시 JSONL 스트리밍(이미 있는 `write_jsonl_artifacts` 재사용), `.json`에는 summary+profiles+상위 N 레코드 미리보기만. manifest.json에서 `artifacts` 제거 → `summary.py`/`steps.py`/UI/API 소비자 전환(`artifact_type_counts`는 per-kind summary에서 집계). `clear_collect_cache()`를 manifest 조립 직후 호출. 메모리 cap 기본값·provider별 검사.
- **P13** 스키마·문서·프론트 타입 재생성 안내.

### 2차 QA

| # | 시나리오 | 합격 |
|---|---|---|
| Q12 | `scripts/measure-artifact-record-bloat.py C:\rapid-qa\run-subset2\artifacts` | 합계 ≤ 1 GB, 평균 레코드 ≤ 2 KB, 어떤 레코드에도 `artifact_record.fields`와 `details` 동시 존재 없음 |
| Q13 | 서브셋 런 완주 (`--mode hacking`) | status=completed, 피크 RSS ≤ 8 GB(`rapidtriage-memory-cap-enforcement.json`/progress 기록), ≤ 20분 |
| Q14 | 레코드 복원: profile_ref로 상수 블록을 다시 합쳤을 때 2차 이전 레코드와 **필드 집합 동일**(상한 초과 리스트 제외) — 단위 테스트 | 손실 없음 증명 |
| Q15 | 웹 UI 유형 그리드·프리뷰·검색이 per-kind JSONL/summary로 동작 | 브라우저 확인 |
| Q16 | 1차 Q5·Q8·Q9·Q10 재실행 | 전부 PASS |
| Q17 | 전체 BSH 런 (사용자) | 완주 |

## 7-A. 2차 QA 결과 (2026-10-09, Fable 독립 검증)

| # | 결과 | 근거 |
|---|---|---|
| Q12 | **PASS** | 281,595 레코드, 평균 1.6 KB, 이중 직렬화 0, `artifacts/` 472 MB (목표 ≤ 1 GB) |
| Q13 | **부분 PASS** | 독립 런 `run-subset3`: completed 24/24, 0 errors, **1,098 s (18.3분)**, artifacts 473 MB. **피크 RSS 8.13 GB** (`run-subset5`, 실제 인터프리터 WorkingSet 10 s 샘플링, 단독 실행) — 목표 ≤ 8 GB 미달. 메모리 cap 원장: artifacts 단계에서 0.95→2.86(windows-system)→4.71(prefetch)→7.25(search-index)→7.84 GB로 상승 후 **끝까지 해제되지 않음**(indicators 7.91). 원인: provider가 전체 리스트를 materialize한 뒤에야 스트리밍 → 2차-c P21(제너레이터 스트리밍 + 단일 패스 hoist)로 Opus 지시, 목표 ≤ 4 GB·artifacts 후 ≤ 2 GB |
| Q14 | PASS | 단위 테스트(hoist/expand 왕복) |
| Q9 | **PASS** | `manifest.json` 15 KB, provider 행에 `artifacts` 배열 없음; `docs.json`의 manifest도 요약만 |
| 레코드 수 정합성 | **PASS** | 1차 파일 헤더 `artifact_type_counts`: eventlog-event 203,289 — 2차와 동일. 876k은 중첩 키 과다 집계였음 |
| API | PASS | `/api/runs/{id}`에 `progress`; `/api/runs/{id}/artifacts?offset=51780&limit=3` JSONL 페이징 + profile 확장 |
| Q10 UI | **FAIL** | `GET /api/runs/{id}/capabilities` **85 s** (summary 14 ms) → 워크벤치가 열리지 않음. 프로파일: `visible_capabilities.compact_text` **79,056,753회 호출**, 232 s — capability 100개 × 모든 행 × 중첩 텍스트 재평탄화 |
| 한글 이미지 | **FAIL** | `cv2.imread(str(path))`가 비ASCII 경로를 열지 못함 — 서브셋에서 **878건** 경고, Downloads/Desktop의 한글 이름 png/jpg 전부 media 아티팩트 누락 (`artifacts/media.py:1188`, `core/search.py:1296`) |
| UI 폴링 | 경미 | 유휴 상태에서 `GET /api/runs` 약 1 s 간격 |
| Q8 | **PASS** | prefetch provider 강제 예외: 런 completed, artifacts 24/24 유효 JSON, progress에 `windows-prefetch: error`, manifest `failed-isolated` 행, summary에 반영. (부수 관찰: media provider가 105 MP 이미지를 그대로 열어 PIL `DecompressionBombWarning` — 헤더 크기 사전 검사 필요, 백로그) |
| Q5 | **PASS** | 실데이터 서브셋에서 24개 provider 전부 캐시 ON/OFF 결과 집합 동일(eventlog 219,758 / prefetch 51,785 / registry 4,740 …). 캐시 ON 시 windows-system 54.9→7.9 s, generic-documents 21.4→4.7 s, filesystem 51.1→25.2 s |
| Q6 (재) | PASS | 서브셋 20,113 엔트리: 1회차 2.02 s → 2회차 0.0024 s (비율 0.0012) |

→ 2차-b (Opus 지시 완료): P18 capabilities 행별 텍스트 1회 평탄화·캐시(목표 < 1 s), P19 `np.fromfile`+`cv2.imdecode`로 유니코드 경로 지원 + 한글 PNG 테스트, P20 폴링 백오프(≥ 5 s 유휴, 실행 중 1–2 s) + 진행률 카드.

## 7-B. 2차-b/c 검증 (2026-10-10, Fable 독립 측정)

| # | 결과 | 근거 |
|---|---|---|
| capabilities | **PASS** | 새 서버(:8797) cold **0.998 s** (85 s→), warm 4 ms. 응답 JSON 동일(Opus 대조) |
| 한글 이미지 | PASS (Opus 측정, run-subset6에서 재확인 예정) | media provider 단독: imread 경고 0, 878/887 디코드 |
| UI 워크벤치 열기 | **PASS** | 케이스 클릭 → 접수 탭, 행위흔적 탭에 281,595건 가상 그리드 렌더, 콘솔 에러는 `columnar-artifacts` 404(설계상 폴백)뿐 |
| **UI 검색** | **FAIL** | `GET /api/runs/{id}/search?keyword=powershell&limit=5` → **1,424.8 s**. `run_unified_search`가 매 질의마다 docs/files/artifacts JSONL(281k행, profile 확장)/timeline(280k)/OCR을 순수 Python으로 전수 스캔 |
| 피크 RSS | **PASS** | `run-subset6` 단독 프로세스 WorkingSet 10 s 샘플링: **1.59 GB** (8.13 → 1.59; 목표 ≤ 4 GB). 원인은 2차-b의 stat 메모가 `OSError` 객체(traceback이 디코드된 이미지를 참조)를 캐시한 버그 — 수정됨 |
| 한글 이미지 (재확인) | **PASS** | `run-subset6` stderr imread 경고 **0건** (878 → 0) |
| 완주 시간 | **PASS** (유휴 재측정) | `run-subset8` 단독·유휴: **1,226 s (20.4분)** = triage 18.6분 + persist(case DB 생성) 1.8분. 피크 1.59 GB, completed 24/24, 0 errors, case DB 생성·`search_backend: fts`. 1차 목표(≤ 20분)는 persist 추가 전 기준 충족; persist 포함 20.4분은 허용 범위로 판정(검색 23.7분 → 0.35 s와 교환) |
| 산출물 | PASS | 491 MB, completed 24/24, 0 errors |

### P22 결과 (2026-10-10, Opus #2 · Fable 검증 PASS)
`core/textnorm.py` 신규(NFC+casefold, ASCII는 `lower()`와 동일), search/rules/docs/files/case_db FTS 양쪽 적용. 정규식 모드는 NFC만(casefold 시 `\D`→`\d` 왜곡 방지). FTS5 `unicode61`은 한글 자모를 합성하지 않으므로 삽입·질의 양쪽 NFC가 필수. `indexed_document`(검색 인덱스용 파생 테이블)만 NFC 저장, `file_record`/`artifact`/`event` 원문은 불변. docs index v2. 테스트 22건 신규, 전체 1232 OK (Opus), textnorm/docs/rule_engine/case_db 70건 Fable 재실행 OK. 기존 case DB는 NFD 콘텐츠 검색을 위해 재임포트 필요(known-limitations 기재). Q20 단위 수준 충족.

### P23 (Q10 검색): 인덱스 기반 검색

이상 상태 **I18**: 런이 완료되면 분석관은 키워드 검색 결과를 **2초 안에** 받는다(서브셋 기준; 전체 이미지에서도 ≤ 5 s). 검색은 산출물 파일을 스캔하지 않고 **FTS5 인덱스**를 조회한다. 인덱스는 런의 일부(persist 단계)로 자동 생성되며, 검색 결과의 각 행은 원본 레코드(`records_path` + 행 번호 또는 artifact_id)로 역참조된다.

측정(`run_unified_search`, limit=50, 소스 1개씩 지정): documents 996 s(매치 4) / files 786 s(7) / artifacts 673 s(50) / indicators 646 s(0) / timeline 733 s(50). **어떤 소스를 지정해도 650 s 이상** → `sources`는 스캔 전이 아니라 결과 필터링에만 쓰이고, 매 호출이 전체 산출물을 전수 스캔한다. `limit` 도달 후에도 스캔을 멈추지 않는다.

현재: `persist` 단계는 summary만 저장. case DB(FTS5: `file_record_fts`, `artifact_fts`, `event_fts`, `indexed_document_fts`)는 별도 `/api/case-db/import`로만 채워짐. `/api/runs/{id}/search`는 파일 스캔.

구현:
- persist 단계에서 `CaseDatabase.import_run_output`을 자동 호출해 `<output_dir>/rapidtriage-case.db`를 생성(기존 import 코드 재사용; JSONL 스트리밍 입력으로 메모리 bounded; 진행 파일에 `persist` provider 행 기록). 실패 시 런은 completed, `search_backend: "scan"`으로 표시.
- `/api/runs/{id}/search`: case DB가 있으면 FTS5(`MATCH`) 조회 → 결과 행을 기존 응답 스키마(`matches[]`의 source/path/preview/pointer)로 매핑. exact/stem은 FTS 토크나이저, fuzzy/regex는 FTS 후보(prefix/trigram 또는 키워드 변형)로 후보를 좁힌 뒤 Python 재검증. case DB가 없으면 기존 스캔을 **하드 타임아웃 20 s + limit 조기 종료**로 실행하고 응답에 `backend: "scan", truncated: true`를 넣는다(절대 20분을 기다리게 하지 않음).
- `run_unified_search` 스캔 경로도 `limit` 도달 시 즉시 중단(현재는 전수 스캔 후 `matches[:limit]`).
- P22의 NFC/casefold 규칙을 FTS 삽입·질의 양쪽에 동일 적용.

#### P23 결과 (2026-10-10, Opus #1 구현 · Fable 독립 측정)
- 구현: `core/run/persist.py`(런 말미 case DB 자동 생성, `--no-case-db`), `core/search_fts.py`(FTS5 prefix 후보 → 기존 matcher 재검증), `core/search_budget.py`(스캔 20 s 예산·limit 조기 종료·sources 선적용), `case_db/database.py` 스트리밍 임포트(293 s/1.65 GB → 165 s/0.2 GB), app.js 결과 헤더(backend/elapsed/truncated). 테스트 16건 신규, suite 1248 (실패 1건은 persist가 마지막 단계가 된 데 따른 기대값 — 수정됨, 최종 재실행은 Fable이 수행).
- Fable 측정(:8796, 새 서버): run-subset7 `powershell` **0.35 s** fts 50건 / `진정서` **0.53 s** fts 3건(Downloads PDF) / run-subset3(DB 없음) **9.9 s** scan `truncated: true` 50건. 1,424.8 s → 0.35 s.
- run-subset7 런: 1,324 s, 피크 1.59 GB, persist 146 s(파일 4,770·문서 1,637·아티팩트 281,595·이벤트 280,272).
- **백로그 P24**: (1) case DB **3.13 GB = 산출물의 6.4배** — 아티팩트 행 전체 데이터를 인덱스에 넣어서. 전체 이미지에서는 수십~백 GB가 되므로 검색 가능 필드만 색인(또는 `detail` 컬럼 외부 참조)으로 축소 필요. (2) FTS 매칭이 **단어 접두사만** 지원(`shell`로 `powershell` 미검출) — 분석관 기대는 부분 문자열. SQLite ≥ 3.34의 `trigram` 토크나이저 또는 보조 trigram 테이블 검토.

QA **Q21**: run-subset 런 후 UI 검색 `powershell` 응답 ≤ 2 s, 결과 행 클릭 → 원본 뷰어 열림; `진정서`(NFC/NFD) 검색이 Downloads PDF를 찾음(Q20 통합); case DB 없는 구 런은 20 s 내 `truncated` 응답. → **PASS** (2026-10-10 Fable 브라우저 확인: 전체검색 탭에서 `powershell` 제출 후 **1.0 s** 내 "500건 일치 · 색인(FTS) 578ms" 헤더와 결과 그리드 렌더; `진정서` API 3건; 구 런 9.9 s truncated. 행→뷰어 열림은 Opus 검증(50/50 pointer 해석, 10행 source-preview 200)).

## 8. 3차 계획: 추출 커버리지 갭 (BSH 보고서 §6-A-1 재분류에서 도출)

최종 사용자 A에게: "Downloads에 948개가 있었는데 도구는 500개만 보여준다"는 상태는 **검색 결과를 신뢰할 수 없다**는 뜻이다. 어떤 성능 개선보다 우선한다.

| # | 이상 상태 | 현재 | 이유 |
|---|---|---|---|
| I14 | 추출 경로 길이에 무관하게 모든 할당 파일이 추출된다. | 경로 ≥ 260자 **7,987건 콘텐츠 손실** (`Error Creating File`) | Windows MAX_PATH. tsk_recover(4.15 win32)는 `\\?\` 접두사를 쓰지 않는다 |
| I15 | 0바이트 파일도 files 인덱스에 존재·타임스탬프와 함께 기록된다(`deletion_state=allocated, size=0`). | 23,997건이 추출 트리에 없어 인덱스에서 소실 | tsk_recover 설계. 존재 자체가 증거(예: 삭제 전 생성된 로그) |
| I16 | 커버리지 비교는 **inode(MFT ref) 기준**으로 수행되어 fls 출력 인코딩에 영향받지 않는다. 한글 파일명은 이미 원본 이름대로 추출됨(검증: Downloads 500=500, Screenshots 194=194). | fls 목록 mojibake로 경로 문자열 비교가 5,881건 + 한글 디렉터리 하위 ~3,200건을 거짓 결손으로 보고 | 커버리지 수치의 신뢰성. 보고서 수치가 틀리면 분석관이 엉뚱한 곳을 의심한다 |
| I17 | ADS는 `파일경로:스트림명` 레코드로 인덱스에 등록되고 Zone.Identifier는 다운로드 출처 아티팩트로 파싱된다. | 1,822건 미추출 | 다운로드 출처(URL) 증거 |

### 구현
- **P14 (I14)** 추출 경로 단축 + 긴 경로 폴백: (a) 추출 루트를 짧게(`<output>\_e01\fs`), (b) tsk_recover stderr를 **전체 파일로 저장**하고 `Error Creating File`/`Error writing file` 라인을 파싱해 실패 inode·경로 목록 `extraction-failures.json` 생성, (c) 실패 항목을 `icat -o <off> <image> <inode>`로 `_e01\long\<inode>.bin`에 개별 복구하고 원 경로 매핑을 `long-path-map.json`에 기록, files 인덱스는 원 경로를 표시. 장기적으로는 3단계(이미지 직접 읽기)에서 소멸.
- **P15 (I15)** `fls -rp` 결과(또는 native MFT 워크)의 0바이트 할당 파일을 files 인덱스에 `source=mft-listing, size=0` 후보로 추가. 추출 트리 스캔과 병합 시 경로 중복 제거.
- **P16 (I16)** `scripts/fls-coverage-diff.py`를 inode 기준 비교로 변경: `fls -rp` 대신 `fls -rpl`(long: inode+크기+시각)을 UTF-8로 받고(`tsk` win32는 콘솔 코드페이지를 깨뜨리므로 `fls -rp` 출력을 `-o`로 파일에 직접 쓰거나 `PYTHONUTF8`/`chcp 65001` 환경에서 실행 — 어느 쪽이 올바른 UTF-8을 내는지 먼저 10개 한글 경로로 검증), 추출 매니페스트에는 `tsk_recover` 직후 `fls -rpl` 매핑으로 각 경로의 inode를 부여. 결손은 inode 집합 차로 계산하고 ADS(`:stream`)와 0바이트(`$DATA` 크기 0)를 분모에서 분리해 **(a) 콘텐츠 보유 파일 커버리지, (b) 0바이트 등재율, (c) ADS 등재율** 세 수치를 보고. 0바이트 판정은 `$FILE_NAME` `Size:`가 아니라 `$DATA` 속성 크기를 쓴다(보고서 §6-A-1의 오판 재발 방지).
- **P17 (I17)** `tsk_recover`가 못 쓰는 ADS를 `fls` 목록의 `:stream` 항목에서 `icat`으로 개별 복구(Zone.Identifier 우선, 크기 상한 1 MB).

### QA
| # | 시나리오 | 합격 |
|---|---|---|
| Q18 | BSH 재추출 후 inode 기준 커버리지 | 할당 regular 파일 중 콘텐츠 보유(`$DATA`>0) 항목 **100% 복구**(long-path 폴백 포함), 0바이트 항목 100% 인덱스 등재, ADS Zone.Identifier 100% |
| Q19 | `Users/user/Downloads` 디렉터리 | 인덱스 행 수 = fls 할당 regular 500 + ADS 행 448 (fls 948은 ADS 포함 수치) |

### 8-A. 3차 결과 (2026-10-09, Opus #2 구현 · Fable 검증)

- 테스트: `tests/test_rapidtriage_extraction_gaps.py` 17건 신규, 전체 suite 1210 OK (Opus 실행), 3차 모듈 Fable 재실행 OK. ruff/vulture/compileall clean.
- **long-path 폴백 검증**: 7,979 대상 중 첫 200건 `icat` 복구 → 200/200, 12,934,364 B, 크기 전부 목록과 일치. Fable이 inode 517676·287148·377831을 **독립 `icat`으로 재계산한 sha256이 복구 파일과 3/3 일치**. 전체 1.31 GB, 4워커 기준 ~15분 예상.
- **inode 기준 커버리지(P16)**: (a) 콘텐츠 보유 할당 **589,918 / 597,919 = 98.66%** (unique inode 98.50%), 결손 8,001행 = long-path 클래스 → 폴백 적용 시 100% 예상; (b) 0바이트 등재 2 / 23,988 (P15 전); (c) ADS 등재 0 / 1,825 (P17 전, Zone.Identifier 1,563). 매칭: path-exact 589,925 / wildcard 2 / parent-size 4.
- **발견**: fls 출력은 mojibake가 아니라 **CP949 ANSI 출력**. cp949로 8,112/8,116 비ASCII 행이 정상 디코드(손실 2행). `name_hint`로 보존, 식별은 inode+size.
- 한계(명시): files.json은 여전히 카테고리 필터를 적용하므로 sidecar 행(0바이트·long-path·ADS)도 카테고리 매칭 시에만 노출 — "모든 파일 인덱스"는 4차(인덱스 우선 설계) 범위. 구 체크포인트 resume 시 stderr 2000자 preview만 사용 가능.
- Q18(전체 이미지 재추출)·Q20(한글 검색)은 미실행. **Q20 선결 과제**: 저장소에 `unicodedata` 사용이 여전히 0건 → NFC/casefold 정규화(원 리뷰 High #14)를 P22로 추가.
| Q20 | 한글 파일명 검색 | `진정서` 키워드로 Downloads의 해당 PDF가 검색됨 (NFC 정규화 포함) |

## 6. 검증 절차

1. Opus(high) 구현 → 본인 테스트 실행 → 변경 요약 보고.
2. Fable: Q1–Q9 직접 실행. Q10 브라우저 확인. 불일치 항목은 §2와 1:1 대조하여 미달 목록 작성 → 재구현 지시. 전부 일치할 때까지 반복.
3. 사용자: Q11 실행.
