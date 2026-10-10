# RapidTriage 성능·구조 리뷰 — BSH.E01 (135.6 GB) 런 8c821ed6a78d

날짜: 2026-10-09 · 대상 커밋: `b8376b1` · 장비: i7-11700 (8C/16T), 128 GB RAM, C: NVMe SSD 2 TB, **D: 7200rpm HDD 10 TB**

## 0. 결론 먼저

- 런은 **실패**했다. 42시간(2026-10-07 03:59Z → 10-08 21:38Z) 뒤 `Object of type bytes is not JSON serializable`로 triage 단계가 죽었고, persist(case DB) 단계는 실행되지 않아 **검색 가능한 산출물이 하나도 없다**.
- 42시간 중 **32.5시간이 "manifest" 단계** — 23개 아티팩트 provider를 **메인 스레드에서 순차 실행**하며, provider들이 646,661개 파일 트리를 **약 99번 반복 rglob + 정렬**하고 파일을 md5/sha1/sha256로 해시한 시간이다. E01 추출(tsk_recover) 7시간, docs 34분, files 1.6시간이 나머지다.
- 프로세스 `42652`는 RSS **27.5 GB**, CPU 누적 **114,640초(31.8 CPU-h)** — 2.6일 동안 평균 0.5코어만 사용. 16스레드·128 GB 장비에서 **단일 스레드 + 전부 메모리 상주 + JSON을 DB로 쓰는 설계**가 병목이다.
- **Python이 문제가 아니다.** Plaso, dissect, Velociraptor의 파서 상당수가 Python/Go이고 100 GB급 이미지를 수 시간에 처리한다. 문제는 (1) O(provider × 전체 트리) 반복 스캔, (2) 파일을 디스크로 전부 추출한 뒤 다시 읽는 2중 I/O, (3) 결과를 중첩 dict로 쌓아 7 GB JSON으로 직렬화, (4) 병렬성 부재, (5) HDD다. 이 다섯 가지는 언어와 무관하며 Rust로 다시 써도 같은 설계면 느리다.

## 1. 런 타임라인 재구성 (파일 mtime·job store 기준, KST)

| 구간 | 시작 → 끝 | 소요 | 근거 |
|---|---|---|---|
| E01 추출 (`mmls` + `tsk_recover -e`, 646,661 파일, 135 GB → HDD) | 10-07 12:59 → 20:03 | **7.1 h** | `_e01/rapidtriage-e01-stage-status.json` mtime |
| fingerprint (전체 트리 stat) | 20:03 → ? | 포함 | `rapidtriage-run-fingerprint.json` 20:03 |
| **manifest = 23 provider 순차 수집** | 20:03 → 10-09 04:28 | **32.4 h** | `rapidtriage-manifest.json` `generated_at` 04:28:41 |
| docs (43,604 문서 텍스트 추출 + 역색인) | 04:28 → 05:02 | 0.6 h | `rapidtriage-docs-index.json` `generated_at` 05:02 |
| files (category 스캔 + signature + duplicate) | 05:02 → 06:38 | 1.6 h | job store `completed_at` 21:38Z |
| manifest JSON 직렬화 중 **crash** | 06:38 | — | 7.2 GB 파일이 `srum-schema-row` → `row_fields.IdBlob` (bytes)에서 끊김 |
| artifacts / timeline / indicators / summary / persist | 실행 안 됨 | — | `artifacts/` 디렉터리 없음, `files.json exists: False` |

## 2. 원인 (시간 기여도 순)

### 2.1 [최대] 23 provider × 전체 트리 반복 스캔, 단일 스레드 — `core/docs.py:115 build_manifest`

```python
for provider in all_providers():                       # 23개, 순차
    "artifacts": [item.to_dict() for item in collect_cached(provider, root)]
```

- 각 provider의 `collect()`는 `sorted(iter_evidence_paths(root, "*"), key=lambda p: str(p).lower())`를 호출한다 — **전체 646k 경로를 Path 객체로 materialize하고 소문자 문자열로 정렬**. 호출 지점이 **99곳** (`windows/system.py` 20곳, `execution.py` 7, `filesystem.py` 7, `browser.py` 6, `generic.py` 5 …). 한 provider 안에서도 함수마다 다시 걷는다.
- `collect_artifact_stages`(`run/__init__.py:1142`)에는 ThreadPool이 있지만 **manifest 단계가 먼저 같은 수집을 순차로 끝내 버리고 캐시(`collect_cached`)에 넣기 때문에 병렬 경로는 캐시 적중만 한다.** 즉 설계상 병렬 스케줄러는 이 런에서 한 번도 일을 안 했다.
- 240곳에서 `source_hashes`(md5+sha1+sha256, 파일 전체 읽기)를 계산한다. `hash_cache`는 프로세스 내 dict라 동일 파일 중복은 막지만, 서로 다른 파일 수십만 개를 HDD에서 다시 읽는 것은 막지 못한다.
- 측정(§5): 이 패턴 1회 = **148 s** (warm cache). 99회 ≈ **4.1 h가 walk만**이고, 나머지 ~28 h는 각 함수의 per-file `open()`/`stat()`/3중 hash/파싱이다.

### 2.2 [둘째] 2중 I/O: 이미지 → 디스크 추출 → 다시 읽기, 그것도 HDD

- `tsk_recover -e`로 135 GB를 D:(HDD)에 646k개 파일로 쓴 뒤(7 h), 모든 단계가 그 트리를 다시 읽는다. 작은 파일 수십만 개의 random read는 HDD에서 100~200 IOPS 수준이다.
- AXIOM/X-Ways는 이미지를 **직접** 읽고(MFT 1회 파싱 → 파일 레코드 테이블), 필요한 파일만 on-demand로 꺼낸다. 이 레포에도 `pyewf + dissect.ntfs` 네이티브 경로(`core/e01.py:170`, `e01_native.py`)가 있지만 역시 **전부 추출**하는 데 쓰인다.
- C: NVMe 2 TB는 비어 있다. 최소한 추출 트리와 output_dir은 SSD로 옮겨야 한다.

### 2.3 [셋째] 메모리 상주 + JSON-as-database

- `manifest_payload`(23 provider의 모든 artifact dict), `docs_payload`(43k 문서 전문 `text_by_path`), `postings`(23.3M term × 258M `{"document_id","count"}` dict), `files_payload`(모든 candidate dict)가 **동시에** 메모리에 있다 → RSS 27.5 GB. Python dict 1개 ≈ 200 B이므로 postings만 50 GB급 객체가 될 수 있다(GC 스캔 비용도 비례).
- 출력은 `json.dump(..., indent=2)` (`docs.py:461`). 7.2 GB manifest + 5.2 GB docs-index. **API는 `json.loads(path.read_text())`로 통째로 읽는다**(`api/app/*` 8곳, `core/json_stream.py` 스트리밍 로더 사용 0곳). 설령 런이 성공했어도 웹 UI는 이 파일을 열 수 없다.
- manifest와 artifacts/*.json은 **같은 데이터를 두 번** 쓴다(manifest = 23 provider artifact 전체 포함 + artifacts 단계가 kind별로 또 기록).
- 역색인을 JSON으로 만들 이유가 없다. `core/run/sqlite_fts.py`와 case DB FTS5가 이미 있다 — 그러나 persist 단계가 **triage가 다 끝난 뒤** JSON을 다시 읽어 DB에 넣는 구조라 42시간 뒤에나 검색이 가능해진다.

### 2.4 [넷째] 크래시 원인 — bytes가 JSON에 유입

- `artifacts/windows/execution.py:2726` `"row_fields": row` — ESE 네이티브 파서가 돌려준 raw 컬럼(`IdBlob` 등 binary)을 그대로 넣는다. `write_result`에 `default=` 핸들러가 없어 32시간짜리 결과가 직렬화 단계에서 전부 사라졌다.
- 구조적 교훈 두 가지: (a) **단계 산출물은 생성 즉시 스트리밍으로 써야**(JSONL/SQLite) 마지막 직렬화에서 전부 잃지 않는다; (b) `write_result`에 `default=_json_safe`(bytes → hex/base64, datetime → isoformat) + 각 provider 출력에 대한 "JSON-safe" 단위 테스트가 필요하다. 1154개 테스트가 이것을 못 잡은 이유는 SRUM fixture가 bytes 컬럼을 포함하지 않아서다.

### 2.5 [부수] 기타

- `prepare_run_input_root`가 **단일 파티션만** 복구(`e01.py:1823`) — BSH는 6개 파티션인데 3번째(218 GB NTFS)만 추출됐다. 다른 데이터 파티션이 있었다면 조용히 빠졌다.
- `build_run_input_fingerprint`가 또 한 번 전체 트리를 stat한다.
- 모니터(`monitor-run.py`)는 5분 폴링이라 문제를 1일 늦게 알았다. 단계별 진행률(처리 파일 수/초)이 없어 "느린 건지 죽은 건지"를 구분할 수 없었다.

## 3. 즉시 조치 (코드 변경 최소, 다음 런을 42 h → 수 시간으로)

1. **SSD 사용**: `output_dir`와 `_e01/filesystem`을 C: 아래로. 가장 싸고 효과 큰 변경.
2. **manifest 단계에서 artifact 수집 제거**: `build_manifest`는 provider 이름/지원 여부만 쓰고, 수집은 `collect_artifact_stages`(ThreadPool, `max_workers`)에만 맡긴다. 이것만으로 23 provider가 병렬이 된다(GIL이 있어도 I/O·hash·struct 파싱은 상당 부분 release됨; 더 나아가 `ProcessPoolExecutor`로 바꾸면 16코어 활용).
3. **트리 1회 walk → 공유 인벤토리**: 런 시작 시 `os.scandir` 기반으로 `(path, size, mtime, ext, name_lower)` 테이블을 한 번 만들어 SQLite(또는 메모리 리스트)에 넣고, 99곳의 `iter_evidence_paths(root, "*")`를 그 인벤토리 조회(`WHERE name_lower = ? / ext = ? / path LIKE ?`)로 바꾼다. 각 provider가 필요한 것은 "특정 이름/확장자/디렉터리의 파일"이지 전체 트리가 아니다.
4. **해시 정책**: provider가 모든 파일을 3중 해시하지 않도록 `source_hashes`를 sha256 단일 + 크기 상한(예: 256 MB) + 지연 계산(리뷰어가 항목을 열거나 export할 때)으로. NSRL 매칭이 필요하면 md5만.
5. **JSON-safe 직렬화**: `write_result(payload, path)`에 `default=` 추가 + `row_fields` 생성 시 bytes → `{"hex": ..., "utf16_preview": ...}` 변환. 테스트: 모든 provider 출력 dict를 `json.dumps`로 돌리는 계약 테스트 1개.
6. **단계별 즉시 기록**: 각 provider 결과를 `artifacts/<kind>.jsonl`로 완료 즉시 쓰고, manifest/summary는 요약만 담는다. 실패해도 완료된 provider 결과는 남는다.
7. **진행률**: provider별 `files_seen/sec`, 현재 경로를 stage-status에 30초마다 기록. `rapidtriage web`에서 그대로 표시.

위 1–3만 적용해도 manifest 32 h → 1–2 h 수준이 현실적이다(파일 수 646k, 병렬 8).

## 4. AXIOM형 목표를 위한 구조 제안

목표가 "E01 투입 → 파일시스템별 빠른 아티팩트/파일 인덱싱 → 즉시 검색 → 필요한 것만 리뷰·추출"이라면 현재의 "추출 → 전수 스캔 → JSON → 나중에 DB" 파이프라인을 뒤집어야 한다.

```
E01 (pyewf / libewf)                    ← 이미지 직접 읽기, 추출 없음
  └─ 파티션 열거 (mmls 또는 dissect.volume)   ← 모든 파티션
       └─ 파일시스템 워커 (dissect.ntfs / pytsk3)  ← MFT 1회 순회
            ├─ files 테이블 (SQLite, WAL)   path, mft_ref, size, SI/FN 시각, allocated/deleted, ads, ext, sig
            ├─ 라우팅: 경로/이름 규칙 → 아티팩트 큐  (NTUSER.DAT→registry, *.evtx→eventlog, *.pf→prefetch …)
            └─ 콘텐츠 큐: 문서/텍스트 → FTS5 (bounded), 이미지 → 썸네일/EXIF (지연)
  워커 풀 (ProcessPool N=코어수): 큐에서 (image, partition, mft_ref)를 받아 파서 실행 → artifacts 테이블에 행 단위 INSERT
  UI: SQLite를 바로 조회(페이지네이션, FTS5). 런 진행 중에도 검색 가능.
  리뷰/추출: 선택한 mft_ref만 이미지에서 on-demand로 읽어 해시 + 복사
```

핵심 원칙:

- **인덱스가 제품이다.** JSON 산출물은 export 형식이지 저장소가 아니다. SQLite(WAL) 하나가 run의 단일 진실이며, API·UI·보고서는 전부 이것을 읽는다. 지금의 case DB(FTS5, 트리거, 스키마 버전)는 이미 그 역할에 가깝다 — persist 단계를 "마지막"이 아니라 "처음"으로 옮기면 된다.
- **파일 추출은 하지 않는다.** MFT 레코드와 데이터 런을 알면 어떤 파일이든 이미지에서 바로 읽을 수 있다. 추출은 사용자가 선택한 항목에만. 이렇게 하면 §2.2의 7 h와 디스크 135 GB가 사라지고, 삭제 파일·ADS·allocated/deleted 구분(이전 리뷰 Critical #1)도 MFT 플래그에서 정확히 나온다.
- **스캔은 한 번, 파서는 라우팅으로.** provider가 트리를 걷는 대신, 인벤토리 워커가 파일을 보고 "이건 registry 파서에게" 식으로 보낸다. 99회 walk → 1회.
- **병렬은 프로세스 단위.** GIL 때문에 CPU-bound 파서(BinXML, ESE, 레지스트리)는 `ProcessPoolExecutor`. 각 워커는 자기 pyewf 핸들을 연다(핸들은 프로세스 간 공유 불가).
- **스트리밍·bounded 메모리.** 어떤 단계도 전체 결과를 리스트로 들고 있지 않는다. 역색인은 FTS5가 하고, duplicate 그룹은 `GROUP BY sha256` 쿼리로 한다.
- **Rust는 선택적 가속.** 측정 후 병목인 파서(예: EVTX BinXML, MFT)만 Rust로. 지금의 `rapidcore`는 함수 1개·maturin 미연동·오프셋 버그라 유지 가치가 낮다. `dissect.ntfs`, `python-evtx`/`evtx`(Rust 바인딩 `evtx` crate의 pyevtx-rs), `python-registry`, `libesedb-python` 같은 검증된 파서를 쓰는 편이 자체 struct 파싱보다 빠르고 정확하다.

규모 감각: 646k 파일 MFT 순회는 dissect.ntfs로 수 분, 아티팩트 파싱은 8 프로세스로 30분–1시간, 문서 FTS 색인(43k 문서)은 10–20분. 135 GB 이미지 전체를 한 번 순차 읽기(해시)는 HDD ~15분/SSD ~2분이다. **같은 작업을 현재 42 h가 아니라 1–2 h에 끝내는 것이 설계상 가능**하며, 그 다음에야 "정확도 검증"이 반복 가능해진다.

## 5. 측정값

- 전체 트리 1회 walk, 추출 트리 646,661 파일 / 725,814 엔트리, D: HDD, OS 캐시 warm 상태 (2026-10-09 측정):
  - `os.walk`: **86.2 s**
  - provider 패턴 `sorted(root.rglob("*"), key=lambda p: str(p).lower())`: **148.0 s**
  - → 호출 지점 99곳 × 148 s ≈ **4.1 h가 순수 트리 반복 walk**. cold cache(런 초반)에서는 이보다 길다. 인벤토리 1회 구축으로 대체하면 ~1.5분.
- 서버 프로세스: RSS 27.5 GB, CPU 114,640 s, 시작 10-07 12:59 KST.
- 산출물: `rapidtriage-manifest.json` 7,188,213,806 B(truncated/invalid), `rapidtriage-docs-index.json` 5,244,764,148 B (`term_count` 23,348,749, `token_occurrence_count` 258,033,984), `rapidtriage-e01.json` 1.5 MB.

## 6. 진행 중인 검증 작업에 대한 조언

- 지금 런(8c821ed6a78d)은 재시작해도 같은 경로를 밟는다. **재실행 전에 §3의 1·2·5를 먼저 적용**하라. 특히 5번 없이는 또 마지막에 죽는다.
- 검증 반복을 위해 **BSH 이미지에서 작은 서브셋**(예: `Windows\System32\config`, `winevt\Logs`, 사용자 프로필 1개)만 포함하는 E01을 FTK Imager로 만들어 10분 안에 끝나는 known-answer 런을 돌려라. 135 GB 전체는 성능 측정용으로만.
- `docs/validation/real-image-bsh-mft-parity-2026-10-06.md`의 MFT 파리티(99.9999%)와 fls 커버리지(94.57%)는 좋은 외부 기준점이다 — 새 구조에서도 같은 스크립트(`scripts/mft-reference-diff.py`, `fls-coverage-diff.py`)를 CI 수준으로 고정하라.
