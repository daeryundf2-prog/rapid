# R8 벤치마크와 복구율 측정 실행서

근거: `feat/r8-overhaul` 브랜치 커밋(`081c97a..HEAD`), `scripts/r8-bench.py`, `scripts/r8-recovery-diff.py`, `scripts/r8-plan-timing.py`.
복구 모드 동작은 `docs/r8-recovery-mode.md`에 따로 정리했다.

이 문서는 **엔지니어링 측정 절차**다. 릴리스 증거가 아니며, 산출물은 Git에 넣지 않는다.

---

## 0. 공통 규칙

| 규칙 | 내용 |
|---|---|
| 읽기 전용 | 세 스크립트 모두 증거 이미지를 읽기만 한다. `r8-bench.py`는 실행 전후로 모든 세그먼트(E01..E99)의 크기와 mtime을 비교하고, 하나라도 바뀌면 종료 코드 3을 낸다. |
| 개수만 기록 | 출력 JSON에는 개수, 시간, coverage만 남는다. 증거 파일 이름, 경로, 내용은 기록하지 않는다. 이미지는 경로 해시(`image_set_id`, 12자리)로만 구분한다. |
| 산출물 위치 | `--out-root`, `--output`, 임시 디렉터리는 모두 Git 밖에 둔다. 측정 결과 파일은 **절대 커밋하지 않는다**. |
| 동일 조건 | baseline과 after는 같은 이미지, 같은 `--mode`, 같은 `--extra-run-args`, 같은 환경 변수, 같은 하드웨어에서 잰다. |
| 디스크 배치 | 증거와 출력이 같은 회전식 디스크에 있으면 처리량이 디스크에 묶인다. 가능하면 출력은 다른 디스크(SSD)에 둔다. baseline과 after의 배치는 같아야 한다. |

- 불변성 검사는 실행 전후 세그먼트(`.E01`, `.Ex01`, `.EAA`, `.ExAA` 계열 포함)의 크기와 mtime만 비교하며 해시는 계산하지 않는다. `r8-bench-run.log`에는 rapidtriage 표준 출력이 그대로 담겨 증거 경로가 들어갈 수 있으므로, 이 로그는 `--out-root` 아래에만 두고 Git 밖에 둔다.

---

## 1. `scripts/r8-bench.py`: 한 번의 실행 벤치마크

`rapidtriage run <image> --mode <mode> --read-only --output-dir <dir>`를 한 번 돌리고 결과를 `<out-root>/<label>/<image_set_id>/r8-bench.json`(스키마 `r8-bench-v1`)으로 남긴다. 실행 로그는 같은 폴더의 `r8-bench-run.log`에 쌓인다.

```powershell
python scripts/r8-bench.py --image <E01 첫 세그먼트> --label baseline --out-root <Git 밖 출력 루트> --rapid-root <baseline 체크아웃>
python scripts/r8-bench.py --image <E01 첫 세그먼트> --label after --out-root <Git 밖 출력 루트>
```

| 플래그 | 의미 |
|---|---|
| `--image` | E01 첫 세그먼트 경로 (필수) |
| `--label` | 실행 이름, 예: `baseline`, `after` (필수) |
| `--out-root` | 출력 루트, Git 밖 (필수) |
| `--mode` | `rapidtriage run` 모드. 기본값 `recovery` |
| `--rapid-root` | 실행할 rapidtriage 체크아웃. 하위 프로세스의 cwd가 되므로 baseline 체크아웃을 따로 지정할 수 있다. 기본값은 스크립트가 들어 있는 저장소 |
| `--extra-run-args` | `rapidtriage run`에 그대로 넘길 추가 인자 (문자열 하나) |

종료 코드: 세그먼트가 바뀌면 3, 그 밖에는 `rapidtriage run`의 종료 코드를 그대로 돌려준다.

### JSON 필드

| 필드 | 의미 |
|---|---|
| `schema` | `r8-bench-v1` |
| `label` | `--label` 값 |
| `image_set_id` | 이미지 경로의 SHA-256 앞 12자리. 이름 대신 쓰는 식별자 |
| `mode` | 실행 모드 |
| `code_rev` | `--rapid-root`의 짧은 커밋 해시. git이 없으면 `null` |
| `run_exit_code` | `rapidtriage run` 종료 코드 |
| `wall_s` | 실행 전체 벽시계 시간(초) |
| `peak_rss_mb` | 2초 간격으로 잰 프로세스 트리(자식 포함) RSS 최댓값(MB). psutil이 없으면 `null` |
| `cpu_count` | 논리 CPU 수 |
| `system_cpu_mean` | 실행 동안 시스템 CPU 사용률 평균(%). psutil이 없으면 `null` |
| `stages` | 단계 이름별 완료 시점. 실행 시작부터 각 단계 출력 파일이 마지막으로 쓰인 시각까지의 초. 단계별 소요 시간이 아니라 **누적 오프셋**이다 |
| `provider_ms` | 아티팩트 스케줄러 단계별 provider 소요 시간 합계(ms) |
| `counts` | run summary의 `*_count` 값과 `counts` 묶음 |
| `coverage` | run summary의 coverage 목록 (상한, 건너뛴 파티션, 지원하지 않는 파일시스템) |
| `segment_count` | 확인한 세그먼트 수 |
| `segments_unchanged` | 실행 전후 크기와 mtime이 모두 같으면 `true` |

---

## 2. `scripts/r8-recovery-diff.py`: 기준 도구 대비 복구율

pyewf와 pytsk3로 이미지의 **모든 파티션**을 직접 훑어 기준 목록을 만들고, rapid 실행 디렉터리의 추출 결과와 비교한다.

```powershell
python scripts/r8-recovery-diff.py --image <E01 첫 세그먼트> --run-dir <rapid 실행 디렉터리> --output <Git 밖>\recovery-diff.json
```

| 플래그 | 의미 |
|---|---|
| `--image` | E01 첫 세그먼트 (필수) |
| `--run-dir` | rapid 실행 또는 추출 디렉터리 (필수) |
| `--max-entries` | 파티션마다 파일 항목 N개에서 탐색을 멈춘다. 빠른 확인용이며 R8 판정에는 쓰지 않는다 |
| `--output` | 결과 JSON 경로 (필수) |

종료 코드: 모든 파티션의 `status`가 `ok`면 0, 하나라도 아니면 2.

### 대조 방식

- **할당 파일**은 경로로 맞춘다.
- **삭제 파일**은 MFT 레코드 번호(다른 파일시스템은 inode 주소)로 맞춘다. rapid는 삭제 항목을 `_deleted_mft/<주소>-<이름>` 또는 `_deleted/.../<주소>-<이름>`으로 쓰기 때문에 경로로는 맞출 수 없다.
- **NTFS 삭제 기준**은 디렉터리 탐색 결과와 MFT 레코드 전수 검사(ils와 같은 방식)의 합집합이다. 실제 볼륨에서 TSK가 `$OrphanFiles`를 열지 못하는 경우가 있어서, 디렉터리 탐색만으로는 부모가 사라진 삭제 파일을 놓친다.
- 메타데이터가 이미 사라져 이름만 남은 삭제 항목은 `ref_deleted_name_only`로 따로 세고 재현율 분모에서 뺀다. 어떤 도구도 그 내용을 복구할 수 없기 때문이다.

### JSON 필드

최상위:

| 필드 | 의미 |
|---|---|
| `schema_version` | 출력 스키마 버전 |
| `release_evidence_status` | 항상 `engineering_check_only` |
| `max_entries` | `--max-entries` 값 (없으면 `null`) |
| `rapid_files` | rapid 쪽 파일 수 |
| `partitions` | 파티션별 결과 목록 |

파티션 항목:

| 필드 | 의미 |
|---|---|
| `status` | `ok`면 정상 비교. 그 밖의 값은 열지 못했거나 지원하지 않는 파티션 |
| `fs_type` | 파일시스템 종류 (예: `ntfs`) |
| `deleted_reference` | 삭제 기준을 만든 방식. NTFS는 `directory-walk+mft-scan`, 그 밖에는 `directory-walk` |
| `ref_allocated` | 기준 도구가 찾은 할당 파일 수 |
| `ref_deleted` | 기준 도구가 찾은, 메타데이터가 남아 있는 삭제 파일 수 |
| `ref_deleted_name_only` | 이름만 남은 삭제 항목 수 (분모 제외) |
| `rapid_allocated_matched` | rapid가 맞춘 할당 파일 수 |
| `rapid_deleted_matched` | rapid가 맞춘 삭제 파일 수 |
| `allocated_recall` | `rapid_allocated_matched / ref_allocated` |
| `deleted_recall` | `rapid_deleted_matched / ref_deleted` |
| `rapid_only` | 기준 목록에 없고 rapid에만 있는 항목 수 |

---

## 3. `scripts/r8-plan-timing.py`: NTFS 계획 처리량

NTFS 파티션 하나에서 추출 계획 단계의 처리량을 잰다. `local-mft`는 `$MFT`를 로컬 파일로 한 번 순차 복사한 뒤 그 사본에서 레코드를 읽고, `ewf`는 예전처럼 pyewf로 레코드를 무작위로 읽는다.

```powershell
python scripts/r8-plan-timing.py --image <E01 첫 세그먼트> --start-sector <파티션 시작 섹터> --mode ewf --seconds 120
python scripts/r8-plan-timing.py --image <E01 첫 세그먼트> --start-sector <파티션 시작 섹터> --mode local-mft --seconds 120
```

| 플래그 | 의미 |
|---|---|
| `--image` | E01 첫 세그먼트 (필수) |
| `--start-sector` | 대상 NTFS 파티션의 시작 섹터 (필수) |
| `--seconds` | 측정 시간 제한(초) |
| `--mode` | `local-mft` 또는 `ewf` (필수) |

출력은 개수와 초만 담는다. `local-mft` 모드는 `mft_bytes`(사본 크기)와 `copy_seconds`(복사 시간)를 함께 보고하므로, 복사 비용을 포함한 처리량과 뺀 처리량을 둘 다 계산할 수 있다. `$MFT` 사본은 임시 파일로 만들고 종료할 때 지운다. 위치를 정하려면 `TMPDIR`, `TEMP`, `TMP` 중 하나를 Git 밖 작업 폴더로 지정한다.

---

## 4. R8 판정 기준 (PASS)

| 지표 | 기준 |
|---|---|
| `allocated_recall` | 지원하는 파티션마다 **0.995 이상** |
| `deleted_recall` | baseline 이상이면서 **0.95 이상** |
| `wall_s` | 같은 플래그로 잰 baseline의 **0.60배 이하** |
| `segments_unchanged` | 모든 실행에서 `true` (종료 코드 3이 한 번이라도 나오면 실패) |

`wall_s` 개선을 설명할 때 파서 프로세스 풀을 근거로 들지 않는다. EVTX, 레지스트리, ESE 파서를 프로세스 풀에서 돌리는 방안은 검토했지만 출시하지 않았다. run plan의 취소, 부분 결과 행, 실시간 행 카운터가 프로세스 경계를 넘지 못해 실제 실행(항상 run plan 사용)에서는 한 번도 쓰이지 않았기 때문이다. 그 코드가 들어 있던 커밋으로 잰 측정치가 있더라도 그 실행에서 풀은 돌지 않았다. 추출 단계가 파일을 쓰면서 계산한 해시는 실행 범위 다이제스트 캐시를 통해 수집기의 해시 계산에 재사용된다.

`--max-entries`를 준 diff 결과와 서로 다른 플래그로 잰 시간은 판정에 쓰지 않는다. 판정 대상 실행의 coverage 목록도 함께 확인한다. 복구 모드에서 상한이 걸린 항목이 남아 있으면 원인을 기록한다.

---

## 5. 측정 결과

R8 최종 측정 후 기입
