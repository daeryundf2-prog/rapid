# Windows 트리아지에서 먼저 Rust로 옮길 부분

**첫 이식 후보는 EVTX 청크의 BinXML 디코딩이다.** 500,025개 이벤트에서 여섯 의미 필드와 행 순서가 일치했고, Rust 출력을 Python으로 읽는 비용까지 포함해 39.60초가 6.71초로 줄었다. 기본 트리아지의 활성 경과 시간은 1,370.15초여서 이 구간만 옮길 때의 예상 절감은 약 2.4%다. 현 구조 스캐너는 정상 레코드 2,500개를 슬랙으로 분류했고, 기존 Rust 디코딩 행도 Python과 달라서 배포 승인 조건은 아직 충족하지 못했다.

## 측정 조건과 재현

CLI는 실행 모드를 요구한다. 이 측정은 전체 트리를 탐색하는 `fraud`를 선택했다. 읽기 전용 폴더 입력을 사용했고, 검색 DB 생성, 타임라인, 탐지 규칙과 파생 테이블은 기본 설정으로 실행했다. 입력 해제, 볼륨 마운트, 카빙 시간은 포함하지 않는다. 재시작 캐시를 사용하지 않고 매번 새 출력 디렉터리에 썼다.

측정 기준은 `50628c41`, macOS arm64, CPython 3.12.12, 최적화 빌드의 Rust 1.95다. 공유 머신의 파일 캐시를 비우지 않았다. CPU는 사용자 시간과 시스템 시간의 합이고 RSS는 운영체제가 자식 CLI 종료 시 보고한 최댓값이다. 실행 경과 시간은 프로세스 시작부터 종료까지이며 스레드별 프로파일은 별도로 수집했다. 동시 실행된 제공자 시간은 겹친다. [스레드 CPU 프로파일러 문서](https://github.com/sumerc/yappi)

| 합성 입력 | 전체 코퍼스 | 1% 교정 코퍼스 |
|---|---:|---:|
| EVTX 정상 / 슬랙 이벤트 | 500,000 / 25 | 5,000 / 1 |
| MFT 레코드 | 65,536 | 655 |
| USN V2 레코드 | 262,144 | 2,621 |
| 브라우저 방문 | 2,048 | 20 |

각 트리에는 체크섬이 있는 BinXML 로그, 추출 형태의 MFT와 USN 스트림, SYSTEM·SOFTWARE 하이브, 작은 SRUM 위치의 ESE 카탈로그, Firefox SQLite, Prefetch, LNK, OLE Jump List가 있다. ESE는 단순한 테스트 테이블 한 행만 포함한다. 정상 EVTX에는 두 이벤트 ID와 템플릿을 반복하므로 다양한 공급자의 템플릿 적중률은 달라질 수 있다. 코퍼스 10개 파일은 256,347,306바이트다. 이 파일을 담은 320 MiB FAT32 이미지에서 `fls -rp`로 경로를 찾고 각각 `icat`로 읽은 SHA-256이 트리와 모두 일치했다. 컨테이너는 NTFS 볼륨 손상을 재현하지 않는다.

체크아웃 루트에서 다음과 같이 실행한다. 기본 테스트 검색 대상 밖에 있는 도구이며, 이미지 생성에만 mtools가 필요하다. `python`에는 프로젝트와 테스트 의존성이 설치되어 있어야 한다. `--profile`은 선택 의존성 yappi를 사용한다. rustup 설치 환경에서는 사용할 도구체인의 실제 bin 디렉터리를 PATH 맨 앞에 두면 임시 HOME에서도 같은 컴파일러를 쓸 수 있다.

```sh
work=$(mktemp -d "$PWD/.perf.XXXXXX")
export HOME="$work/home" TMPDIR="$work/tmp"
mkdir -p "$HOME" "$TMPDIR"
df -g /
python tools/perf/make_corpus.py "$work/corpus" --image
python tools/perf/make_corpus.py "$work/pilot" --pilot
python tools/perf/profile_run.py "$work/corpus/tree" "$work/default"
python tools/perf/profile_run.py "$work/pilot/tree" "$work/profile" --profile
python -m pstats "$work/profile/threads.pstats"
```

`perf.json`에 wall, user, system, RSS 바이트, 종료 코드가 남는다. 단계 경과 시간은 `rapidtriage-run-progress.json`의 연속 완료 시각 차이, 제공자 시간·행 수는 `rapidtriage-parser-scheduler.json`의 events에서 확인한다. 완료 판정은 run summary의 plan outcome, case DB 상태, 격리된 파서 오류 수도 확인해야 한다.

## 기본 실행에서 소비된 시간

| 측정 단위 | 1% 교정 기본 실행 | 전체 코퍼스 기본 실행 |
|---|---:|---:|
| 전체 wall / CPU / peak RSS | 53.65초 / 37.97초 / 264.05 MiB | 1,903.39초 / 1,044.97초 / 1.73 GiB |
| 아티팩트 수집 (동시 실행) | 27.82초 | 860.40초 |
| 지표 추출 | 7.80초 | 196.76초 |
| DB 적재 | 6.97초 | 134.58초 |
| 타임라인 | 3.75초 | 103.59초 |
| 탐지 규칙 / 파생 테이블 | 3.61초 / 2.41초 | 41.96초 / 28.77초 |

| 제공자 | 교정 경과 초 / 산출 행 | 전체 입력 경과 초 / 산출 행 |
|---|---:|---:|
| Windows 파일시스템 | 27.71 / 3,279 | 201.25 / 10,003 |
| 이벤트 로그 | 14.73 / 5,003 | 860.29 / 500,027 |
| 브라우저 | 3.39 / 41 | 106.14 / 4,097 |
| 실행 아티팩트 (SRUM 포함) | 1.78 / 3 | 1.34 / 3 |
| 최근 파일 | 0.67 / 3 | 1.57 / 3 |
| 레지스트리 | 0.57 / 143 | 0.22 / 143 |
| Prefetch | 0.38 / 2 | 0.48 / 2 |

제공자 표는 같은 progress 기록의 시작~완료 기준이다. 전체 입력의 이벤트 로그는 기록된 1,393.54초에서 디스크 대기 533.25초를 뺐다. 파일시스템 10,003행에는 MFT 5,000개와 USN 5,000개가 포함된다.

전체 wall 1,903.39초에는 공유 볼륨 공간 회복을 기다리며 프로세스가 정지한 533.25초가 들어 있다. 이를 제외한 경과 시간은 **1,370.15초(22분 50초)**다. CPU는 사용자 969.31초와 시스템 75.67초다. 자식 PID와 종료 상태는 wait4로 확인했고, 공간 감시 주기 1초 이내의 종료 검출 오차가 있다. 첫 시도는 공간 하한 근처에서 중단돼 이 수치에서 제외했다.

기본 실행의 상위 세 단계는 아티팩트 수집 **860.40초(62.8%)**, 지표 추출 **196.76초(14.4%)**, DB 적재 **134.58초(9.8%)**였다. 30개 제공자가 완료됐고 격리 오류는 0개였다. 산출물 514,280행, 지표 2,081개, 타임라인 519,124행이다. SQLite를 읽기 전용으로 열어 event 519,124행과 artifact 516,361행(지표 포함)을 확인했다. 전체 산출물은 약 2.71 GB였다.

### 함수 단위 병목

교정 실행 CPU는 사용자 35.90초, 시스템 2.07초였다. 입력 10개에서 산출물 8,476행, 타임라인 8,975행이 생성됐고 DB와 실행 계획이 완료됐다. 30개 제공자 중 격리 오류는 0개였다. 같은 입력에 yappi 1.7.6을 붙이면 595.98초가 걸렸다. 아래 CPU 시간은 **계측 실행 안에서의 순위**로만 읽어야 한다.

| 순위 | 함수·작업 | 자체 CPU 초 | 하위 호출 포함 CPU 초 |
|---|---|---:|---:|
| 1 | JSON `_iterencode_dict` | 37.94 | 57.08 |
| 2 | 이벤트 문자열 마스킹 `redact_recovery_passwords_in` | 36.73 | 62.00 |
| 3 | 공통 필드 분리 `artifact_profiles._residue` | 19.47 | 53.87 |
| 4 | 필드 동일성 비교 `artifact_profiles._same` | 15.71 | 50.24 |
| 참고 | 지표에 사용할 스칼라 순회 `iter_scalar_contexts` | 6.91 | 20.51 |
| 참고 | BinXML `EvtxChunkDecoder.decode_record` | 0.11 | 9.43 |

누적 시간은 호출 관계가 겹친다. JSON 인코딩에는 분석 행과 진행상태 직렬화가 함께 잡힌다. `stream_artifact_collection`은 원시 JSONL을 기록한 뒤 두 번 읽어 공통 필드를 분리한다. 이 비용과 이벤트별 재귀 문자열 순회는 바이너리 디코더를 교체해도 남는다.

### 권장 이식 순서

1. **EVTX의 청크별 BinXML 디코딩을 첫 실험으로 선택한다.** 50만 건에서 의미 필드 전송까지 포함해 단축한 시간이 32.89초다. 이 절감량이 기본 실행에도 그대로 반영된다는 가정이면 1,370.15초에서 약 1,337초로, 약 2.4% 단축된다. 이식 범위는 원본 틱, 청크·레코드 오프셋과 복구 상태를 가진 배치다. 초기에는 Python이 검증, 인용, 마스킹과 최종 행 조립을 담당한다. 동일 코퍼스에서 디코더만 바꿨을 때의 전체 실행 개선량은 후속 측정 대상이다.
2. **EVTX 배치에서 마스킹과 공통 필드 분리를 차례로 평가한다.** 교정 코퍼스의 투영 전 이벤트 5,001행에서 마스킹 후보가 없는 경우 Python 순회는 1.864초, Rust 후보 순회와 Python 확인 루프는 0.232초였다. 같은 행을 프로세스 간에 JSON으로 주고받으면 6.491초로 느려졌다. 기존 마스커의 양성·경계 사례부터 통과시키고 디코더와 같은 프로세스에서 작업한다. 동일 전체 행의 정렬 키 JSON 직렬화는 Python 2.033초, serde_json 0.316초이고 네이티브 파싱에 0.883초가 더 들었다. `_residue`의 자료형 의미, 공통 필드·코드북 확장, 최종 인용을 포함한 완전한 행의 동등성까지 검증한다.
3. **지표 스캔은 트리 순회와 정규식 매칭을 묶어 시험한다.** 후보 매칭만 개선한 실측치는 아래 표와 같다. MFT/USN은 현재 기본 경로가 앞 16 MiB와 각 5,000행으로 제한되어 있어, 반복 파싱·행 보강 비용을 측정한 뒤 별도 작업으로 진행한다. 하이브·ESE·SQLite 자체의 이식은 더 큰 대표 입력에서 우선순위를 다시 정한다.

각 단계는 같은 입력·기본 옵션으로 wall, CPU, RSS를 다시 측정한다. 측정된 순차 구간의 비중이 f, 그 구간의 실효 배속이 s라면 예상 전체 배속은 `1 / (1 - f + f/s)`다. 제공자 실행은 겹치므로 후보 시간 전체를 f로 넣으면 절감량이 과대평가될 수 있다.

## 같은 바이트로 비교한 구현

| 비교 범위 | Python | Rust | 해석 |
|---|---:|---:|---|
| EVTX 구조 인덱스 500,025행 | 9.467초 | 1.621초 | 3회 중앙값의 비 5.84배. release 작업자 기동, JSON 전송과 Python 역직렬화 포함 |
| EVTX 6개 필드·순서 해시, 500,025행 | 39.60초 | 6.71초 | 1회. 같은 6개 값, 출력을 Python으로 읽고 해시하는 시간 포함. 5.90배 |
| EVTX BinXML → XML 500,025행 | 106.389초 | 0.643초 | Python 1회, evtx 3회 중앙값. 약 165배는 서로 다른 XML 렌더링·필드 추출 경계의 관측값 |
| MFT 첫 5,000개 슬롯 | 3.347초 | 0.0195초 | 16 MiB prefix에서 Python 상세 dict와 mft CLI JSONL을 비교한 3회 중앙값. 계보·검증 스키마가 다름 |
| USN 앞 5,000행 | 0.0933초 | 0.000772초 | 같은 479,968바이트를 메모리에서 파싱한 3회 중앙값. Rust 구조체의 전송·행 보강 비용 제외 |
| 지표 후보 정규식 3개 | 0.758초 | 0.148초 | 343,809개 스칼라에서 2,880개 순서·리터럴 일치. 3회 중앙값 5.11배. 필드 순회·분류·인용 제외 |
| Firefox SQLite 조회 3개 | 7.53 ms | 6.17 ms | 전량 입력의 6,144개 조회 행, 타입과 순서 해시 일치. 열린 연결에서 21회 중앙값. 제공자 106초 중 SQL만으로 절감된 시간은 약 1.35 ms |
| SQLite 이벤트 일괄 쓰기 + FTS 트리거 | 1.434초 | 1.180초 | 동일 SQLite 3.53.4, 이벤트 8,975행과 FTS 토큰 위치 318,040개 일치. 3회 시간 범위가 겹침 |
| 최종 JSONL 전체 디코딩 | 0.0376 / 0.3075초 | 0.0234 / 0.1903초 | 교정 코퍼스 EVTX 5,003행 / 파일시스템 3,279행 순. 각각 1.60 / 1.62배, 5회 중앙값 |

여섯 필드 실험은 ID 두 종류·공급자·채널·7자리 소수 초의 시스템 시각·Phase를 같은 JSON 배열로 직렬화해 전체 스트림 SHA-256을 계산했다. 양쪽 모두 `c58f77b2a990df3937934b6b1bd7b1f6617b612dc2f6a5d79478c8f238525604`다. 이 비교는 의미 필드 이식 가능성을 확인한다. 오프셋·인용·복구 플래그의 승인은 전체 행 시험으로 한다. 재현은 `evtx` 0.15.1의 CLI를 설치한 뒤 아래 명령을 쓴다.

```sh
python tools/perf/bench_binxml.py "$work/corpus/tree/Windows/System32/winevt/Logs/Application.evtx" --evtx-dump evtx_dump --expected 500025
```

구조 스캔은 Python을 먼저 실행해 Rust에 파일 캐시 이점이 있을 수 있다. `evtx_dump --recover-records --stop-after-one-error -t 1 -o xml --no-indent --dont-show-record-number`의 출력을 폐기했고 별도 CRC 검사·JSONL 실행에서 500,025행을 셌다. Python은 청크마다 `EvtxChunkDecoder.decode_record`와 `render_evtx_element_xml`을 호출해 271,402,470자를 생성했다. `mft_dump -o jsonl -r 0-4999`는 같은 슬롯을 읽었다. USN에서는 `parse_usn_record_scan`과 `ntfs_core::usn::parse_usn_journal`을 비교했다. JSONL 디코딩은 양쪽 모두 파일 전체를 읽고 중첩 객체를 만들었다. 호이스팅 전의 큰 임시 행, DB 쓰기, Python 객체로 되돌리는 비용은 별도다.

## 후보 크레이트와 적용 범위

2026-11-24에 확인한 발행 버전이다. 아래의 정확성 근거는 각 프로젝트의 시험 범위를 의미한다.

| 후보 | 라이선스·유지 상태 | 확인한 동작과 도입 위험 |
|---|---|---|
| evtx 0.15.1 | MIT OR Apache-2.0, 2026-11-01 발행 | BinXML, XML/JSON, 슬랙 복구 옵션. 중첩 이름 회귀 수정 이력이 있다. 정상 이벤트와 슬랙 중복 처리, 필드 순서, 100 ns를 대조해야 한다. [릴리스 기록](https://docs.rs/crate/evtx/0.15.1/source/CHANGELOG.md) |
| mft 0.10.0 | MIT OR Apache-2.0, 2026-11-06 발행 | 재사용된 부모 시퀀스 처리 수정으로 상류 시험 이미지 3개에서 삭제 경로의 43~99%가 바뀌었다. 삭제 상태·경로·ADS·fixup 결과를 대조한다. [릴리스 기록](https://docs.rs/crate/mft/0.10.0/source/CHANGELOG.md) |
| ntfs-core 0.10.0 | Apache-2.0, 2026-11-12 발행 | USN용 별도 후보. 상류 교차 파서 시험과 퍼징이 있다. 1970년 이전 FILETIME 변환의 손실을 막으려면 원시 틱을 보존해야 한다. [USN 구현](https://docs.rs/crate/ntfs-core/0.10.0/source/src/usn/record.rs) |
| notatin 1.0.1 | Apache-2.0, 2023-08-18 발행 | 로그 재생·삭제 키 복원·원본 오프셋, Windows/Linux 시험. 발행 간격과 로그 재생 기본값을 검토한다. 이 머신에서 reg_dump 빌드 실패로 속도 미측정. [크레이트 문서](https://docs.rs/crate/notatin/1.0.1) |
| libesedb 0.2.7 / ese-core 0.2.2 | LGPL-3.0-or-later (2025-09-10) / Apache-2.0 (2026-08-08) | 전자는 C 라이브러리 배포 검토가 필요하다. 후자는 초기 구현이며 WebCache 37개 컨테이너·360행 상호 검증과 퍼징을 보고한다. SRUM 필드나 복구 정확도는 별도 검증 대상이다. [libesedb](https://docs.rs/crate/libesedb/0.2.7) · [ese-core](https://docs.rs/crate/ese-core/0.2.2) |
| regex 1.13.2 | MIT OR Apache-2.0, 2026-11-18 발행 | 회귀 퍼징·단어 경계 시험이 있다. Python 정규식의 Unicode 경계·대소문자·문자 인덱스와 Rust의 UTF-8 바이트 인덱스를 대조한다. [시험 소스](https://docs.rs/crate/regex/1.13.2/source/tests/regression_fuzz.rs) |
| serde_json / rusqlite | MIT OR Apache-2.0 / MIT | JSONL 디코딩은 잠금 파일의 serde_json 1.0.149, 정렬 키 직렬화는 1.0.154(2026-10-11)로 측정했다. 스트림과 숫자 경계 회귀 시험이 있다. rusqlite 0.43.0은 2026-11-15 발행된 SQLite 바인딩이다. 번들 SQLite 버전·FTS 옵션·트랜잭션을 맞춰야 DB 경계를 비교할 수 있다. [serde_json 회귀 시험](https://docs.rs/crate/serde_json/1.0.154/source/tests/test.rs) · [rusqlite](https://docs.rs/crate/rusqlite/0.43.0) |

현재 `rapidcore`의 EVTX 인덱스는 오프셋·레코드 ID·FILETIME·할당 상태를 내보낸다. PyO3 또는 `rapid-worker evtx-scan`으로 호출할 수 있다. 기본 EVTX 수집기는 Python에서 BinXML을 디코딩하고, 의미 필드·인용·복구 상태를 조립한다. 현 Rust 작업자의 `parse --kind evtx-records`는 다른 행 계약을 사용한다. 작업자 패키징과 행 비교 기반이 이미 있으므로 첫 실험은 이 Rust 워크스페이스에서 한다. Go·Zig의 성능 순위는 측정하지 않았다.

## 차등 시험과 배포 승인

동일한 입력 경로와 파일 해시로 두 경로를 강제 실행한다. Rust 실패 시 Python으로 대체되는 일반 가속 브리지를 사용하면 두 번 모두 Python으로 통과할 수 있으므로 이 시험은 작업자 바이너리를 직접 실행한다. 일반 JSONL 비교에는 같은 논리 루트, 행 순서, 완전한 스키마로 내보낸 두 파일과 독립적으로 산출한 행 수가 필요하다.

```sh
export CARGO_TARGET_DIR="$work/target"
cargo build --locked --release --manifest-path engines/rust/Cargo.toml --bin rapid-worker
worker="$CARGO_TARGET_DIR/release/rapid-worker"
eventlog="$work/corpus/tree/Windows/System32/winevt/Logs/Application.evtx"
python tools/perf/stage_diff.py evtx-scan "$eventlog" --worker "$worker" --expected 500025 --expected-slack 25
python tools/perf/stage_diff.py evtx-full "$eventlog" --worker "$worker" --expected 502525
python tools/perf/stage_diff.py rows python-full.jsonl native-full.jsonl --expected 502525
python -m unittest discover -s tools/perf
python -m unittest discover -s tests
```

검출 사례가 두 가지 있다. 첫째, 2,500청크의 구조 인덱스는 순서와 메타데이터까지 **차이 0행**이었지만, 양쪽 모두 정상 497,500개와 슬랙 2,525개를 보고했다. 생성 정답은 정상 500,000개와 슬랙 25개다. 두 구현이 청크의 여유 공간 시작을 바이트 44에서 읽으며, 이 입력의 마지막 레코드 위치는 44, 여유 공간 시작은 48에 저장된다. 청크마다 정상 행 하나가 슬랙으로 분류됐다. 독립 정답을 준 위 명령은 종료 코드 1이 정상이다. 둘째, 첫 청크로 구성한 단독 로그에서 전체 구조·디코딩 행은 202 대 202였지만 202행 모두 달랐다. 교정 로그 전체도 5,026 대 5,026행에서 다른 행 5,026개였다. 행 수만으로 이식을 승인할 수 없다.

승인 조건은 **전체 코퍼스에서 다른 행 0개, 독립 정답 일치, 기존 전체 테스트 통과**다. 이번 오프라인 Python 스위트는 2,673개 중 2,636개 통과, 실패 0개, 조건부 건너뜀 37개였다. 순서·중복·누락, 정수 FILETIME 한 틱, 타임스탬프 표현·정밀도, 복구 플래그와 그 타입, 원본 경로·해시·바이트 범위·중첩 인용을 비교한다. 잘린 결과, 빈 결과, 빠진 키를 허용하지 않는다. 일반 JSONL 비교에서는 양쪽에서 필드를 미리 제거한 입력을 판별할 수 없으므로 기준은 기존 Python의 완전한 출력이어야 한다. 수정된 샘플에는 알려진 중복·슬랙·잘린 청크·서로 다른 공급자 템플릿을 추가하고 외부 레퍼런스와 대조한다.

Windows에서 release 작업자와 설치 패키지를 빌드하고 깨끗한 환경에서 긴 경로·비ASCII 경로·종료 코드·표준 출력 인코딩을 확인한다. PyO3를 배포하면 지원 Python·CPU 조합별 로딩과 wheel 포함 파일을 점검한다. 작업자 실패·부재 시 기존 Python 동작과 실패 기록을 확인한다. 이 합성 자료는 엔지니어링 기준선이다. 출시 근거는 외부 Windows E01/Ex01, 참조 도구 대조, 실제 규모 측정과 검토 기록이 필요하다.
