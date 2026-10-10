# RapidTriage (daeryundf2-prog/rapid) 전체 리뷰

- 대상: `b8376b1` (2026-10-08), Python ~218k LOC + React v2 UI + Rust 스캐너
- 방법: 5개 관점(증거 무결성 / Windows 파서 / API·보안 / 아키텍처·테스트·문서 / 모바일·메신저·클라우드·분석)으로 코드 직독 + ruff/vulture/pip-audit 실행. 모든 High 이상 항목은 원본 라인을 직접 재확인했다.
- 실제 증거물 테스트는 사용자가 진행 중이므로 본 리뷰는 **정적 코드 리뷰**다.

## 0. 한 줄 요약

문서의 자기평가("AXIOM 대체 아님, commercial_grade_ready=false, 2차 도구 교차검증 필수")는 정확하다. 코드는 **"포맷 인식 + 부분 디코드 + 풍부한 검증 메타데이터"** 단계이며, 법정 제출용 결론을 이 도구 산출물만으로 내려서는 안 되는 구체적 이유가 아래 Critical/High 항목이다. 보안(웹/API)은 로컬 도구 기준으로 양호하다.

## 1. Critical / High (수정 우선순위 순)

| # | 심각도 | 위치 | 문제 | 수정 |
|---|---|---|---|---|
| 1 | **Critical** | `core/e01.py:25` (`tsk_recover -e`), `core/files.py:1440-1452` | `-e`는 allocated+unallocated를 한 트리로 덤프하는데, 이후 파일 스캔이 트리 전체를 `deletion_state="allocated", confidence="high"`로 기록. case DB `is_deleted=0`. **삭제 여부 진술 불가.** (Windows 수집기 `$I`/MFT/USN은 `CANDIDATE_KIND_DELETED_ENTRY`를 쓰지만 E01 메인 경로엔 전달 안 됨) | `tsk_recover`를 `-a`/unalloc 두 번 실행해 분리, 또는 `fls -rd` 결과로 매핑. `_deleted_mft/` 경로는 강제 deleted 라벨 |
| 2 | **Critical** | `core/e01.py:2613-2635`, `core/e01_hash.py:140-173` | 이미지 acquisition hash(E01 내장 MD5/SHA1) 검증 코드 없음(`ewfverify`/`pyewf.get_hash_value` 미호출; CLI는 ewfverify *출력 파일*만 입력받음). 128 MiB 초과 소스는 해시 자체를 `deferred-large-source`로 건너뜀 → 실제 E01은 사실상 항상 미해시 | pyewf `get_hash_value` vs 스트리밍 재계산 비교를 필수 게이트로. 대용량은 백그라운드 전체 해시 |
| 3 | High | `core/e01.py:364-394` | 세그먼트 탐색 정규식 `\.E\d{2}` → E99 이후 `.EAA`, `.EAB`… 누락. "coverage: all-discovered-segments"가 거짓이 됨 | `\.E[0-9A-Z]{2}` + libewf 순서 규칙, 또는 pyewf `glob` |
| 4 | High | `artifacts/windows/execution.py:998-1003` | ShimCache Win8/8.1 FILETIME 오프셋: 실제 `InsertFlags(4)+ShimFlags(4)+FILETIME(8)`인데 `+12/+16` 읽음 → Win8/8.1 `last_mod_date` 전부 오류 | `low=cursor+8, high=cursor+12` |
| 5 | High | `engines/rust/crates/rapidcore/src/evtx.rs:101-102,120-121`, `core/native_accel.py:120-121` | ElfFile minor/major를 38/40에서 읽음(스펙 36/38). ElfChnk last_record/free_space를 40/44에서 읽음(스펙 44/48) → allocation_status 오판. 테스트는 잘못된 정의에 맞춘 샘플이라 통과 | 오프셋 수정 + 실제 evtx 파일 fixture로 테스트 |
| 6 | High | `artifacts/windows/eventlog.py:4137-4141, 4289, 4936, 4869` | 레코드 로컬 BinXML 파서가 포맷과 불일치(name offset을 NameString으로 해석, 0x0C 다음 0xB0 기대). 청크 기반 디코더만 실제 동작하며 그것도 인라인 템플릿 판정 오류·`Data/@Name` 첫 값만 보존 | 실패가 `evtx_binxml_status`로 드러나는 점은 양호. 레코드 로컬 파서 재작성 또는 제거 |
| 7 | High | `artifacts/windows/registry.py:25,3541` | 하이브 워크가 `MAX_HIVE_CELL_RECORDS=500` → SOFTWARE 하이브(수십만 셀)의 선두 500셀만 트리화되는데 `registry-key-tree` 레코드는 완전해 보임. `parse_registry_nk_cell:3682`는 항상 latin-1(`KEY_COMP_NAME` 미확인) | 상한 제거·스트리밍, `flags & 0x20` 분기 |
| 8 | High | `artifacts/windows/prefetch.py:346,378` | MAM 해제가 Windows `ntdll.RtlDecompressBufferEx` 전용 → 비-Windows 호스트는 Win8+ 프리페치 전부 `inventory-only`. `declared_size`(공격자 제어 u32)로 즉시 버퍼 할당 → 조작 증거물 메모리 DoS | declared_size ≤ 64 MiB, 순수 Python/Rust LZXPRESS Huffman 구현 |
| 9 | High | `artifacts/generic.py:561,997,1149,1272`, `android.py:1392`, `mobile/collector.py:648,733,855`, `kakaotalk_windows.py:1038` | 원본 SQLite를 복사·`immutable=1` 없이 `mode=ro`로 직접 open → WAL DB에서 증거 폴더에 `-shm` 생성/핫저널 복구 가능. `core/sqlite_snapshot.py`라는 정석 구현이 있는데 일부만 사용 | 모두 `open_sqlite_snapshot`로 통일 |
| 10 | High | `core/audit_trail.py:952-987`, `core/case_db/database.py:329-375` | 감사 체인 해시가 export 시점에만 계산(자기참조 검증). `tool_version=""`이 모든 호출처 기본값, hostname/platform 미기록. `DROP TRIGGER` 후 변조 추적 불가 | insert 시 `previous_event_hash`/`event_hash` 저장, 버전·호스트·사용자 필수 |
| 11 | High | `core/e01_native.py:328-360`, `core/e01.py:2029-2135` | short read 후 partial 파일을 success로 집계, `errors>0`이어도 stage `completed` | partial-corrupt 레코드 + blocker |
| 12 | High | `artifacts/mobile/helpers.py:337-351`, `cloud.py:5070-5082`, `generic.py:1610-1623` | 자릿수 기반 epoch 추정 → Mac absolute(2001)/WebKit µs(1601)/FILETIME 무음 오변환, 범위 초과 시 예외 미포착으로 수집 전체 중단 | 소스/컬럼별 epoch 명시, `timestamp_kind` 기록 |
| 13 | High | `core/kakaotalk.py:4963-4985` | `openssl enc -K <hex> -iv <hex>` argv로 키 평문 노출(프로세스 목록·EDR 로그). 4 KiB 페이지당 1회 fork(100 MB = 25,600회) | `cryptography`/pycryptodome in-process AES, 루프 1회 |
| 14 | High | `rules.py:110-116,713-719`, `search.py:1430`; 저장소 전체 `unicodedata` 0건 | NFC/NFD·casefold 미적용 → macOS APFS/HFS+ NFD 한글 파일명·메시지가 NFC 키워드로 미검출 | 색인·질의 양쪽 `unicodedata.normalize("NFC", s).casefold()` |
| 15 | High | `core/cloud_api.py:24,699-704` | manifest 기반 generic 클라이언트가 POST 허용 + 재시도 시 body 재전송 → 계정 변경 가능, 읽기 전용 보증 없음 | 기본 GET-only, POST는 명시 플래그 |
| 16 | High (보안·설계) | `api/app/routes_runs.py:55-87`, `helpers.py:210-264` | 토큰 보유자는 `root="C:\"`로 run을 만든 뒤 `source-file?path=`로 호스트 전체 읽기, `output_dir`+`overwrite`로 임의 쓰기. `Path.cwd()`·`~/.rapidtriage`가 암묵 case-db 루트. `--allow-remote-without-auth`와 결합 시 LAN 전체 노출 | 서버측 evidence/output 루트 allowlist, non-loopback+no-auth 조합 코드 차단 |
| 17 | High (프로세스) | `core/commercial_readiness.py:1829-1895, 4063-4088`, `core/validation.py:63-68` | "90/100"은 `min(score, 90)` 하드캡, "usable" 게이트는 백로그 Markdown prose에 "cli/api/rows/output" 단어 존재 여부, "trusted tools"는 레포 자신이 생성한 manifest. 120/120은 JSON `status:"pass"`+파일 존재 확인뿐 | README 수치를 `internal-fixture / external-tool-diff / independent` 3등급으로 분리 표기 |

## 2. Medium (요약)

- **MFT**: 첫 16 MiB·5000 레코드만, `record_number = offset//1024`(4K 레코드 볼륨 오류), ATTRIBUTE_LIST 확장 미해석, `$I30` 파서 없음 → 삭제 파일명 복구 불가 (`filesystem.py:744,5230,5678`)
- **SRUM**: 자체 ESE 파서(`ese_native.py`)는 인상적이나 `SruDbIdMapTable` 조인 없음 → AppId/UserId 미해석, 페이지 체크섬 미검증
- **naive `datetime.now()` 33곳** (`audit.py:124`, `run/summary.py:155`, `timeline.py:82`…) + `timeline.py:483`의 naive→UTC 가정 → KST 환경에서 9시간 어긋남
- **timeline**: dedup·precision·confidence 없음, 비ISO 타임스탬프는 `-inf` 정렬 또는 삭제(`timeline.py:462-471`, `analysis.py:4172`)
- **extract.py:140-146**: 복사 후 원본만 해시, 복제본 검증 없음. case DB 임포트 시 재해시·실패 시 NULL 해시 무상태(`case_db/helpers.py:101-110`)
- **carving.py:681-687**: 할당 파일 내부 매치를 `unallocated-candidate`로 라벨
- **엔진 폴백 시 `extract_dir` 미정리** → native + tsk_recover 산출물 혼합 (`e01.py:1532,1601-1632`); 단일 파티션만 복구(`1823-1830`); ADS 미복구
- **reviewer attribution 자가 주장** + UPDATE로 덮어씀(`routes_case_db.py:154-172`, `database.py:926-947`) — 이력 테이블은 append-only라 흔적은 남음
- **증거 DB 테이블명 f-string 삽입** (`kakaotalk_macos.py:947`, `browser.py:6670`, `macos.py:430` 등) — 영향은 증거 DB 자체로 한정되나 증거 왜곡 가능
- **detect.py:110-121** 메신저 감지가 경로+셀 값 전체 substring(`timeline.db`→LINE)
- **kakaotalk_macos.py:800-803** 복호화 UUID를 *분석 장비*의 platform UUID에서 가져옴 → dead-image 분석 시 항상 오답
- **조용한 실패**: `macos.py:240,346,425` / `browser.py:6566,6657` DB 손상 → `[]`("기록 없음"처럼 보임); `mobile/loaders.py` 로드 실패 시 파일이 결과에서 증발
- `logging` 모듈 사용 0건 — 서버에서 파서 실패가 운영 로그로 남지 않음
- Windows에서 `process_bounds.py` RLIMIT 미적용, `MAX_IMAGE_PIXELS` 미조정
- 의존성 lock 파일 없음, CI pip-audit non-blocking

## 3. 실제 구현 vs 스캐폴딩 (아티팩트별 분류)

(a) 자체 바이너리 파서 / (b) 외부 도구·라이브러리 / (c) 메타·문자열 스캔 / (d) 없음

| 영역 | a | b | c / d |
|---|---|---|---|
| Windows | REGF(500셀 상한), LNK, Jump List CFB, ShellBags, Recycle Bin $I, MFT(16 MiB), USN v2-v4, Prefetch 헤더, ShimCache Win8/10, Amcache, UserAssist, BAM, SRUM ESE(raw), Chrome/Firefox History, EML/MBOX | Prefetch MAM(ntdll), EXIF(Pillow) | EVTX 레코드 BinXML(불일치), Rust EVTX, $LogFile, Windows Search EDB/Windows.db, Login Data/Cookies, SAM F/V native, PST/OST, **$I30 없음** |
| E01 | — | pyewf+dissect.ntfs / ewfmount+tsk_recover | acquisition hash 검증 없음 |
| 메신저 | KakaoTalk PC legacy EDB(OpenSSL) | KakaoTalk macOS(sqlcipher CLI) | WhatsApp/Telegram/Signal/LINE/WeChat/iMessage/Android KakaoTalk 전부 (c): 테이블명 인벤토리 또는 벤더 CSV/JSON 재정규화 |
| 모바일 | APK 인벤토리 | — | iOS Manifest.db(c, fileID→디스크 매핑 없음), Manifest.plist 암호화(d), ADB .ab(d), mmssms/contacts2/calllog(d) |
| 클라우드 | Takeout/iCloud/M365 export 파서 | generic urllib 클라이언트 | provider OAuth 없음 |
| 메모리 | — | — | Volatility *출력 파일* 재적재(실행 없음), raw strings 256 MiB |
| macOS/Linux | Safari/Quarantine/TCC/LaunchAgents, passwd/shell/ssh/auth/auditd/dpkg/cron/systemd | — | Unified Log/Spotlight/FSEvents 힌트만 |

코드 라인 비율 추정: 실제 파싱·수집·검색·API ≈ 55%, readiness/validation/manifest/plan **메타데이터 생성기 ≈ 45%** (`commercial_readiness.py` 5.1k, `forensic_accuracy.py` 2k줄 dict, `validation.py`, `cross_tool.py` 상수부, `messengers.py` 4.1k 전부 manifest 생성). 외부 ground truth로 검증된 비율은 0에 가깝다(문서도 인정).

## 4. 테스트 신뢰도

- 1,154 test 함수. 추정 (a) 실제 파싱 ≈ 40% / (b) 스키마·문서 계약(assertIn on markdown 172건) ≈ 40% / (c) 자기참조(상수 테이블이 자기 자신과 같은지, 점수 함수의 단조성) ≈ 20%.
- 진짜 바이너리 fixture는 `.lnk` 1, `places.sqlite` 1, `.pf` 1뿐. 나머지는 Python으로 손수 pack한 헤더 → **#5처럼 잘못된 오프셋 정의에 맞춘 fixture는 통과**한다.
- `docs/validation/known-answer-corpus/`는 스키마 문서만, corpus 데이터 없음. `tier0-basic`은 텍스트 파일.
- 권고: CFReDS/DFRWS/NIST CFTT 공개 이미지 1~2개 known-answer를 레포에 고정하고 EvtxECmd/RECmd/MFTECmd/PECmd 출력과 row diff.

## 5. 아키텍처

- `core → artifacts` 7건 + `core → api` 1건(`browser_stress.py:32`) 역방향 의존으로 레이어 경계 없음. `artifacts/__init__.py`가 7k줄 모듈 5개를 eager import(~60k줄).
- >3k줄 god-module 15개. 파서 파일 안에 디코더·메시지 카탈로그·report-manifest 생성이 공존(`eventlog.py` def 188개).
- 레거시 혼입: `dashcam_tools/`, `mac-clean.sh`, `hash_videos.py` 등이 wheel·엔트리포인트·keywords(`"dashcam"` 첫 항목)에 포함.
- Rust 엔진은 `scan_evtx` 1개 함수, maturin 미연동, 오프셋 버그 → 유지 가치 낮음.
- 두 UI(`/` vanilla 14개 js, `/v2` React) 병행 → XSS 회귀 면적 2배. 현재는 `escapeHtml` 일관 적용으로 방어됨.

## 6. 긍정적인 점 (유지할 것)

- 기본 127.0.0.1 바인딩, 토큰 헤더 인증 + `compare_digest`, Host/Origin 게이트, `resolve()+relative_to` 경로 confinement, `shell=True`/pickle/yaml.load/eval/extractall **0건**, SQL 파라미터화, 하드코딩 비밀 없음.
- `core/sqlite_snapshot.py`(WAL 복사 + fingerprint 비교)는 정석. 모든 파서가 이것을 쓰면 #9는 해결.
- 거의 모든 레코드에 `validation_required`/`commercial_grade_blockers`/`decode_status`를 붙여 "실패를 성공처럼 보이게 하는" 경우가 드물다(예외: #1, #7, #11).
- 외부 도구 없이 REGF/LNK/CFB/MFT/USN/ESE를 struct 파싱하는 시도 자체는 상당하다.
- `known-limitations.md`는 솔직하다.

## 7. 도구 실행 결과

- `ruff check`: import 정렬 2건 (`tests/test_rapidtriage_artifacts_cli.py` 등, `--fix` 가능)
- `vulture --min-confidence 80`: clean
- `pip-audit`: 프로젝트 의존성 취약점 없음 (venv `pip 24.2` 자체만 경고)
- `unittest discover` (Windows 11, Python 3.12.5, 1630s): **1154 tests, failures=2, skipped=15** — README "802 tests OK"는 stale.
  - 실패 2건 모두 `tests/test_rapidtriage_ntfs_metadata.py:162,186` — mmls 설명이 mojibake(`???s`)인 fixture에서 `selection_method == "fsstat-probe"`를 기대하지만 실제는 `"mmls-description"`. `select_mmls_filesystem`이 깨진 설명에서도 파티션을 고르도록 바뀐 뒤 테스트가 갱신되지 않은 것(`core/ntfs_metadata.py:190-209`). 선택된 `start_sector`(567296) 자체는 맞으므로 결과 오류는 아니지만, **fsstat/OEM-ID fallback 경로가 현재 어떤 테스트로도 실행되지 않는다** — E01 단일 파티션 선택 로직(Medium 항목)과 맞물리므로 fixture를 진짜 비매칭 문자열로 바꿔 fallback을 다시 커버할 것.

## 8. 권고 로드맵

1. **지금**: #4, #5 오프셋 수정(한 줄짜리), #3 정규식, #8 버퍼 상한, #9 snapshot 통일, #7 상한 제거, `datetime.now(timezone.utc)` 일괄 치환.
2. **다음 스프린트**: #1 allocated/deleted 분리, #2 acquisition hash 게이트, #10 감사 체인 insert-time 해시 + 버전/호스트, #11 partial 집계.
3. **구조**: README 수치를 증거 등급별로 재표기(#17), `commercial_readiness`→`backlog_tracker`로 개명, 120항목 테이블을 데이터 파일로 분리, `logging` 도입, dashcam/mac-clean 분리.
4. **검증**: 공개 코퍼스 known-answer + Zimmerman 도구 row diff를 CI에 고정. 사용자가 진행 중인 실제 테스트 결과가 나오면 #1/#2/#4/#5/#12부터 대조하는 것을 권한다.
