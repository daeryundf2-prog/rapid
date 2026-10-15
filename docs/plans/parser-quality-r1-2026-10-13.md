# 파서 품질 1라운드 — 실데이터 적대적 리뷰 반영 (2026-10-13)

브랜치 `fix/parser-quality-r1`(P1 `5fd64d2` 위). 근거: 2026-10-13 적대적 리뷰 3건(Windows 시스템 / 앱·사용자 데이터 / 정리·통합), 실데이터 `C:\rapid-qa\bsh-subset`(런 `682636ce5605`), 독립 파서(python-evtx, regipy, pytsk3, olefile, 자체 바이트 파서)로 대조. 리뷰 스크립트: `C:\Users\HP\AppData\Local\Temp\claude\parse-review\{windows,apps,org}`.

## 1. 결론

모든 공급자가 `completed · parser_error_count 0`을 보고하지만, 그 뒤에는 (1) 공개되지 않은 상한, (2) 제공자를 무시한 이벤트 분류, (3) 잘못된 바이너리 오프셋, (4) 증거 복사본 mtime을 아티팩트 시각으로 쓰는 타임라인, (5) 경로 토큰 매칭으로 생긴 전량 오탐(클라우드·모바일), (6) 증거 SQLite를 `immutable` 없이 열어 사이드카를 쓸 수 있는 패턴이 있다. 법정 증언 자료로 쓸 수 없는 상태다.

## 2. 원칙 (이번 라운드 전체에 적용)

1. **증거를 건드리지 않는다**: 증거 SQLite는 `open_sqlite_snapshot` 또는 `immutable=1`로만 연다. 취득 시각 이후 host mtime을 가진 파일은 "취득 후 변경 의심"으로 표시한다.
2. **상한은 없애거나 공개한다**: 남는 상한은 `*_truncated`, 파일별 총계, `collection_status=partial`, 보고서·검증 이슈 노드에 기록. 새 캡 없음 원칙.
3. **복사본 mtime은 이벤트가 아니다**: 추출 사본의 host mtime은 `source_file_mtime`(취득 사본 시각)으로만 기록하고 타임라인에 넣지 않는다. 타임라인은 아티팩트 내부 시각만, 의미 라벨(created/modified/accessed/event/run/last_written)과 함께.
4. **분류는 (제공자, ID)·경로 세그먼트·구조 키로**: 전역 이벤트 ID 표, 절대 경로 부분 문자열, "name"/"message" 같은 범용 키로 분류하지 않는다.
5. **표준 라이브러리 네이티브**: 새 필수 의존성 없음. 선택 의존성은 `pyproject` extras + guarded import.
6. **테스트는 실패를 재현한 뒤 고친다**: 리뷰 스크립트의 ground truth 수치를 픽스처(합성 바이너리)로 옮겨 단위 테스트에 넣는다.

## 3. 작업 분할 (파일 소유, 병렬)

| 작업 | 소유 파일 | 항목 |
|---|---|---|
| **W1 eventlog** | `rapidtriage/artifacts/windows/eventlog.py`, `tests/test_parser_quality_eventlog.py` | EVTX 10k 캡 제거(청크 순회, 전수) · BinXML 템플릿+치환 배열 네이티브 디코딩 → EventData 이름 필드(TargetUserName, LogonType, IpAddress, SubjectUserName, NewProcessName, CommandLine, ServiceName, ImagePath…) · `user_name`을 EventData에서(Keywords 값 금지) · 로그온 세션은 (TargetUserName, LogonId) 기준 · 분류/탐지 표를 (provider, channel, EventID) 키로(104/1102는 Microsoft-Windows-Eventlog만, Sysmon은 Sysmon 채널만, RDP는 TerminalServices·RemoteConnectionManager만) · EventID 비어 있는 716건(Qualifiers 형태) · 슬랙/범위 밖 타임스탬프(1601 미만·현재+1일 초과) 제외 · 슬랙 복제 레코드는 별도 타입/카운트 · FILETIME 정수 변환(100ns 보존) |
| **W2 registry·계정·ShellBags·실행** | `registry.py`, `os_account.py`(해당 파일), `shellbags.py`, `execution.py`, `tests/test_parser_quality_registry.py` | 16MB/500셀 캡 제거, nk/vk 전수 walk(DRIVERS·ELAM·BBI 포함) · 네이티브 하이브 의미 추출: ComputerName, TimeZoneInformation(보고서 공개), USBSTOR+MountedDevices(`windows-mounted-device`), Services(`windows-service-config`), Run/RunOnce, WordWheelQuery, RecentDocs, TypedPaths, NetworkInterfaces · nk 이름 KEY_COMP_NAME 플래그 판단(한글) · 키 경로 "ROOT" 삽입 제거·일관화 · SAM F/V 디코딩(이름·RID·마지막 로그온·로그온 수·실패 수·암호 설정; 그룹 분리) · ShellBags: 디코더 우선, NTUSER Shell/ShellNoRoam 포함, 캡 제거, `Bags\*` 제외, 경로 복원 · 실행: 문자열 피벗 타입(`amcache-entry`/`shimcache-entry`/`bam-entry`) 제거 또는 `*-string-candidate`로 개명+severity 제거, UserAssist 알려진 폴더 GUID 해석, 레이아웃 라벨 |
| **W3 prefetch·LNK·JumpList·파일시스템·시스템** | `prefetch.py`, `recent_files.py`, `filesystem.py`, `system.py`, `remote_access.py`(해당), `tests/test_parser_quality_prefetch_lnk.py` | Prefetch 실행 횟수 오프셋(메트릭 오프셋 0x128→0xC8), 비-SCCA 내용 `prefetch-invalid-content`, 참조 경로 로드 순서 보존·길이 접두 제거·캡 공개, 볼륨 시리얼·생성 시각 · LNK VolumeID(시리얼·타입·라벨), UNC NetName 복원, Desktop·시작 메뉴 LNK 범위, 비-LNK 플래그 · DestList v3+ 트레일러 4바이트, entry id/pin 오프셋 0x58/0x6C, 호스트명 cp949@0x48, 접근 횟수 0x74, 캡 공개 · 서명 검사 전수(5,000 캡 제거), 확장자 없는 파일 제외, 진짜 불일치(JPEG 내용 .pf 등) 검출 · WER 타임라인 EventTime · 미니덤프 헤더(TimeDateStamp, PID, 예외 코드, 모듈) · 원격 접속 타임스탬프를 Prefetch 실행 시각으로, 중복 제거 · `system.py` naive 시각 `astimezone()` 제거(하이브 TZ 사용) |
| **W4 코어 정리** | `rapidtriage/core/{files.py,timeline.py,indicators.py,docs.py,silent_failure.py,run/steps.py,run/checkpoints.py,run/markdown.py,summary.py}`, `rapidtriage/api/app/tree.py`, `tests/test_parser_quality_core.py` | files: host mtime → `source_file_mtime`, 분류를 경로 세그먼트+확장자로(hwp/hwpx/cell/show/xls/doc 추가, "other" 범주, 제외 파일 공개), 삭제 플래그(NTFS 조인/`$SI`·`$FN` 시각 포함), 중복 그룹 캡 공개 · timeline: 타입별 명시 매핑(Prefetch 실행 8회, 레지스트리 last_written, LNK 대상 MAC, DestList, WER EventTime, Amcache), 일반 walker 제거, (source, ts, kind) 중복 제거, 참조 경로 이벤트 제거, 범위 필터, TZ 공개 · indicators: 증거 유래 필드만 스캔, IP 문맥 검증(버전 문자열 제외), 자체 해시 필드 제외, 총계·절단 공개, 노드명 "지표 후보", 규칙 0 적용 표시 · docs: HWP 5.0(OLE+zlib 레코드) / HWPX(zip XML) / OLE2 .doc·.xls 텍스트, PDF 네이티브(FlateDecode, Tj/TJ, ToUnicode CMap, 이미지 스트림 제외), 암호 문서 플래그, 바이너리 본문 금지, FTS trigram 토크나이저(가능 시) · silent_failure/steps: 캡·절단을 warning으로 승격, 무응답 verdict를 step 레벨에 반영 · 보고서: 누락 도구(yara/tesseract/sleuthkit), 캡, TZ, 취득 사본 시각 설명, "uncapped" 문구 제거 · 체크포인트 불일치 · 케이스 DB 연결 키(event.artifact_id/file_record_id, indexed_document.file_record_id, hash_record) · `tree.py` 그룹을 domains.ts와 일치 |
| **W5 앱 데이터** | `rapidtriage/core/sqlite_snapshot.py`, `artifacts/windows/browser.py`, `artifacts/cloud.py`, `artifacts/mobile/*`, `artifacts/media.py`, `artifacts/generic.py`, `artifacts/kakaotalk_windows.py`, `artifacts/memory.py`, `artifacts/synthetic_media.py`, `artifacts/android.py`(immutable), `tests/test_parser_quality_apps.py` | 저널 판정(매직 `d9d505f920a163d7`+레코드 수>0일 때만 hot), 스냅숏 실패는 parser_error, 프로필 `continue` 제거 · 브라우저 History/Downloads 행 전개(방문별), Cookies·Login Data(값 아님, 메타만)·Web Data·Bookmarks·Shortcuts·Top Sites·Sessions·Extensions(manifest/Secure Preferences) 파싱, 통합 타임라인 캡 제거, `browser-history` 타입 Edge/Chrome 포함 · 모든 증거 SQLite 열기 `immutable=1`(generic/android/mobile/kakaotalk) · cloud/mobile: 내보내기 루트 서명(Takeout `archive_browser.html`, M365 매니페스트, iOS `Manifest.db`, UFED/Cellebrite 매니페스트) 없으면 분류 금지, 브라우저 확장 트리 제외, 구조 키만 사용, unknown provider zip 미발행 · media: Exif 서브 IFD(DateTimeOriginal/Make/Model/Software), SEFT 트레일러 허용, 내용 기반 매직, jfif/heic/gif, 이미지 타임스탬프 필드, GPS ISO, MP4 ftyp/mvhd · generic: OLE2 요약 속성(.doc/.xls), 암호 문서 플래그, lastPrinted/revision/template 최상위, `.bin` LLM 오탐 제거, placeholder 행 제거, zip DOS 시각 로컬 표기, 잠금 파일 소유자 · kakaotalk: cp949 디코딩, 셀 경계 존중, 슬라이딩 중복 제거, 캡 공개 · memory: MDMP 스트림(시각·PID·예외·모듈), printf 템플릿·OID·ComSpec 오탐 제거 · synthetic_media 임포트 예외 보고 |

공통: 각 작업은 자기 테스트 파일만 추가한다. 공유 파일을 고쳐야 하면 소유자에게 메모(최종 보고에 기재). 한국어 메시지. LF. Python 3.11 호환.

## 4. 검증

1. 단위: 각 `tests/test_parser_quality_*.py`가 리뷰의 ground truth 수치를 합성 픽스처로 재현(예: 메트릭 오프셋 0x128 Prefetch의 run_count, DestList v3 2번째 엔트리 정렬, 16MB 초과 하이브 키 수, 0으로 채워진 저널, 제공자 다른 ID 104).
2. 통합: `python -m unittest discover -s tests` 전체, ruff/vulture/compileall/doc-refs/스냅샷/diff-check.
3. 실데이터 재실행: `rapidtriage run` → `C:\rapid-qa\run-subset8`, 리뷰 스크립트 재실행으로 수치 대조(이벤트 280,191 live, Prefetch run_count 417/417, DestList 4,693, ShellBags 1,381, SAM 6계정, USB 5, 브라우저 874/1,799/273, 클라우드·모바일 오탐 0, 지표 자체 해시 0, 타임라인 2026-10 사본 시각 0, `.hwp` 색인 416).
4. 적대적 리뷰 2차(읽기 전용) 후 잔여 수정.

## 5. 결과 기록

통합 2026-10-14(W1~W5 변경 위, 미커밋). "이후" 열은 각 워커가 `C:\rapid-qa\bsh-subset`(런 `682636ce5605`) 대조로 보고한 수치이며, 통합 단계에서 실데이터 재실행(§4.3 `run-subset8`)은 하지 않았다. "이전" 열은 §1 리뷰와 §3 작업표에 적힌 결함만 옮겼다(새로 잰 값 아님).

| 영역 | 항목 | 이전(리뷰 근거) | 이후(워커 보고) | 비고 |
|---|---|---|---|---|
| W1 EVTX | 수집 이벤트(live) | 파일당 10k 캡 | 281,519 | 계획 §4 목표 280,191보다 많음 — 슬랙 복제 레코드 분리·EventID(Qualifiers) 716건 포함 여부는 2차 리뷰에서 대조 |
| W1 EVTX | 4624 로그온 | 전역 ID 표 분류 | 1,877 | (provider, channel, EventID) 키 |
| W1 EVTX | 7045 서비스 설치 | 〃 | 340 | |
| W3 Prefetch | run_count 일치 | 메트릭 오프셋 0x128 오독 | 417/417 | |
| W3 JumpList | DestList 항목 | v3+ 트레일러·오프셋 오류 | 4,693 | |
| W2 ShellBags | 항목 | 캡·`Bags\*` 포함 | 1,381 | BagMRU 구조 디코드, NTUSER Shell/ShellNoRoam 포함 |
| W2 SAM | 계정 | F/V 미디코딩 | 6 | 그룹 분리 |
| W2 USB | 장치 | 문자열 피벗 | 5 | USBSTOR+MountedDevices |
| W2 레지스트리 | 키 수 | 16MB/500셀 캡 | 248,904 | nk/vk 전수 walk |
| W5 브라우저 | 방문/다운로드 등 | 프로필당 요약 1행 | 874 / 1,799 / 273 / 2,308 / 75 | 워커 보고 순서 그대로(§4 목표 874/1,799/273) |
| W5 클라우드 | 오탐 | 경로 토큰 매칭 전량 오탐 | 0 | 내보내기 루트 서명 필수 |
| W5 모바일 | 오탐 | 〃 | 0 | |
| W5 미디어 | DateTimeOriginal | Exif 서브 IFD 미해석 | 44/44 | |
| W4/W5 문서 | 문서 메타데이터 | — | 1,189 | OLE2 요약 속성 등 |
| W4 문서 | `.hwp` 텍스트 | 바이너리 본문 | 403/416 | 13건 미추출(암호·손상 여부 확인 필요) |
| W4 지표 | 자체 해시 지표 | 자체 해시 필드 스캔 | 0 | |
| W4 타임라인 | 취득 사본 시각 이벤트 | 1 | 목표 0 | 사본 mtime은 `source_file_mtime`만, 타임라인 제외 |

통합 검증(2026-10-14): `python -m unittest discover -s tests` 전체, ruff, vulture(80), compileall, `scripts/check-doc-refs.py`, `scripts/update-api-snapshot.py`(경로 변화 없음), `git diff --check`, 변경 파일 NUL/CRLF 검사. 출력 샘플 5종은 `scripts/update-output-samples.py`로 재생성(호스트 의존 값 `source_file_ctime`·호스트 속성은 테스트 정규화에서 마스킹).

API 계약(통합 단계): `/tree` kind 노드의 `collection_status`·`skip_reasons`·`skipped_row_count` 전달, 리뷰 docs 로케이터 `/candidates/<n>`, `/files` NTFS 조인에 `$SI`/`$FN` 시각·`is_deleted`·`attributes`, `/docs` `candidates` 페이지와 `matched` 필터(`matched=1` = 이전 `results`), `canonical_run_case`의 `legacy_run_case_ids()` 확인 — `docs/plans/analysis-workbench-p1-2026-10-12.md` §3.3, `tests/test_parser_quality_integration.py`.

남은 일:
- Prefetch 출력 크기(실데이터 약 1 GB): 참조 경로 전수 보존의 대가 — 행 분리 또는 별도 JSONL 필요.
- HEIF/HEIC EXIF: 박스 구조 해석 없이 스캔에 의존 — `iinf`/`iloc` 기반 Exif 항목 추출 필요.
- PDF CID 폰트(Type0, ToUnicode 없는 Identity-H): 텍스트 복원 불가 — 미추출로 공개만 함.
- 방화벽 이벤트 ID 2097/2099/2052: (provider, channel, EventID) 의미를 Microsoft 문서로 확인한 뒤 분류표 확정.
- 콘솔: `/docs` 기본 응답이 `candidates`로 바뀌었다. 프런트엔드 브랜치가 문서 그리드를 `candidates`·`/candidates/<n>` 로케이터로 옮기기 전까지, 현재 번들(`rapidtriage/web/static/v2`)의 문서 그리드는 `results`를 읽어 빈 목록을 보인다 — 프런트엔드 반영과 번들 재빌드가 필요하다(임시로는 `fetchDocsPage`·`getRunDocs`에 `&matched=1`).
- §4.3 실데이터 재실행과 §4.4 적대적 리뷰 2차.
- (r2, 미착수) 아티팩트 단계 병렬화: `rapidtriage/core/run/__init__.py`의 제공자 24개가 GIL 아래 스레드 8개로 실행되어 594초 단계에 스레드 시간 4,262초가 쌓였다. 제공자별 프로세스 풀이면 단계 시간을 가장 느린 제공자 수준으로 줄일 수 있으나(행 순서·ID 불변 필요), 위험 때문에 이번 라운드에서는 구현하지 않는다.

## 5b. 2·3라운드 결과 (2026-10-14, 브랜치 `fix/parser-quality-r2`, PR #9)

R2-A(아티팩트)·R2-B(코어·케이스 DB)·R2-C(성능) 변경 위에서 통합. 수치는 각 워커가 `C:\rapid-qa\bsh-subset` 실데이터 재실행으로 보고한 값이며, 통합 단계에서 다시 재지 않았다.

| 영역 | 항목 | 이전 | 이후 | 비고 |
|---|---|---|---|---|
| 타임라인 | 이벤트 수 | 345,198 | 323,245 | 중복 15,014→0, 링크 시각(link-time) 이벤트 2,004→0 |
| 타임라인 | 출력 크기 | 704 MB | 281 MB | |
| 지표 | 지표 후보 | 8,887(1,000 상한) | 4,293(상한 없음) | MD5 오탐 0 |
| 케이스 DB | `file_record` | 4,953 | 19,033 | files 출력 `inventory`(선택 범주 밖 파일 전부, "기타" 포함) 반영 |
| 케이스 DB | `hash_record` | 0 | 5,949 | |
| 케이스 DB | `event.file_record_id` 연결 | 4.3% | 100% | |
| 파일 | 서명 불일치(정렬된 검사) | 34 | 153 | 워커 보고 "aligned"(검사 모집단 정렬) |
| 문서 | 텍스트 추출 ok | 1,959 | 2,015 | |
| 문서 | "계약" 검색 재현율 | 31% | 100% | |
| 문서 | 소유자 암호 PDF 복호 | — | 6/14 | |
| 메모리 | IOC 오탐 | — | 0 | |
| USB | VID/PID 해석 | — | 5/5 | |
| Amcache | 새 테이블 | — | 6 | 장치 PnP·컨테이너·센서스 등(트리: devices/os) |
| LNK 추적 | 진료실1(cp949 머신 이름) | — | 3,068행 | `machine_id_encoding` 공개 |
| 카카오톡 | 메시지 / deviceinfo 오탐 | — | 146 / 0 | |
| EVTX 4104 | 스크립트 블록 무절단 | — | 407/407 | |
| EVTX Security | 오래된(stale) 레코드 라벨 | — | 39 | `stale_below_first_record_count` |
| 브라우저 | 자동 완성 값 마스킹 | — | 99.9% | |
| 미디어 | HEIC 크기 | 미해석 | 해석 | `irot` 회전은 미반영(아래) |
| 성능 | persist 단계 | 455 s / 5.54 GB | 200 s / 2.28 GB | 케이스 DB 일괄 적재(`case_db/bulk_import.py`) |
| 성능 | search-index | 11.7 s | 2.0 s | |
| 성능 | synthetic-media | 43.8 s | 14.7 s | |

통합 단계 변경:
- 출력 샘플: `manifest-windows-artifacts.json` 재생성. 불일치는 비결정적 순서가 아니었다 — 이전 샘플의 LNK `embedded_paths`에 두 StringData 문자열이 제어 문자(0x18)로 붙은 값(`...Case Notes.docx\u0018C:\Users\alice\Documents`)이 들어 있었고, R2-A가 경로 스캔을 제어 문자에서 끊도록 고쳐 두 경로로 나뉘었다(정렬된 집합이라 순서는 결정적). 그 밖에 `machine_id_encoding`, EVTX 절단 공개 필드(`text_truncated_*`, `payload_truncated_rows`, `triage_text_limits`), `stale_below_first_record_count` 추가.
- API `/files`: `scope=candidates|inventory`(기본 candidates), 두 scope 모두 `category` 필터, `candidate_count`/`inventory_count`(없으면 `null` + `inventory_note`), 고른 목록만 응답에 싣는다. NTFS 조인 뒤 `recovery.deletion_state`(inventory 행은 `deletion_state`)를 최종 `is_deleted`에 맞춘다(allocated/deleted/unknown만 갱신). `/tree` inventory 범주 노드("기타")에 `scope:"inventory"`. 계약은 `docs/plans/analysis-workbench-p1-2026-10-12.md` §3.3, 스키마는 `docs/rapidtriage-output-schemas.md` `files`, 테스트 `tests/test_parser_quality_integration.py`(`FilesInventoryScopeTests`, `test_join_keeps_deletion_state_in_step_with_is_deleted`). OpenAPI 스냅숏은 경로 변화 없음.

남은 일(2라운드 이후):
- 아티팩트 단계 제공자 프로세스 풀: 여전히 GIL 아래 스레드 8개(스레드 시간 4,262 s / 단계 594 s). 행 순서·ID 불변 조건으로 설계 필요.
- 미디어 엔트로피 계산: 최적화 효과가 작음 — 다른 접근 필요.
- 브라우저 확장: 43개 중 15개만 이름 해석(나머지는 manifest·Secure Preferences 등 원본 없음).
- KT PDF: ToUnicode 없는 폰트 — 텍스트 복원 불가, 미추출로 공개만.
- HEIC `irot`(회전) 미반영: 가로·세로가 회전 전 값.
- LNK UTF-16 한국어 경로 잘림: 일부 경로가 중간에서 끊긴다 — StringData/IDList 경로 디코드 재검토.
- 델타(차분) 파일의 경로 inventory: 아직 inventory에 들어가지 않는다.
- `/inventory/<n>` 로케이터의 검토 표시(review-batch/review-map) 해석: 케이스 DB가 후보와 경로가 겹치는 inventory 행을 건너뛰므로 순번이 아닌 경로 기준 해석이 필요하다(미구현).
- 콘솔: 파일 그리드가 inventory 노드(`scope:"inventory"`)를 `/files?scope=inventory`로 요청하도록 프런트엔드 반영 필요.

### 3라운드 (2026-10-14, 같은 브랜치, PR #9)

2라운드 결과를 실데이터로 다시 검토해 고쳤다. 수치는 `C:\rapid-qa\run-subset9` 출력과 `C:\rapid-qa\bsh-subset` 증거(읽기 전용)를 놓고 제공자·단계 함수를 직접 호출해 다시 쟀다. 측정 스크립트는 `parse-verify\r2\r3_*.py`이다. 테스트는 `tests/test_parser_quality_r3.py`의 18건이며, 모두 2라운드 코드에서 실패한다. 계약은 `docs/rapidtriage-output-schemas.md`의 "Parser-quality r3"에 정리했다.

| 영역 | 항목 | 2라운드 | 3라운드 | 비고 |
|---|---|---|---|---|
| 브라우저 | 자동 완성 값 마스킹(3,002행) | 1,748 (58.2%) | 3,002 (100.0%) | 2라운드 표의 "99.9%"는 실측이 아니었다. 명시 규칙과 자리표시자만으로 2,373건(79.0%)이 마스킹되고, 기본 마스킹(`form-input-default`)이 629건을 더한다. 규칙별: 이름 기반 1,139 · 비밀 199 · 값 패턴 224 · 한국인 이름 58 · 주민번호 조각 24 · Edge 자리표시자 729. |
| 브라우저 | 주소 필드(`TYPE_109` 포함) | 104/121 | 121/121 | |
| 타임라인 | Amcache 인벤토리 키 시각 이벤트 | 769 | 6 | 하이브·섹션당 1건씩(드라이버 435→1, PnP 161→1, 바로 가기 99→1, 컨테이너 32→1, 패키지 26→1, 센서스 16→1). `amcache-schema-row`(파일당 키, 2,588건)는 행별로 유지한다. |
| 타임라인 | 유효 범위 상한 | 실행 시작 + 1일(2026-10-15) | 취득 목록 + 1일(2026-10-10) | `max_basis: acquisition-listing + 1 day`. 지문(fingerprint)은 5,000개에서 잘렸지만 files 목록(19,033개)은 상한에 걸리지 않았다. 범위 밖으로 빠진 이벤트는 0건이다. |
| 지표 | 대소문자를 보존한 URL | 0 | 1,164 | `value_fold`로 중복을 제거한다. URL은 1,785개에서 1,784개가 됐다. |
| 지표 | 루프백·형식 오류 HTTP.sys URL | 6 | 0 | `url:malformed-netloc` / `url:loopback-host` |
| 지표 | MD5·SHA1 규칙 해시 매칭 | 불가(죽은 조건) | 가능 | |
| 아티팩트 ID | 행 위치 의존 | 의존 | 비의존 | browser·windows-execution·windows-registry 각 행 앞에 한 행을 끼워 넣어도 나머지 ID가 같았다. 접미사 충돌은 0건이고, 5만 행 기준 비용은 행당 약 60µs이다. |
| 보고서 | 검증 이슈 / 알림 | 20 / — | 9 / 11 | 알림(notice)은 `validation_notices`로 따로 센다. 행 문구에 단계 수준이 그대로 찍힌다. |
| 보고서 | 합성 미디어 문구 | "행 단위 절단 1행" | "후보 1104개 중 592개 파일 미선별 (파일 수 상한 512개)" | |
| 보고서 | 후보 파일 "modified=" 사본 시각 | 15행 | 0행 | "수정 시각: 취득 사본(원본 아님)"으로 바꾸고 atime 공개 줄을 넣었다. |
| 문서 | `.log` 바이너리 구제 | 26건 ok | 26건 binary-rejected | LevelDB `.log` 파일이다. 구제는 PDF·HWP·OLE·OOXML 추출기에만 적용한다. |
| 문서 | desktop.ini `noise_hint` | — | 18/20 | 나머지 2건은 `LocalizedFileNames`에 실제 powershell.exe가 있다. |
| EVTX | Servicing 2(Setup.evtx) 이름 미해석 | 89행 data_0..2·`_2` | 89행 `template-undecoded` | 템플릿의 이름 오프셋이 NameString 머리를 가리키지 않는다(재사용된 청크로 보임). 해시로 검증하는 근처 탐색은 다른 이름을 돌려줘서 쓰지 않았다. |
| 메모리 | `10.6.0.1`(vid&/pid& 옆) | IP 피벗 | 제외 | ASDSvc.exe.4564.dmp에서 `192.168.0.100`은 유지된다. |
| 스케줄러 | `worker_limit_source` | "min(4, …)"(값 8과 불일치) | "min(8, cpu_count=N, scheduled parser kinds=K) = 8" | |

남은 일(3라운드 이후):
- Servicing 2 템플릿 이름: 재사용된 청크의 템플릿을 다른 청크의 정의와 맞춰 보는 복원은 하지 않았다(지금은 공개만 한다).
- 자동 완성 기본 마스킹 때문에 검색어·자유 입력이 미리보기에 보이지 않는다. 일치 여부는 `value_sha256`으로 찾는다. 원문 열람은 원본 Web Data를 봐야 한다.
- 이전 출력의 `artifact_id`는 새 ID와 대응되지 않는다. 다시 실행해야 새 ID가 생긴다(위 스키마 문서의 마이그레이션 설명 참고).
