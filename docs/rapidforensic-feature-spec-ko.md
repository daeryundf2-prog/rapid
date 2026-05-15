# RapidForensic 한글 기능 명세서

최신화 기준: 2026-05-15  
대상 브랜치: `codex/rapidforensic-complete`  
제품 구현명: `rapidtriage`

## 1. 목적

RapidForensic은 분석관이 단일 포렌식 케이스에서 증거 입력, 추출, 아티팩트 분석, 검색, 리뷰, 보고서 후보 작성을 한 흐름으로 처리하도록 돕는 로컬 우선 triage 도구다.

핵심 목표는 다음 3가지다.

1. 증거 이미지나 폴더를 넣으면 내부 데이터를 안전하게 분석한다.
2. 필요한 파일과 아티팩트를 추출하고 원본 근거를 확인한다.
3. 키워드 검색 결과를 리뷰 상태와 보고서 후보로 연결한다.

상용 포렌식 도구의 모든 기능을 대체한다고 주장하지 않는다. 현재는 usable 기능을 넓게 노출하고, commercial-grade 여부는 별도 gate로 분리한다.

## 2. 사용자 유형

| 사용자 | 주요 목적 | 필요한 화면 |
| --- | --- | --- |
| 디지털 포렌식 분석관 | 증거 이미지 분석, 검색, 리뷰, 보고서 후보 작성 | 케이스 워크벤치, artifact tree, source viewer, evidence tray |
| 침해사고 대응 담당자 | 실행 흔적, 원격접속, 웹쉘, 악성 IOC, 로그 삭제 확인 | timeline, event pivot, IOC/YARA, remote-access view |
| 내부 감사 담당자 | 문서 유출, USB, 클라우드 동기화, 출력/메일 흔적 확인 | file search, USB view, cloud/mail view, report bundle |
| QC 담당자 | 기능 동작 여부, 누락, 대형 데이터 성능, 정확도 검증 | QC checklist, validation package, readiness panel |
| 개발자 | parser 추가, fixture 검증, UI 연결 확인 | taxonomy audit, test suite, API schema |

## 3. 제품 경계

### 3.1 포함

- 로컬 GUI와 CLI
- 폴더/마운트 이미지/E01-derived export 분석
- 파일 manifest, hash, category, document text extraction
- Windows/macOS/Linux/Android/cloud/email/media/memory 관련 artifact collector
- case DB 기반 검색/리뷰/보고서 후보
- validation package와 readiness gate
- 대형 검색을 위한 cursor/resume/truncation 표시

### 3.2 제외 또는 제한

- 모든 이미지 포맷의 완전 native mount 보장
- 모든 Windows artifact의 상용급 full parser 보장
- 암호화 데이터 무단 복호화
- cloud 계정 무단 수집
- 독립 기관 검증 완료 claim
- Windows/macOS signed installer와 notarization 완료 claim

## 4. 핵심 워크플로우

GUI와 CLI 산출물은 아래 6단계를 같은 순서로 보여야 한다. 기능이 내부에 있더라도 이 흐름에서 보이지 않으면 사용자는 “지원하지 않는다”고 판단하므로, 신규 기능은 반드시 단계, viewer, next action을 함께 연결한다.

| 단계 | 사용자에게 보이는 이름 | 핵심 질문 | 대표 산출물 |
| --- | --- | --- | --- |
| 1 | 입력 | 이 증거를 안전하게 읽을 수 있는가? | evidence support, dependency check, source fingerprint |
| 2 | 추출 | 원본 경로와 해시를 보존하면서 필요한 파일을 꺼냈는가? | extract manifest, skipped/capped rows, SHA256 |
| 3 | 분석 | OS, 파일 시스템, 문서, 웹/AI, 메신저 아티팩트가 row로 나왔는가? | artifacts, files, docs, timeline, warnings |
| 4 | 검색 | 전체 검색과 현재 파일 검색이 누락 없이 이어지는가? | case search, source search, cursor/resume state |
| 5 | 리뷰 | 원본 뷰어에서 확인하고 판단 상태를 남겼는가? | relevant, needs-review, excluded, note, tag |
| 6 | 보고서 | 선택 증거가 citation/provenance와 함께 묶였는가? | report candidates, evidence tray, limitation |

### 4.1 입력

1. 사용자가 GUI 또는 CLI에서 source를 선택한다.
2. `rapidtriage evidence <source>`가 입력 종류를 판정한다.
3. source가 폴더라면 직접 scan한다.
4. source가 이미지라면 adapter가 mount/export/tool dependency를 확인한다.
5. source가 archive나 DB라면 bounded extraction/search profile을 적용한다.

### 4.2 분석

1. manifest를 만든다.
2. file category와 hash를 계산한다.
3. artifact collector를 실행한다.
4. document/search index 후보를 만든다.
5. timeline/normalized case output을 만든다.
6. validation, limitation, parser confidence를 함께 기록한다.

### 4.3 검색

1. global search에서 전체 case DB 또는 run output을 검색한다.
2. current-file search에서 source viewer 내부 파일을 검색한다.
3. SQLite, document, PDF, Office, EML, MBOX 등은 cap과 cursor 상태를 표시한다.
4. 검색이 중간에 끊기면 결과 없음으로 오판하지 않도록 `resume_token`과 `truncated`를 보여준다.

### 4.4 리뷰

1. 분석관은 결과 row를 열어 source viewer로 원본 근거를 확인한다.
2. row에 `relevant`, `needs-review`, `excluded` 등 상태를 붙인다.
3. report 포함 여부, tag, note, reviewer metadata를 저장한다.
4. evidence tray에서 선택 증거를 모은다.
5. 보고서 후보 또는 submission bundle로 내보낸다.

## 5. 지원 입력 상세

| 그룹 | 확장자/형태 | 현재 기대 동작 | QC 포인트 |
| --- | --- | --- | --- |
| 폴더 | directory | 직접 scan, artifact collector 실행 | 권한 오류, locked file, symlink loop |
| 마운트 이미지 | mounted root | 폴더처럼 처리 | read-only 여부, source path provenance |
| EWF | `.E01`, `.Ex01`, split EWF | dependency check, mount/export workflow | libewf/Sleuth Kit 설치, hash, encrypted/corrupt handling |
| RAW | `.dd`, `.raw`, split raw | adapter 판정, partition/filesystem workflow | split gap, offset, filesystem detection |
| Virtual disk | `.vhd`, `.vhdx`, `.vmdk`, `.vdi`, `.qcow`, `.qcow2` | qemu-img/외부 tool 기반 workflow | differencing chain, converted raw hash |
| Archive image | `.iso`, `.dmg`, `.wim`, `.swm` | archive image adapter | compressed/encrypted archive, path traversal |
| 일반 archive | `.zip`, `.tar`, `.gz`, `.7z` 계열 | bounded extraction/search | zip bomb, nested archive cap |
| SQLite/DB | `.sqlite`, `.db`, `.edb` 일부 | source viewer/table/search/sidecar | WAL/SHM/journal, 대형 table cursor |
| 문서 | PDF, Office, TXT, CSV, JSON, XML, HTML | bounded text extraction | stream/member cap, encoding |
| 메일 | EML, MBOX, PST/OST workflow | email viewer/import 후보 | attachment, header, thread |
| 메신저 | KakaoTalk, WhatsApp, Telegram 등 export/DB | 서비스별 parser 후보 | schema version, encryption, key authority |

## 6. 사용자 노출 기능 그룹

### 6.1 증거 이미지 입력 및 추출

- E01/Ex01 adapter
- RAW/split image adapter
- virtual disk adapter
- ISO/DMG/WIM/SWM adapter
- archive extraction cap
- VSS/APFS snapshot workflow
- FDE unlock runbook
- unallocated carving workflow
- source hash/provenance recording

상용급 보강 필요:

- 실제 Windows 11 E01 end-to-end trace
- BitLocker/FileVault/LUKS on-the-fly unlock 실증
- VSS/APFS snapshot mount fixture
- corrupt/encrypted image fixture

### 6.2 파일 시스템 분석

- manifest, file category, hash
- MFT triage
- USN triage
- `$LogFile` workflow
- Recycle Bin `$I`/`$R` mapping 목표
- timestamp anomaly/time stomping 후보
- extension signature mismatch 후보
- duplicate/hash cache workflow

상용급 보강 필요:

- 100만~1000만 FILE record path reconstruction
- USN rename/delete replay
- LogFile transaction fixture
- NSRL/whitelist 연동 실측

### 6.3 Windows 이벤트 로그

- EVTX/EventLog triage
- log clear event warning
- logon session correlation
- USB/WLAN/Print/BITS provider pivot
- ETL workflow 노출
- Hayabusa/EvtxECmd diff workflow

상용급 보강 필요:

- native BinXML full parser
- provider message rendering
- corrupt/deleted recovery corpus
- record-level trusted-tool diff

### 6.4 Registry 및 계정

- Registry hive tree workflow
- NTUSER/UsrClass user activity
- SAM/SECURITY/SYSTEM 계정/권한 workflow
- USBSTOR, MountedDevices, setupapi.dev.log 통합 목표
- ShellBags
- RecentDocs, MUICache, Clipboard
- autoruns/persistence 통합 view 목표
- Wi-Fi/network profile 후보

상용급 보강 필요:

- LOG1/LOG2 transaction replay
- deleted cell allocator 검증
- RECmd/ShellBagsExplorer diff
- SAM/LSA/privilege row-level fixture

### 6.5 실행 흔적

- Prefetch
- LNK
- JumpList
- Amcache
- ShimCache/AppCompatCache
- BAM/DAM
- Windows Timeline/ActivitiesCache
- BITS qmgr.dat
- Task Scheduler, WMI, services, Run keys

상용급 보강 필요:

- OS version별 binary layout fixture
- “실행 증거 아님” 같은 legal limitation wording
- USB 파일 실행 상관관계 E2E

### 6.6 인터넷/브라우저

- Chrome/Edge/Firefox/Safari history/download/session/cache 후보
- WebCacheV01.dat workflow
- browser storage/cookie/extension/sync 후보
- incognito/pagefile/memory URL carving 후보
- OneDrive/Google Drive sync DB 후보

상용급 보강 필요:

- browser별 timestamp semantics
- deleted history 표시
- locked live DB handling
- 대형 profile fixture

### 6.7 AI 서비스 사용기록

- ChatGPT/Claude/Gemini/Perplexity 웹 사용 흔적
- AI prompt/response pairing 후보
- ChatGPT/Copilot desktop app local DB 후보
- Ollama, LM Studio, GPT4All local LLM 흔적
- Windows Recall workflow 항목

상용급 보강 필요:

- 서비스별 export/schema version fixture
- Q/A pairing confidence calibration
- privacy/legal warning UX

### 6.8 문서, 메일, Windows Search

- PDF/Office/TXT/CSV/JSON/XML text extraction
- bounded extraction cap
- EML/MBOX parse diagnostics
- PST/OST workflow
- Windows.edb/Search index workflow
- Print Spooler SPL/SHD 목표
- Sticky Notes plum.sqlite 목표
- macro/metadata risk flag 목표

상용급 보강 필요:

- ESE full parser
- PST/OST libpff parity
- malicious macro corpus
- large MBOX/EML cap/cancel

### 6.9 메신저, 모바일, 카카오톡

- PC KakaoTalk Windows legacy/post-patch workflow
- KakaoTalk macOS DB 후보 탐지
- mobile export import taxonomy
- WhatsApp/Telegram/Signal/LINE/Discord/WeChat/Instagram schema matrix 목표
- location/health/screen time export row
- media-message-contact-call correlation 목표

상용급 보강 필요:

- 실제 version별 fixture
- 암호화 store legal authority gate
- deleted row validation
- attachment/media mapping

### 6.10 클라우드 및 SaaS

- Google Takeout workflow
- iCloud export workflow
- M365/Teams/eDiscovery export workflow
- AWS CloudTrail, Azure Activity Log, GCP Audit Logs taxonomy
- OAuth/token secure handling workflow

상용급 보강 필요:

- provider별 pagination/backoff
- signed offline evidence package
- RBAC/audit for token reveal

### 6.11 미디어, OCR

- image gallery review
- EXIF/GPS extraction
- EXIF map marker 목표
- OCR queue
- OCR hit viewer
- video/audio preview/transcript workflow
- steganography/deepfake suspicion profile

상용급 보강 필요:

- Korean OCR confidence calibration
- large media thumbnail cache
- malicious media sandbox
- perceptual hash fixture

### 6.12 메모리 포렌식

- hiberfil/pagefile/memory URL carving
- Volatility import workflow
- MEMORY.DMP/minidump workflow
- BitLocker key recovery workflow 노출
- process tree/malware pattern workflow

상용급 보강 필요:

- Windows version별 memory image fixture
- hiberfil decompression
- Volatility output schema mapping
- credential/secret redaction

### 6.13 침해사고/원격접속

- AnyDesk, TeamViewer, Chrome Remote Desktop, RustDesk 흔적 taxonomy
- RDP/logon/session pivot
- Defender/Firewall tampering
- LotL/PowerShell/WMI command history workflow
- YARA/IOC/TI workflow
- WebShell detection taxonomy

상용급 보강 필요:

- 실제 도구별 log fixture
- ATT&CK mapping
- false positive/false negative 문서

### 6.14 리뷰, 검색, 보고서

- global search
- current-file source search
- SQLite cursor/resume
- document extraction cap 표시
- source viewer
- evidence tray
- review status/note/tag/include-in-report
- report candidate export
- submission bundle
- commercial readiness panel

상용급 보강 필요:

- large result virtualization E2E
- keyboard review workflow
- citation completeness
- immutable audit hash chain

## 7. GUI 요구사항

### 7.1 레이아웃

| 영역 | 목적 |
| --- | --- |
| 좌측 artifact tree | 기능을 숨기지 않고 분석관 언어로 노출 |
| 상단 command bar | evidence 선택, dependency check, run, cancel, export |
| 중앙 result table | 대량 row를 virtualized table로 표시 |
| 우측 preview/detail | 파일/DB/EVTX/Registry/Email/Image/Media/source 근거 확인 |
| 하단 evidence tray | 선택 증거, 보고서 포함 상태, citation |
| readiness panel | usable/validated/commercial-grade 분리 |

### 7.2 UX 원칙

- 결과 없음과 부분 검색을 반드시 구분한다.
- 대형 DB table은 cursor/resume 상태를 표시한다.
- source viewer는 원본 경로, hash, parser, offset/index를 보여준다.
- 분석 중 실패한 parser는 전체 job을 죽이지 않고 실패 근거를 남긴다.
- secret/key/token 원문은 기본 숨김 처리한다.
- 기능이 구현대기/검증대기이면 UI에 그렇게 표시한다.

## 8. 데이터 모델

공통 artifact row는 가능한 한 아래 필드를 가진다.

| 필드 | 의미 |
| --- | --- |
| `provider` | collector 또는 parser 이름 |
| `artifact_type` | 안정적인 machine-readable type |
| `source_path` | 원본 경로 |
| `source_hash` | 가능한 경우 원본 hash |
| `timestamp` | normalize된 시간 |
| `timezone` | 원본 timezone 또는 assumption |
| `details` | parser별 상세 |
| `confidence` | 추출 신뢰도 |
| `limitations` | 법정/기술 제한 |
| `parser_version` | parser 버전 |
| `offset` 또는 `record_id` | 원본 근거 위치 |
| `review_status` | 리뷰 상태 |
| `include_in_report` | 보고서 포함 여부 |

## 9. 성능 요구사항

| 영역 | 목표 |
| --- | --- |
| 파일 manifest | stream/chunk 기반, 대형 디렉터리에서 메모리 폭증 방지 |
| SQLite search | cursor/resume, searched_rows/total_rows/truncated 표시 |
| document extraction | 파일 크기, ZIP member, PDF stream cap |
| GUI table | DOM virtualization |
| job queue | progress/cancel/retry/checkpoint |
| parser isolation | parser crash가 전체 run을 중단하지 않도록 격리 |
| hot path | EVTX/Registry/ESE/MFT/USN/hash/indexing은 Rust/Go/C++ sidecar 후보 |

## 10. 보안/법정성 요구사항

- 모든 증거 입력은 read-only를 기본 전제로 한다.
- output path가 evidence root 내부이면 contamination warning을 띄운다.
- token/query 인증은 운영 기본값에서 금지 또는 제한한다.
- browser secret, messenger key, cloud token은 authority gate와 audit log가 필요하다.
- preview는 active content를 실행하지 않는다.
- report item은 source provenance를 가져야 한다.
- validation package는 command, output, hash, limitation, parser version을 포함한다.
- 상용급 claim은 external validation gate 통과 전 금지한다.

## 11. 완료 판정

기능은 4단계로 판정한다.

| 단계 | 의미 |
| --- | --- |
| 노출됨 | GUI/CLI/문서에서 사용자가 찾을 수 있음 |
| 사용 가능 | 입력을 넣고 산출물이 생성됨 |
| 검증됨 | fixture 또는 known-answer test가 있음 |
| 상용급 | 실제 대형 케이스, trusted-tool diff, 독립 검증, 운영 증거가 있음 |

현재 다수 기능은 “노출됨/사용 가능/내부 검증” 단계에 있으며, “상용급”은 별도 증거가 붙어야 한다.
