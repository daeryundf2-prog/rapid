# RapidForensic 사용자 노출 포렌식 기능 세분화

이 문서는 `artifact collector` 개수만 보면 실제 기능이 적어 보이는 문제를 줄이기 위해 작성한다. 현재 코드는 여러 기능을 하나의 collector 안에 묶어 둔 경우가 많다. 예를 들어 `browser` collector 하나 안에는 인터넷 사용기록, 다운로드, 브라우저 저장소, AI 서비스 방문, AI 대화 후보 복원, citation manifest, 검증 gate가 같이 들어 있다.

목표는 GUI와 QC 문서에서 "23개 collector"가 아니라 "분석자가 실제로 선택하고 확인할 수 있는 기능 단위"로 보여주는 것이다.

## 0. 구조 정리 원칙

앞으로 새 포렌식 기능은 "파서가 존재한다"만으로 완료 처리하지 않는다. 모든 기능은 `visible capability registry`를 통과해야 하며, 다음 필드가 비어 있으면 GUI 사용 가능 기능으로 보지 않는다.

| 필드 | 의미 |
| --- | --- |
| `id` / `label` | 사용자가 기능 목록에서 볼 수 있는 고유 기능명 |
| `status` | 사용 가능, 부분 구현, 목록화, 검증 필요, 외부 자료 필요 중 하나 |
| `terms` | 검색/필터/신호 매칭에 쓰는 키워드 |
| `tab` | GUI에서 열릴 기본 탭 |
| `viewer` | 사용자가 결과를 확인할 기본 viewer |
| `artifact_types` | 이 기능이 만들어내거나 확인하는 결과 row/type |
| `workflow_stage` | ingest, extract, parse, search, review, report 중 어느 흐름에 속하는지 |
| `next_action` | 분석관이 다음에 해야 할 검증/리뷰 행동 |
| `gui_surfaces` | feature catalog, capability chip, viewer 등 실제 노출 위치 |

현재 `/api/forensic-capabilities`와 `/api/runs/{run_id}/capabilities`는 위 계약을 포함한다. GUI는 완료된 run에서는 API에서 내려온 capability 계약을 우선 사용하고, 정적 설정은 API가 없을 때의 fallback으로만 사용한다. 이 원칙 때문에 앞으로 기능을 추가할 때는 `파서 구현 -> ArtifactRecord/산출물 저장 -> capability registry 등록 -> GUI 노출 -> 테스트` 순서를 지켜야 한다.

또한 `artifacts` 출력은 각 레거시 row 안에 `artifact_record` 필드를 함께 싣는다. 이 필드는 `ArtifactRecordV1` 계약이며 `artifact_id`, `artifact_family`, `artifact_type`, `parser`, `parser_version`, `source`, `confidence`, `validation_required`, `commercial_grade_ready`, `commercial_grade_blockers`, `legal_limitations`, `fields`를 가진다. 기존 collector가 아직 레거시 row를 만들더라도, 실행 결과는 검색/리뷰/보고서/columnar store가 공통으로 사용할 수 있는 표준 row를 같이 제공해야 한다.

## 1. 현재 집계 방식의 문제

현재 `artifact_collectors()` 기준 collector는 23개다.

하지만 사용자 관점 기능은 다음처럼 더 잘게 나뉜다.

| 층위 | 의미 | 예시 |
| --- | --- | --- |
| Collector | 실행 단위 또는 코드 모듈 | `browser`, `windows-execution`, `mobile-export` |
| Artifact type | 결과 row/type 단위 | `browser-ai-usage`, `srum-row-candidate`, `mobile-message` |
| Parser stage | 내부 파싱 단계 | Chromium History SQLite, AI Q/A pairing, Registry free-cell recovery |
| Viewer task | 사용자가 실제로 하는 일 | URL 확인, 원본 DB row 열기, 리뷰 표시, 보고서 포함 |
| Validation gate | 법정 제출 전 검증 조건 | trusted-tool diff, known-answer corpus, large-case benchmark |

따라서 GUI에는 collector 23개만 보여주면 안 된다. 최소한 artifact type과 parser stage까지 펼쳐야 한다.

현재 `taxonomy-audit` 기준 사용자 노출 forensic target은 48개이며, 동적 artifact type까지 포함해 48/48개가 GUI/QC 바인딩을 가진다. 이 수치는 "상용급 검증 완료"가 아니라 "사용자가 기능을 찾고 실행/검토할 수 있는 노출 계약이 빠지지 않는다"는 의미다.

## 2. 최상위 사용자 기능 그룹

GUI에서는 다음 14개 상위 그룹으로 보여주는 것이 적절하다.

1. 증거 이미지 입력 및 추출
2. 파일 시스템 분석
3. Windows 이벤트 로그
4. Windows 레지스트리 및 계정
5. 실행 흔적
6. 인터넷/브라우저 사용기록
7. AI 서비스 사용기록
8. 문서/이메일/검색 인덱스
9. 메신저/모바일/카카오톡
10. 클라우드/계정 Export
11. 이미지/영상/음성/OCR
12. 메모리 포렌식
13. 침해사고/웹쉘/원격접속
14. 리뷰/검색/보고서/검증

## 3. 증거 이미지 입력 및 추출

현재 이 영역은 단일 collector보다 `e01`, `input_root`, `run`, `extract`, `image` workflow에 흩어져 있다. GUI에서는 독립 기능처럼 보여야 한다.

| 사용자 노출 기능 | 현재 내부 단계 | 현재 상태 | Windows QC 확인 |
| --- | --- | --- | --- |
| E01/Ex01 선택 | E01/Ex01 입력 탐지, ewf/tsk/export workflow | 부분 구현 | 실제 Windows 11 E01 선택 후 의존성/파티션/추출 진행 여부 |
| E01 의존성 검사 | libewf/ewfmount/tsk/qemu-img 등 외부 도구 확인 | 부분 구현 | 누락 도구가 한글로 명확히 표시되는지 |
| 파티션 선택 | 파티션 목록/추천/수동 start sector | 부분 구현 | 여러 파티션 이미지에서 선택 UI 동작 |
| 파일 추출 | 추출 manifest, hash, source provenance | 부분 구현 | 추출 파일과 원본 hash/provenance 연결 |
| RAW/split image | `.dd`, `.raw`, `.img`, `.001` 등 | 부분 구현 | split gap, 순서, 누락 segment 경고 |
| ISO/DMG/WIM/SWM | archive/container scan | 부분 구현 | Windows에서 DMG/ISO/WIM 입력 시 오류 메시지와 fallback |
| VHD/VHDX/VMDK/VDI/QCOW | qemu-img 기반 변환/scan | 부분 구현 | 변환 hash/provenance 보존 |
| AD1/L01/Lx01/AFF/AFF4/XVA | native보다 verified export 중심 | 감지/부분 | 네이티브 불가 시 export workflow 안내 |

숨은 기능으로 빼서 보여줄 항목:

- 이미지 형식 자동 인식
- 의존성/권한 진단
- 파티션 브라우저
- 파일 시스템 추출
- 추출 manifest
- 추출물 hash 검증
- 중단/재개 checkpoint
- unsupported image fallback 안내

## 4. 파일 시스템 분석

관련 collector:

- `windows-filesystem`
- `generic-documents`
- `media-image`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| 파일 목록/메타데이터 | run file inventory | baseline | 대형 NTFS 직접 row 추출 검증 |
| `$MFT` 파일 감지 | `mft-file` | partial+ | 전체 attribute-list/runlist/parent path |
| `$MFT` record 후보 | `mft-record` | partial+ | 100만~1000만 record path reconstruction |
| `$UsnJrnl` 감지 | `usn-journal-file` | partial+ | v2/v3/v4 full replay |
| USN record 후보 | `usn-record` | partial+ | rename/delete replay, FRN cache |
| 문서 후보 | `document-pattern` | implemented | legacy Office/deleted doc coverage |
| 이미지 파일 | `media-image` | partial+ | 대량 gallery, perceptual validation |
| 영상 파일 | `media-video` | partial | sandboxed playback, thumbnail |
| 음성 파일 | `media-audio` | partial | waveform, transcript alignment |

숨은 기능으로 빼서 보여줄 항목:

- MFT source row 보기
- MFT record detail 보기
- USN 변경 이력 보기
- 파일 경로 재구성 confidence
- 삭제/복구 후보 표시
- 파일 hash cache
- 중복 파일 그룹
- 파일 내부 검색

## 5. Windows 이벤트 로그

관련 collector:

- `eventlog`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| EVTX 파일 inventory | `eventlog-file` | partial+ | corrupt/deleted corpus |
| XML/JSON/CSV event import | `eventlog-event` | baseline+ | source tool diff |
| native EVTX record 후보 | `eventlog-record-candidate` | partial+ | BinXML full grammar |
| EVTX chunk 구조 | `eventlog-chunk` / Rust sidecar | partial | chunk checksum, slack/recovery validation |
| 이벤트 탐지/위험 분류 | `eventlog-detection` | partial+ | rule coverage, FP/FN |
| 이벤트 요약 | `eventlog-summary` | baseline | channel/provider completeness |
| message rendering | details field | partial | provider DLL/resource message |
| recovery context | details field | partial | slack/deleted 검증 |

숨은 기능으로 빼서 보여줄 항목:

- 이벤트 채널별 보기
- EventRecordID gap 보기
- provider/message rendering 상태
- high-risk event만 보기
- Sysmon/Defender/RDP/WMI pivots
- corrupt/deleted record 후보
- Hayabusa/EvtxECmd diff 상태

추가 숨은 sidecar:

- `engines/rust/crates/rapidcore`에는 대용량 처리용 `file-inventory-record`, `eventlog-file`, `eventlog-chunk`, `eventlog-event` 산출이 있다.
- GUI/문서에서는 이 Rust sidecar 결과도 Python collector 결과와 같은 `File System`, `Windows Event Logs` 그룹 아래로 합쳐서 보여야 한다.
- 사용자는 "Python 파서 결과"와 "Rust sidecar 결과"를 구분할 필요가 없다. 다만 보고서에는 parser/version/provenance가 남아야 한다.

## 6. Windows 레지스트리 및 계정

관련 collector:

- `windows-registry`
- `windows-os-account`
- `windows-shellbags`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| Hive inventory | `registry-hive` | partial+ | LOG1/LOG2 replay |
| Hive string pivots | `registry-hive-strings` | partial | false positive control |
| Hive cell 후보 | `registry-hive-cell` | partial+ | full regf/hbin tree |
| deleted cell 후보 | `registry-deleted-cell-candidate` | partial+ | allocator validation |
| key tree node | `registry-key-tree-node` | partial+ | full parent/subkey/value list |
| deleted key recovery | `registry-key-recovery-candidate` | partial+ | RECmd diff |
| deleted value recovery | `registry-value-recovery-candidate` | partial+ | transaction replay |
| user activity | `registry-user-activity` | partial+ | UserAssist binary decode 등 |
| OS/account summary | `windows-os-account-summary` | partial+ | native SAM/SECURITY full parser |
| user profile | `windows-user-profile` | partial+ | profile lifecycle diff |
| SAM account 후보 | `windows-sam-account-candidate` | partial+ | F/V full decode |
| SAM group 후보 | `windows-sam-group-candidate` | partial+ | alias membership |
| group membership | `windows-group-membership` | partial+ | nested group handling |
| privilege assignment | `windows-privilege-assignment` | partial+ | SECURITY policy validation |
| mounted devices | `windows-mounted-device` | partial+ | volume serial correlation |
| service config | `windows-service-config` | partial+ | service binary path validation |
| ShellBags export | `shellbag-key` | partial+ | binary shell item decode |
| ShellBags native 후보 | `shellbag-native-candidate` | partial+ | BagMRU/Bags relationship |

숨은 기능으로 빼서 보여줄 항목:

- NTUSER.DAT 사용자 활동
- UsrClass.dat ShellBags
- RecentDocs/TypedURLs/TypedPaths
- Run/RunOnce persistence
- MountPoints2/USB 흔적
- SAM 사용자/그룹/권한
- deleted registry 후보
- transaction log 준비 상태

## 7. 실행 흔적

관련 collector:

- `windows-execution`
- `windows-prefetch`
- `windows-system`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| Amcache hive | `amcache-hive` | partial+ | version별 schema map |
| Amcache entry | `amcache-entry` | partial+ | timestamp semantics 검증 |
| ShimCache entry | `shimcache-entry` | partial+ | OS build별 binary layout |
| BAM/DAM entry | `bam-entry` | partial+ | binary value full decode |
| SRUM DB file | `srum-database-file` | partial+ | ESE row parser |
| SRUM table 후보 | `srum-table-candidate` | partial+ | table schema mapping |
| SRUM row 후보 | `srum-row-candidate` | partial+ | counter/timestamp validation |
| PowerShell history | `powershell-history-command` | implemented baseline | multiline/context correlation |
| Prefetch file | `prefetch-file` | partial+ | compressed/version corpus |
| Prefetch reference | `prefetch-reference` | partial+ | volume/file metric validation |
| Task Scheduler | `task-scheduler-task` | partial+ | TaskCache/EVTX correlation |
| Defender log | `defender-support-log` | partial+ | Defender EVTX/quarantine linkage |
| Firewall log | `firewall-log` | partial+ | process/SRUM/browser correlation |
| WER report | `wer-report` | partial+ | dump/cab validation |
| WMI repository | `wmi-repository-file` | partial+ | permanent event consumer decode |
| UWP package | `uwp-package` | partial | app package metadata depth |

숨은 기능으로 빼서 보여줄 항목:

- 실행 흔적 통합 보기
- "실행 증거 아님" caveat 표시
- Prefetch run count/last run
- PowerShell 명령 검색
- LotL 의심 명령 pivot
- SRUM network/app usage
- Defender/Firewall/WER/Task/WMI 위험 rule

## 8. 인터넷/브라우저 사용기록

관련 collector:

- `browser`
- `macos-system`
- `mobile-export` 일부

이 영역은 특히 숨겨진 기능이 많다. GUI에서는 반드시 별도 메뉴로 보여야 한다.

| 사용자 노출 기능 | 내부 단계/artifact | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| Chromium History | `extract_chromium_history_and_downloads` | implemented baseline+ | browser version별 schema drift |
| Chrome/Edge/Brave history | `browser-history-downloads` | baseline+ | deleted history validation |
| Chromium downloads | `downloads` details | baseline+ | interrupted/chain semantics |
| Firefox Places | `extract_firefox_history` / `browser-history` | baseline+ | downloads/session parity |
| macOS Safari history | `extract_safari_history` / `macos-browser-history-downloads` | baseline | downloads/cache/session parity |
| 통합 browser timeline | `unified_timeline` | baseline+ | timestamp/transition full validation |
| internet usage summary | `internet_usage` details | baseline+ | category rule tuning |
| top domains | `top_domains` details | baseline+ | domain normalization validation |
| 검색어 추출 | `query_hint` | baseline | URL parameter false positive |
| browser source hash | `source_hashes` | implemented | raw DB row viewer E2E |
| browser citation manifest | `browser-history-download-citation-manifest-v1` | partial+ | trusted-tool diff |
| browser storage inventory | `browser-storage-inventory` | partial++ | full cache/session schema decode |
| cache inventory | `browser-cache-inventory` | partial | request/response reconstruction |
| session storage | `browser-session-storage-inventory` | partial | browser version schema |
| extensions | `browser-extension-inventory` | partial | extension-specific parsers |
| sync/Web Data | `browser-sync-inventory` | partial | account/sync scope semantics |
| cookie store inventory | `browser-cookie-store-inventory` | partial | lawful decrypt gate validation |
| credential store inventory | `browser-credential-store-inventory` | partial | DPAPI/keychain validation |

숨은 기능으로 빼서 보여줄 항목:

- 브라우저 통합 타임라인
- URL 방문 기록
- 다운로드 기록
- 검색어/쿼리 힌트
- 도메인/카테고리 요약
- 브라우저 프로필별 보기
- 쿠키/세션/확장프로그램 inventory
- 민감 저장소 legal warning
- 원본 SQLite row 열기
- Hindsight/BrowserHistoryView diff 상태

## 9. AI 서비스 사용기록

관련 collector:

- `browser`
- `macos-system`
- `mobile-export`

지원 서비스 감지 목록:

- ChatGPT
- OpenAI
- Claude
- Gemini/Bard/Google AI Studio
- Perplexity
- Microsoft Copilot/Bing Chat
- Poe
- Hugging Face Chat
- Grok/xAI
- You.com
- Phind
- Mistral Le Chat
- DeepSeek
- Meta AI
- Character.AI
- Notion AI

| 사용자 노출 기능 | 내부 단계/artifact | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| AI 서비스 방문 감지 | `browser-ai-usage`, `macos-browser-ai-usage` | partial+ | service export diff |
| URL/title 기반 서비스 분류 | `detect_ai_service` | partial+ | 최신 서비스/도메인 업데이트 |
| URL query 기반 prompt hint | `query_hint`, `prompt_hint` | baseline | query에 질문이 없는 서비스 한계 |
| browser storage scan | Local Storage, Session Storage, IndexedDB, Cache | partial+ | deleted fragment recovery |
| Q/A fragment 추출 | role/content, prompt/question/answer/response/completion | partial+ | provider schema별 parser |
| Q/A pairing | transcript pair confidence/orphan count | partial+ | official export diff |
| source offset/hash | candidate manifest | partial+ | browser source viewer E2E |
| AI 대화 후보 보기 | `browser-ai-conversation`, `macos-browser-ai-conversation` | partial+ | chat-like viewer polish |
| mobile AI usage | `mobile-browser`, `mobile-app`, risk flags | partial | app-specific local DB parser |

중요한 한계:

- 브라우저 history는 "AI 서비스를 방문했다"는 증거이지, 항상 질문/답변 본문을 의미하지 않는다.
- 질문/답변 본문은 browser storage/cache에 남은 조각을 후보로 복원하는 방식이다.
- ChatGPT/Claude/Gemini/Perplexity 공식 export와 diff되지 않으면 "완전한 대화 복원"으로 쓰면 안 된다.

GUI 표시 권장:

- `AI 방문 기록`
- `AI 질문 후보`
- `AI 답변 후보`
- `Q/A pair`
- `출처 storage`
- `confidence`
- `원본 offset`
- `서비스 export 검증 필요`

## 10. 문서, 이메일, Windows Search

관련 collector:

- `generic-documents`
- `email`
- `windows-search-index`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| 일반 문서 후보 | `document-pattern` | implemented | file-type specific parser expansion |
| EML/EMLX | `email-message` | partial+ | attachment/deleted validation |
| MBOX/Maildir | `email-mailbox`, `email-message` | partial+ | threading validation |
| PST/OST/MSG | `email-mailbox` inventory | partial | libpff/native MAPI decode |
| Windows.edb file | `windows-search-edb-file` | partial+ | full ESE catalog/page parser |
| Windows.edb pivot | `windows-search-edb-pivot` | partial+ | row timestamp/deleted state |
| EDB page 후보 | `windows-search-edb-page-candidate` | partial+ | table/page semantics validation |
| EDB table 후보 | `windows-search-edb-table-candidate` | partial+ | full table decode |
| EDB row 후보 | `windows-search-edb-row-candidate` | partial+ | row-level known-answer |
| Search index export | `windows-search-index-entry` | baseline+ | trusted export mapping |
| Search index summary | `windows-search-index-summary` | baseline | large corpus validation |

숨은 기능으로 빼서 보여줄 항목:

- 문서 본문 검색
- 이메일 conversation 보기
- 첨부파일 추출
- PST/OST inventory 경고
- Windows.edb path/url/content pivot
- ESE page/row 후보 보기
- source viewer/citation

## 11. 메신저, 모바일, 카카오톡

관련 collector:

- `mobile-export`
- `android-apk`
- `kakaotalk-windows`
- `kakaotalk-macos`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| Vendor export source | `mobile-export-source` | partial+ | Cellebrite/XRY/GrayKey/AXIOM fixture diff |
| 모바일 메시지 | `mobile-message` | partial+ | per-service schema corpus |
| 모바일 연락처 | `mobile-contact` | partial+ | merge/split entity UI |
| 통화 기록 | `mobile-call` | partial+ | timezone/device validation |
| 설치 앱 | `mobile-app` | partial+ | package risk model validation |
| 모바일 파일 | `mobile-file` | partial+ | media/file hash provenance |
| 계정 | `mobile-account` | partial+ | service identity validation |
| 모바일 미디어 | `mobile-media` | partial+ | attachment linking |
| 모바일 브라우저 | `mobile-browser` | partial+ | browser schema별 parser |
| 모바일 correlation | `mobile-correlation-summary` | partial++ | device-wide timeline |
| 모바일 채팅 DB 후보 | `mobile-chat-database` | partial+ | native DB/decryption/deleted recovery |
| iOS backup source | `ios-backup-source` | partial+ | encrypted backup unlock workflow |
| iOS backup metadata | `ios-backup-metadata` | partial+ | protected data class |
| iOS backup file | `ios-backup-file` | partial+ | app DB parser |
| iOS keychain inventory | `ios-keychain-inventory` | partial+ | lawful decrypt gate |
| Android APK | `android-apk` | partial+ | binary manifest/signature chain |
| Android app data | `android-app-data` | partial+ | app-specific schema |
| PC KakaoTalk DB | `kakaotalk-windows-app-database` | triage+ | post-BigBang independent validation |
| PC KakaoTalk crypto 후보 | `kakaotalk-windows-crypto-material-candidate` | triage+ | legal authority and version matrix |
| PC KakaoTalk user ID 후보 | `kakaotalk-windows-user-id-candidate` | triage+ | UID/userDir validation |
| PC KakaoTalk source 후보 | `kakaotalk-windows-source-candidate` | triage+ | memory/edb/registry correlation |
| PC KakaoTalk summary | `kakaotalk-windows-correlation-summary` | triage+ | trusted tool comparison |
| macOS KakaoTalk DB | `kakaotalk-macos-database` | inventory | message decode research |
| macOS KakaoTalk summary | `kakaotalk-macos-summary` | inventory | live user data validation |

메신저 서비스별로 GUI에 드러낼 항목:

- KakaoTalk
- WhatsApp
- Telegram
- Signal
- WeChat
- LINE
- Discord
- Instagram
- iMessage
- Facebook Messenger
- Viber
- Skype
- Slack
- Microsoft Teams
- Reddit
- X/Twitter
- TikTok
- Snapchat
- Matrix/Element
- Wire
- Threema
- Session
- Wickr

각 서비스마다 필요한 표시:

- export 기반인지 native DB 기반인지
- 암호화/키/권한 필요 여부
- 메시지/참여자/첨부/반응/읽음/삭제 상태
- schema version
- trusted tool diff 여부

## 12. 클라우드 및 SaaS Export

관련 collector:

- `cloud-export`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| 클라우드 계정 | `cloud-account` | partial+ | provider scope validation |
| 위치 기록 | `cloud-location` | partial+ | timezone/deleted retention |
| 활동 기록 | `cloud-activity` | partial+ | product-specific schema |
| Gmail/메일 | `cloud-mail` | partial+ | MBOX/threading validation |
| Drive/파일 | `cloud-file` | partial+ | version/deleted/share state |
| Teams/메시지 | `cloud-message` | partial+ | Purview/Graph diff |
| Audit log | `cloud-audit` | partial+ | provider-native export diff |
| Google Takeout | profile details | partial+ | product matrix completeness |
| iCloud | profile details | partial+ | ADP/shared album |
| M365/Teams/OneDrive | profile details | partial+ | permissions graph |
| Cloud API collect | separate workflow | partial | OAuth/device flow and vault |

숨은 기능으로 빼서 보여줄 항목:

- Google Takeout
- Gmail
- Drive
- Photos
- Location
- My Activity
- iCloud Photos/Drive/Mail
- Microsoft 365
- Teams
- OneDrive
- SharePoint
- Audit/eDiscovery
- Slack/Dropbox/Box style exports

## 13. 이미지, 영상, 음성, OCR

관련 collector:

- `media-image`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| 이미지 inventory | `media-image` | partial+ | gallery E2E |
| 이미지 hash | details hashes | implemented | hash cache scale |
| perceptual hash | details | partial+ | similarity validation |
| OCR queue hint | details | partial+ | native OCR worker |
| 이미지 thumbnail | details | partial | UI large gallery |
| 영상 inventory | `media-video` | partial | safe playback |
| 영상 transcript sidecar | details | partial | transcript cue validation |
| 오디오 inventory | `media-audio` | partial | waveform generation |
| 오디오 transcript sidecar | details | partial | diarization/transcript validation |

숨은 기능으로 빼서 보여줄 항목:

- 이미지 갤러리
- 유사 이미지 그룹
- OCR 대기열
- OCR 결과 보기
- 번역 sidecar
- 영상/음성 미리보기
- transcript cue citation

## 14. 메모리 포렌식

관련 collector:

- `memory-volatility`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| Volatility JSON import | plugin별 artifact type | partial+ | plugin schema matrix |
| process list import | dynamic | partial+ | process tree/risk scoring |
| network import | dynamic | partial+ | socket/process correlation |
| malfind import | dynamic | partial+ | memory region viewer |
| direct dump indicator scan | `memory-dump-indicators` | partial+ | full memory parser |
| BitLocker candidate scan | details | partial | key validation |
| URL/IP/string scan | details | partial | false-positive control |

숨은 기능으로 빼서 보여줄 항목:

- 메모리 덤프 감지
- Volatility 결과 import
- 프로세스/네트워크/명령줄 보기
- BitLocker 후보
- 악성 문자열/URL/IP 후보
- 메모리 원본 offset citation

## 15. 침해사고, 웹쉘, 원격접속

관련 collector:

- `windows-system`
- `windows-remote-access`
- `linux-system`

| 사용자 노출 기능 | artifact type | 현재 상태 | 남은 보강 |
| --- | --- | --- | --- |
| RDP config | `rdp-config` | partial | registry/event correlation |
| RDP cache | `rdp-cache-file` | partial | bitmap viewer |
| RDP destination | `rdp-destination` | partial | MRU validation |
| Zone.Identifier | `zone-identifier` | partial | download/browser correlation |
| Webshell source 후보 | `webshell-source-candidate` | partial+ | YARA/rule pack validation |
| Web server log | `web-server-log` | partial+ | IIS/Apache/Nginx full fields |
| Linux shell history | `linux-shell-history` | baseline | timestamp/session correlation |
| Linux auth log | `linux-auth-log-event` | baseline | distro-specific parsing |
| Linux auditd | `linux-auditd-event` | baseline | rule interpretation |
| SSH authorized keys | `linux-ssh-authorized-key` | baseline | key owner/history |
| SSH known hosts | `linux-ssh-known-host` | baseline | hashed-host handling |
| Cron | `linux-cron-entry` | baseline | user/system coverage |
| systemd | `linux-systemd-service` | baseline | persistence scoring |
| container config | `linux-container-config` | baseline | runtime-specific parsing |

숨은 기능으로 빼서 보여줄 항목:

- 원격접속 흔적
- 웹쉘 후보
- 서버 로그 상관
- 다운로드 파일 provenance
- Linux persistence
- SSH 접근 흔적

## 16. 리뷰, 검색, 보고서 연결 기능

관련 영역:

- Case DB
- Search
- Source viewer
- Review workflow
- Report/export

| 사용자 노출 기능 | 현재 상태 | GUI 노출 필요 |
| --- | --- | --- |
| 전체 키워드 검색 | baseline+ | 항상 상단 고정 |
| 현재 파일 내부 검색 | baseline+ | source viewer 안에서 노출 |
| Artifact metadata 검색 | baseline+ | 결과 family filter |
| SQLite row search | baseline+ | table/rowid locator |
| OCR text 검색 | partial | sidecar 여부 표시 |
| AI/브라우저/메신저 검색 | partial+ | family tabs |
| 결과 dedup | partial+ | duplicate collapse |
| fuzzy/regex/proximity | partial+ | advanced search panel |
| source viewer | partial+ | 원본 hash/offset/row locator |
| evidence tray | partial+ | 선택/제외/보고서 포함 |
| review status | partial+ | relevant/needs-review/excluded |
| note/tag | partial+ | keyboard-first |
| 비교 보기 | partial | A/B/C compare |
| citation manager | partial+ | source hash/parser/offset |
| report draft | partial+ | limitation 자동 포함 |
| validation package | partial+ | known-answer/trusted diff 상태 |

## 17. GUI에서 숨은 기능을 보여주는 방식

권장 좌측 tree:

1. Case Overview
2. Evidence Images
3. File System
4. Timeline
5. Windows Artifacts
6. Browser / Internet
7. AI Usage
8. Search Index / Documents
9. Email
10. Messenger / Mobile
11. Cloud
12. Media / OCR
13. Memory
14. Incident Response
15. Review / Report

각 tree node 아래에는 다음을 표시한다.

- 결과 수
- 처리 상태
- 검증 상태
- 상용급 blocker 수
- source viewer 가능 여부
- report 포함 가능 여부

## 18. Windows QC에서 확인할 항목

실제 Windows 테스트 시 "기능이 숨어서 안 보이는 문제"를 확인하려면 다음을 체크한다.

- [ ] E01을 넣었을 때 `Browser / Internet` 그룹이 별도 표시되는가.
- [ ] Chrome/Edge/Firefox history row 수가 프로필별로 보이는가.
- [ ] 다운로드 기록과 방문 기록이 분리되어 보이는가.
- [ ] AI Usage 그룹이 별도로 보이는가.
- [ ] ChatGPT/Claude/Gemini/Perplexity/Copilot 방문이 AI 서비스별로 집계되는가.
- [ ] AI 대화 후보가 방문 기록과 분리되어 보이는가.
- [ ] AI 대화 후보에 source storage, offset, hash, confidence가 보이는가.
- [ ] browser storage inventory가 cache/session/extension/cookie/credential로 분리되는가.
- [ ] 민감 저장소는 법적 경고와 함께 기본 비공개로 표시되는가.
- [ ] 검색 결과에서 browser/AI/message/email/document family filter가 되는가.
- [ ] 검색 결과를 누르면 source viewer에서 원본 DB row 또는 파일 offset으로 이동하는가.
- [ ] review tray에 선택 후 보고서에 citation이 들어가는가.
- [ ] 각 artifact에 "상용급 blocker"가 숨지 않고 보이는가.

## 19. 지금 부족한 표시 방식

현재 부족한 점은 기능 자체보다 "보이는 구조" 쪽이 크다.

1. `browser` collector 아래의 기능이 너무 많이 숨겨져 있다.
2. AI 방문과 AI 대화 후보가 사용자에게 같은 기능처럼 보일 위험이 있다.
3. `mobile-export` 안에 메신저, 연락처, 통화, 앱, 파일, 브라우저가 같이 묶여 있다.
4. `windows-execution` 안에 Amcache, ShimCache, BAM/DAM, SRUM, PowerShell이 같이 묶여 있다.
5. `windows-system` 안에 Task, Defender, Firewall, WER, WMI, Zone.Identifier, 웹쉘, 서버 로그가 같이 묶여 있다.
6. `windows-registry` 안에 hive inventory, key tree, deleted recovery, user activity가 같이 묶여 있다.
7. `media-image` 이름 때문에 영상/음성/OCR 기능이 숨는다.
8. `macos-system` 안에 macOS 브라우저와 AI 사용기록이 숨어 있다.

## 20. 우선 UI/문서에 반영할 새 기능명

다음 이름을 GUI/문서/체크리스트의 사용자 노출 기능명으로 사용한다.

| 내부 collector | 사용자 노출 기능명 |
| --- | --- |
| `browser` | 브라우저 방문 기록 |
| `browser` | 브라우저 다운로드 기록 |
| `browser` | 브라우저 통합 타임라인 |
| `browser` | 브라우저 캐시/세션/확장/쿠키 저장소 |
| `browser` | AI 서비스 방문 기록 |
| `browser` | AI 대화 후보 |
| `macos-system` | macOS Safari/Chrome/Firefox 기록 |
| `mobile-export` | 모바일 메시지 |
| `mobile-export` | 모바일 연락처/통화 |
| `mobile-export` | 모바일 앱/파일/미디어 |
| `mobile-export` | 모바일 브라우저 기록 |
| `cloud-export` | Google Takeout |
| `cloud-export` | iCloud Export |
| `cloud-export` | Microsoft 365/Teams/OneDrive |
| `windows-execution` | Amcache |
| `windows-execution` | ShimCache |
| `windows-execution` | BAM/DAM |
| `windows-execution` | SRUM |
| `windows-execution` | PowerShell 기록 |
| `windows-system` | Task Scheduler |
| `windows-system` | Defender |
| `windows-system` | Firewall |
| `windows-system` | WER |
| `windows-system` | WMI |
| `windows-system` | Zone.Identifier |
| `windows-system` | 웹쉘/웹서버 로그 |
| `windows-registry` | Registry Hive |
| `windows-registry` | Registry Deleted Recovery |
| `windows-registry` | NTUSER/UsrClass 사용자 활동 |
| `windows-os-account` | SAM/SECURITY/SYSTEM 계정/권한 |
| `media-image` | 이미지 분석 |
| `media-image` | 영상 분석 |
| `media-image` | 음성/Transcript |
| `media-image` | OCR Queue |

## 21. 결론

전용 파서가 적은 것이 아니라, 현재 기능 표시 단위가 너무 굵다. 특히 `browser`, `mobile-export`, `windows-execution`, `windows-system`, `windows-registry`, `macos-system`, `media-image`는 내부 기능을 반드시 분리해서 보여줘야 한다.

다음 구현 우선순위는 GUI와 API summary에서 위 사용자 노출 기능명을 별도 capability card로 보여주는 것이다. 그렇게 해야 분석자가 "인터넷 사용기록이 되는지", "AI 사용기록이 되는지", "메신저가 어디까지 되는지"를 한눈에 확인할 수 있다.

## 22. 2026-05-14 구현 반영: GUI capability model 1차 연결

이번 라운드에서 단순 문서 분류를 실제 GUI 설정으로 옮겼다. `rapidtriage/web/static/app_workbench_config.js`에 `VISIBLE_FORENSIC_CAPABILITY_GROUPS`와 `VISIBLE_CAPABILITY_STATUS_LABELS`를 추가했고, `rapidtriage/web/static/app.js`의 기능 지도 카드가 각 대분류 아래의 세부 기능 단계와 상태를 같이 보여주도록 연결했다.

완료된 점:

| 영역 | 추가 노출 capability |
| --- | --- |
| 증거 입력 | E01/Ex01, RAW/split, VM disk, AD1/L01/AFF/XVA export workflow |
| EVTX | chunk/record, provider message rendering, corrupt/deleted recovery |
| Registry/계정 | hive tree, NTUSER/UsrClass 사용자 활동, deleted key/value 후보, SAM/SECURITY/SYSTEM |
| 실행/파일시스템 | Amcache, ShimCache, BAM/DAM, Windows.edb row 후보, MFT/USN 경로 재구성 |
| 인터넷 사용기록 | 방문 기록, 다운로드 기록, cache/session/extension/cookie, LocalStorage/IndexedDB, 통합 타임라인 |
| AI 사용기록 | AI 서비스 방문 기록, AI 질문/답변 후보, AI export parser |
| 문서/메일/DB | PDF/Office/text 검색, SQLite viewer, EML/MBOX, PST/OST import 제한 |
| 메신저/모바일 | PC KakaoTalk Windows DB, macOS KakaoTalk inventory, 모바일 메시지/SMS/통화, WhatsApp/Telegram/Signal/LINE |
| 클라우드 | Google Takeout, iCloud export, M365/Teams/OneDrive |
| 미디어/OCR | 이미지 gallery, 영상 preview, 음성 transcript, OCR Queue/번역 |
| DFIR/메모리 | memory dump indicators, PowerShell/LoL/Fileless, WebShell/웹서버 로그 |
| 리뷰/보고서 | 통합 검색/source viewer, evidence tray, citation bundle, audit hash chain |

GUI 표기 방식:

1. 각 기능 카드에는 기존의 큰 모듈명 외에 하위 capability chip이 표시된다.
2. capability에는 `사용 가능`, `부분 구현`, `목록화`, `검증 필요`, `외부 자료 필요` 상태가 붙는다.
3. 분석 모드의 dense UI에서도 chip이 너무 길게 화면을 밀지 않도록 요약 설명은 숨기고 상태 chip만 남긴다.
4. 기능 지도의 통계에는 대분류 수, 기존 function 수, 새 visible step 수가 함께 나온다.
5. capability chip에는 `data-capability-filter`와 `data-capability-tab`이 붙어, chip을 누르면 대분류 필터가 아니라 해당 세부 기능의 대표 키워드로 바로 이동한다.
6. 완료된 run을 열 때 GUI가 `/api/runs/{run_id}/capabilities`를 읽어 capability별 `signal_count`를 chip에 표시한다. 신호가 있는 chip은 `has-signals` 스타일로 강조된다.
7. Python API taxonomy와 JS GUI taxonomy가 어긋나지 않도록, 모든 Python capability id가 `app_workbench_config.js`에도 존재하는지 정적 테스트로 고정했다.

이번에 해결한 부족점:

1. "인터넷 사용기록이 되냐"는 질문이 `browser` 하나로 뭉개지지 않고 방문/다운로드/저장소/캐시/타임라인으로 보인다.
2. "AI 사용기록이 되냐"는 질문이 브라우저 방문 흔적과 질문/답변 후보, export parser로 분리된다.
3. 메신저/모바일/클라우드가 단순 import가 아니라 제품/자료 종류별 capability로 보인다.
4. Windows.edb, SRUM, MFT/USN처럼 아직 깊이 보강이 필요한 항목은 `목록화` 또는 `검증 필요`로 표시되어 과장되지 않는다.
5. `/api/forensic-capabilities`와 `/api/runs/{run_id}/capabilities`가 추가되어, 동일한 capability taxonomy를 API에서도 확인할 수 있다.
6. run별 capability API는 artifact 출력과 summary를 대표 키워드로 스캔해 `signal_count`와 `has_signals`를 붙인다. 이제 GUI가 다음 단계에서 케이스별 readiness를 실제 값으로 덮어쓸 수 있다.

아직 남은 보강:

1. API와 프론트는 capability status와 signal count를 연결했다. 다음 단계는 signal count 계산을 단순 대표 키워드가 아니라 parser output schema와 trusted-tool diff 결과로 보정하는 것이다.
2. 각 capability chip은 현재 대표 키워드 필터까지 연결됐다. 다음 단계는 source viewer anchor와 대표 artifact row까지 이어지는 딥링크다.
3. 현재는 Python/JS 양쪽에 taxonomy가 중복된다. 완성형은 JSON 단일 원본 또는 build-time 생성으로 옮기는 것이다.
4. capability별 trusted-tool diff 결과와 known-answer fixture 통과 여부를 상태 계산에 반영해야 한다.
5. Lucene/Elasticsearch/DuckDB 등 대용량 검색 backend 후보는 아직 GUI 표기만 있고, 실제 benchmark 후 선택해야 한다.
6. 메신저/클라우드/AI export는 버전별 fixture가 부족하므로 `부분 구현` 이상으로 올리려면 실제 샘플 검증이 필요하다.

## 23. 2026-05-14 외부 평가 반영: 전통 핵심 아티팩트와 안티포렌식 보강

추가 평가에서 지적된 핵심은 맞다. 기존 taxonomy는 최신 브라우저/AI 사용기록을 잘 끌어올렸지만, 실제 DFIR/정보유출 현장에서 먼저 확인하는 전통 핵심 아티팩트와 안티포렌식 탐지 항목이 일부 큰 범주 안에 묻혀 있었다. 이번 라운드에서는 해당 항목들을 GUI/API capability card로 별도 노출하여 분석관이 "지원 여부", "현재 구현 상태", "남은 검증"을 바로 확인할 수 있게 했다.

이번에 추가한 사용자 노출 capability:

| 기능 그룹 | 신규 capability | 현재 상태 | 보강 맥락 |
| --- | --- | --- | --- |
| 복원 / 암호화 해제 | VSS/APFS 스냅샷 | 목록화 | 삭제 파일 복구, 랜섬웨어 이전 시점 확인을 위한 이미지 단계 핵심 기능 |
| 복원 / 암호화 해제 | BitLocker/FileVault/LUKS unlock | 외부 자료 필요 | 복구키/패스워드를 받은 합법 unlock workflow와 provenance 필요 |
| 복원 / 암호화 해제 | 비할당 영역 카빙 | 목록화 | 파일시스템 메타데이터가 사라진 삭제 파일/SQLite row 복원 |
| 파일시스템 / 안티포렌식 | $LogFile transaction | 목록화 | $UsnJrnl을 보완하는 create/rename/delete transaction 분석 |
| 파일시스템 / 안티포렌식 | Recycle Bin $I/$R 매핑 | 목록화 | 원래 경로와 삭제 시각을 직관적으로 보여주는 휴지통 전용 뷰 |
| 파일시스템 / 안티포렌식 | Time stomping 탐지 | 목록화 | MFT $SIA/$FNA 불일치 기반 시간 조작 의심 표시 |
| 파일시스템 / 안티포렌식 | 확장자 변조 탐지 | 부분 구현 | 파일 스캔에서 PE/PDF/ZIP/SQLite/이미지 등 magic header와 확장자 mismatch를 `file_signature_profile` / `signature_mismatch_candidates`로 표시 |
| 이벤트 로그 DFIR | ETW/ETL trace | 목록화 | EVTX 외 ETL 기반 USB/WMI/network 행위 추적 |
| 이벤트 로그 DFIR | 로그 삭제 High-Risk | 부분 구현 | Event ID 1102/104 등 로그 삭제 시도 표시 |
| 이벤트 로그 DFIR | 로그온 세션 통합 뷰 | 목록화 | 4624/4634/4647 등 인증 이벤트를 세션으로 재구성 |
| USB / 지속성 / 네트워크 | USB 및 외장매체 연결 이력 | 목록화 | USBSTOR, MountedDevices, setupapi.dev.log 종합 |
| USB / 지속성 / 네트워크 | Persistence/Autoruns 통합 뷰 | 부분 구현 | Run key, 서비스, 스케줄러, WMI persistence를 한 화면에 통합 |
| USB / 지속성 / 네트워크 | Wi-Fi/네트워크 프로필 | 목록화 | 과거 SSID, 접속 시간, 네트워크 프로필 추적 |
| 사용자 실행 / 활동 | LNK 및 JumpList | 부분 구현 | USB 파일 실행, 문서 열람, AppID mapping 확인 |
| 사용자 실행 / 활동 | Windows Timeline ActivitiesCache | 목록화 | Win10/11 사용자 활동과 문서/앱 실행 증거 |
| 사용자 실행 / 활동 | BITS qmgr.dat 전송 | 목록화 | 백그라운드 다운로드/유출 job 추적 |
| 사용자 실행 / 활동 | RecentDocs/Clipboard/MUICache | 목록화 | 사용자 활동 보조 증거를 실행 흔적과 연결 |
| 브라우저 심화 복원 | 시크릿 모드 URL 카빙 | 목록화 | pagefile/hiberfil/memory 잔재에서 URL/검색어 후보 복원 |
| 브라우저 심화 복원 | WebCacheV01.dat | 목록화 | ESE 기반 legacy/webview 통신 흔적 분석 |
| 브라우저 심화 복원 | OneDrive/Google Drive sync DB | 목록화 | 데스크톱 클라우드 sync DB 기반 파일 유출 시점 확인 |
| 로컬/데스크톱 AI | Ollama/LM Studio/GPT4All | 목록화 | 로컬 LLM 모델/프롬프트/로그 흔적 |
| 로컬/데스크톱 AI | ChatGPT/Copilot 데스크톱 앱 DB | `desktop-ai-app-artifact` | 브라우저 밖 AI 앱 로컬 SQLite/cache 분석 |
| 로컬/데스크톱 AI | Windows Copilot Recall | `windows-recall-database`, `windows-recall-snapshot-file` | CoreAIPlatform/UKP DB schema inventory, snapshot hash/signature, OCR/app/window table 후보와 privacy warning |
| 문서 유출 보조 아티팩트 | Print Spooler SPL/SHD | 목록화 | 출력 문서, 사용자, 프린터, 인쇄 시각 확인 |
| 문서 유출 보조 아티팩트 | 문서 메타데이터/매크로 위험 | 부분 구현 | 작성자/수정 이력/인쇄 시각/VBA 위험 플래그 |
| 문서 유출 보조 아티팩트 | Sticky Notes plum.sqlite | 목록화 | 메모장 텍스트/삭제 row/account attribution |
| 모바일 위치 / 생활 패턴 | 위치 정보/동선 지도 | 목록화 | GPS, Wi-Fi, 기지국, 앱 DB 위경도 통합 |
| 모바일 위치 / 생활 패턴 | Health/Fitness 활동 | 목록화 | 걸음 수, 심박, 수면, 기기 조작 가능성 |
| 모바일 위치 / 생활 패턴 | Screen Time/Digital Wellbeing | 목록화 | 앱별 사용 시간과 화면 켜짐/꺼짐 |
| IaaS 보안 로그 | AWS CloudTrail | 목록화 | 클라우드 인프라 침해사고 감사 로그 |
| IaaS 보안 로그 | Azure Activity Log | 목록화 | Azure/Entra/M365 감사 로그 상관 |
| IaaS 보안 로그 | GCP Audit Logs | 목록화 | GCP IAM/service account 감사 로그 |
| 미디어 심화 포렌식 | 사진 EXIF GPS 지도 | 부분 구현 | 이미지 갤러리와 지도/타임라인 연결 |
| 미디어 심화 포렌식 | Steganography 의심 스캔 | 목록화 | entropy/trailing data/known signature 기반 의심 큐 |
| 미디어 심화 포렌식 | Deepfake/조작 의심 | 목록화 | 모델/버전/오탐 경고가 붙은 조작 의심 점수 |
| 디스크 내 메모리 파일 | hiberfil/pagefile 통합 카빙 | 목록화 | 디스크 이미지 내부 메모리 파일 문자열/URL/secret carving |
| 디스크 내 메모리 파일 | MEMORY.DMP/Minidump | 목록화 | crash dump inventory와 의심 문자열 추출 |
| 원격접속 / Tampering | AnyDesk/TeamViewer/RustDesk | 목록화 | 랜섬웨어/유출 사고에서 흔한 상용 원격제어 흔적 |
| 원격접속 / Tampering | Defender/EDR 무력화 | 부분 구현 | Defender 예외, 서비스 중지, policy 변경, 로그 삭제 상관 |
| 검색 / 타임라인 고급 | Super Timeline | 부분 구현 | MFT/USN/EVTX/Registry/Web/Execution 단일 시간축 |
| 검색 / 타임라인 고급 | De-NISTing/Whitelisting | 부분 구현 | `rapidtriage files --known-good-hash-feed`로 MD5/SHA1/SHA256 피드를 읽어 known-good 파일을 표시하거나 `--hide-known-good`로 숨김. Full NSRL RDS import/update와 검색 결과 suppression UI는 남음 |
| 검색 / 타임라인 고급 | YARA / IOC 스캐너 | 부분 구현 | 로컬 rule/IOC hit를 `ioc_scanner_hits`로 모아 source pointer와 manifest를 제공. Native YARA grammar/신뢰 corpus diff는 남음 |

구현 반영:

1. `rapidtriage/web/static/app_workbench_config.js`에 위 capability group과 chip을 추가했다.
2. `rapidtriage/core/visible_capabilities.py`에도 동일 capability를 추가해 `/api/forensic-capabilities`와 `/api/runs/{run_id}/capabilities`에서 같은 taxonomy가 보인다.
3. 정적 테스트는 대표 capability ID가 GUI 설정에 반드시 노출되는지 확인한다.
4. API 테스트는 AnyDesk, USBSTOR/setupapi, Print Spooler 같은 샘플 artifact row가 capability signal로 잡히는지 확인한다.

아직 남은 보강:

1. 이번 반영은 “사용자에게 숨기지 않는 capability 노출” 단계다. 상용급 parser 완료를 의미하지 않는다.
2. `목록화` 항목은 parser 구현, fixture, trusted-tool diff, FP/FN 문서가 있어야 `부분 구현` 또는 `사용 가능`으로 올릴 수 있다.
3. VSS/APFS snapshot, FDE unlock, ETL, $LogFile, WebCacheV01, Recall DB/snapshot, BITS, SPL/SHD, AnyDesk/TeamViewer/RustDesk는 실제 Windows/macOS 샘플 기반 검증이 필요하다.
4. YARA/IOC, De-NISTing, Super Timeline은 대용량 성능과 UI cursor pagination이 같이 검증돼야 한다.
5. Deepfake/steganography는 법정 표현이 특히 민감하므로 “탐지”가 아니라 “의심 후보” wording, 모델 버전, 오탐 경고를 강제해야 한다.

## 24. 2026-05-14 구현 반영: 빠른 triage 파서 1차 보강

이번 라운드는 단순 기능명 추가가 아니라 실제 artifact row가 생성되는 항목을 먼저 올렸다. 상용급 최종 decoder는 아니지만, Windows E01 또는 추출 폴더 안에 관련 파일이 있으면 분석관이 GUI/API/검색에서 바로 볼 수 있는 triage row가 생긴다.

부분 구현으로 승격한 capability:

| capability | 새 artifact row | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| Recycle Bin $I/$R 매핑 | `recycle-bin-entry` | `$Recycle.Bin` 아래 `$I*` metadata에서 원래 경로, 삭제 시각, 삭제 파일 크기를 읽고 sibling `$R*` payload hash를 연결한다. | MFT/USN delete timeline 상관, Windows 버전별 fixture, trusted parser diff |
| 확장자 변조 탐지 | `file-signature-mismatch`, `file_signature_profile`, `signature_mismatch_candidates` | Windows artifact scan과 일반 파일 스캔 모두 PE/PDF/PNG/JPEG/GIF/ZIP/OLE/RAR/7z/SQLite magic header와 확장자를 비교해 mismatch 파일을 위험 후보로 표시한다. | 전체 파일타입 parser, 오탐 정책, archive 내부 파일 검사 |
| Print Spooler SPL/SHD | `print-spooler-job` | `spool/PRINTERS`의 `.SPL`/`.SHD` 파일을 찾아 hash, mtime, bounded strings, 문서 경로 후보를 추출한다. | SPL/SHD 구조 decoder, printer eventlog 상관, driver별 spool fixture |
| AnyDesk/TeamViewer/RustDesk | `third-party-remote-control-artifact` | AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop 경로/파일을 찾아 URL/IP/string pivot과 product tag를 생성한다. | 제품별 session decoder, peer ID/IP/파일전송 로그 검증, 계정 attribution |

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts.py`에 Recycle Bin + signature mismatch fixture를 추가했다.
2. 같은 테스트 파일에 Print Spooler + AnyDesk fixture를 추가했다.
3. visible capability status는 위 4개 항목을 `목록화`에서 `부분 구현`으로 올렸다.
4. API signal matching이 실제 새 artifact type 이름으로도 잡히도록 capability terms를 보강했다.

중요한 제한:

1. `recycle-bin-entry`의 삭제 시각은 `$I` metadata 기반이다. 보고서 확정 증거로 쓰려면 MFT/USN과 교차검증해야 한다.
2. `file-signature-mismatch`는 “위장/은닉 의심”이지 의도 입증이 아니다. 정상적인 무확장 파일, 캐시, 임시 파일에서 오탐이 가능하다.
3. `print-spooler-job`은 현재 bounded string inventory다. 실제 출력된 문서명/소유자/프린터를 구조적으로 확정하려면 SPL/SHD decoder가 필요하다.
4. `third-party-remote-control-artifact`는 파일 존재와 string pivot이다. 실제 접속 세션, 원격 ID, 파일 전송 여부는 제품별 로그 decoder가 필요하다.

## 25. 2026-05-14 구현 반영: 앱/클라우드/디스크 메모리 triage 2차 보강

이번 라운드는 GUI에만 보이던 일부 capability를 실제 수집 결과로 연결했다. 목표는 Windows/macOS 단일 케이스에서 "파일이 있으면 분석관에게 숨지 않고 보이는 것"이다. 아직 상용급 확정 decoder가 아니라 triage-normalized row이며, 각 row에는 `validation_required` 또는 commercial blocker를 남긴다.

부분 구현으로 승격한 capability:

| capability | 새 artifact row | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| Sticky Notes plum.sqlite | `sticky-note`, `sticky-note-db-unreadable` | `plum.sqlite`를 read-only SQLite로 열고 note text, deleted flag, account hint, created/updated 후보, text hash를 추출한다. | Sticky Notes 버전별 schema fixture, deleted row recovery, 계정/기기 attribution 교차검증 |
| Ollama/LM Studio/GPT4All | `local-llm-artifact` | `.ollama`, LM Studio, GPT4All 경로와 `.gguf/.ggml/.safetensors` 모델 파일, config/log/db 파일을 inventory row로 노출한다. | 제품별 prompt/history DB parser, 모델 provenance, 앱 버전별 fixture |
| AWS CloudTrail | `cloud-iaas-audit` | `Records` CloudTrail JSON에서 eventTime, eventSource, eventName, principal, source IP, account, region, request preview를 정규화한다. | AWS organization/account scope, CloudTrail digest/log integrity, provider console/SIEM diff |
| Azure Activity Log | `cloud-iaas-audit` | Azure/Entra path 또는 `operationName`, `callerIpAddress`, `subscriptionId`, `resourceId` 기반 감사 row를 IaaS audit으로 분류한다. | tenant/subscription scope, Entra/M365 상관, provider-native diff |
| GCP Audit Logs | `cloud-iaas-audit` | `protoPayload.methodName`, principalEmail, callerIp, project label 후보를 GCP audit row로 정규화한다. | project/folder/org scope, service account key abuse fixture, provider-native diff |
| hiberfil/pagefile 통합 카빙 | `disk-memory-file-indicators` | `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`를 메모리 후보로 스캔해 URL/IP/프로세스/BitLocker pivot을 생성한다. | hiberfil decompression, pagefile structure-aware carving, disk offset citation 강화 |
| MEMORY.DMP/Minidump | `crash-dump-indicators` | `MEMORY.DMP`와 `.dmp`를 crash dump 후보로 분리하고 bounded pivot scan 결과를 표시한다. | minidump 구조 parser, Volatility profile handoff, dump type별 fixture |

대용량 보호:

1. 로컬 LLM 모델 파일과 디스크 메모리 파일은 크기가 큰 경우 전체 해시를 즉시 계산하지 않고 `hash_status=deferred-large-file` 또는 `deferred-large-memory-file`로 표시한다.
2. 메모리 파일은 기존 bounded scan range를 유지해 pagefile/hiberfil이 커도 전체를 무제한 읽지 않는다.
3. Sticky Notes는 row limit을 두고 추출하며, 본문 원문과 별도로 `text_sha256`을 남겨 리뷰/보고서 citation에 쓸 수 있게 했다.

검증 포인트:

1. `tests/test_rapidtriage_generic_documents.py`가 `generic-documents` collector 노출, Sticky Notes row, 로컬 LLM 모델 inventory를 검증한다.
2. `tests/test_rapidtriage_cloud_export.py`가 AWS CloudTrail `Records` JSON을 `cloud-iaas-audit`로 정규화하는지 검증한다.
3. `tests/test_rapidtriage_memory_volatility.py`가 `pagefile.sys`와 `MEMORY.DMP`를 각각 disk-memory/crash-dump artifact로 분리하는지 검증한다.
4. Python/JS capability taxonomy는 해당 capability들을 `목록화`에서 `부분 구현`으로 올리고, 실제 artifact type term을 추가했다.

중요한 제한:

1. `sticky-note`는 SQLite live row 중심이다. 삭제된 free page 복원은 아직 아니다.
2. `local-llm-artifact`는 모델/앱 파일 존재와 역할 분류다. 프롬프트/대화 복원은 제품별 DB schema가 필요하다.
3. `cloud-iaas-audit`는 provider export row 정규화다. 클라우드 계정 전체 범위나 로그 무결성을 증명하지 않는다.
4. `disk-memory-file-indicators`는 bounded string pivot이다. hiberfil 압축 해제나 pagefile 구조 복원은 다음 단계다.

## 26. 2026-05-14 구현 반영: Windows 활동/웹캐시/동기화 DB triage 3차 보강

이번 라운드는 사용자 행위 입증과 정보유출 조사에서 자주 보는 Windows 활동/전송/웹뷰/클라우드 동기화 흔적을 실제 artifact row로 연결했다. 목표는 "분석 메뉴에만 있고 결과에는 안 보이는 기능"을 줄이는 것이다.

부분 구현으로 승격한 capability:

| capability | 새 artifact row | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| Windows Timeline ActivitiesCache | `activities-cache-db` | 기존 Windows system collector의 `ActivitiesCache.db` read-only SQLite schema/timeline sample inventory를 visible capability와 연결했다. | ActivitiesCache 테이블별 row semantics, app/document/URL attribution, deleted state 검증 |
| BITS qmgr.dat 전송 | `bits-qmgr-transfer-candidate` | `qmgr0.dat/qmgr1.dat/qmgr.dat/qmgr.db`와 `Network/Downloader` DB 후보를 bounded string scan하여 URL/path pivot, mtime, hash, risk flag를 만든다. | BITS job 구조 decoder, owner/state/retry/transfer time, trusted BitsParser/Velociraptor diff |
| WebCacheV01.dat | `webcachev01-ese-file` | `WebCacheV01.dat`의 ESE header, page size 후보, bounded URL/path/string pivot을 추출한다. | ESE catalog/table/long value decoder, container별 history/cache/cookie row 복원, deleted record recovery |
| OneDrive/Google Drive sync DB | `desktop-cloud-sync-db` | OneDrive/Google Drive/DriveFS 경로의 sync DB 후보를 read-only SQLite schema inventory로 열고 file/sync/delete/share/account semantic hint를 만든다. | provider/version별 sync DB parser, upload/delete/share timestamp semantics, account scope 검증 |

대용량/안전 설계:

1. `WebCacheV01.dat`는 ESE 전체 row decode가 아니라 header와 bounded string pivot만 수행한다.
2. `desktop-cloud-sync-db`는 SQLite schema와 row count만 읽고, 원문 값은 기본적으로 노출하지 않는다.
3. 브라우저/클라우드 sync 대형 DB는 `safe_browser_file_hashes` 정책으로 일정 크기 이상이면 전체 해시를 지연한다.
4. BITS qmgr 파일은 2MB prefix scan으로 제한해 대형/손상 파일에서도 collector가 멈추지 않게 했다.

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts.py::test_windows_system_collector_maps_bits_qmgr_transfer_candidates`가 BITS URL/path pivot과 reportability blocker를 검증한다.
2. `tests/test_rapidtriage_windows_artifacts.py::test_windows_browser_collector_maps_webcache_and_cloud_sync_db_candidates`가 WebCache ESE signature와 OneDrive sync DB SQLite inventory를 검증한다.
3. Python/JS visible capability status는 ActivitiesCache, BITS, WebCacheV01, desktop cloud sync DB를 `부분 구현`으로 올리고 실제 artifact type terms를 추가했다.

중요한 제한:

1. `bits-qmgr-transfer-candidate`는 URL/path string 후보이지 완성된 BITS job record가 아니다.
2. `webcachev01-ese-file`은 ESE header/string pivot이다. 방문 시각, container, cache entry, 삭제 상태를 아직 확정하지 않는다.
3. `desktop-cloud-sync-db`는 schema inventory다. 파일이 업로드/삭제/공유됐다는 최종 결론은 provider-specific parser와 계정 scope 자료가 필요하다.

## 27. 2026-05-14 구현 반영: NTFS 로그/ETL/USB/Wi-Fi triage 4차 보강

이번 라운드는 정보유출/침해사고 조사에서 “있으면 반드시 보여야 하는데 아직 메뉴 수준에 가까웠던” Windows 저수준 흔적을 실제 artifact row로 연결했다. 모두 상용급 최종 판정 parser가 아니라 bounded triage row이며, 보고서 확정 전 검증 요구사항을 row 내부에 남긴다.

부분 구현으로 승격한 capability:

| capability | 새 artifact row | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| `$LogFile` transaction | `ntfs-logfile-transaction-candidate` | `$LogFile` 파일을 찾아 `RSTR/RCRD/CHKD` signature, path string pivot, source hash, scan byte, mtime을 기록한다. | redo/undo record decoder, `$MFT/$UsnJrnl` timeline join, LogFileParser/MFTECmd diff |
| ETW/ETL trace | `etl-trace-file` | `.etl` 파일을 이벤트 로그 collector에서 노출하고 provider hint, USB/WMI/network/execution family, URL/path/IP pivot을 bounded scan한다. | ETW event header decoder, provider manifest field rendering, tracerpt/WPT/Velociraptor diff |
| USB 및 외장매체 연결 이력 | `usb-setupapi-device-install-candidate` | `setupapi.dev.log`에서 `USBSTOR`/`USB\\VID...` install-context line과 timestamp hint를 추출한다. | USBSTOR/Enum USB/MountedDevices/drive-letter 상관, first/last connect 검증 |
| Wi-Fi/네트워크 프로필 | `wifi-profile` | `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces` XML에서 profile name, SSID, connection mode, auth/encryption, MAC randomization을 정규화한다. | WLAN AutoConfig EVTX/ETL 연결 시각, NetworkList registry 상관, trusted parser diff |

대용량/안전 설계:

1. `$LogFile`은 8MB prefix scan으로 제한해 대형 파일에서 수집기가 멈추지 않도록 했다.
2. `.etl`은 4MB prefix scan으로 provider/string pivot만 추출한다. 구조 decode를 가장하지 않는다.
3. `setupapi.dev.log`는 4MB scan과 최대 500개 install context entry 제한을 둔다.
4. Wi-Fi profile은 XML 파일 단위 정규화라 대용량 부담이 작고, 연결 여부 판정은 하지 않는다.

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts.py::test_windows_filesystem_collector_maps_ntfs_logfile_transaction_candidates`가 `$LogFile` signature/path pivot row를 검증한다.
2. `tests/test_rapidtriage_windows_artifacts.py::test_windows_eventlog_collector_maps_etl_trace_files`가 `.etl` provider hint와 USB/network pivot을 검증한다.
3. `tests/test_rapidtriage_windows_artifacts.py::test_windows_system_collector_maps_setupapi_usb_and_wifi_profiles`가 SetupAPI USB install 후보와 WLAN profile XML 정규화를 검증한다.
4. Python/JS visible capability status는 `$LogFile`, ETL, USB, Wi-Fi를 `부분 구현`으로 올리고 실제 artifact type terms를 추가했다.

중요한 제한:

1. `ntfs-logfile-transaction-candidate`는 transaction page 후보와 string pivot이다. 파일 생성/삭제/rename 결론을 단독으로 내리면 안 된다.
2. `etl-trace-file`은 provider/string inventory다. ETW event payload를 구조적으로 해석하지 않는다.
3. `usb-setupapi-device-install-candidate`는 설치 흔적이다. 실제 연결 시각/드라이브 문자/파일 복사 여부는 registry와 파일시스템 timeline 상관이 필요하다.
4. `wifi-profile`은 저장된 네트워크 설정이다. 실제 접속 여부나 위치/물리적 존재 입증은 EventLog/ETL/NetworkList와 결합해야 한다.

## 28. 2026-05-14 구현 반영: 로그온 세션 통합 row 보강

이전까지는 4624/4634/4647 이벤트가 각각의 이벤트 row로만 보였고, 분석관이 계정별 세션을 직접 머릿속에서 묶어야 했다. 이번 라운드에서는 EventLog collector가 인증 이벤트를 `TargetLogonId`/`LogonId` 또는 계정·소스 IP pivot 기준으로 묶어 `eventlog-logon-session` row를 추가한다.

부분 구현으로 승격한 capability:

| capability | 새 artifact row | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| 로그온 세션 통합 뷰 | `eventlog-logon-session` | 4624, 4634, 4647, 4672, 4778, 4779를 세션 key로 묶어 시작/종료, duration, 계정, logon type, source IP, risk flag를 만든다. | Security channel 전체 export 완전성 검증, logon ID 재사용 처리, RDP/network/process 상관 |

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts.py::test_windows_eventlog_collector_builds_logon_session_rows`가 4624/4634 fixture를 같은 세션으로 묶고 duration/risk flag를 검증한다.
2. visible capability status는 `logon-session-timeline`을 `부분 구현`으로 올리고 실제 artifact type term인 `eventlog-logon-session`을 추가했다.

중요한 제한:

1. Security 로그가 필터링되었거나 일부만 export된 경우 `open-or-not-observed` 상태가 정상적으로 나올 수 있다.
2. Windows의 LogonId는 재사용될 수 있으므로 장시간/다중 부팅 분석에서는 boot/session boundary와 함께 검증해야 한다.
3. RDP 여부는 LogonType 10과 4778/4779 등 이벤트 기반 triage이며, 최종 판단은 TerminalServices 로그와 네트워크 흔적을 함께 봐야 한다.

## 29. 2026-05-14 구현 반영: MFT Time Stomping triage 보강

이전까지 Time Stomping은 사용자 노출 taxonomy에만 있었고, 실제 MFT row에는 위험 플래그가 없었다. 이번 라운드에서는 native `$MFT` FILE record에서 `$STANDARD_INFORMATION`과 `$FILE_NAME` attribute의 FILETIME 4종을 비교해 불일치가 있으면 `timestamp_stomping_analysis`와 `mft-sia-fna-timestamp-mismatch` risk flag를 남긴다.

부분 구현으로 승격한 capability:

| capability | 새 필드 / risk flag | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| Time stomping 탐지 | `timestamp_stomping_analysis`, `time_stomping_suspected`, `mft-sia-fna-timestamp-mismatch` | MFT row별 `$SIA/$FNA`의 created/modified/MFT modified/accessed time을 비교하고 mismatch field, 값, file name namespace를 기록한다. | `$UsnJrnl`, `$LogFile`, Prefetch, LNK/JumpList와 자동 상관하고 MFTECmd/analyzeMFT diff corpus로 FP/FN 검증 |

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts.py::test_windows_filesystem_collector_imports_mft_and_usn_rows`가 정상 MFT fixture에서 `sia-fna-compared`와 `time_stomping_suspected=False`를 검증한다.
2. `tests/test_rapidtriage_windows_artifacts.py::test_windows_filesystem_collector_flags_mft_sia_fna_timestamp_mismatch`가 `$FILE_NAME` timestamp를 다르게 만든 fixture에서 mismatch 4건과 risk flag를 검증한다.
3. Python/JS visible capability status는 `timestamp-stomping-detection`을 `부분 구현`으로 올리고 실제 row 필드명을 검색 term으로 추가했다.

중요한 제한:

1. `$SIA/$FNA` 불일치는 강한 단서지만 단독으로 “의도적 시간 조작”을 확정하지 않는다.
2. NTFS 정상 동작, copy/move, archive extraction, legacy timestamp propagation으로도 일부 divergence가 생길 수 있다.
3. 보고서 확정에는 USN/$LogFile/execution artifact와 신뢰 도구 diff가 필요하다.

## 30. 2026-05-14 구현 반영: RecentDocs/Clipboard/MUICache 사용자 활동 보강

RecentDocs와 file dialog MRU는 이미 `registry-user-activity`로 정규화되고 있었지만, 사용자 노출 capability 이름에 포함된 `MUICache`와 `Clipboard`가 별도 category로 분류되지 않았다. 이번 라운드에서는 registry activity classifier에 `muicache`와 `clipboard-history` category를 추가하고, 민감한 clipboard 값은 `sensitive-content-review` 플래그를 붙인다.

부분 구현으로 승격한 capability:

| capability | 새 category / risk flag | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| RecentDocs/Clipboard/MUICache | `muicache`, `clipboard-history`, `sensitive-content-review` | Reg export/native hive string pivot에서 RecentDocs, RunMRU, OpenSavePidlMRU 외에 Shell MUICache와 Clipboard 관련 key를 `registry-user-activity` row로 정규화한다. | `RecentFileCache.bcf` parser, CloudClipboard store decoder, value timestamp semantics, trusted RECmd/RegistryExplorer diff |

검증 포인트:

1. `tests/test_rapidtriage_windows_artifacts_collectors.py::test_registry_user_activity_normalizes_mru_dialog_network_and_device_rows`가 RecentDocs, OpenSavePidlMRU, MUICache, Clipboard, MountPoints2, Network share를 한 fixture에서 검증한다.
2. visible capability status는 `recentdocs-clipboard-muicache`를 `부분 구현`으로 올리고 실제 row type인 `registry-user-activity`와 category term을 추가했다.

중요한 제한:

1. MUICache는 표시 이름/cache 성격이 강해 단독 실행 증거가 아니다.
2. Clipboard 관련 값은 민감정보를 포함할 수 있으므로 보고서 포함 전 범위/권한/최소 공개 원칙이 필요하다.
3. Clipboard history의 실제 content store는 Windows 버전과 CloudStore 구조에 따라 달라질 수 있어 추가 fixture가 필요하다.

## 31. 2026-05-14 구현 반영: pagefile/hiberfil/memory URL 카빙 실사용 보강

이전 메모리 collector는 `pagefile.sys`, `hiberfil.sys`, `MEMORY.DMP`, `.raw/.vmem` 등에서 URL/IP/프로세스/BitLocker 문자열을 bounded scan으로 뽑았지만, URL이 어떤 의미인지 구분하지 못했다. 이번 라운드에서는 URL pivot마다 private browsing context, AI 서비스, 검색엔진/검색어 후보를 분류하고 `web_recovery_profile`로 요약한다.

부분 구현으로 승격한 capability:

| capability | 새 필드 / risk flag | 구현 내용 | 남은 상용급 보강 |
| --- | --- | --- | --- |
| Memory dump indicators | `web_recovery_profile`, URL `classification` | memory/pagefile/hiberfil/crash dump URL pivot에 host, service, category, query term hash/preview, confidence를 붙인다. | Volatility process ownership, full memory parser, fragmented URL FP/FN corpus |
| 시크릿 모드 URL 카빙 | `private-browsing-url-candidate`, `search-query-url-candidate`, `ai-service-url-candidate` | URL 주변 문자열에서 `Incognito/InPrivate/private browsing` context를 잡고, ChatGPT/Claude/Gemini/Perplexity 등 AI 서비스 URL과 검색어 query parameter를 분류한다. | Browser history/WebCacheV01/DNS/process 상관, stale memory 판단, acquisition-time correlation |

검증 포인트:

1. `tests/test_rapidtriage_memory_volatility.py::test_disk_memory_files_and_crash_dumps_are_scanned_as_visible_artifacts`가 `pagefile.sys` fixture에서 Incognito context, Google 검색어, ChatGPT URL을 분류하고 risk flag를 검증한다.
2. visible capability status는 `memory-dump-indicators`와 `incognito-memory-pagefile-carving`을 `부분 구현`으로 올리고 실제 output field/risk flag term을 추가했다.

중요한 제한:

1. pagefile/hiberfil/memory 문자열은 stale, fragmented, copied cache일 수 있어 단독 방문 증거가 아니다.
2. URL query preview는 분석 편의상 제한 길이로 노출되며, 원문 검색어는 report inclusion 전에 민감정보 검토가 필요하다.
3. 상용급 판정에는 process owner, browser DB, DNS/cache, WebCacheV01, acquisition timestamp와의 상관분석이 필요하다.

## 32. 2026-05-14 구조 반영: Run Workflow Contract 추가

이전 GUI는 “분석/추출/검색” 3개 핵심 흐름을 화면에서만 추정했다. 이번 구조정리에서는 `rapidtriage-run-summary.json`에 `workflow.profile_version=run-workflow-contract-v1`을 추가하여, 실행 산출물 자체가 `ingest -> extract -> parse -> index -> review -> report` 상태를 증명하게 했다.

GUI 노출 계약:

| stage | GUI primary tab | 의미 | 상태 판단 근거 |
| --- | --- | --- | --- |
| `ingest` | Summary | E01/RAW/VM/폴더 입력, source/analysis root, fingerprint/checkpoint | `source`, `fingerprint`, image metadata outputs |
| `extract` | Files | 문서/파일 후보 추출과 해시 manifest | `docs-extract`, `files-extract` step/output |
| `parse` | Artifacts | manifest, docs/files scan, 전용 artifact collector | `manifest`, `docs`, `files`, `artifacts-*` |
| `index` | Search | docs index, timeline, indicators, FTS 최적화 | `docs-index`, `timeline`, `indicators` |
| `review` | Review | silent-failure, parser crash, memory cap, preview sandbox handoff | warning/zero-row/reused-output evidence |
| `report` | Report | run summary/report/timeline report | `summary`, `report`, `timeline_report` |

2026-05-14 추가 보강:

각 stage는 이제 `handoff_outputs`를 함께 가진다. 이 배열은 output 이름, 사용자 관점 역할, 권장 viewer, GUI action, reportability note를 담는다. GUI는 이 값을 사용해 stage 카드에서 `/api/runs/{run_id}/outputs/{output_name}/file` 링크를 바로 노출한다. 즉 분석관은 “단계가 완료됨”이라는 추상 상태에서 멈추지 않고, 해당 단계를 신뢰하기 전에 열어봐야 할 산출물로 즉시 이동할 수 있다.

또한 stage output은 `/api/runs/{run_id}/outputs/{output_name}/preview`로 bounded preview를 열 수 있다. GUI의 `Preview` 버튼은 이 API를 사용해 report, summary, timeline, artifact JSON 같은 run output을 source viewer rail 안에서 바로 확인하게 한다. 이 preview는 `run-output-preview-v1`로 표시되며, source evidence citation을 대체하지 않는 review aid로 명시된다.

각 stage는 이제 `analyst_checklist`도 가진다. 체크리스트는 stage별 필수 확인 항목, severity, ready/warning/blocked/pending 상태, 기대 output, 실제 연결 output, 다음 행동을 담는다. 상단 `analyst_checklist_summary`는 전체 확인 항목의 상태를 요약해 GUI에서 “어떤 단계가 아직 신뢰 가능한 결론으로 가기 전에 열람/해결되어야 하는가”를 바로 보여준다. 이 기능은 상용 도구처럼 복잡한 버튼을 많이 늘리는 대신, 분석관이 누락하기 쉬운 검증 행위를 workflow 카드 안에 고정시키는 목적이다.

동일한 체크리스트는 `rapidtriage-run-report.md`의 `Workflow analyst checklist` 섹션에도 반영된다. 즉 GUI에서 보던 stage verification item과 ready/warning/blocked/pending 요약이 markdown 보고서에도 남아, 후속 리뷰자가 어떤 확인 의무가 남았는지 재현할 수 있다.

검증 포인트:

1. `tests/test_rapidtriage_run.py::test_run_workflow_contract_maps_internal_steps_to_analyst_flow`가 내부 step/output을 6개 사용자 stage로 매핑하고 warning stage를 검증한다.
2. `tests/test_rapidtriage_run.py::assert_run_mode_outputs`가 모든 run mode의 summary에 workflow contract와 stage lookup이 포함되는지 확인한다.
3. GUI는 `renderCoreEvidenceWorkflow`, `renderRunWorkflowContract`, `renderRunWorkflowOutputLinks`, `renderRunWorkflowChecklist`, `renderRunWorkflowOutputViewer`에서 이 계약을 읽어 단일 케이스 흐름, stage별 산출물 링크/미리보기, 분석관 체크리스트를 표시한다.
4. `rapidtriage-run-report.md`는 `Workflow analyst checklist` 섹션에 같은 체크리스트를 기록해 GUI와 보고서의 검토 기준을 맞춘다.

중요한 제한:

1. 이 구조는 workflow visibility contract이며, 각 parser의 상용급 정확도를 자동으로 보장하지 않는다.
2. E01/RAW/VM 입력의 dependency preflight와 실제 mount/extract 성공 여부는 기존 image workflow manifest와 함께 봐야 한다.
3. 대용량 검증은 stage contract만으로 충분하지 않고 cursor API, fixture corpus, trusted-tool diff 결과가 별도로 필요하다.
