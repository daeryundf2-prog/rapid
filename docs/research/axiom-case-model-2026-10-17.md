# AXIOM Examine 케이스 모델 관찰 — RapidForensic과 비교 (2026-10-17)

사용자가 제공한 AXIOM 9.9 케이스 폴더(E01 1개, 2026-08 처리, 동글 없이 열람만 가능)를 **실행하지 않고** 케이스 DB(`Case.mfdb`, SQLite 8.6 GB, 75 테이블)와 부속 파일(`Case Information.txt/xml`, `Export*/`, 로그)을 읽기 전용(`mode=ro&immutable=1`)으로 분석했다. 행 내용(PII)은 읽지 않았고 스키마·메타데이터·건수만 사용했다. 원본 경로·사건 정보는 이 문서에 적지 않는다.

목적: (1) "케이스 만들기"가 어떤 정보로 시작되는가, (2) 아티팩트가 어떻게 분류·열 구성되는가, (3) 검토(태그·메모·내보내기)가 어떻게 돌아가는가를 관찰해 우리 콘솔의 격차를 정리한다.

## 1. 케이스 생성 모델 — 우리에게 없는 단계

AXIOM은 **케이스 → 증거(여러 개) → 스캔(처리 1회) → 작업(job)** 의 4층이다. 우리는 "런 1개 = 케이스 1개"라서 첫 층이 없다.

| AXIOM | 저장 위치 | 내용 |
|---|---|---|
| 케이스 정보 | `case_info` + `case_info_attribute` + `case_info_note` | 사건 번호, 사건명, 사건 유형, 검사관, 설명, 생성 시각/생성자(UTC), 케이스 폴더, 첨부 관리자, 태그 동기화 설정, 케이스 메모(작성자·시각·삭제 표시) |
| 증거 | `source_evidence` (증거 번호, 위치, 검색 모드) ↔ `source`(트리: Image › Partition › Folder › File/FileSlack/UnallocatedSpace/Hiberfil/OrphanedRoot) | 증거 번호는 사용자가 입력. 소스 트리 183만 노드, 속성(`source_attribute`) 1,675만 행: MFT 레코드/부모 번호, SI 4종 시각, 보안 ID, 논리 크기, MD5, 삭제 여부, 클러스터 오프셋/수, 물리 섹터, 사용자 접근 가능 여부, MIME |
| 스캔 설정 | `scan_attribute` | AXIOM 버전, 중복 제거, 키워드/정규식 수(28), 아카이브 검색, 모바일 백업 검색, 해시 스킵, 해시 태깅, 중첩 컨테이너 깊이(5), OCR 상태, PhotoDNA 임계값, 아티팩트 처리 모드, **아티팩트 시간창 필터(시작/끝/날짜 없는 항목 포함)**, 특권 콘텐츠 모드, 검색 소요(19,318 s)·인덱싱 소요 |
| 처리 항목 | `process_item` | 드라이브별 항목: 유형(전체/섹터 레벨/분할되지 않은 공간), 상태(완료/검색 중-100%), 암호화·해제 여부, 출발점(사용자 추가/백로그), 검색 경로 JSON, 소요(ms) |
| 처리 문제 | `scan_problem`, `source_exception` | 사유 id + 지역화 파라미터 JSON(이 케이스는 예외 600건, 사유 1종) |
| 작업 | `job`, `job_attribute` | 유형(특성 추출, 인덱싱 등)·상태·시작/끝·버전·파라미터 JSON, 사후 작업(2개월 뒤 인덱스 재생성)도 기록 |
| 사용자 | `user`, `user_info`, `user_case`, `user_case_setting`, `user_setting` | 케이스별 사용자 설정: 태그 단축키, 시간대(KST), 날짜 형식, 미디어 분류, **내보내기 이력**, 마지막 소스 위치, 절대/상대 시간 필터 이력 |

`Case Information.txt`는 위 설정 + "선택한 검색 항목"(플랫폼별 아티팩트 체크리스트, 컴퓨터 플랫폼만 200+)을 사람이 읽는 형태로 복제한 것이다. 처리 시작 시 **무엇을 켰는지가 케이스에 고정**된다.

### 우리 격차 (P2 "케이스 만들기" 요구사항으로 승격)
1. 케이스 생성 대화상자: 사건 번호(필수)·사건명·사건 유형·검사관·의뢰처·설명·케이스 폴더 → `rapidtriage-case.db`에 `case_info`/`case_note`.
2. 증거 추가: 케이스 안에 증거 N개(번호·종류 E01/폴더/모바일 내보내기·해시 검증 상태·검색 모드), 증거마다 런 1개 이상.
3. 처리 옵션 스냅샷: 켠 프로바이더·키워드 수·시간창·OCR·중복 제거를 케이스에 고정 저장하고 접수 대시보드에 "처리 설정" 카드로 표시(우리 `rapidtriage-run-summary.json`의 `profile`·`safety`·`resource_caps`가 원재료).
4. 사용자/검사관 모델: 메모·태그·내보내기 이력에 작성자·시각을 남긴다(지금 리뷰 마크에는 작성자가 없음).
5. 문제 보고: 처리 문제를 사유별 집계 + 항목 연결(우리 `warnings` 19건은 평문 목록).

## 2. 아티팩트 분류 — 15 그룹 × 프로그램 × 아티팩트 버전

- `artifact_group`(15): Additional Sources, Analyst created, Application Usage, Cloud Storage, Communication, Connected Devices, Custom, Documents, Email & Calendar, Encryption & Credentials, Location & Travel, Media, Operating System(60 아티팩트), Refined Results(14), Web Related(43).
- `artifact_program`(약 110): 프로그램 단위 묶음(Chrome 13, Edge 17, Windows Search 6, AmCache 7, SRUM 5, File Signature Mismatch 5, Windows Event Logs 11 세부 …). 트리는 그룹 › 프로그램 › 아티팩트로 접힌다.
- `artifact_version`: 아티팩트마다 버전 번호가 있고 결과(`scan_artifact_hit`)는 버전에 묶인다 → 파서 버전이 바뀌어도 옛 결과를 그대로 읽는다. 우리에겐 파서 버전이 결과에 없다(인용 재현성 격차).
- 이 케이스 결과 1,762,839건. 상위: Windows Event Logs 590,810 · UsnJrnl 363,950 · File Signature Mismatch(Document) 271,200 · Pictures 223,508 · Potential Browser Activity 85,106 · SRUM App Resource 36,321 · Windows Search-Image 19,591 · Edge Cache 13,587 · Email Attachments 12,920 · Scheduled Task Events 10,618 · $LogFile 10,587.
- **Refined Results(파생 아티팩트)**: Locally Accessed Files and Folders 5,341(LNK·Jump List·Shellbags·MRU에서 경로+사용자+접근 수를 통합), Identifiers-People 3,680(모든 아티팩트의 사람 식별자 열을 모아 한 표), Google Searches 399, Social Media URLs, Rebuilt Webpages, Parsed Search Queries, Cloud Services URLs, Identifiers-Device, Passwords and Tokens 131, Classifieds/Web Chat/Malware-Phishing/Facebook URLs, User Accounts(통합). 공통 열은 `Artifact`·`Artifact ID`로 원본 행을 가리킨다.
- 결과 위치(`hit_location`): `hit_type` 0=파싱 1=카빙, `deleted_source_file` 플래그. 이 케이스는 파싱 157만 / 카빙 40만, 삭제 원본 2.8만 → 모든 행에 "파싱/카빙 · 삭제 원본" 두 비트가 붙는다.
- `hit_set`(28개): 같은 값(해시 등)으로 행을 묶는 관계 집합 — 중복 제거·"같은 파일의 다른 흔적" 연결.
- 해시: `hit_hash`(루트 소스별), `hit_alternative_hashes`(PhotoDNA·SHA-2/3·BLAKE2, 매치된 해시 DB 값), `hit_media_category`(Project VIC 연결).
- 비어 있지만 스키마가 있는 것: `mitre_attack_rule`(스캔별 규칙 세트 저장), `yara_rules`, `keyword_search`, `snapshot/snapshot_item`, `media_category` → AXIOM은 규칙 세트 원문을 케이스에 보존한다. 우리 `triage-flags` 요약에 규칙 버전 목록을 넣기로 한 설계와 같은 방향이며, **규칙 YAML 원문 해시를 `summary.json`에 함께 저장**해야 재현성이 같아진다.

### 우리 16 도메인과의 대응
| AXIOM 그룹 | 우리 도메인(`features/tree/domains.ts`) | 비고 |
|---|---|---|
| Operating System | 운영체제·계정 + 실행 흔적 + 파일시스템 + 레지스트리 + 이벤트 로그 | AXIOM은 한 그룹 60개, 우리는 5 도메인으로 분할(사건 유형 탐색엔 우리가 유리) |
| Web Related | 웹·브라우저 | 브라우저별 세부(캐시·세션·탭·파비콘·로컬 스토리지·확장)가 우리보다 10배 세밀 |
| Communication, Email & Calendar | 메신저·메일 | Outlook 약속/연락처, 첨부 통합 표가 없음 |
| Media | 미디어·문서 | Skin tone, PhotoDNA, 원본 가능성(Potential Original Media), 카테고리 |
| Documents | 미디어·문서 | 문서 유형별 아티팩트(PDF/RTF/HWP/Backstage/Sticky Notes) |
| Connected Devices | 연결 장치·원격 | RDP(이벤트+비트맵 캐시)·USB·Your Phone |
| Refined Results | (없음) | **파생 아티팩트 계층 부재** — 가장 큰 구조 격차 |
| Custom(시그니처 불일치·카빙 아카이브) | 파일시스템 › 시그니처 불일치/복구 | 유형별 분리(문서/사진/컨테이너/오디오/비디오) |
| Encryption & Credentials | 안티 포렌식 | 암호화 파일·안티포렌식 도구 |
| Location & Travel, Cloud Storage | 위치·여행, 클라우드 | 동일 |
| Analyst created, Additional Sources | (없음) | 분석가 생성 아티팩트·추가 소스(DMG/ISO 등 중첩) |

## 3. 아티팩트별 열(셀) 모델 — `fragment_definition`

AXIOM의 열 설계는 테이블 하나로 통제된다: 아티팩트 버전마다 `name, sort_order, precedence, importance(1|2), data_type(String|DateTime|Integer|Float|List|Attachment), content_type(의미 태그)`. 총 1,760 열 정의, 의미 태그 80여 종. 우리 `FieldDef{key,label,format,timeKind,derive,expectWhen}`와 1:1로 대응되며, 차이는 다음 세 가지다.

1. **의미 태그(content type)** — `PersonIdentifier`, `PersonSenderIdentifier`, `PersonRecipientIdentifierList`, `DeviceIdentifier`, `FileSystemIdentifier`, `DataIdentifier`(해시), `Url`, `FilePath`, `Location/Latitude/Longitude`, `CreationDateTime/LastModifiedDateTime/LastAccessDateTime/SentDateTime/ReceivedDateTime/DateTimeLocal`, `Attachment/Image/Video/Audio/Document`, `Password`, `SearchTerm`, `AccessCount`, `SkinTonePercentage`, `PhotoDnaHash`. 이 태그가 **Refined Results(사람/장치 식별자 통합), 타임라인(시각 종류), 지도(좌표), 연결(Connections) 뷰**를 자동으로 만든다. 우리는 `timeKind`만 있다 → `FieldDef.semantic`(사람·장치·경로·URL·해시·좌표·검색어·첨부)을 추가하면 "모든 계열의 사람 식별자 한 표", "경로 통합 표"를 공짜로 얻는다.
2. **importance** — 1(핵심)/2(보조)로 "행 완전성" 판단과 기본 열 노출에 쓴다. 우리 `core/table` 구분과 같다.
3. **시각 이름 규약** — 모든 시각 열 이름에 "UTC (yyyy-mm-dd)" 또는 "Local Time"이 박혀 있어 혼동이 없다. 우리는 ts_kind 칩으로 대신한다(동일 목적, 더 좁은 열).

### 계열별 핵심 열 비교(우리 카탈로그 `docs/research/forensic-field-catalog-*` 대비)
| 계열 | AXIOM 열(순서대로) | 우리 카탈로그에 없는 것 |
|---|---|---|
| Windows Event Logs | Event ID, Event Type, SID, Created UTC, Record ID, **Description Summary**, Level, Keywords, Provider, Task Category, Computer, Event Data | 사람이 읽는 **요약 문장** 열(이벤트 ID별 템플릿) |
| Event Logs – User Events(4624/4625/4634/4672…) | Event ID, Created, Record ID, Summary, **Logon Type, Subject User/Domain/SID, Target User/Domain/SID**, Event Data | 우리도 로그온 유형·원격 IP를 넣었으나 Subject/Target 분리가 없음 |
| RDP | Event ID, Created, Registry Key Modified, **Direction(인/아웃)**, Summary, Origin Service/Domain/IP/Port, Destination User/Domain/IP/Port | 방향 열, 레지스트리(Terminal Server Client 서버 목록) 시각과 이벤트의 통합 |
| Pictures | Image, 파일명, 확장자, 생성/접근/수정 UTC, 크기, **Skin Tone %**, 원본 W/H, Exif 추출 상태, 생성 Local, **DateTimeOriginal Local, Modified Local, Timezone**, Software, Make, Model, 카메라/렌즈 일련번호, 위도/경도/참조, 고도, Exif 전체, MD5, SHA1, PhotoDNA, **Potential Original Media**, Category | Exif 추출 상태, 로컬/UTC 쌍, 일련번호, 원본 가능성 판단, 카테고리(해시 세트) |
| KakaoTalk Shared Pictures(Windows) | Message ID, Chat ID, Sender ID, Sent UTC, 크기, 썸네일 URL, 썸네일, 다운로드 위치, 다운로드 완료 UTC, 첨부, 첨부 URL, **Deleted**, 확장자, MIME, 첨부 ID | 우리 메신저 핵심 열(대화방·발화자·방향·첨부·삭제)과 일치. 다운로드 완료 시각·썸네일 URL 추가 가치 |
| Outlook Emails | Sender Name/Email, Recipients, Subject, Exchange 계정, Created/Sync/**Submitted/Delivered**/Modified UTC, Body, Start/End(약속), Call Duration, **Folder**, CC, BCC, 본문 유형, Attachments, Headers, Priority, Importance, Sensitivity, **Read**, MD5, SHA1, 첨부 메시지 여부, Thread ID, Message ID | 폴더·읽음·스레드 ID·제출/배달 시각 쌍(Date-Received 지표의 근거) |
| Email Attachments(통합) | 파일명, Artifact, Artifact ID, Subject, 확장자, 크기, 생성/접근/수정, MD5, SHA1, 썸네일, Skin Tone, To, From, 이메일 시각, 첨부, CC, BCC | **모든 메일 계열의 첨부를 한 표**로 |
| LNK | Linked Path, 생성/수정/접근, **Target 생성/수정/접근**, Arguments, Target Attributes, Drive Type, **VSN, Volume Name**, Show Command, NetBIOS, MAC, Target Size | 우리 카탈로그와 동일(USB VSN 교차 지표의 근거) |
| Prefetch | App Name, Path, Run Count, File Created, Last Run, File Hash, 2nd~8th Last Run, Volume Name/Created, Volume2 Name/Created, File, Directory | 8회 실행 시각을 열로 펼침(우리는 배열) |
| USB | Device Class ID, Serial, Friendly Name, **Associated User Accounts**, Last Drive Letter, Last Connected, First Connected Local, First Connect Since Reboot, Install, First Install, **Last Insertion, Last Removal**, Class, Description, Manufacturer, Volume GUID, VSN Dec/Hex | 사용자 연결(MountPoints2), 삽입/제거 시각(이벤트 로그 결합) |
| Shellbags | Path, First/Last Interaction, Mode, FS 수정/접근/생성, MFT Record, bag MRU path | 동일 |
| UsnJrnl | File Name, USN, Timestamp, Reason, MFT Record/Ref, Parent Record/Ref, Attributes, Source Info, Security ID | 동일 |
| NTFS Timestamp Mismatch | File Name, MFT Record, SI/FN 생성·수정·접근·MFT수정 8개, **Reason** | 우리 `si_before_fn` 지표가 같은 것. AXIOM은 아티팩트로 승격(903건) |
| User Accounts – Windows | User Name, Full Name, Type, SID, RID, Internet User/UID(MS 계정), Profile Path, Last Login, Last PW Change, PW Required/Secured/Hint, LM/NTLM Hash, Description, Groups, Login Script, **Last Incorrect PW Login, Login Count, Disabled, Auto Logon** | 로그인 수·비활성·자동 로그온·마지막 실패 |
| Scheduled Tasks | Name, Command(List), Author, Created Local, Run As, Last Run Local, Privilege Level, Description, Status, Triggers, Actions, Run Options, Hidden, File | Hidden·Privilege Level 열 |
| Locally Accessed Files(파생) | Path, Path Type, Accessed UTC/Local, User, Access Count, Artifact, Artifact ID | **파생 통합 표** |
| Potential Browser Activity | URL, User Agent | 카빙 URL 8.5만 — 우리 브라우저 카빙 없음 |

## 4. 검토(Review) 모델

- **태그**: `tag`(시스템 태그 Bookmark/Evidence/Of interest + 예외 태그, 색상 int, 유형 system/user) ↔ `case_tag`(케이스에 허용된 태그) ↔ `hit_case_tag`(행×태그). 이 케이스: Evidence 107,827행, Bookmark 29,427행 — **검토 태그가 10만 단위로 붙는다**. 우리 리뷰 마크(관련/재검토/제외/보고서 포함)는 4종 고정이라 사용자 정의 태그·색·단축키(`TagShortcuts` 설정: 태그 id + 키 + 수정자)가 없다.
- **메모**: `hit_note`, `source_note`, `case_info_note` 모두 작성자·시각·삭제 표시(soft delete). 이 케이스는 0건(태그 중심 검토).
- **태그 동기화**: `TagSyncingEnabled` — 같은 해시/값의 행(`hit_set`)에 태그를 전파.
- **시간 필터 이력**: 절대/상대 시간 필터를 사용자 설정에 기록(요일 필터, DST 포함) → 자주 쓰는 조건 재사용. 우리 조건 패널(U-F1)에 "최근 조건" 저장이 없음.
- **내보내기**: Excel 내보내기는 **아티팩트별 xlsx 1개**(한국어 파일명) + `Attachments/` + `ExportSummary.json`(옵션·요약·문제). 모든 시트의 열 규약: `레코드 | 태그 | 주석 | <아티팩트 열…> | 소스 | 위치 | 증거 번호 | 삭제된 출처 | 검색 결과 | 항목 ID`. 즉 **행마다 소스 경로·물리 위치·증거 번호·삭제 여부·파싱/카빙·고유 ID**가 따라간다. 우리 추출/보고서 번들에는 "위치(오프셋)"와 "검색 결과(파싱/카빙)"가 없다.
- **파생 결과로 검토 시작**: Identifiers-People·Locally Accessed·Passwords and Tokens·Malware URLs처럼 "검사관이 먼저 볼 표"가 아티팩트로 제공된다. 우리 트리 "특이사항" 섹션(U-F4)이 비슷한 역할이지만 규칙 결과(플래그)이지 통합 표는 아니다.
- 로그로 본 뷰 종류: column view(격자), Explorers(파일 시스템/레지스트리 탐색기), viewCard(상세 카드). 타임라인·연결·지도 뷰는 라이선스/동글 없이는 확인 불가.

## 5. 우리 콘솔에 반영할 항목(우선순위)

| # | 항목 | 어디에 | 근거 |
|---|---|---|---|
| A1 | **케이스 만들기 흐름**(사건 정보 → 증거 N개 → 처리 옵션 스냅샷 → 실행), 작성자 있는 메모/태그 | P2 첫 항목(`docs/plans/run-model-p2-2026-10-12.md` 갱신) | §1 |
| A2 | `FieldDef.semantic` 의미 태그 + **파생 통합 표**(사람 식별자, 장치 식별자, 로컬 접근 경로, 첨부 통합, 암호/토큰, URL 분류) | 뷰어 라운드 2 후속(U-F8) 또는 P4 | §2 Refined Results, §3-1 |
| A3 | 행 공통 메타: 파싱/카빙 · 삭제 원본 · 물리 위치(오프셋) · 증거 번호 · 파서 버전 — 그리드 열·인용·내보내기에 항상 포함 | 현재 라운드 인용(U-F6)과 내보내기 | §2 hit_location, §4 내보내기 |
| A4 | 사용자 정의 태그(색·단축키)와 태그 전파(같은 해시) | 검토 단계 | §4 |
| A5 | 이벤트 로그 **요약 문장** 열(ID별 템플릿), RDP 방향 열, 계정 로그인 수/비활성/자동 로그온, 이미지 Exif 상태·로컬/UTC 쌍·원본 가능성 | 카탈로그 YAML 보강(D1 후속) | §3 표 |
| A6 | 규칙 세트 원문 해시를 지표 요약에 저장(MITRE/YARA 보존 방식) | `triage-flags` summary.json | §2 |
| A7 | 조건 패널 "최근 조건" 저장, 요일/시간대 필터 | U-F1 후속 | §4 |
| A8 | 브라우저 카빙 URL(Potential Browser Activity) · 브라우저 세부(캐시·세션·탭·확장) · 시그니처 불일치 유형 분리 | P3 파서 깊이 | §2 |
| A9 | 처리 문제를 사유별 집계 + 항목 연결, 사후 작업(인덱스 재생성) 이력 | 처리 단계(P2) | §1 |

## 6. 관찰 방법 메모
- 열람 명령: `sqlite3.connect('file:<mfdb>?mode=ro&immutable=1', uri=True)` — WAL/저널 생성 없이 읽기. 8.6 GB에서 집계 쿼리 수십 개가 수 분 내 완료.
- 스키마 덤프·집계·열 정의 원문은 세션 스크래치(`scratchpad/axiom/{schema,agg,frags}.txt`)에 있으며 저장소에는 넣지 않는다.
- 동글 없는 Examine은 열람만 가능하므로 UI 캡처 대신 DB·내보내기·로그로 역추적했다. 타임라인/연결/지도 뷰의 실제 동작은 미확인.

## 7. AXIOM Examine 실행 관찰 — UI/UX/접근성 (2026-10-17, 무면허 모드)

동글 없이 Examine 9.11을 띄워 아티팩트 탐색기만 직접 조작했다(대시보드·레지스트리·미디어 탐색기·커넥션·타임라인·파일 시스템 탐색기는 비활성). 스크린샷은 세션 스크래치에만 두고 저장소에는 넣지 않는다(케이스 데이터 포함). 조작은 PowerShell `SetForegroundWindow` + `mouse_event`/`SendKeys`, 접근성은 UI Automation 트리 덤프로 확인했다.

### 7.1 화면 구조
- **4단 고정 레이아웃**: 메뉴(파일·도구·프로세스·도움말) › 필터 바(필터 세트 · 증거 · 아티팩트 · 콘텐츠 유형 · 날짜/시간 · 태그/주석 · 더 많은 내용 · 키워드 검색 · 고급) › [왼쪽 탐색기 전환 + 트리] [중앙 결과 + 뷰 전환] [오른쪽 세부 정보] [접힌 세로 탭 "태그 및 주석"] › 상태 바(시간대 UTC+9).
- **탐색기 전환**(Alt+1~7): 케이스 대시보드·레지스트리·미디어 탐색기·아티팩트·커넥션·타임라인·파일 시스템. 우리 레일(Alt+1~5)과 같은 발상이지만 AXIOM은 "데이터 종류별 탐색기", 우리는 "조사 단계별"이다. 둘 다 필요: 단계 레일 안에서 탐색 단계가 데이터 탐색기(아티팩트/파일/레지스트리/타임라인)를 품는다.
- **결과 뷰 전환**(Alt+Shift+1~7): 대화 · 세계지도 · 열 · 축소판 그림 · 클래식(격자 위 + 세부 아래) · 행(카드) · 히스토그램(아티팩트별 건수 막대 + 기준선 저장/로드 비교). 우리 v2에는 열/썸네일/대화/히스토그램이 있고 **클래식(상하 분할)과 기준선 비교가 없다**.
- 트리: 그룹(상세 결과·웹 관련·커뮤니케이션·미디어·이메일 및 캘린더·문서·추가 소스·클라우드 저장소·애플리케이션 사용량·운영 체제·암호화 & 로그인 정보·…) › 아티팩트, 건수 우측 정렬. 필터를 걸면 트리가 "일치하는 결과 N / 그룹별 N"으로 바뀐다(전체 대비 비율 `1,762,839개 중 590,810개`를 제목에 표시).

### 7.2 좋은 점(가져올 것)
1. **셀 안 라벨+값 2줄**: 혼합 아티팩트 격자에서 "주요 세부 정보 / 지원 세부 정보 / 추가 세부 정보 / 날짜 및 시간" 4열을 쓰고, 셀마다 위에 작은 라벨(예: "연결된 경로"), 아래 값. 종류가 섞여도 열이 깨지지 않는다. 단일 아티팩트로 필터하면 그 아티팩트의 실제 필드 열(이벤트 ID·이벤트 유형·보안 식별자·생성한 날짜/시간·레코드 ID·설명 요약…)로 자동 전환된다. → 우리 교차 kind 격자(도메인 노드가 여러 artifact_type을 합칠 때)에 **"요약 열 + 라벨 2줄 셀"** 모드를 넣고, 단일 계열이면 카탈로그 열로 전환(U-F3와 정합).
2. **행 왼쪽 태그 스트라이프**: 북마크(연두)·증거(빨강) 색 막대가 행 좌측 6 px에 붙어 스크롤 중에도 보인다. 우리 리뷰 마크 칩보다 밀도가 높다 → 그리드 행 좌측 스트라이프 추가(색은 토큰).
3. **행 보기(카드)**: 제목(경로) · "아티팩트 — 그룹" 부제 · 핵심 시각 1줄 · 우측 굵은 날짜 열 · 호버 시 인라인 액션(내보내기/보고서 생성, 소스 파일 열기). 우리 "행 뷰" 밀도 설계의 참고.
4. **세부 정보 패널 규약**: 제목(대표 값) › 노란 안내 배너("일부 정보를 표시할 수 없습니다 · 소스 찾기") › 증거 번호 카드 › 아티팩트 정보(라벨 우측 정렬·값 굵게·시각 옆 ⏱ 타임라인 아이콘) › 증거 정보(소스 파티션+경로, 복구 방법 파싱/카빙, 삭제된 출처, 위치 File Offset, 증거 번호). 파생 결과 행은 "원본 아티팩트" 링크로 원 행에 점프. → 우리 뷰어 메타 시트의 **고정 꼬리 섹션(소스·복구 방법·위치·증거 번호·원본 행 링크)** 으로 채택(§5 A3).
5. **필터 바**: 조건마다 드롭다운 팝오버(검색 상자 + 체크리스트 + 초기화 + 취소/허용), 적용되면 버튼 라벨이 선택값으로 바뀌고 굵게("Windows 이벤트 로그"), 우측에 "필터 저장 · 필터 지우기"가 나타난다. 날짜 팝오버에 절대/상대 탭 + "날짜/시간 스탬프 없는 히트 포함" + **최근 필터 3개**. 태그 팝오버에 태그별 건수. "더 많은 내용"으로 바에 올릴 조건을 고른다(프로필·부분 결과·키워드 목록·스킨톤·미디어 범주화·VICS). → U-F1 조건 패널과 같은 방향. 추가할 것: 적용된 조건이 **바의 라벨 자체로 표시**(칩 대신), 최근 조건, 필터 세트 저장/관리.
6. **태그 패널**: 세로 탭으로 접혀 있다가 펼치면 기존 태그 체크(색 사각형) + 새 태그 + 주석 + 태그 관리. 도구 메뉴에 태그 관리 Ctrl+B. → 사용자 정의 태그(§5 A4).
7. **썸네일 뷰**: 번호 캡션, 지연 로딩, 호버 확대 팝업, 정렬 기준/크기 드롭다운, 오른쪽에 미리 보기(확대/축소 %) + "관련 미디어 아티팩트 (4)" + 세부(크기·스킨톤 %·원본 W/H·Exif 상태·해시). **검사관 보호 바**: 미디어 흐리게 · 음향 켜기 · 리마인더 설정(휴식 알림). → 우리 미디어 갤러리에 흐리게 토글·관련 미디어 묶음(같은 해시/pHash)을 추가.
8. **프로세스 메뉴**: 새로운 증거를 사례에 추가 · 사례에서 증거 제거 · 카빙으로 아티팩트 재처리 · 키워드 추가 · 해시로 사진/비디오 분류 · CPS 내보내기 · Magnet.AI 분류. 처리 단계가 "사례 메뉴"로 살아 있다 → 우리 처리 단계(P2)의 카드 목록과 대응.
9. 단축키 체계: 탐색기 Alt+N, 뷰 Alt+Shift+N, 태그 Ctrl+B, 열기 Ctrl+O, 종료 Alt+F4. 우리는 Alt+1~5 레일 + 단일 키(F/T/J/K/R) — 충돌 없음.

### 7.3 나쁜 점(피할 것)
1. **접근성 이름 부재**: UIA 트리에서 최소화/최대화/닫기·홈·팝아웃·필터 드롭다운·열 옵션 버튼이 모두 이름 없음(`Button ''`). 트리 항목 이름이 뷰모델 클래스명(`Magnet.ViewModels.NavigationItems.ArtifactTypeGroupItem`), 격자 행 이름이 `VirtualArtifactHitItem [값/ID/IsSelected:True]`, 셀 이름이 "항목: …, 열 표시 인덱스: N"으로 **셀 값이 노출되지 않는다**. 검색 상자 이름이 'WatermarkTextBox'. 스크린 리더로는 사실상 사용 불가. → 우리 a11y 계약(모든 버튼 이름·행/셀 값·트리 항목 레이블·폼 라벨)을 유지하고 e2e로 지킨다.
2. **키보드**: 격자에서 Tab이 셀 단위로 이동하며 수평 스크롤을 끌고 가 첫 열이 사라진다. 포커스 링이 선택 강조와 구분되지 않고, 화살표 이동 후 이전 행 강조가 남아 2행이 선택된 것처럼 보인다. 팝오버는 Esc로 닫히지만 "더 많은 내용"은 취소 버튼만 닫는다(모달 불일치). → 우리는 행 단위 포커스(J/K), 가시 포커스 링, 모든 팝오버 Esc 닫힘·포커스 복귀.
3. **정렬 불일치(지역화)**: 트리의 아티팩트가 한국어 라벨인데 **영문 원명 순**으로 정렬되어(`$LogFile 분석, AmCache…, 자동 실행 항목, 기본 브라우저, 파일 연결, 점프 목록, 키워드 검색어, 알려진 DLL, LNK 파일…`) 한국어 사용자가 위치를 예측할 수 없다. 메뉴·열 라벨에는 번역 품질 편차("암호화 & 로그인 정보", "엔딩 섹터", "스타팅 섹터"). → 우리 트리는 한국어 라벨 기준 정렬(또는 고정 포렌식 순서), 용어집 기반 라벨.
4. **열 머리글 잘림**: 단일 아티팩트 열 모드에서 "이벤..."처럼 머리글이 잘리고 툴팁 없이 ⋮ 메뉴(열 숨기기·모든 열 표시·열에서 필터링·열 고정)만 있다. 기본 폭이 내용 기준이 아니다. → 우리는 머리글 최소 폭 + 줄임 시 title, 열 폭 자동 맞춤.
5. **상태 전환 공백**: 아티팩트 필터 적용 직후 격자가 비고(로딩 표시 없음) 오른쪽 세부는 이전 행(LNK)을 그대로 보여 수 초간 불일치. 트리 항목 클릭 직후에도 이전 아티팩트의 열 구성이 남아 빈 셀만 보였다. → 로딩 스켈레톤 + 선택 해제 시 세부 패널 비움(우리 150 ms 디바운스 규칙 유지).
6. **제목 품질**: 세부 패널 제목이 대표 값 하나(이벤트 ID "17", 쓰레기 시각 "1628-03-03 AM 6:30:56")라 무엇인지 알 수 없다. 카빙 LNK의 비정상 시각(1628년)이 경고 없이 표시된다. → 우리 뷰어 제목은 "아티팩트 종류 · 대표 값", 비정상 시각은 특이사항 규칙(`timestamp_out_of_range`)으로 표시.
7. **트리 스크롤**: 항목이 많고 휠/PageDown 반응이 둔해(가상화) 원하는 아티팩트를 찾기 어렵다. 트리 검색 입력이 없고 아티팩트 필터 팝오버의 검색으로 우회해야 한다. → 우리 트리 검색 입력(이미 계획) + U-F7 빈 계열 숨김이 그대로 해법.
8. **창 모드 아이콘**: 패널 우상단 "팝아웃" 버튼(id=PopOutButton)이 있으나 이름·툴팁이 없어 발견이 어렵다. → U-F2 창 모드는 명령 팔레트·단축키·툴팁 3경로.
9. 무면허 모드에서 비활성 기능이 회색 처리될 뿐 사유(라이선스 필요)를 설명하지 않는다("고급" 링크·"이동" 버튼). → 우리 DisabledReason 규칙 유지.

### 7.4 이번 라운드에 즉시 반영
- 그리드 행 좌측 리뷰 스트라이프(7.2-2), 혼합 kind 격자의 라벨 2줄 셀(7.2-1), 세부 패널 고정 꼬리 섹션(7.2-4), 필터 바 라벨 치환·최근 조건(7.2-5), 비정상 시각 규칙(7.3-6)을 `docs/plans/viewer-families-2026-10-15.md` U-F8로 추가한다. 나머지는 §5 표의 P2/P4 항목에 흡수.
