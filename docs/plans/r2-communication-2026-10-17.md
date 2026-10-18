# R2 — 커뮤니케이션·유출 경로 라운드 (2026-10-17)

근거: `docs/plans/axiom-parity-roadmap-2026-10-17.md` §2 R2, `docs/research/axiom-parity-matrix-2026-10-17.md` §4 갭 1·2·3·5·6. 목표: 커뮤니케이션 그룹 "있음" 0/54 → ≥30/54, 유출 경로(메신저·웹메일·클라우드·메일) 증거가 행 단위로 나오고 통합 보기(사람·첨부·URL)·특이사항 규칙에 자동 반영.

## 1. 최종 사용자가 보는 문제
- 업무 PC 이미지에 Teams·Slack·Telegram Desktop·LINE PC·카카오톡 PC가 있어도 대화가 행으로 나오지 않는다(인벤토리·키 후보만). 누가 누구에게 무엇을 보냈고 어떤 파일을 전송했는지 답할 수 없다.
- 브라우저 캐시는 목록만 있어 웹메일 첨부 업로드·웹하드 업로드 페이지를 복원하지 못한다. 레거시 Edge/IE 기록은 구조 인벤토리뿐이다.
- OneDrive·Dropbox·Google Drive·네이버 MYBOX 동기화 클라이언트의 계정·동기화 폴더·업로드/삭제 이벤트가 열로 정리되지 않는다.
- Outlook PST/OST는 문자열 인벤토리뿐이라 폴더·약속·연락처·첨부를 볼 수 없다.

## 2. 이상 상태
- 메신저·메일 도메인에 앱별 노드(대화·첨부·연락처)가 생기고, 메신저 계열 카탈로그 열(대화방·발화자·방향·첨부·삭제)로 보인다. 대화 뷰로 읽을 수 있다.
- 웹·브라우저 도메인에 "캐시 항목", "레거시 Edge/IE", "웹메일 업로드 후보" 노드가 생긴다.
- 클라우드 도메인에 클라이언트별 노드(계정·동기화 폴더·이벤트)가 생기고 `cloud.bulk_upload` 지표가 뜬다.
- 메일 도메인에 PST/OST 메시지·약속·연락처·첨부 노드가 생긴다(외부 도구 있을 때; 없으면 "도구 없음" 사유).
- 통합 보기 사람·첨부·URL 표와 특이사항이 새 행을 자동으로 읽는다(카탈로그 의미 태그로).

## 3. 설계 — 4갈래(각자 워크트리·브랜치, 코디네이터가 `feat/axiom-adoption` 위에 병합)
공통: 순수 표준 라이브러리(프로젝트 정책), 각 파서는 바운디드(파일 크기·행 수 상한, 손상 입력 격리), 행에 `recovery_method`·`parser_version`·`source_path`·`source_offset`, 모든 라벨 한국어, 픽스처는 합성(실제 앱 DB 스키마를 코드로 생성; 실데이터·PII 금지). 새 artifact_type마다 카탈로그 YAML 계열(열·의미 태그·규칙 id)·`features/tree/domains.ts` 노드(추가만)·`known-limitations` 갱신·OpenAPI 영향 없음.

### 3.1 M1 — Windows 데스크톱 메신저 공급자 `windows-messenger` (`rapidtriage/artifacts/windows/messenger.py`)
- 경로 서명(`AppData\Roaming|Local\<app>`): Teams(IndexedDB/LevelDB `.ldb/.log` + `Teams\IndexedDB`, 신규 Teams `EBWebView`), Slack(`Slack\IndexedDB`, `Local Storage\leveldb`), Discord(`discord\Local Storage\leveldb`), Telegram Desktop(`tdata` — 암호화: 존재·세션·캐시 파일 인벤토리 + 미디어 캐시 `user_data\cache`), WhatsApp Desktop(`WhatsApp\IndexedDB`/`LocalStorage`, `msgstore` 없음 명시), Skype(`Skype for Desktop\IndexedDB`, 구 `main.db` SQLite), LINE PC(`LINE\Data\...` SQLite/암호화 표시), WeChat PC(`WeChat Files\<wxid>\Msg\*.db` SQLCipher — 인벤토리), Zoom(`Zoom\data\zoomus.db`, `zoommeeting.db`).
- 행 유형: `chat-message`(앱·대화방·발화자·수신자·시각·본문·방향·삭제 여부), `chat-attachment`(파일명·크기·경로·해시·전송 방향), `chat-contact`, `chat-app-inventory`(암호화/미지원 앱: 존재·버전·마지막 사용·파일 수). LevelDB/IndexedDB는 레코드 수준 파싱 대신 **바운디드 문자열·JSON 조각 복구**(`.ldb` 블록 압축 해제는 snappy → 순수 파이썬 구현, 상한 적용)로 메시지 후보를 뽑고 `recovery_method=carved`로 표기.
- `artifacts/mobile/messengers.py`의 프로필(표 이름·열 매핑)을 재사용할 수 있는 SQLite 앱(Skype main.db, Zoom, LINE 일부)은 재사용.
- 규칙: `messenger.external_file_transfer`(B: 첨부 전송 상대가 조직 외부 도메인/미등록 연락처), `messenger.after_hours_burst` 기존 규칙에 앱 추가.

### 3.2 M2 — 카카오톡 PC 메시지·공유 사진 + Outlook PST/OST·ICS (`artifacts/kakaotalk_windows.py`, `artifacts/email_external.py`, 새 `artifacts/email_pst.py`)
- 카카오톡: 런 단계에서 키 재료 후보가 있고 `kakaotalk-decrypt`(`core/kakaotalk.py`)가 복호 가능하면 `kakaotalk-message`(대화방·발화자·시각·본문·첨부 참조·삭제) 행 생성; 불가하면 `kakaotalk-app-inventory`에 "복호 키 없음 — 사유". 공유 사진 캐시(`KakaoTalk\...\cache`, 썸네일·원본) → `kakaotalk-shared-picture`(메시지 id 연결 가능 시, 다운로드 위치·완료 시각·MIME·해시). 암호 크래킹·키 브루트포스는 하지 않는다(정책).
- Outlook: `pffexport`/`readpst` 래퍼 출력을 `email-message`(발신·수신·CC·BCC·제목·제출/배달 시각·폴더·읽음·스레드 id·메시지 id)·`calendar-event`(제목·시작·종료·참석자·장소)·`contact`(이름·이메일·전화·조직)·`email-attachment`(파일명·크기·해시·원본 메시지 참조) 행으로 정규화; 도구 없으면 `email-container-inventory` + `/doctor` 표시. ICS 파일 파서(순수 파이썬, RFC 5545 VEVENT) → `calendar-event`.
- 규칙: `email.external_bulk_attachments`(B: 외부 도메인 수신자에 첨부 n개 이상/하루), `email.deleted_folder_recent`(C).

### 3.3 M3 — 브라우저 심화 (`artifacts/windows/browser.py` + 새 `artifacts/windows/browser_cache.py`, `browser_webcache.py`)
- Chromium 캐시 항목 디코딩: Simple Cache(`f_*` 항목: EOF 헤더·키·HTTP 응답 헤더)와 블록파일(`index`, `data_0..3`) → `browser-cache-entry`(URL·호스트·메서드·상태·Content-Type·Content-Length·응답 시각·본문 해시·본문 크기·압축 여부). 본문은 저장하지 않고 해시·크기·앞 256바이트 서명만. 상한: 항목 수 200k, 본문 읽기 4 MB.
- 레거시 Edge/IE `WebCacheV01.dat`(`ese_native.py`): 컨테이너 행 `History`·`Content`·`Cookies`·`DOMStore`·`iedownload` → `browser-history`(기존 유형 재사용)·`browser-cache-entry`·`browser-cookie`·`browser-download`.
- 프로필 경로 추가: Opera(`Opera Software\Opera Stable`), Naver Whale(`Naver\Naver Whale\User Data`), Vivaldi, Brave 확인.
- 웹메일·웹하드 업로드 후보: 캐시 항목·히스토리 URL 패턴(Naver 메일 `mail.naver.com`·`upload`, Daum, Gmail `mail.google.com/mail/u/*/?ui=2&ik=…&attid`, 웹하드 `webhard`, `wetransfer`, `sendanywhere`, `dropbox.com/upload`)과 POST 캐시 항목 → `web-upload-candidate`(URL·서비스·시각·크기·관련 파일 이름 후보). 패턴 목록은 YAML(출처 명시).
- 규칙: `browser.webmail_upload`(B), `browser.filesharing_upload`(B).

### 3.4 M4 — 클라우드 동기화 클라이언트 (`artifacts/cloud.py` 확장 + 새 `artifacts/cloud_sync.py`)
- OneDrive: `settings\Personal|Business1\*.dat`(SyncEngineDatabase.db SQLite, `.odl`/`.odlgz` 로그 — gzip 해제 후 바운디드 문자열) → `cloud-sync-account`(계정·테넌트·동기화 루트)·`cloud-sync-file`(경로·상태·크기·수정 시각·공유 여부)·`cloud-sync-event`(업로드/다운로드/삭제/이름 변경·시각·경로). Dropbox: `Dropbox\instance1\*.dbx`는 암호화 → 인벤토리 + `info.json` 계정·루트 + `host.db`. Google Drive(DriveFS): `DriveFS\<account>\metadata_sqlite_db`·`mirror_sqlite_db` → 파일·이벤트. 네이버 MYBOX: 경로 서명·SQLite 인벤토리(`NaverMYBOX`). iCloud for Windows: 경로 서명.
- 규칙: `cloud.bulk_upload`(A: 1시간 내 업로드 n≥50 또는 500 MB, 기본값 params), `cloud.sync_folder_outside_user_profile`(C).

## 4. QA 시나리오 (타협 없음)
| # | 시나리오 | 기준 |
|---|---|---|
| Q-R2-1 | 합성 픽스처 9앱 | 각 앱 최소 1 양성 픽스처(메시지 2+·첨부 1+·연락처 1+ 또는 인벤토리) + 손상 입력 1(격리, 런 계속) |
| Q-R2-2 | 카카오톡 PC | 키 있음 픽스처 → 메시지 행·공유 사진 연결; 키 없음 → 인벤토리 사유 "복호 키 없음" |
| Q-R2-3 | PST/ICS | 외부 도구 없는 호스트에서 `email-container-inventory` + doctor 안내; ICS 픽스처 → calendar-event 3행 |
| Q-R2-4 | 캐시 디코딩 | Simple Cache·블록파일 픽스처 각 10항목 → URL·상태·Content-Type·본문 해시; 본문 미저장 단언 |
| Q-R2-5 | WebCacheV01 | 합성 ESE 또는 실데이터(run-subset10에 있으면) → History/Content 행 |
| Q-R2-6 | 업로드 후보 | 웹메일·웹하드 URL 패턴 픽스처 → `web-upload-candidate`, 규칙 B 발화 |
| Q-R2-7 | 클라우드 | OneDrive SyncEngine·odl 픽스처 → 계정·파일·이벤트; `cloud.bulk_upload` 양성/오탐 |
| Q-R2-8 | 카탈로그·트리 | 새 artifact_type 전부 카탈로그 계열에 매핑(의미 태그 포함), 트리 노드 한국어 정렬, 빈 계열 숨김과 호환, 통합 보기 사람·첨부·URL 표에 반영 |
| Q-R2-9 | 실데이터 | run-subset10(브라우저·카카오톡 행 있음)에서 새 공급자 실행: 캐시 항목 ≥1, 카카오톡 인벤토리 사유, 오류 0, 추가 시간 ≤60 s |
| Q-R2-10 | 게이트 | unittest/ruff/vulture/compileall/doc-refs/OpenAPI, vitest/tsc/biome/contrast/e2e, 적대적 리뷰 0 미해결 |

## 5. 결과 기록
(구현 후)
